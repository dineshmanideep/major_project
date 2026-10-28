 ## Lazy branch rekeying strategy

  The system does not immediately generate a new key when a member is revoked. Instead, it marks only the affected branch as “stale,” then rotates that
  branch key at the next safe trigger.

  This avoids unnecessary work for inactive branches while ensuring no new message is encrypted with the old branch key after rekeying begins.

  Example branches:

  factory/line3/oven
  factory/line3/motor

  If a vendor is revoked from factory/line3/motor, only the motor branch rotates. The oven branch keeps its existing key and version.

  ### Branch state

  Each managed branch in KeyController stores:

  @dataclass
  class _BranchState:
      root_key: bytes
      key_version: int = 1
      members: set[str] = field(default_factory=set)
      stale_since: datetime | None = None
      last_rekey_at: datetime | None = None

  Meaning:

  - root_key: current 32-byte key for the branch.
  - key_version: increments every time the branch root key changes.
  - members: devices/consumers allowed to obtain the current branch credential.
  - stale_since: set when a member is revoked; means rotation is required.
  - last_rekey_at: operational record of the latest completed rotation.

  A BranchCredential supplied to an authorised device contains:

  @dataclass(frozen=True)
  class BranchCredential:
      branch_path: str
      root_key: bytes
      key_version: int

  The device uses root_key as its held ancestor key and derives keys for individual descendant topics.

  ———

  ## 1. Initial branch setup

  A trusted Key Controller creates each protected branch and gives it an initial root key.

  controller.create_branch(
      "factory/line3/motor",
      members={"motor-01", "gateway", "vendor"},
  )

  The controller generates a secure random 32-byte key unless one is explicitly supplied for testing.

  At this point:

  Branch: factory/line3/motor
  Version: 1
  Members: motor-01, gateway, vendor
  Stale: false

  All authorised members receive or retrieve a credential containing:

  branch_path = factory/line3/motor
  root_key = K_motor_v1
  key_version = 1

  For a message on factory/line3/motor/speed, the publisher derives:

  K(factory/line3/motor/speed)
      = HKDF-Expand(K_motor_v1, "speed")

  ———

  ## 2. Revocation: mark stale, do not rekey yet

  When the vendor loses access:

  controller.revoke("vendor", "factory/line3/motor")

  The important implementation is:

  def revoke(self, device_id: str, branch_path: str, *, now=None) -> None:
      state = self._state(branch_path)

      if device_id not in state.members:
          raise KeyControllerError("device is not authorised for this branch")

      state.members.remove(device_id)
      state.stale_since = now or _now()

  After this call:

  Branch: factory/line3/motor
  Version: 1
  Members: motor-01, gateway
  Stale: true
  Revoked: vendor

  No new key has been generated yet. This is the “lazy” part.

  Why do this?

  - If the branch is idle, no telemetry is currently being sent under the old key.
  - The controller avoids immediate rekey/distribution work for inactive branches.
  - The branch is still marked as needing rotation, so it cannot continue indefinitely with the old key.

  The revoked vendor is immediately denied any future controller credential request:

  controller.credential_for("vendor", "factory/line3/motor")
  # raises KeyControllerError

  ———

  ## 3. Next publish triggers rekey before encryption

  A managed publisher gets its current credential immediately before encrypting:

  credential = self.controller.credential_for(
      self.device_id,
      self.branch_path,
  )

  The controller checks whether the branch is stale:

  def credential_for(self, device_id: str, branch_path: str, *, now=None):
      state = self._state(branch_path)

      if device_id not in state.members:
          raise KeyControllerError("device is not authorised for this branch")

      if state.stale_since is not None:
          self._rekey(state, now or _now())

      return BranchCredential(
          branch_path,
          state.root_key,
          state.key_version,
      )

  If stale, _rekey runs before the publisher receives its credential:

  @staticmethod
  def _rekey(state: _BranchState, at: datetime) -> None:
      state.root_key = secrets.token_bytes(KEY_LENGTH)
      state.key_version += 1
      state.stale_since = None
      state.last_rekey_at = at

  The state becomes:

  Branch: factory/line3/motor
  Version: 2
  Members: motor-01, gateway
  Stale: false
  Root key: K_motor_v2

  Then the publisher encrypts the new telemetry message with the new root key:

  envelope = encrypt_payload(
      plaintext,
      topic,
      credential.root_key,
      credential.branch_path,
      self.device_id,
      credential.key_version,
  )

  For example:

  Topic: factory/line3/motor/speed
  Derived encryption key: HKDF-Expand(K_motor_v2, "speed")
  Envelope key_version: 2

  Therefore, the next message after revocation is never encrypted using the old K_motor_v1 branch key.

  ———

  ## 4. Why the revoked member cannot decrypt new messages

  Before revocation, the vendor might possess:

  K_motor_v1

  After lazy rekeying, the publisher uses:

  K_motor_v2

  The old leaf-topic key is:

  K_speed_v1 = HKDF-Expand(K_motor_v1, "speed")

  The new one is:

  K_speed_v2 = HKDF-Expand(K_motor_v2, "speed")

  Since K_motor_v2 is freshly random, the revoked vendor cannot calculate K_speed_v2 from K_motor_v1.

  The test explicitly verifies that decrypting a version-2 envelope with the revoked member’s old credential fails:

  with self.assertRaises(EnvelopeError):
      decrypt_payload(
          envelope,
          MOTOR_SPEED,
          revoked_credential.root_key,
          revoked_credential.branch_path,
      )

  AES-GCM authentication fails, so no plaintext is returned.

  ———

  ## 5. Subscriber behavior after rekey

  An authorised controller-managed subscriber refreshes its credential before decrypting:

  credential = self.controller.credential_for(
      self.device_id,
      self.branch_path,
  )

  plaintext = decrypt_payload(
      parse_envelope(payload),
      topic,
      credential.root_key,
      credential.branch_path,
  )

  For the gateway:

  gateway → authorised → receives K_motor_v2 → decrypts version-2 telemetry

  For the revoked vendor:

  vendor → no longer authorised → controller rejects credential request
         → cannot access K_motor_v2
         → cannot decrypt subsequent messages

  The implementation silently ignores messages for which a subscriber is no longer authorised:

  except KeyControllerError:
      return

  ———

  ## 6. Bounded staleness for idle branches

  A lazy strategy needs a maximum delay. Otherwise, a revoked branch that never publishes again could remain stale forever.

  The controller has a configurable limit:

  controller = KeyController(
      max_staleness=timedelta(minutes=5)
  )

  A scheduler/background task periodically calls:

  rekeyed = controller.rekey_expired()

  The relevant logic is:

  def rekey_expired(self, *, now=None) -> list[str]:
      current_time = now or _now()
      rekeyed = []

      for path, state in self._branches.items():
          if (
              state.stale_since is not None
              and current_time - state.stale_since >= self.max_staleness
          ):
              self._rekey(state, current_time)
              rekeyed.append(path)

      return rekeyed

  Timeline:

  10:00  Vendor revoked from motor branch
         motor branch becomes stale

  10:03  No publish occurs
         branch remains stale; no rotation yet

  10:05  Scheduler calls rekey_expired()
         branch root key rotates from K_motor_v1 to K_motor_v2

  10:10  A future publisher retrieves version-2 credentials
         next telemetry uses K_motor_v2-derived topic keys

  ———

  ## 7. Branch confinement

  The rekey operation changes only the exact managed branch state:

  state = self._state(branch_path)
  self._rekey(state, current_time)

  It does not iterate across all branches or alter siblings.

  Example:

  factory/line3/motor  → vendor revoked → version 1 → version 2
  factory/line3/oven   → unaffected     → stays version 1

  The test verifies this directly:

  oven_before = controller.credential_for("oven-01", OVEN)

  controller.revoke("vendor", MOTOR)
  controller.credential_for("motor-01", MOTOR)  # triggers motor rekey

  oven_after = controller.credential_for("oven-01", OVEN)

  self.assertEqual(oven_after, oven_before)

  This is important because revoking a motor-branch vendor should not force oven devices, dashboard users, or unrelated branches to replace their keys.

  ———

  ## Current prototype boundary

  The rekeying state machine and cryptographic rotation are implemented. The current Python code models credential distribution through credential_for(...).

  For a production system, the next security layer would be authenticated, encrypted delivery of the rotated BranchCredential to remaining devices—ideally
  using the planned ML-KEM bootstrap/session mechanism.  
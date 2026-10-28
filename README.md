# MP-1 Secure MQTT Prototype

This repository contains a Python reference implementation of encrypted,
topic-hierarchical MQTT telemetry. The MQTT broker is an untrusted relay: it
receives MQTT topic names and encrypted bytes, but never application plaintext
or topic-key material.

## Implemented features

### 1. Topic-hierarchical key derivation

**Code:** `src/topic_keys.py`

This module creates a separate 32-byte AES-256 key for every concrete MQTT
topic, starting from a securely provisioned branch key.

- `derive_child_key(parent_key, child_segment)` derives one child key with
  HKDF-Expand/HMAC-SHA-256.
- `derive_topic_key(held_key, held_path, requested_topic)` walks from an
  authorised ancestor to a requested descendant topic.
- A holder of `factory/line3` can derive keys such as
  `factory/line3/oven/temp` and `factory/line3/motor/speed`.
- A holder of `factory/line3/motor` can derive motor descendants but cannot
  derive an oven key, its parent key, or a sibling branch key.
- Key derivation uses a domain-separated, length-prefixed label encoding:
  `MP1-TOPIC-KDF-v1 || uint16_be(segment_length) || UTF-8 segment`.
- Empty segments, MQTT wildcards (`+` and `#`), non-string paths, oversized
  segments, parent requests, and sibling requests are rejected.
- A fixed derivation vector is tested so a future ESP32/mbedTLS port can match
  the Python output byte-for-byte.

### 2. AES-256-GCM telemetry encryption

**Code:** `src/message_envelope.py`

Every sensor payload is encrypted using the AES-256 key derived for its exact
MQTT topic.

- `encrypt_payload(...)` derives the topic key, creates a random 96-bit nonce,
  and produces an AES-256-GCM envelope.
- `decrypt_payload(...)` derives the same key for an authorised consumer and
  verifies then decrypts the envelope.
- The envelope includes `protocol_version`, `key_version`, `sequence`, `sender_id`,
  Base64 `nonce`, Base64 `ciphertext`, and Base64 authentication `tag`.
- The plaintext is encrypted; the MQTT topic is intentionally not placed in
  the payload because MQTT already provides it for routing.
- AES-GCM additional authenticated data binds the protocol version, MQTT
  topic, sender ID, and key version to the ciphertext. A relay cannot move a
  valid message to another topic, alter its claimed sender, or change its key
  version without authentication failure.
- `serialise_envelope(...)` produces compact JSON bytes suitable for an MQTT
  payload; `parse_envelope(...)` validates and parses received JSON.
- The implementation validates exact fields, protocol version, Base64 fields,
  nonce length, tag length, and authentication tag before returning plaintext.
- Each publisher maintains a positive sequence per topic. The sequence is part
  of the AES-GCM authenticated data, so a broker cannot alter it undetected.

### 3. Encrypted MQTT publisher and subscriber prototype

**Code:** `src/mqtt_prototype.py`

This is the first end-to-end application layer over the encryption modules.

- `EncryptedPublisher` accepts sensor bytes, derives the exact topic key,
  encrypts once, serialises the envelope, and publishes only ciphertext bytes.
- `EncryptedSubscriber` subscribes to `held_path/#`, derives authorised topic
  keys locally, and stores successfully decrypted `(topic, plaintext)` pairs.
- Invalid, malformed, and unauthentic received messages are recorded in the
  subscriber's `rejected` list rather than being exposed as telemetry.
- Subscribers keep the newest sequence for each topic, sender, and key-version
  combination and reject replayed or out-of-order valid envelopes.
- `InMemoryBroker` simulates an untrusted MQTT broker for deterministic tests.
  It only forwards topic names and byte payloads; it does not know keys or
  perform decryption.
- `PahoMqttTransport` is a live adapter for a Mosquitto-compatible broker,
  using the `paho-mqtt` package. The caller subscribes first, then runs its
  MQTT client network loop.
- `FaultInjectingBroker` extends the in-memory relay for recovery tests by
  deliberately dropping selected publishes once.

### 4. Multiple authorised subscribers

**Code:** `tests/test_mqtt_prototype.py`

The prototype demonstrates group-style encrypted delivery.

- A publisher encrypts one envelope for `factory/line3/oven/temp`.
- Two separate authorised consumers, such as a dashboard and historian, use
  their `factory/line3` branch key to decrypt that exact same ciphertext.
- A motor-only consumer is subscribed only to `factory/line3/motor/#`; it does
  not receive oven telemetry and its key cannot derive an oven-topic key.
- A malformed/tampered transport payload is rejected by the receiver.

### 5. Trusted Key Controller and branch membership

**Code:** `src/key_controller.py`

`KeyController` represents the trusted service that owns membership and branch
root keys. It is intentionally separate from the MQTT broker.

- `create_branch(branch_path, members, root_key=None)` creates a managed branch
  with a random 32-byte root key by default and version `1`.
- `add_member(device_id, branch_path)` authorises a device, gateway, or
  consumer for that branch.
- `credential_for(device_id, branch_path)` returns the member's current
  `BranchCredential`: branch path, current root key, and key version.
- Unauthorised members and unknown branches are rejected with
  `KeyControllerError`.
- `branch_status(branch_path)` exposes safe operational state—members,
  key-version, stale flag, and last rekey time—without exposing the root key.
- In this Python prototype, credential retrieval models a secure controller to
  device distribution channel. Authenticating and encrypting that distribution
  channel with ML-KEM is not implemented yet.

### 6. Lazy, branch-confined revocation rekeying

**Code:** `src/key_controller.py`, `src/managed_mqtt.py`

Revocation is implemented as lazy rekeying for one managed branch.

- `revoke(device_id, branch_path)` immediately removes the member and marks
  only that branch as stale. It does not rotate the key at revocation time.
- On the next authorised `credential_for(...)` request, the controller creates
  a fresh random 32-byte branch root key, increments `key_version`, clears the
  stale state, and records the rekey time.
- A revoked member cannot obtain the new credential. Its old root key cannot
  authenticate or decrypt messages encrypted after the rotation.
- `rekey_expired()` forces rotation for stale idle branches after the configured
  `max_staleness` period, so a silent branch cannot remain stale indefinitely.
- Rekeying is confined to the affected configured branch. For example,
  revoking a member of `factory/line3/motor` rotates motor and its descendants;
  a separately managed `factory/line3/oven` branch retains its root key and
  version.

### 7. Controller-managed MQTT endpoints

**Code:** `src/managed_mqtt.py`

These helpers combine the Key Controller with encrypted MQTT operations.

- `ControllerManagedPublisher` asks the controller for its current credential
  immediately before each encryption. Therefore, a stale branch is rekeyed
  before the next ciphertext is published.
- The current credential's `key_version` is embedded in the AES-GCM envelope,
  so recipients authenticate both the ciphertext context and its key version.
- `ControllerManagedSubscriber` obtains its current credential before
  decrypting. Once revoked, it can no longer retrieve the rotated key and does
  not expose subsequent telemetry.
- The integration test verifies a gateway receives messages before and after
  rotation, while a revoked vendor receives only the pre-revocation message.

### 8. Hardware-free encrypted key-distribution simulation

**Code:** `src/simulated_key_distribution.py`

This feature simulates devices, the Key Controller, and encrypted MQTT key
updates entirely in Python; no ESP32 or physical sensor is needed.

- `SimulatedDevice` represents a software-only publisher, gateway, or vendor.
  It stores received branch credentials locally.
- Each simulated device has a unique 32-byte controller-to-device distribution
  key. This models the authenticated session key that ML-KEM onboarding will
  establish in the final project; it is not itself an ML-KEM implementation.
- `SimulatedKeyDistributor` encrypts the branch root key separately for every
  remaining authorised device using AES-256-GCM, then sends it over MQTT on
  `_bootstrap/<device-id>/branch-key-update`.
- The broker forwards encrypted update bytes only. It cannot read the new root
  key. A revoked device is no longer a controller member, receives no update,
  and retains only its obsolete key.
- `SimulatedManagedPublisher` and `SimulatedManagedSubscriber` use credentials
  stored by the simulated device, rather than reading keys directly from the
  controller. This models the final device-side behavior.
- Tests cover initial key delivery, encrypted rekey delivery to remaining
  members, exclusion of the revoked vendor, and encrypted telemetry after key
  rotation.

### 9. Authenticated post-quantum ML-KEM onboarding

**Code:** `src/pqc_onboarding.py`

The software simulation now implements the planned post-quantum bootstrap
instead of relying on a pre-shared key-update channel.

- Each simulated device creates an ML-KEM-512 keypair and signs its bootstrap
  request with a device Ed25519 identity key.
- The Key Controller validates the pre-registered device public key, performs
  ML-KEM encapsulation, and derives a 32-byte key-distribution session key.
- The controller signs its response using its Ed25519 identity key; the device
  verifies this signature before ML-KEM decapsulation and session-key use.
- The resulting per-device session key replaces the simulation placeholder
  distribution key and encrypts later branch-key updates.
- Invalid device identities and altered controller responses are rejected in
  the test suite.
- The Key Controller and each device retain separate copies of the
  independently ML-KEM-derived session key. The distributor uses only the
  controller-side copy; it does not read a device's local key state.
- Devices send an AES-GCM-protected installation acknowledgement after each
  key update. The controller retries a dropped update or acknowledgement, and
  a session can be expired and established afresh through onboarding.

### 10. End-to-end session recovery simulation

**Code:** `tests/test_end_to_end_session.py`

The simulation now covers the practical lifecycle around session establishment:

- The controller and device independently retain the same ML-KEM-derived
  session key, with separate local state.
- A branch-key update is considered installed only after the controller verifies
  the device's encrypted acknowledgement.
- A dropped update is retransmitted up to a configured attempt limit.
- A dropped acknowledgement is recovered by retransmitting the same versioned
  update; the device re-acknowledges it without accepting conflicting key data.
- Expiring controller-side session state prevents further key distribution until
  the device completes a fresh authenticated ML-KEM onboarding exchange.

## Security properties tested

**Test files:** `tests/test_topic_keys.py`, `tests/test_message_envelope.py`,
`tests/test_mqtt_prototype.py`, and `tests/test_key_controller.py`.

- Deterministic cross-platform KDF test vector.
- Different sibling topic labels derive different keys.
- Parent and sibling derivation attempts fail.
- Authorised branch holders decrypt successfully.
- Ciphertext, MQTT-topic, and sender-ID modifications fail AES-GCM
  authentication.
- Sequence-number modification fails authentication; replayed valid envelopes
  are rejected by receiver replay state.
- Two authorised subscribers decrypt one published ciphertext.
- A limited-branch subscriber cannot access another branch.
- Revocation is lazy, is rekeyed before the next managed publish, and prevents
  a former member from decrypting new ciphertext.
- Rekeying one branch leaves a sibling branch unchanged.
- Idle stale branches are rekeyed at their configured deadline.
- Simulated devices receive only their own encrypted key-update messages.
- A revoked simulated device retains only its old credential and cannot decrypt
  telemetry encrypted after the rotated credential is distributed.
- ML-KEM onboarding requires a registered device identity and rejects a forged
  controller response.

## Install and verify

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the complete test suite:

```bash
python3 -m unittest discover -s tests -v
```

## Run the complete software simulation

No hardware is required. This command creates simulated sensors, gateway,
dashboard, vendor, trusted Key Controller, and an untrusted in-memory MQTT
broker, then runs the complete key-distribution, telemetry, revocation, and
rekeying scenario:

```bash
python3 -m src.full_simulation
```

The console trace shows public routing metadata only (topics and encrypted byte
lengths), then reports which simulated users could decrypt before and after the
vendor is revoked. It never prints branch keys.

## Run local evaluation metrics

Measure the implemented KDF, AES-GCM encryption/decryption, ML-KEM onboarding,
lazy rekeying, and envelope size in the local Python process:

```bash
python3 -m src.evaluation
```

The output is JSON with mean microsecond timings. These values are useful for
the simulation report, but are not ESP32 or network-latency measurements.

## Not implemented yet

The following planned project components are intentionally outside the current
Python prototype:

- ESP32 firmware implementing the matching mbedTLS HKDF and AES-GCM logic.
- Production deployment and performance validation of ML-KEM on physical
  ESP32 hardware. The local simulation uses ML-KEM-512 successfully but is not
  a hardware compatibility result.
- Persistent Key Controller storage, real device identity credentials, and an
  administration API.
- Production MQTT authorisation/ACL configuration and durable reconnect logic.
- Logical Key Hierarchy optimisation for distribution to very large groups.
- Latency, rekey-cost, and long-duration reliability benchmarking.
- Persistent replay state across subscriber restarts. Replay state is currently
  retained in memory for the lifetime of each simulated subscriber.

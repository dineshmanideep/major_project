Your project will build an MQTT system where the broker transports encrypted sensor data but cannot read or alter it undetected. Authorised users receive access
  to an MQTT topic branch—for example factory/line3/#—without needing a separate key for every leaf topic.

  ## Clear project objectives

   Objective                               What it delivers                                             Success criterion
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   1. Hierarchical group E2E encryption    Multiple sensors publish once; multiple authorised           Broker never has payload keys; allowed consumers decrypt
                                           consumers decrypt the same ciphertext.                       and others cannot.
  ──────────────────────────────────────  ───────────────────────────────────────────────────────────  ────────────────────────────────────────────────────────────
   2. Topic-hierarchical key derivation    One branch key derives keys for all of its descendants.      K(line3) derives K(line3/oven/temp), but a leaf key cannot
                                                                                                        derive parent/sibling keys.
  ──────────────────────────────────────  ───────────────────────────────────────────────────────────  ────────────────────────────────────────────────────────────
   3. Lazy tree-based rekeying             Revocation only changes keys in the impacted branch,         A revoked member cannot decrypt after rekey; unrelated
                                           triggered when needed.                                       branches keep their keys.
  ──────────────────────────────────────  ───────────────────────────────────────────────────────────  ────────────────────────────────────────────────────────────
   4. Post-quantum onboarding              ML-KEM establishes initial secret material instead of        A newly authorised ESP32 completes onboarding and
                                           classical Diffie–Hellman.                                    encrypts/decrypts using derived keys.

  ## High-level architecture

  flowchart LR
      P1[ESP32: oven temperature] -->|AES-GCM ciphertext| B[MQTT broker\nuntrusted relay]
      P2[ESP32: motor speed] -->|AES-GCM ciphertext| B

      B --> G[Raspberry Pi gateway]
      B --> D[Dashboard]
      B --> H[Historian / vendor]

      KC[Key Controller\ntrusted, on gateway] -->|ML-KEM onboarding\nbranch credentials| P1
      KC -->|ML-KEM onboarding\nbranch credentials| P2
      KC -->|authorised branch key| G
      KC -->|authorised branch key| D
      KC -->|authorised branch key| H

      KC --> R[Membership + rekey state]

  The broker may see MQTT topic names, timing, and ciphertext size, but must never receive application payload keys.

  Important correction to make before coding: your report says devices handshake “with the broker.” Since the broker is untrusted, the handshake must logically
  terminate at the trusted Key Controller, with the broker only relaying bootstrap messages. Also authenticate the controller and device identities; ML-KEM alone
  establishes a secret but does not itself prove who sent the public key.

  ## How to implement each methodology

  ### 1. Hierarchical group E2E encryption

  Implement this first as the working baseline.

  - ESP32 reads a sensor value.
  - It gets the symmetric key for its exact topic.
  - It encrypts once using AES-256-GCM.
  - It publishes an envelope to MQTT.
  - Every authorised subscriber derives the same topic key and decrypts locally.
  - The broker forwards unchanged ciphertext only.

  Suggested envelope:

  {
    "v": 1,
    "key_version": 4,
    "sender_id": "esp32-oven-01",
    "nonce": "base64-encoded 96-bit nonce",
    "ciphertext": "base64-encoded encrypted payload",
    "tag": "base64-encoded GCM tag"
  }

  Use MQTT topic and selected metadata as AES-GCM AAD:

  AAD = protocol_version || mqtt_topic || key_version || sender_id

  This prevents an attacker from moving valid ciphertext from one topic/device context to another.

  ### 2. Topic-hierarchical key derivation

  Use HKDF-SHA-256 to derive child keys deterministically.

  K(child) = HKDF-Expand(
    PRK  = K(parent),
    info = "MP1/topic/v1/" || UTF-8(child_segment),
    L    = 32 bytes
  )

  For this topic tree:

  factory
  └── line3
      ├── oven
      │   └── temp
      └── motor
          └── speed

  a dashboard authorised for factory/line3 holds K(line3) and can derive:

  K(line3/oven)
  K(line3/oven/temp)
  K(line3/motor)
  K(line3/motor/speed)

  A vendor authorised only for factory/line3/motor holds K(motor) and can derive K(speed), but cannot derive K(line3) or oven keys.

  ### 3. Tree-based lazy rekeying

  Keep branch membership and versions in the Key Controller.

  branch                    version   stale   authorised members
  factory/line3             4         false   gateway, dashboard
  factory/line3/motor       7         false   gateway, vendor

  On revocation:

  1. Remove the device from the branch membership list.
  2. Mark the affected branch stale.
  3. Do not immediately interrupt a silent branch.
  4. Before the next publish to that branch, generate a fresh branch root key and increment its version.
  5. Securely distribute the new key only to remaining authorised members.
  6. The publisher uses the new version before its payload is accepted/published.
  7. Force rekey after a maximum staleness timeout even if the branch is idle.

  For the first prototype, make this simple and correct: rekey the revoked branch and all descendants. Optimise to full Logical Key Hierarchy distribution only
  after the baseline works. The relevant security property is that no message is sent under an old key after the rekey commit.

  ### 4. Post-quantum ML-KEM onboarding

  Use ML-KEM only when a device joins or receives refreshed branch-key material; continue using AES-256-GCM for every telemetry packet.

  1. Device boots with an identity credential.
  2. It generates an ML-KEM keypair.
  3. It sends its public key to _bootstrap/<device-id> through MQTT.
  4. Key Controller verifies the device identity and its permitted branch.
  5. Controller encapsulates to the device’s ML-KEM public key.
  6. Device decapsulates the ciphertext; both obtain the same shared secret.
  7. Derive an encrypted key-distribution session key from that shared secret.
  8. Controller sends the authorised branch key/version encrypted under that session key.
  9. Device derives leaf-topic keys locally.

  Use a signed controller response or a pre-provisioned controller public key, otherwise a malicious broker could impersonate the controller during bootstrap.

  ## Detailed implementation: Objective 2 — topic-hierarchical key derivation

  This should be your first substantial module because it is hardware-independent, easy to test, and required by all other objectives.

  ### Module API

  derive_child_key(parent_key, child_label) -> 32-byte key

  derive_topic_key(
      held_key,
      held_path,
      requested_topic
  ) -> 32-byte key or AuthorisationError

  Example:

  held_path      = factory/line3
  requested_topic = factory/line3/oven/temp

  The function validates that the requested topic is a strict descendant of held_path, then derives sequentially:

  K(oven) = derive_child_key(K(line3), "oven")
  K(temp) = derive_child_key(K(oven),  "temp")

  If the request is factory/line2/..., return an authorisation error without attempting derivation.

  ### Canonicalisation rules

  These must be identical on ESP32 and Raspberry Pi or keys will differ.

  - Use UTF-8 topic segment bytes.
  - Split topics only by /.
  - Disallow empty segments, +, and # in cryptographic topic paths.
  - Define whether topic names are case-sensitive; MQTT normally is, so retain case.
  - Include a fixed protocol/version label in HKDF info.
  - Do not concatenate ambiguous text directly; length-prefix each segment.

  A safe info encoding is:

  "MP1-KDF-v1" || uint16_be(length(segment)) || UTF-8(segment)

  ### Python prototype logic

  def derive_child_key(parent_key: bytes, segment: str) -> bytes:
      info = b"MP1-KDF-v1" + len(segment.encode()).to_bytes(2, "big") + segment.encode()
      return HKDF(
          algorithm=hashes.SHA256(),
          length=32,
          salt=None,
          info=info,
      ).derive(parent_key)

  The ESP32 implementation should use mbedTLS HKDF with exactly the same SHA-256, output length, and info bytes.

  ### Required tests

  1. Same root key and path always produce the same leaf key.
  2. Different sibling labels produce different keys.
  3. A line3 holder derives line3/oven/temp.
  4. An oven holder cannot request line3/motor/speed.
  5. Raspberry Pi and ESP32 test vectors produce byte-for-byte identical results.
  6. Changing KDF version/domain label changes every derived key.
  7. Cache lookup does not alter output.

  Use fixed test vectors committed to the repository, for example a fixed 32-byte root key and expected hex output for three paths. These become the contract
  between your Python and ESP32 implementations.

  ## Recommended build order

  1. Create a local Mosquitto + Python publisher/subscriber prototype using a manually provisioned AES key.
  2. Implement and test the KDF module in Python.
  3. Replace the single AES key with per-topic derived keys.
  4. Port AES-GCM and the exact KDF test vectors to ESP32.
  5. Add multi-subscriber and branch-authorisation tests.
  6. Add Key Controller membership records and lazy rekeying.
  7. Integrate ML-KEM onboarding last, because ESP32/liboqs integration is the riskiest component.
  8. Run latency, rekey-cost, security, and one-hour reliability tests.

  The best first coding milestone is therefore: a Python-only encrypted MQTT prototype with hierarchical HKDF-derived keys and two authorised subscribers. It
  proves the core contribution before hardware and ML-KEM complexity are introduced.

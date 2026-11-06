# Classical Secure MQTT Simulation: Complete Execution Flow & Line-by-Line Code Analysis

> **Document Name:** `flow.md`  
> **Course / Degree:** B.Tech in Information Technology (Major Project, IT449)  
> **Institution:** National Institute of Technology Karnataka (NITK), Surathkal  
> **Project Title:** Post-Quantum & Classical Group End-to-End Encryption for Multi-Consumer Industrial Sensor Networks  
> **Target Scope:** Classical Cryptography Simulation (`classical_simulation/`)  
> **Authors:** Jaivant Kosaraju (231IT028), Paluvadi Dinesh Manideep (231IT047)  
 

---

## 1. Verbatim Terminal Execution Output

When executing the standalone classical simulation script from the terminal:

```bash
(.venv) [dinesh@dinesh code]$ python3 -m classical_simulation.full_simulation
```

The system executes the multi-device scenario and produces the following output:

```text
================================================================================
  MP-1 SECURE MQTT SIMULATION (CLASSICAL X25519 ECDH VERSION)
  Objectives: Group E2EE + Topic KDF + Lazy Revocation + O(log N) LKH Rekeying
  Key Establishment: Classical X25519 (Curve25519) + Ed25519 Signatures
================================================================================

[STEP 1] Devices perform Classical X25519 ECDH Onboarding...
  -> motor-01   completed X25519 ECDH handshake; derived 32-byte distribution key.
  -> oven-01    completed X25519 ECDH handshake; derived 32-byte distribution key.
  -> gateway    completed X25519 ECDH handshake; derived 32-byte distribution key.
  -> dashboard  completed X25519 ECDH handshake; derived 32-byte distribution key.
  -> vendor     completed X25519 ECDH handshake; derived 32-byte distribution key.

[STEP 2] Controller provisions initial branch credentials and LKH trees...
  -> Distributed factory/line3/motor (v1) to motor-01 with LKH path keys.
  -> Distributed factory/line3/motor (v1) to gateway with LKH path keys.
  -> Distributed factory/line3/motor (v1) to vendor with LKH path keys.
  -> Distributed factory/line3/oven (v1) to oven-01 with LKH path keys.
  -> Distributed factory/line3/oven (v1) to gateway with LKH path keys.
  -> Distributed factory/line3/oven (v1) to dashboard with LKH path keys.

[STEP 3] Sensor nodes publish initial encrypted telemetry (Version 1)...
  [PUBLISH] motor-01 -> factory/line3/motor/speed (v1, seq 1, 198 bytes)
  [PUBLISH] oven-01  -> factory/line3/oven/temp (v1, seq 1, 201 bytes)
  [DECRYPT] gateway   successfully decrypted: factory/line3/motor/speed -> {"rpm": 1500, "status": "nominal"}
  [DECRYPT] gateway   successfully decrypted: factory/line3/oven/temp -> {"temp_c": 182.5, "status": "nominal"}
  [DECRYPT] dashboard successfully decrypted: factory/line3/oven/temp -> {"temp_c": 182.5, "status": "nominal"}
  [DECRYPT] vendor    successfully decrypted: factory/line3/motor/speed -> {"rpm": 1500, "status": "nominal"}

[STEP 4] Revoking 'vendor' from 'factory/line3/motor'...
  -> Branch 'factory/line3/motor' marked stale (O(1) operation; zero immediate rekey traffic).
  -> Sibling branch 'factory/line3/oven' remains stale=False (confined rekeying property).

[STEP 5] Next publish triggers LKH rekey rotation before payload transmission...
  -> Key Controller rotated 'factory/line3/motor' to Version 2.
  -> LKH Binary Tree broadcast package generated: 1 messages (O(log N)).
  -> Active member 'motor-01' updated LKH root key to Version 2.
  -> Active member 'gateway' updated LKH root key to Version 2.
  -> Revoked member 'vendor' rejected by LKH package: client vendor could not decrypt any key in the LKH rekey package

[STEP 6] Publishing telemetry under Version 2...
  [PUBLISH] motor-01 -> factory/line3/motor/speed (v2, seq 2, 202 bytes)
  [DECRYPT] gateway   successfully decrypted Version 2 payload: {"rpm": 1650, "status": "accelerating"}
  [REJECTED] vendor    failed to decrypt Version 2 payload: message authentication failed

================================================================================
  FINAL SECURITY & ACCESS AUDIT SUMMARY
================================================================================
  Gateway total decrypted messages:  3 (v1 motor, v1 oven, v2 motor)
  Dashboard total decrypted messages:1 (v1 oven only)
  Vendor total decrypted messages:   1 (v1 motor only)
  Vendor total rejected messages:    1 (v2 motor rejected post-revocation)
  Total bytes relayed by broker:     4942 bytes across 26 messages
================================================================================
```

---

## 2. Line-by-Line Execution Trace & Code Association

Below is the detailed walkthrough of what happens at every line of the terminal output, including the exact Python files, classes, methods, and line numbers executing in the background.

```
================================================================================
  MP-1 SECURE MQTT SIMULATION (CLASSICAL X25519 ECDH VERSION)
  Objectives: Group E2EE + Topic KDF + Lazy Revocation + O(log N) LKH Rekeying
  Key Establishment: Classical X25519 (Curve25519) + Ed25519 Signatures
================================================================================
```
* **What is happening:** The simulation environment initializes. It instantiates the untrusted pub/sub broker relay (`SimulationBroker`), the trusted membership controller (`KeyController`), and the onboarding authority (`ClassicalOnboardingController`).
* **Code executing:**  
  - `full_simulation.py` Lines 52–57: Calls `key_controller.create_branch("factory/line3/motor", ...)` and `key_controller.create_branch("factory/line3/oven", ...)`.
  - `key_controller.py` Lines 60–75: Generates a cryptographically random 32-byte root key for each branch (`secrets.token_bytes(32)`) and registers authorized member IDs.

---

### Step 1: Classical X25519 ECDH Onboarding
```text
[STEP 1] Devices perform Classical X25519 ECDH Onboarding...
  -> motor-01   completed X25519 ECDH handshake; derived 32-byte distribution key.
  -> oven-01    completed X25519 ECDH handshake; derived 32-byte distribution key.
  -> gateway    completed X25519 ECDH handshake; derived 32-byte distribution key.
  -> dashboard  completed X25519 ECDH handshake; derived 32-byte distribution key.
  -> vendor     completed X25519 ECDH handshake; derived 32-byte distribution key.
```
* **What is happening:** Each of the 5 devices connects over the simulated MQTT network and establishes a private, isolated 32-byte symmetric session key ($K_{\text{dist}}$) with the Key Controller using Elliptic Curve Diffie-Hellman over Curve25519 (X25519). The handshake is mutually authenticated using asymmetric Ed25519 digital signatures to prevent Man-in-the-Middle (MitM) attacks.
* **Code executing:**
  1. `full_simulation.py` Lines 72–89: Iterates over each device ID.
  2. `classical_onboarding.py` Lines 110–121: `ClassicalOnboardingClient.__init__()` generates an ephemeral X25519 private key (`x25519.X25519PrivateKey.generate()`) and an Ed25519 signing keypair (`ed25519.Ed25519PrivateKey.generate()`).
  3. `classical_onboarding.py` Lines 127–137: `client.generate_request()` constructs a canonical payload `_canonical("request", device_id, ecdh_pub)`, signs it with Ed25519, and outputs JSON.
  4. `simulation_broker.py` Lines 41–46: `broker.publish("_bootstrap/{dev_id}/onboarding-request", req_bytes)` relays the payload blindly to the Key Controller.
  5. `classical_onboarding.py` Lines 170–205: `onboard_controller.process_onboarding_request()`:
     - Verifies the device's Ed25519 signature against the pre-registered identity key.
     - Generates an ephemeral X25519 keypair for the controller.
     - Computes the Diffie-Hellman shared secret: `shared_secret = controller_priv.exchange(device_pub)`.
     - Derives the 32-byte session key: $K_{\text{dist}} = \text{HKDF-SHA-256}(SS, \dots)$ via `_session_key()`.
     - Signs the response containing the controller's X25519 public key.
  6. `classical_onboarding.py` Lines 139–165: `client.accept_response()`:
     - Verifies the controller's Ed25519 signature.
     - Computes `shared_secret = device_priv.exchange(controller_pub)`.
     - Derives the exact same 32-byte $K_{\text{dist}}$. Both sides now share $K_{\text{dist}}$.

---

### Step 2: Credential Provisioning & LKH Tree Setup
```text
[STEP 2] Controller provisions initial branch credentials and LKH trees...
  -> Distributed factory/line3/motor (v1) to motor-01 with LKH path keys.
  -> Distributed factory/line3/motor (v1) to gateway with LKH path keys.
  -> Distributed factory/line3/motor (v1) to vendor with LKH path keys.
  -> Distributed factory/line3/oven (v1) to oven-01 with LKH path keys.
  -> Distributed factory/line3/oven (v1) to gateway with LKH path keys.
  -> Distributed factory/line3/oven (v1) to dashboard with LKH path keys.
```
* **What is happening:** The Key Controller provisions the initial 32-byte branch root keys to authorized devices by encrypting each key under the recipient device's unique $K_{\text{dist}}$ using AES-256-GCM. The devices decrypt the key, save it locally, and return an authenticated acknowledgment (`b"installed"`). Simultaneously, the controller builds a balanced binary Logical Key Hierarchy (LKH) tree for each branch and initializes each client's path keys from its leaf node to the root.
* **Code executing:**
  1. `full_simulation.py` Lines 93–96: Constructs `LkhTree(BRANCH_MOTOR, ["motor-01", "gateway", "vendor"])` and `LkhTree(BRANCH_OVEN, ["oven-01", "gateway", "dashboard"])`.
  2. `lkh_tree.py` Lines 84–140: `LkhTree._build()` constructs balanced binary trees bottom-up, assigning breadth-first node IDs with root = 1.
  3. `classical_onboarding.py` Lines 212–224: `onboard_controller.create_key_update()` encrypts the 32-byte root key under $K_{\text{dist}}$ using AES-256-GCM with AAD `_update_aad(device_id, branch, version)`.
  4. `classical_onboarding.py` Lines 167–200: `client.process_key_update()` decrypts the payload, stores the `BranchCredential`, encrypts an ACK payload `b"installed"`, and sends it to `_bootstrap/{dev_id}/branch-key-ack`.
  5. `classical_onboarding.py` Lines 226–243: `onboard_controller.process_key_ack()` decrypts the ACK; verifies `plaintext == b"installed"`; marks the credential active.
  6. `lkh_tree.py` Lines 142–151 & `full_simulation.py` Lines 111–113: `lkh_trees.get_path_keys(dev_id)` supplies the node keys along the leaf-to-root path to instantiate `LkhClient(dev_id, branch, path_keys)`.

---

### Step 3: Publishing Initial Encrypted Telemetry (Version 1)
```text
[STEP 3] Sensor nodes publish initial encrypted telemetry (Version 1)...
  [PUBLISH] motor-01 -> factory/line3/motor/speed (v1, seq 1, 198 bytes)
  [PUBLISH] oven-01  -> factory/line3/oven/temp (v1, seq 1, 201 bytes)
  [DECRYPT] gateway   successfully decrypted: factory/line3/motor/speed -> {"rpm": 1500, "status": "nominal"}
  [DECRYPT] gateway   successfully decrypted: factory/line3/oven/temp -> {"temp_c": 182.5, "status": "nominal"}
  [DECRYPT] dashboard successfully decrypted: factory/line3/oven/temp -> {"temp_c": 182.5, "status": "nominal"}
  [DECRYPT] vendor    successfully decrypted: factory/line3/motor/speed -> {"rpm": 1500, "status": "nominal"}
```
* **What is happening:** Sensors publish encrypted telemetry. Under Objective 1 (Group E2EE), `motor-01` encrypts its reading **once**; the broker routes that single ciphertext to both `gateway` and `vendor`. Both decrypt it successfully. Meanwhile, `dashboard` only receives and decrypts `oven-01` data.
* **Code executing:**
  1. `full_simulation.py` Lines 147–154: `motor-01` retrieves its root key for `factory/line3/motor` and calls `encrypt_payload()`.
  2. `message_envelope.py` Lines 83–114: `encrypt_payload()`:
     - Calls `derive_topic_key()` in `topic_keys.py` to derive $K_{\text{speed}} = \text{HKDF-Expand}(K_{\text{motor}}, \texttt{"speed"})$.
     - Generates a 12-byte CSPRNG nonce (`os.urandom(12)`).
     - Constructs topic-bound AAD via `_aad("factory/line3/motor/speed", "motor-01", 1, 1)`.
     - Encrypts via `AESGCM(topic_key).encrypt(nonce, plaintext, aad)`.
     - Returns JSON envelope with ciphertext, nonce, tag, sequence, and version (198 bytes).
  3. `simulation_broker.py` Lines 41–46: Relays the envelope to subscribers matching the topic filter.
  4. `message_envelope.py` Lines 149–171: `decrypt_payload()`:
     - Parses envelope, verifies schema.
     - `ReplayProtector.accept()` checks that sequence counter (1) $> \text{last\_seen}$ (0).
     - Derives topic key from held branch root key using `derive_topic_key()`.
     - Reconstructs AAD using the arrival topic and decrypts ciphertext using AES-256-GCM.
     - `gateway` decrypts both messages; `dashboard` decrypts oven data; `vendor` decrypts motor data.

---

### Step 4: Lazy Revocation of Vendor
```text
[STEP 4] Revoking 'vendor' from 'factory/line3/motor'...
  -> Branch 'factory/line3/motor' marked stale (O(1) operation; zero immediate rekey traffic).
  -> Sibling branch 'factory/line3/oven' remains stale=False (confined rekeying property).
```
* **What is happening:** The administrator revokes `vendor` from the motor branch. Under Objective 3 (Lazy Revocation), the controller removes `vendor` from the membership set and sets `stale_since = now`. Crucially, **zero keys are generated and zero network packets are sent at this moment** ($O(1)$ complexity). Sibling branch `factory/line3/oven` is completely untouched.
* **Code executing:**
  1. `full_simulation.py` Line 188: Calls `key_controller.revoke("vendor", "factory/line3/motor")`.
  2. `key_controller.py` Lines 82–89: In `KeyController.revoke()`:
     - Removes `"vendor"` from `state.members`.
     - Sets `state.stale_since = datetime.now(timezone.utc)`.
     - Returns immediately without performing any cryptography or network transmissions.
  3. `full_simulation.py` Lines 190–191: Asserts that `key_controller.is_stale(BRANCH_MOTOR) == True` while `key_controller.is_stale(BRANCH_OVEN) == False`.

---

### Step 5: Next Publish Triggers $O(\log N)$ LKH Rekeying
```text
[STEP 5] Next publish triggers LKH rekey rotation before payload transmission...
  -> Key Controller rotated 'factory/line3/motor' to Version 2.
  -> LKH Binary Tree broadcast package generated: 1 messages (O(log N)).
  -> Active member 'motor-01' updated LKH root key to Version 2.
  -> Active member 'gateway' updated LKH root key to Version 2.
  -> Revoked member 'vendor' rejected by LKH package: client vendor could not decrypt any key in the LKH rekey package
```
* **What is happening:** `motor-01` is ready to publish its next reading and requests its credential. The controller detects `stale_since != None` and triggers on-demand rotation. A fresh root key is drawn for Version 2. The LKH binary tree rotates ancestor keys and broadcasts an LKH rekey package. Active members (`motor-01`, `gateway`) decrypt the package and update to Version 2. The revoked `vendor` attempts to process the package, finds no matching keys, and is permanently locked out.
* **Code executing:**
  1. `full_simulation.py` Line 196: `motor-01` calls `key_controller.credential_for("motor-01", BRANCH_MOTOR)`.
  2. `key_controller.py` Lines 90–98 & 124–128: `KeyController.credential_for()` detects `state.stale_since is not None`, calls `_rekey()`, generates a fresh 32-byte key (`secrets.token_bytes(32)`), increments `key_version = 2`, and clears `stale_since = None`.
  3. `lkh_tree.py` Lines 156–234: `LkhTree.revoke_member("vendor")`:
     - Evicts `"vendor"` leaf node.
     - Generates fresh keys for nodes on the path from leaf to root.
     - Encrypts the fresh root key under the sibling node key using AES-256-GCM.
     - Generates 1 rekey message ($M \le 2\lceil\log_2 3\rceil - 1$).
  4. `lkh_tree.py` Lines 235–241: `serialize_rekey_package()` converts messages to broadcast JSON.
  5. `simulation_broker.py` Line 41: Publishes package to `_bootstrap/factory/line3/motor/lkh-rekey`.
  6. `lkh_tree.py` Lines 273–319: `LkhClient.process_rekey_package()`:
     - `motor-01` and `gateway` find a message encrypted with a sibling node key they hold, decrypt the new root key, update `node_keys[1]`, and set `key_version = 2`.
     - `vendor` executes `process_rekey_package()`, but holds no matching sibling keys; raises `LkhError("client vendor could not decrypt any key in the LKH rekey package")`.

---

### Step 6: Telemetry Publication under Version 2 & Revocation Enforcement
```text
[STEP 6] Publishing telemetry under Version 2...
  [PUBLISH] motor-01 -> factory/line3/motor/speed (v2, seq 2, 202 bytes)
  [DECRYPT] gateway   successfully decrypted Version 2 payload: {"rpm": 1650, "status": "accelerating"}
  [REJECTED] vendor    failed to decrypt Version 2 payload: message authentication failed
```
* **What is happening:** `motor-01` encrypts telemetry under Version 2 ($V_K = 2$) and sequence number 2. The authorized `gateway` decrypts it successfully. The revoked `vendor` attempts to decrypt the packet using its stale Version 1 key, but AES-256-GCM tag verification fails, proving forward secrecy.
* **Code executing:**
  1. `full_simulation.py` Lines 226–232: `motor-01` calls `encrypt_payload()` with the fresh Version 2 root key, sequence = 2, and plaintext `{"rpm": 1650, "status": "accelerating"}`.
  2. `message_envelope.py` Lines 83–114: Derives subtopic key from Version 2 root key, constructs AAD with `key_version = 2` and `sequence = 2`, and encrypts with AES-256-GCM.
  3. `simulation_broker.py` Line 41: Relays 202-byte ciphertext envelope on `factory/line3/motor/speed`.
  4. `full_simulation.py` Lines 237–240 & `message_envelope.py` Lines 149–171:
     - `gateway` calls `decrypt_payload()` with its Version 2 root key. Decryption succeeds.
  5. `full_simulation.py` Lines 242–248:
     - `vendor` attempts to call `decrypt_payload()` using its stale Version 1 root key.
     - `AESGCM.decrypt()` fails because the topic key is wrong. It catches `InvalidTag` and raises `EnvelopeError("message authentication failed")`.
     - The revoked vendor is completely locked out.

---

### Final Audit Summary
```text
================================================================================
  FINAL SECURITY & ACCESS AUDIT SUMMARY
================================================================================
  Gateway total decrypted messages:  3 (v1 motor, v1 oven, v2 motor)
  Dashboard total decrypted messages:1 (v1 oven only)
  Vendor total decrypted messages:   1 (v1 motor only)
  Vendor total rejected messages:    1 (v2 motor rejected post-revocation)
  Total bytes relayed by broker:     4942 bytes across 26 messages
================================================================================
```
* **What is happening:** Confirms that all security policies held across the entire session:
  - `gateway` decrypted 3 messages (subscribed to `#`, holds keys for both branches).
  - `dashboard` decrypted 1 message (confined strictly to `oven` branch).
  - `vendor` decrypted 1 message (received Version 1 before revocation, rejected on Version 2).
  - The broker relayed 26 total messages (4,942 bytes) with zero knowledge of plaintext or keys.

---

## 3. Comprehensive Code File Breakdown (All 8 Files)

Below is the exhaustive, function-by-function explanation of all 8 Python files comprising the `classical_simulation/` package.

---

### File 1: [`classical_simulation/topic_keys.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/topic_keys.py) (68 Lines)
**Role:** Implements Objective 2 — One-way topic-hierarchical key derivation using RFC 5869 HKDF-Expand with HMAC-SHA-256.

* **Lines 14–16:** Defines `KEY_LENGTH = 32` (256-bit symmetric key) and `_DOMAIN = b"MP1-TOPIC-KDF-v1"` (unambiguous domain separation tag to prevent cross-protocol key reuse).
* **Lines 19–20:** `TopicKeyError(ValueError)`: Custom exception raised when a topic path is malformed, uses wildcards, or attempts unauthorized parent/sibling derivation.
* **Lines 23–32:** `_segments(path: str) -> tuple[str, ...]`: Canonical topic validator. Splits path by `/`. Rejects empty strings, empty segments (`//`), and MQTT wildcards (`+`, `#`).
* **Lines 35–40:** `_encode_info(segment: str) -> bytes`: Encodes a segment label with unambiguous length-prefixing: `_DOMAIN + len(segment).to_bytes(2, "big") + segment.encode("utf-8")`.
* **Lines 43–55:** `derive_child_key(parent_key: bytes, child_segment: str) -> bytes`:
  - Validates `parent_key` is exactly 32 bytes and `child_segment` contains no slashes.
  - Executes one block of HKDF-Expand:  
    $$\text{HMAC-SHA-256}\Big(\text{parent\_key},\, \text{\_encode\_info}(\text{child\_segment}) \parallel \texttt{0x01}\Big)$$
  - Returns a 32-byte child key. Due to SHA-256 preimage resistance, computing `parent_key` from the output is computationally impossible ($2^{256}$ operations).
* **Lines 57–67:** `derive_topic_key(held_key: bytes, held_path: str, requested_topic: str) -> bytes`:
  - Checks if `held_path` is a true prefix of `requested_topic`. If not, raises `TopicKeyError("requested topic is outside the held branch")`.
  - Iteratively applies `derive_child_key()` for each remaining path segment, achieving $O(d)$ path traversal.

---

### File 2: [`classical_simulation/message_envelope.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/message_envelope.py) (175 Lines)
**Role:** Implements Objective 1 — AES-256-GCM authenticated payload encapsulation, topic-bound AAD, and anti-replay protection.

* **Lines 22–24:** Defines constants: `PROTOCOL_VERSION = 1`, `NONCE_LENGTH = 12` (96-bit GCM nonce), and `TAG_LENGTH = 16` (128-bit authentication tag).
* **Lines 27–28:** `EnvelopeError(ValueError)`: Custom exception raised on tampering, unauthentic messages, or replay detection.
* **Lines 31–41:** `ReplayProtector`:
  - Holds state `_last_seen: dict[tuple[str, str, int], int]` mapping `(topic, sender_id, key_version) -> last_sequence`.
  - `accept(topic, sender_id, key_version, sequence)`: If `sequence <= previous`, raises `EnvelopeError("replayed or out-of-order message")`. Otherwise updates `_last_seen`.
* **Lines 44–54:** `_b64encode()` and `_b64decode()`: Helper functions converting binary cryptographic material to/from Base64 strings for JSON serialization.
* **Lines 57–80:** `_aad(topic: str, sender_id: str, key_version: int, sequence: int) -> bytes`:
  - Constructs canonical Authenticated Additional Data binding:  
    $$\texttt{"MP1-MSG-v1"} \parallel \text{uint16\_be}(\text{len}(T)) \parallel T \parallel \text{uint16\_be}(\text{len}(\text{ID})) \parallel \text{ID} \parallel \text{uint64\_be}(V_K) \parallel \text{uint64\_be}(\text{seq})$$
  - Defeats topic relocation, sender spoofing, and sequence tampering.
* **Lines 83–114:** `encrypt_payload(...) -> dict[str, Any]`:
  - Derives leaf topic key via `derive_topic_key()`.
  - Generates 12-byte CSPRNG nonce (`os.urandom(12)`).
  - Calls `AESGCM(topic_key).encrypt(nonce, plaintext, aad)`.
  - Splits ciphertext and 16-byte tag.
  - Returns a compact JSON-serializable dictionary.
* **Lines 117–146:** `parse_envelope(...)`: Validates envelope dictionary schema, field types, and Base64 lengths.
* **Lines 149–171:** `decrypt_payload(...) -> bytes`:
  - Parses envelope. Checks sequence counter against `ReplayProtector`.
  - Derives topic key from held branch root key.
  - Computes AAD and calls `AESGCM(topic_key).decrypt(nonce, ciphertext + tag, aad)`.
  - Catches `InvalidTag` and raises `EnvelopeError("message authentication failed")`.
* **Lines 173–175:** `serialise_envelope()`: Encodes dictionary to UTF-8 JSON bytes with sorted keys and compact separators.

---

### File 3: [`classical_simulation/lkh_tree.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/lkh_tree.py) (319 Lines)
**Role:** Implements Objective 3 — Logical Key Hierarchy (LKH) balanced binary key tree for $O(\log N)$ group rekeying.

* **Lines 24–25:** Defines `NONCE_LENGTH = 12` and `_LKH_DOMAIN = b"MP1-LKH-REKEY-v1"`.
* **Lines 28–29:** `LkhError(ValueError)`: Custom exception for LKH tree and client processing errors.
* **Lines 32–42:** `_lkh_aad(branch_path, target_node_id, encrypting_node_id, key_version) -> bytes`: Canonical AAD binding branch name, node IDs, and version into each LKH rekey ciphertext.
* **Lines 45–60:** `LkhNode`: Dataclass representing a tree node. Fields: `node_id`, `key` (32 bytes), `parent_id`, `left_id`, `right_id`, `member_id`, and `members_in_subtree: set[str]`.
* **Lines 62–140:** `LkhTree.__init__()` and `_build(members)`:
  - Takes list of group members. Creates leaf nodes with random 32-byte keys.
  - Builds balanced binary tree bottom-up by pairing adjacent nodes under new parent nodes.
  - Uses breadth-first search (BFS) queue to assign canonical 1-based node IDs (root node is always `node_id = 1`).
* **Lines 142–151:** `get_path_keys(member_id: str) -> dict[int, bytes]`: Walks from the member's leaf node up to root node 1, returning all `{node_id: key}` along its ancestor path.
* **Lines 156–234:** `revoke_member(member_id: str) -> tuple[bytes, list[dict[str, Any]]]`:
  - Evicts `member_id`. Increments `self.key_version += 1`.
  - Identifies compromised ancestor path: `path_to_root`.
  - Generates fresh 32-byte keys for each compromised node (`new_keys`).
  - For each node on the path, encrypts the new key under the unrevoked sibling node key using AES-256-GCM.
  - Produces at most $2\lceil\log_2 N\rceil - 1$ rekey messages ($O(\log N)$ bound).
  - Updates tree node keys and returns `(new_root_key, rekey_messages)`.
* **Lines 235–250:** `serialize_rekey_package()` and `deserialize_rekey_package()`: JSON wire serialization for the broadcast package.
* **Lines 252–319:** `LkhClient`:
  - Maintained by each subscriber/publisher holding path keys.
  - `process_rekey_package(package)`: Searches broadcast messages for an item encrypted with a node key it holds. Iteratively decrypts up the tree until root key `node_keys[1]` is updated to the new version.
  - If client was revoked, no matching key exists, raising `LkhError("could not decrypt any key")`.

---

### File 4: [`classical_simulation/key_controller.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/key_controller.py) (129 Lines)
**Role:** Implements Objective 3 — Trusted branch membership authority and lazy revocation state machine.

* **Lines 18–19:** `KeyControllerError(ValueError)`: Custom exception for invalid branch operations.
* **Lines 22–29:** `BranchCredential`: Immutable dataclass holding `branch_path`, `root_key` (32 bytes), and `key_version`.
* **Lines 32–38:** `_BranchState`: Internal state tracking `root_key`, `key_version`, `members: set[str]`, `stale_since: datetime | None`, and `last_rekey_at`.
* **Lines 51–60:** `KeyController.__init__(max_staleness)`: Initializes controller with bounded staleness window (default: 10 minutes).
* **Lines 61–75:** `create_branch(branch_path, members, root_key)`: Validates path, generates random 32-byte root key (`secrets.token_bytes(32)`), and stores initial state.
* **Lines 76–80:** `add_member(device_id, branch_path)`: Adds device ID to authorized membership set.
* **Lines 82–89:** `revoke(device_id, branch_path, now)`:
  - Evicts `device_id` from `state.members`.
  - Sets `state.stale_since = now` ($O(1)$ lazy revocation).
  - Emits zero network packets.
* **Lines 90–100:** `credential_for(device_id, branch_path, now)`:
  - Verifies device authorization.
  - If `state.stale_since is not None`: Triggers on-demand rotation via `_rekey()`.
  - Returns fresh `BranchCredential`.
* **Lines 101–110:** `rekey_expired(now)`: Background monitor. If $(\text{now} - \text{stale\_since}) \ge \text{max\_staleness}$, forces rotation to preserve forward secrecy.
* **Lines 124–128:** `_rekey(state, now)`: Generates fresh random 32-byte root key, increments `key_version += 1`, resets `stale_since = None`.

---

### File 5: [`classical_simulation/classical_onboarding.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/classical_onboarding.py) (321 Lines)
**Role:** Implements Objective 4 (Classical) — Authenticated initial key establishment using ephemeral X25519 Curve25519 ECDH and Ed25519 digital signatures.

* **Lines 41–48:** Domain separation constants (`_DOMAIN_ONBOARD`, `_DOMAIN_DIST`, `_DOMAIN_KEY_UPDATE`, `_DOMAIN_KEY_ACK`).
* **Lines 50–51:** `ClassicalOnboardingError(ValueError)`: Custom exception for onboarding failures.
* **Lines 54–57:** `_canonical(kind, device_id, value)`: Builds canonical byte string for signature generation and verification.
* **Lines 59–65:** `_session_key(shared_secret, device_id)`: Derives 32-byte $K_{\text{dist}}$ using HKDF-SHA-256 over the raw Curve25519 shared secret.
* **Lines 76–88:** `_update_aad()` and `_ack_aad()`: Constructs AAD for credential updates and installation ACKs.
* **Lines 91–105:** `SimulatedClassicalDevice`: Software representation of a physical sensor/subscriber holding its device ID, distribution session key, and branch credentials.
* **Lines 107–146:** `ClassicalOnboardingClient`:
  - `__init__()`: Generates ephemeral X25519 private key (`_ecdh_private_key`) and Ed25519 identity key (`_identity_private_key`).
  - `generate_request()`: Signs canonical request containing its 32-byte X25519 public key.
  - `accept_response(payload)`: Verifies controller's Ed25519 signature, computes `shared_secret = _ecdh_private_key.exchange(controller_pub)`, derives identical 32-byte $K_{\text{dist}}$.
* **Lines 148–198:** `client.process_key_update(payload)`: Decrypts branch root key under $K_{\text{dist}}$ using AES-256-GCM, stores it, generates encrypted ACK payload (`b"installed"`).
* **Lines 201–270:** `ClassicalOnboardingController`:
  - `register_device_identity(device_id, pubkey)`: Whitelist registration.
  - `process_onboarding_request(req)`: Verifies device signature, generates controller ephemeral X25519 keypair, computes shared secret, derives $K_{\text{dist}}$, signs response.
  - `create_key_update()`: Encrypts root key under $K_{\text{dist}}$ using AES-256-GCM.
  - `process_key_ack()`: Decrypts and authenticates device ACK (`b"installed"`).

---

### File 6: [`classical_simulation/simulation_broker.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/simulation_broker.py) (52 Lines)
**Role:** In-memory untrusted MQTT pub/sub relay.

* **Lines 14–31:** `_match_topic(sub_filter: str, topic: str) -> bool`:
  - Implements MQTT 3.1.1 topic matching rules.
  - Supports `#` (multi-level wildcard, matches all remaining levels).
  - Supports `+` (single-level wildcard, matches exactly one segment).
* **Lines 34–52:** `SimulationBroker`:
  - `subscribe(topic_filter, callback)`: Registers callback for topic filter.
  - `publish(topic, payload)`: Appends `(topic, len(payload))` to `relayed_messages`, finds all matching subscriptions, and invokes callbacks.
  - `total_bytes_relayed` and `total_messages_relayed`: Exposes network telemetry for auditing.

---

### File 7: [`classical_simulation/full_simulation.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/full_simulation.py) (267 Lines)
**Role:** Complete end-to-end multi-device lifecycle scenario runner.

* **Lines 35–38:** Defines topic branches: `factory/line3/motor` and `factory/line3/oven`.
* **Lines 41–265:** `run_classical_simulation(verbose=True)`:
  - **Step 0:** Sets up `SimulationBroker`, `KeyController`, `ClassicalOnboardingController`.
  - **Step 1:** Onboards `motor-01`, `oven-01`, `gateway`, `dashboard`, `vendor` via X25519 ECDH.
  - **Step 2:** Provisions initial branch credentials and initializes LKH trees.
  - **Step 3:** Publishes Version 1 telemetry; verifies selective decryption (`gateway` decrypts both, `dashboard` decrypts oven, `vendor` decrypts motor).
  - **Step 4:** Revokes `vendor` lazily ($O(1)$ timestamp update).
  - **Step 5:** On-demand publish triggers LKH rekey broadcast; remaining members update; `vendor` is rejected.
  - **Step 6:** Publishes Version 2 telemetry; `gateway` decrypts; `vendor` fails with authentication error.
  - **Step 7:** Emits final security audit summary.

---

### File 8: [`classical_simulation/evaluation.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/evaluation.py) (142 Lines)
**Role:** Microsecond performance benchmarking and comparative evaluation suite.

* **Lines 30–43:** `ClassicalEvaluationMetrics`: Dataclass holding benchmark timings (`iterations`, `ecdh_onboarding_us`, `kdf_us`, `encrypt_us`, `decrypt_us`, `lazy_rekey_us`, `lkh_rekey_us`, `lkh_rekey_messages`, `telemetry_envelope_bytes`).
* **Lines 45–52:** `_mean_us(operation, iterations)`: High-precision timer using Python `time.perf_counter_ns()`. Runs benchmark across 100 iterations and computes mean latency in microseconds.
* **Lines 54–105:** `measure_classical()`: Benchmarks KDF derivation ($4.01\ \mu\text{s}$), AES-GCM encryption ($7.08\ \mu\text{s}$), decryption ($7.88\ \mu\text{s}$), X25519 onboarding ($432.23\ \mu\text{s}$), lazy rekey ($7.78\ \mu\text{s}$), and LKH tree rekeying ($29.48\ \mu\text{s}$, 5 messages for $N=8$).
* **Lines 107–134:** `print_comparison_table()`: Formats and prints the comparative table analyzing Classical (X25519) vs. Post-Quantum (ML-KEM-512) metrics.


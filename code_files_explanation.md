# MP-1 Codebase: Exhaustive Line-by-Line & Architectural Code Guide

> **Project**: Major Project-I (IT449) — National Institute of Technology Karnataka (NITK), Surathkal  
> **Topic**: *Post-Quantum Secured, Hierarchical Group End-to-End Encryption for Multi-Consumer Industrial Sensor Networks*  
> **Students**: Jaivant Kosaraju (211IT023) & Paluvadi Dinesh Manideep (211IT041)  
>  

---

## Table of Contents
1. [Architectural Overview & Subsystem Map](#1-architectural-overview--subsystem-map)
2. [Core Cryptographic Engine (`src/`)](#2-core-cryptographic-engine-src)
   - [2.1 `src/topic_keys.py`](#21-srctopic_keyspy)
   - [2.2 `src/message_envelope.py`](#22-srcmessage_envelopepy)
   - [2.3 `src/lkh_tree.py`](#23-srclkh_treepy)
   - [2.4 `src/pqc_onboarding.py`](#24-srcpqc_onboardingpy)
   - [2.5 `src/simulated_key_distribution.py`](#25-srcsimulated_key_distributionpy)
   - [2.6 `src/evaluation.py`](#26-srcevaluationpy)
3. [Classical Simulation Engine (`classical_simulation/`)](#3-classical-simulation-engine-classical_simulation)
   - [3.1 `classical_simulation/topic_keys.py`](#31-classical_simulationtopic_keyspy)
   - [3.2 `classical_simulation/message_envelope.py`](#32-classical_simulationmessage_envelopepy)
   - [3.3 `classical_simulation/lkh_tree.py`](#33-classical_simulationlkh_treepy)
   - [3.4 `classical_simulation/classical_onboarding.py`](#34-classical_simulationclassical_onboardingpy)
   - [3.5 `classical_simulation/key_controller.py`](#35-classical_simulationkey_controllerpy)
   - [3.6 `classical_simulation/simulation_broker.py`](#36-classical_simulationsimulation_brokerpy)
   - [3.7 `classical_simulation/full_simulation.py`](#37-classical_simulationfull_simulationpy)
   - [3.8 `classical_simulation/evaluation.py`](#38-classical_simulationevaluationpy)
4. [Live Post-Quantum TCP Network Implementation (`network_implementation/`)](#4-live-post-quantum-tcp-network-implementation-network_implementation)
   - [4.1 `network_implementation/config.py`](#41-network_implementationconfigpy)
   - [4.2 `network_implementation/broker_service.py`](#42-network_implementationbroker_servicepy)
   - [4.3 `network_implementation/controller_service.py`](#43-network_implementationcontroller_servicepy)
   - [4.4 `network_implementation/publisher_node.py`](#44-network_implementationpublisher_nodepy)
   - [4.5 `network_implementation/subscriber_node.py`](#45-network_implementationsubscriber_nodepy)
   - [4.6 `network_implementation/run_network_demo.py`](#46-network_implementationrun_network_demopy)
   - [4.7 `network_implementation/test_network.py`](#47-network_implementationtest_networkpy)
5. [Live Classical TCP Network Implementation (`classical_network/`)](#5-live-classical-tcp-network-implementation-classical_network)
   - [5.1 `classical_network/config.py`](#51-classical_networkconfigpy)
   - [5.2 `classical_network/broker_service.py`](#52-classical_networkbroker_servicepy)
   - [5.3 `classical_network/controller_service.py`](#53-classical_networkcontroller_servicepy)
   - [5.4 `classical_network/publisher_node.py`](#54-classical_networkpublisher_nodepy)
   - [5.5 `classical_network/subscriber_node.py`](#55-classical_networksubscriber_nodepy)
   - [5.6 `classical_network/run_classical_network_demo.py`](#56-classical_networkrun_classical_network_demopy)
   - [5.7 `classical_network/test_classical_network.py`](#57-classical_networktest_classical_networkpy)
6. [Formal Security Verification (`formal_verification/`)](#6-formal-security-verification-formal_verification)
   - [6.1 `formal_verification/mp1_protocol.pv`](#61-formal_verificationmp1_protocolpv)

---

## 1. Architectural Overview & Subsystem Map

The project implements a zero-trust, post-quantum resilient, hierarchical publish/subscribe security architecture for MQTT in industrial Internet of Things (IIoT) sensor networks.

The repository is structured into four distinct execution environments:
1. **Core Library (`src/`)**: Reference post-quantum cryptographic primitives (ML-KEM-512 lattice KEM, Ed25519 signatures, RFC 5869 HKDF-SHA-256 topic KDF, AES-256-GCM AEAD envelopes, and $O(\log N)$ LKH binary tree rekeying).
2. **Classical Simulation Engine (`classical_simulation/`)**: Standalone, memory-efficient comparative baseline utilizing classical X25519 (Curve25519) ECDH key establishment alongside lazy revocation and confined LKH rekeying.
3. **Live Post-Quantum TCP Network (`network_implementation/`)**: Multi-process live deployment over real OS TCP sockets using pure-Python asyncio MQTT 3.1.1 relay server, autonomous Key Controller daemon, and PQC sensor publishers/subscribers.
4. **Live Classical TCP Network (`classical_network/`)**: Multi-process live deployment over real OS TCP sockets executing the classical X25519 ECDH baseline with pure-Python asyncio MQTT broker, classical controller daemon, and autonomous publisher/subscriber nodes.

```
+---------------------------------------------------------------------------------------+
|                                    MQTT BROKER                                        |
|                          (Untrusted Pure-Python TCP Relay)                            |
+---------------------------------------------------------------------------------------+
       ^                                  ^                                  ^
       | Bootstrap Topics                 | Data Topics                      | Rekey Broadcast
       v                                  v                                  v
+-----------------------+      +-----------------------+      +-----------------------+
|    KEY CONTROLLER     |      |   SENSOR PUBLISHERS   |      | CONSUMER SUBSCRIBERS  |
|  (X25519 / ML-KEM-512 |      | (motor-01, oven-01)   |      | (gateway, dashboard,  |
|  + Ed25519 + LKH Tree)|      | Encrypts 1x (O(1))    |      |  vendor) - Decrypts   |
+-----------------------+      +-----------------------+      +-----------------------+
```

---

## 2. Core Cryptographic Engine (`src/`)

### 2.1 `src/topic_keys.py`
**Purpose**: Deterministic, one-way topic-hierarchical key derivation matching RFC 5869 HKDF-Expand with HMAC-SHA-256.

```python
KEY_LENGTH = 32  # AES-256 key size (256 bits)
_DOMAIN = b"MP1-TOPIC-KDF-v1"
```
- **Line 11-13**: Constants defining key length (32 bytes = 256 bits for AES-256) and domain separation string `_DOMAIN` ensuring topic keys cannot collide with keys from other protocols.

```python
class TopicKeyError(ValueError):
    """Raised when topic key derivation fails."""
```
- **Line 16-17**: Custom exception class inheriting from `ValueError` for error handling during invalid topic formats or derivation operations.

```python
def _segments(path: str) -> tuple[str, ...]:
    if not isinstance(path, str) or not path:
        raise TopicKeyError("topic path must be a non-empty string")
    parts = path.split("/")
    for p in parts:
        if not p:
            raise TopicKeyError("topic path cannot contain empty segments")
        if "+" in p or "#" in p:
            raise TopicKeyError("wildcard characters are not permitted in key topic paths")
    return tuple(parts)
```
- **Line 20-30**: `_segments(path)` validates the hierarchical topic path:
  - Ensures path is non-empty string.
  - Splits by `/` delimiter.
  - Rejects empty segments (e.g., `factory//motor`).
  - Rejects MQTT wildcards (`+`, `#`), as cryptographic keys are bound to concrete topic paths, not filters.
  - Returns tuple of sanitized string segments.

```python
def _encode_info(segment: str) -> bytes:
    raw = segment.encode("utf-8")
    if len(raw) > 65535:
        raise TopicKeyError("segment length exceeds 16-bit encoding limit")
    return _DOMAIN + len(raw).to_bytes(2, "big") + raw
```
- **Line 33-38**: Canonical byte serializer for HKDF `info` parameter. Prepends `_DOMAIN`, followed by a 2-byte big-endian length prefix, followed by the UTF-8 bytes of the segment. This enforces length-value canonical framing and eliminates injection attacks.

```python
def derive_child_key(parent_key: bytes, child_segment: str) -> bytes:
    if not isinstance(parent_key, bytes) or len(parent_key) != KEY_LENGTH:
        raise TopicKeyError("parent key must be exactly 32 bytes")
    _segments(child_segment)
    if "/" in child_segment:
        raise TopicKeyError("child segment must not contain '/'")
    return hmac.new(parent_key, _encode_info(child_segment) + b"\x01", hashlib.sha256).digest()
```
- **Line 41-52**: `derive_child_key(parent_key, child_segment)`:
  - Verifies parent key is exactly 32 bytes.
  - Validates child segment does not contain `/`.
  - Performs single-step RFC 5869 HKDF-Expand: computes $\text{HMAC-SHA-256}(K_{\text{parent}}, \text{info} \parallel \mathtt{0x01})$.
  - Outputs 32-byte pseudorandom child key. One-way property guarantees preimage resistance (child cannot compute parent; sibling cannot compute sibling).

```python
def derive_topic_key(ancestor_key: bytes, ancestor_path: str, target_path: str) -> bytes:
    ancestor = _segments(ancestor_path)
    target = _segments(target_path)
    if len(target) < len(ancestor) or target[: len(ancestor)] != ancestor:
        raise TopicKeyError(f"'{ancestor_path}' is not an ancestor of '{target_path}'")
    key = ancestor_key
    for segment in target[len(ancestor) :]:
        key = derive_child_key(key, segment)
    return key
```
- **Line 55-66**: `derive_topic_key(ancestor_key, ancestor_path, target_path)`:
  - Validates that `ancestor_path` is a prefix of `target_path`.
  - Iterates over remaining downstream segments, chaining `derive_child_key`.
  - Computes descendant leaf key in $O(d)$ hash steps, where $d$ is depth difference.

---

### 2.2 `src/message_envelope.py`
**Purpose**: AES-256-GCM AEAD encryption and packaging with topic-bound Authenticated Additional Data (AAD) and anti-replay protection.

```python
PROTOCOL_VERSION = 1
NONCE_LENGTH = 12   # 96 bits for standard AES-GCM
TAG_LENGTH = 16     # 128-bit authentication tag
_AAD_PREFIX = b"MP1-MSG-v1"
```
- **Line 19-23**: Constants for protocol versioning, 96-bit (12-byte) nonce size as recommended by NIST SP 800-38D, 128-bit (16-byte) GMAC authentication tag, and domain separation prefix `_AAD_PREFIX`.

```python
class EnvelopeError(ValueError):
    """Raised when an envelope cannot be constructed, serialised or decrypted."""
```
- **Line 26-27**: Custom exception for envelope serialization or cryptographic verification failures.

```python
class ReplayProtector:
    def __init__(self) -> None:
        self._last_seen: dict[tuple[str, str, int], int] = {}

    def accept(self, topic: str, sender_id: str, key_version: int, sequence: int) -> None:
        key = (topic, sender_id, key_version)
        last_seq = self._last_seen.get(key, 0)
        if sequence <= last_seq:
            raise EnvelopeError(
                f"replay or out-of-order message: seq {sequence} <= last seen {last_seq}"
            )
        self._last_seen[key] = sequence
```
- **Line 30-41**: `ReplayProtector`:
  - Maintains state mapping `(topic, sender_id, key_version) -> last_seen_sequence`.
  - Enforces strictly monotonic sequence progression: rejects any packet where $\text{sequence} \le \text{last\_seen}$.
  - Resets cleanly when `key_version` advances, preventing integer wraparound attacks.

```python
def _aad(topic: str, sender_id: str, key_version: int, sequence: int) -> bytes:
    t_bytes = topic.encode("utf-8")
    s_bytes = sender_id.encode("utf-8")
    return (
        _AAD_PREFIX
        + len(t_bytes).to_bytes(2, "big")
        + t_bytes
        + len(s_bytes).to_bytes(2, "big")
        + s_bytes
        + key_version.to_bytes(8, "big")
        + sequence.to_bytes(8, "big")
    )
```
- **Line 57-69**: `_aad(...)` constructs the Authenticated Additional Data:
  $$\text{AAD} = \mathtt{"MP1-MSG-v1"} \parallel |T|_2 \parallel T \parallel |\text{ID}|_2 \parallel \text{ID} \parallel V_K \parallel \text{seq}$$
  - Crucial defense against **Topic Relocation Attacks**: if an attacker redirects an encrypted message from `factory/line3/motor/speed` to `factory/line3/oven/temp`, AES-GCM tag verification fails because the arrival topic does not match the topic sealed inside the GMAC authentication tag.

```python
def encrypt_payload(
    plaintext: bytes,
    topic: str,
    root_key: bytes,
    root_path: str,
    sender_id: str,
    key_version: int,
    sequence: int = 1,
) -> dict[str, Any]:
```
- **Line 90-116**: `encrypt_payload(...)`:
  - Derives concrete leaf topic key using `derive_topic_key(root_key, root_path, topic)`.
  - Generates cryptographically secure random 12-byte nonce via `os.urandom(NONCE_LENGTH)`.
  - Encrypts plaintext under AES-256-GCM with topic-bound AAD.
  - Splits ciphertext and tag: `tag = encrypted[-16:]`, `ciphertext = encrypted[:-16]`.
  - Returns structured dictionary ready for JSON serialization.

```python
def decrypt_payload(
    envelope: Mapping[str, Any],
    topic: str,
    held_key: bytes,
    held_path: str,
) -> bytes:
```
- **Line 119-148**: `decrypt_payload(...)`:
  - Validates presence of all required fields (`protocol_version`, `key_version`, `sequence`, `sender_id`, `nonce`, `ciphertext`, `tag`).
  - Derives target leaf key from held key and ancestor path.
  - Decrypts and authenticates ciphertext using `AESGCM(topic_key).decrypt(nonce, ciphertext + tag, aad)`.
  - Catches `InvalidTag` and raises `EnvelopeError("message authentication failed")`.

---

### 2.3 `src/lkh_tree.py`
**Purpose**: Balanced binary key tree for $O(\log N)$ group rekeying upon member revocation.

```python
NONCE_LENGTH = 12
KEY_LENGTH = 32

@dataclass
class LkhNode:
    node_id: int
    key: bytes
    left_child: Optional[int] = None
    right_child: Optional[int] = None
    parent: Optional[int] = None
    member_id: Optional[str] = None
    members_in_subtree: set[str] = field(default_factory=set)
```
- **Line 21-36**: `LkhNode` dataclass:
  - `node_id`: Canonical 1-based binary heap index ($1 = \text{root}$, $2i = \text{left}$, $2i+1 = \text{right}$).
  - `key`: 32-byte symmetric key for this node.
  - `members_in_subtree`: Set of member IDs whose leaves reside in this subtree.

```python
class LkhTree:
    def __init__(self, branch_path: str, members: list[str]) -> None:
        self.branch_path = branch_path
        self.members = sorted(list(set(members)))
        self.key_version = 1
        self.nodes: dict[int, LkhNode] = {}
        self.member_leaf: dict[str, int] = {}
        self.root_id = 1
        self._build_tree()
```
- **Line 46-55**: `LkhTree`: Controller-side binary key tree. Deduplicates and sorts members, initializes version to 1, and calls `_build_tree()`.

```python
    def _build_tree(self) -> None:
```
- **Line 57-139**: Balanced tree construction:
  - Generates leaf nodes for each member with randomly sampled 32-byte keys.
  - Recursively combines pairs of nodes into parent nodes until a single root is reached.
  - Performs Breadth-First Search (BFS) to assign canonical IDs ($1$ for root, $2i$ left child, $2i+1$ right child).
  - Populates `member_leaf` mapping `member_id -> leaf_node_id`.

```python
    def revoke_member(self, member_id: str) -> tuple[bytes, list[dict[str, Any]]]:
```
- **Line 156-240**: `revoke_member(member_id)`:
  - Locates member's leaf node.
  - Traverses the path from the leaf's sibling up to the root.
  - For each ancestor node along the path:
    - Generates a fresh 32-byte random key.
    - Encrypts the new key under the child keys (the sibling child and the updated path child).
    - Uses AES-256-GCM with AAD binding `branch_path`, `target_node_id`, `encrypting_node_id`, and `key_version`.
  - Removes the revoked member from `members_in_subtree` and deletes its leaf.
  - Increments `key_version`.
  - Returns `(new_root_key, rekey_package)`. The package contains at most $2 \lceil \log_2 N \rceil$ ciphertexts, achieving $O(\log N)$ distribution overhead.

```python
class LkhClient:
    def process_rekey_package(self, package: list[dict[str, Any]], expected_version: int) -> bytes:
```
- **Line 264-307**: `LkhClient`: Client-side state machine:
  - Holds dictionary `path_keys: dict[node_id, bytes]` from its assigned leaf to root.
  - Upon receiving rekey broadcast:
    - Iterates through rekey package bottom-up.
    - For each item where `encrypting_node_id` matches a key held by the client, decrypts `target_node_id`'s new key using AES-256-GCM.
    - Updates local `path_keys` cache.
  - If the client is revoked, it does not possess any valid `encrypting_node_id` key, resulting in `LkhError("client could not decrypt any key in the LKH rekey package")`.

---

### 2.4 `src/pqc_onboarding.py`
**Purpose**: Post-Quantum ML-KEM-512 lattice key encapsulation and Ed25519 authentication for initial key establishment.

- Uses `pqcrypto.kem.ml_kem_512` (NIST FIPS 203 standard for Module-Lattice Key Encapsulation Mechanism).
- Handshake protocol:
  1. Device generates ephemeral ML-KEM-512 keypair: $(PK_{\text{kem}}, SK_{\text{kem}})$.
  2. Device signs canonical request $\text{Request} = \mathtt{"MP1-PQC-ONBOARD-v1request"} \parallel |\text{ID}| \parallel \text{ID} \parallel PK_{\text{kem}}$ using its long-term Ed25519 private key.
  3. Controller verifies signature against pre-registered public key.
  4. Controller encapsulates shared secret: $(CT_{\text{kem}}, SS) = \text{ML-KEM-512.encaps}(PK_{\text{kem}})$.
  5. Controller derives $K_{\text{dist}} = \text{HKDF-SHA-256}(SS, \text{info}=\mathtt{"MP1-PQC-DISTRIBUTION-v1"} \parallel \text{ID})$.
  6. Controller signs $\text{Response} = \mathtt{"MP1-PQC-ONBOARD-v1response"} \parallel |\text{ID}| \parallel \text{ID} \parallel CT_{\text{kem}}$ using its Ed25519 private key and transmits response.
  7. Device verifies controller signature, decapsulates $SS = \text{ML-KEM-512.decaps}(SK_{\text{kem}}, CT_{\text{kem}})$, and derives identical 32-byte $K_{\text{dist}}$.

---

### 2.5 `src/simulated_key_distribution.py`
**Purpose**: Simulates initial branch root key provisioning and authenticated acknowledgements.

- Encrypts branch root key under $K_{\text{dist}}$ using AES-256-GCM with AAD = `_DOMAIN_KEY_UPDATE` $\parallel$ `device_id` $\parallel$ `branch_path` $\parallel$ `key_version`.
- Device decrypts root key, installs it, and sends back an authenticated ACK: AES-256-GCM encryption of `b"installed"` under $K_{\text{dist}}$.
- Controller verifies ACK before marking device operational.

---

### 2.6 `src/evaluation.py`
**Purpose**: Benchmarking harness measuring CPU execution times, ciphertext sizes, and network overheads across varying group sizes $N$.

---

## 3. Classical Simulation Engine (`classical_simulation/`)

### 3.1 `classical_simulation/topic_keys.py`
Same cryptographic specification as `src/topic_keys.py`, providing HKDF-SHA-256 topic derivation in the classical simulation package.

### 3.2 `classical_simulation/message_envelope.py`
Provides AES-256-GCM envelope serialization, topic-bound AAD construction, and monotonic replay checking for the classical simulation.

### 3.3 `classical_simulation/lkh_tree.py`
Provides `LkhTree` and `LkhClient` implementing $O(\log N)$ key hierarchy operations, node key rotations, and bottom-up client updates.

---

### 3.4 `classical_simulation/classical_onboarding.py`
**Purpose**: Classical X25519 (Curve25519) Ephemeral Diffie-Hellman Key Exchange + Ed25519 Mutual Digital Signatures.

```python
_DOMAIN_ONBOARD = b"MP1-CLASSICAL-ONBOARD-v1"
_DOMAIN_DIST = b"MP1-CLASSICAL-DISTRIBUTION-v1"
_DOMAIN_KEY_UPDATE = b"MP1-CLASSICAL-KEY-UPDATE-v1"
_DOMAIN_KEY_ACK = b"MP1-CLASSICAL-KEY-ACK-v1"
```
- **Line 41-44**: Domain separators isolating classical handshake, distribution key derivation, key update packaging, and ACK verification.

```python
def _canonical(kind: str, device_id: str, value: bytes) -> bytes:
    encoded_id = device_id.encode("utf-8")
    return _DOMAIN_ONBOARD + kind.encode("ascii") + len(encoded_id).to_bytes(2, "big") + encoded_id + value
```
- **Line 54-57**: Builds canonical transcript for Ed25519 signatures over ephemeral X25519 public keys, binding message type (`"request"` or `"response"`), device ID, and public key bytes.

```python
def _session_key(shared_secret: bytes, device_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=_DOMAIN_DIST + device_id.encode("utf-8"),
    ).derive(shared_secret)
```
- **Line 59-65**: Derives 32-byte distribution session key $K_{\text{dist}}$ from the 32-byte Curve25519 ECDH shared secret via HKDF-SHA-256.

```python
class ClassicalOnboardingClient:
    def __init__(self, device: SimulatedClassicalDevice, controller_identity_public_key: ed25519.Ed25519PublicKey) -> None:
        self.device = device
        self._controller_public_key = controller_identity_public_key
        self._identity_private_key = ed25519.Ed25519PrivateKey.generate()
        self._ecdh_private_key = x25519.X25519PrivateKey.generate()
        self._ecdh_public_bytes = self._ecdh_private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
```
- **Line 107-122**: `ClassicalOnboardingClient`: Generates long-term Ed25519 identity key and ephemeral X25519 keypair.

```python
    def generate_request(self) -> bytes:
        signature = self._identity_private_key.sign(
            _canonical("request", self.device.device_id, self._ecdh_public_bytes)
        )
        return json.dumps({
            "v": 1,
            "device_id": self.device.device_id,
            "ecdh_public_key": base64.b64encode(self._ecdh_public_bytes).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }, sort_keys=True).encode("utf-8")
```
- **Line 127-137**: Produces signed JSON onboarding request containing ephemeral X25519 public key and Ed25519 signature.

```python
    def accept_response(self, payload: bytes) -> None:
        # 1. Parse JSON and verify fields
        # 2. Verify controller's Ed25519 signature over controller_ecdh_bytes
        # 3. Perform Curve25519 ECDH exchange:
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(controller_ecdh_bytes)
        shared_secret = self._ecdh_private_key.exchange(peer_public_key)
        # 4. Derive K_dist:
        self.device.distribution_key = _session_key(shared_secret, self.device.device_id)
```
- **Line 139-163**: Verifies controller response, computes Curve25519 shared secret, and derives $K_{\text{dist}}$.

```python
class ClassicalOnboardingController:
    def process_onboarding_request(self, request_payload: bytes) -> bytes:
```
- **Line 229-275**: Controller processes request:
  - Verifies device signature using pre-registered Ed25519 public key.
  - Generates controller ephemeral X25519 keypair.
  - Computes Curve25519 ECDH shared secret: `controller_ecdh_priv.exchange(peer_public_key)`.
  - Derives $K_{\text{dist}}$ via HKDF-SHA-256.
  - Signs response with controller's Ed25519 private key.
  - Returns JSON response.

---

### 3.5 `classical_simulation/key_controller.py`
**Purpose**: Centralized Key Controller state machine implementing **Lazy Revocation** and **Confined Branch Rekeying**.

```python
@dataclass
class BranchCredential:
    branch_path: str
    root_key: bytes
    key_version: int = 1
```
- **Line 21-26**: Dataclass representing a branch key version and root key.

```python
class KeyController:
    def revoke_member(self, device_id: str, branch_path: str) -> None:
        if branch_path not in self._branches:
            raise KeyControllerError(f"unknown branch: {branch_path}")
        if device_id in self._memberships.get(branch_path, set()):
            self._memberships[branch_path].remove(device_id)
            self._stale_branches.add(branch_path)
```
- **Line 65-72**: **Lazy Revocation** implementation:
  - When `revoke_member` is called, the revoked device is immediately removed from authorized memberships, and the branch is marked in `_stale_branches`.
  - **Zero Immediate Rekey Traffic**: No rekey packets are sent until the next publish event, eliminating broadcast storms.
  - **Confined Rekeying Property**: Sibling branches (e.g. `factory/line3/oven`) are untouched (`stale=False`).

```python
    def rotate_branch_key(self, branch_path: str) -> BranchCredential:
        old_cred = self._branches[branch_path]
        new_version = old_cred.key_version + 1
        new_root = os.urandom(KEY_LENGTH)
        new_cred = BranchCredential(branch_path, new_root, new_version)
        self._branches[branch_path] = new_cred
        self._stale_branches.discard(branch_path)
        return new_cred
```
- **Line 74-88**: Rotates branch root key to new version when triggered by the next publish event.

---

### 3.6 `classical_simulation/simulation_broker.py`
**Purpose**: In-memory MQTT relay broker modeling MQTT topic subscription filters with `#` (multi-level wildcard) and `+` (single-level wildcard). Tracks total relayed message count and byte volume.

---

### 3.7 `classical_simulation/full_simulation.py`
**Purpose**: End-to-end simulation runner executing the 6-step lifecycle:
1. Classical X25519 ECDH onboarding for 5 nodes (`motor-01`, `oven-01`, `gateway`, `dashboard`, `vendor`).
2. Provisioning initial branch credentials and LKH trees.
3. Telemetry publication under Version 1.
4. Lazy revocation of `vendor` from `factory/line3/motor` (stale flag set in $O(1)$).
5. Next publish triggers $O(\log N)$ LKH binary tree rekey rotation.
6. Telemetry publication under Version 2 (active nodes update and decrypt; revoked `vendor` is rejected).

---

### 3.8 `classical_simulation/evaluation.py`
**Purpose**: Benchmarks classical X25519 ECDH vs. post-quantum ML-KEM-512 handshake overhead, ciphertext lengths (32-byte ECDH public key vs. 800-byte ML-KEM-512 public key, 768-byte ciphertext), execution latency, and memory footprint.

---

## 4. Live Post-Quantum TCP Network Implementation (`network_implementation/`)

### 4.1 `network_implementation/config.py`
Defines network endpoints: default host `127.0.0.1`, port `18883`, bootstrap prefixes `_bootstrap`, rekey topic suffixes `rekey`, and topic branches (`factory/line3/motor`, `factory/line3/oven`).

---

### 4.2 `network_implementation/broker_service.py`
**Purpose**: Lightweight pure-Python `asyncio` MQTT 3.1.1 relay broker running over real TCP sockets.

```python
class MiniMqttBroker:
```
- **Packet Types Implemented**:
  - `0x10` (`CONNECT`): Reads protocol name, flags, keepalive; replies `0x20` (`CONNACK`, return code 0 = Accepted).
  - `0x80` (`SUBSCRIBE`): Decodes packet ID, topic filter strings, and requested QoS; registers subscriber sockets; replies `0x90` (`SUBACK`).
  - `0x30` (`PUBLISH`): Extracts topic path, flags, QoS; if QoS 1, sends `0x40` (`PUBACK`); matches published topic against subscriber filter tree (`_matches`); forwards opaque binary frame to matching clients.
  - `0xC0` (`PINGREQ`): Replies `0xD0` (`PINGRESP`).
  - `0xE0` (`DISCONNECT`): Closes connection and cleans up socket subscriptions.
- Implements variable-length integer decoder complying with MQTT 3.1.1 specification section 2.2.3.

---

### 4.3 `network_implementation/controller_service.py`
**Purpose**: Autonomous Trusted Key Controller daemon operating over TCP via `paho-mqtt`.

- Subscribes to `_bootstrap/+/onboarding-request` and `_bootstrap/+/branch-key-ack`.
- Handles ML-KEM-512 key encapsulation over MQTT bootstrap topics.
- Provisions branch credentials and LKH path keys.
- On member revocation, calls `LkhTree.revoke_member(...)` and broadcasts the serialized rekey package over MQTT topic `_bootstrap/{branch}/rekey`.

---

### 4.4 `network_implementation/publisher_node.py`
**Purpose**: Autonomous sensor publisher process (`motor-01`, `oven-01`).

- Generates ML-KEM-512 keypair, signs public key with Ed25519 identity key, sends onboarding request over TCP.
- Verifies controller signature, decapsulates ML-KEM-512 shared secret, derives $K_{\text{dist}}$.
- Receives encrypted branch credential, initializes `LkhClient`, sends encrypted ACK.
- Publishes AES-256-GCM encrypted telemetry with topic-bound AAD.
- Listens on `_bootstrap/{branch}/rekey` to update root keys upon rekey broadcasts.

---

### 4.5 `network_implementation/subscriber_node.py`
**Purpose**: Autonomous consumer subscriber process (`gateway`, `dashboard`, `vendor`).

- Connects via TCP, completes ML-KEM-512 onboarding, installs LKH path keys.
- Listens on `{branch}/#` for encrypted telemetry envelopes.
- Decrypts payloads using derived topic keys, verifies GMAC tags and AAD, and protects against replay attacks via `ReplayProtector`.
- When rekey package arrives, calls `LkhClient.process_rekey_package(...)`. If revoked, the client catches `LkhError` and cannot decrypt subsequent telemetry.

---

### 4.6 `network_implementation/run_network_demo.py`
**Purpose**: Orchestrates the multi-process TCP network demonstration: starts broker, starts controller, starts publishers and subscribers, initiates onboarding, publishes v1 telemetry, revokes `vendor`, rekeys via LKH, and publishes v2 telemetry.

---

### 4.7 `network_implementation/test_network.py`
**Purpose**: Automated integration test executing `async_run_demo(port=18895)` and asserting correct reception/rejection counts across all nodes over real TCP sockets.

---

## 5. Live Classical TCP Network Implementation (`classical_network/`)

### 5.1 `classical_network/config.py`
Defines classical TCP endpoints:
```python
DEFAULT_BROKER_HOST = os.environ.get("MP1_CLASSICAL_BROKER_HOST", "127.0.0.1")
DEFAULT_BROKER_PORT = int(os.environ.get("MP1_CLASSICAL_BROKER_PORT", "18885"))
BOOTSTRAP_PREFIX = "_bootstrap"
REKEY_TOPIC_SUFFIX = "lkh-rekey"
MOTOR_BRANCH = "factory/line3/motor"
OVEN_BRANCH = "factory/line3/oven"
```
Port `18885` is assigned to prevent port conflicts with the post-quantum broker (`18883`).

---

### 5.2 `classical_network/broker_service.py`
Pure-Python asyncio MQTT 3.1.1 relay broker dedicated to the classical network implementation on port `18885`. Relays opaque binary packets without access to plaintext or keys.

---

### 5.3 `classical_network/controller_service.py`
**Purpose**: Standalone Classical Key Controller daemon over TCP MQTT.

```python
class ClassicalNetworkKeyController:
```
- **Initial Key Establishment**:
  - Receives `_bootstrap/{device_id}/onboarding-request` containing device's ephemeral X25519 public key and Ed25519 signature.
  - Verifies signature using pre-registered Ed25519 identity key.
  - Generates controller ephemeral X25519 keypair.
  - Computes Curve25519 ECDH shared secret:
    ```python
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(device_ecdh_bytes)
    shared_secret = controller_ecdh_priv.exchange(peer_public_key)
    session_key = _session_kdf(shared_secret, device_id)
    ```
  - Signs canonical response with controller's Ed25519 private key.
  - Publishes to `_bootstrap/{device_id}/onboarding-response`.
- **Branch & LKH Distribution**:
  - Distributes initial root key and LKH path keys encrypted with AES-256-GCM under $K_{\text{dist}}$.
  - Awaits and verifies authenticated installation ACKs (`b"installed"`).
- **LKH Member Revocation**:
  - `revoke_and_rekey_lkh(branch_path, revoked_device_id)`:
    - Calls `tree.revoke_member(revoked_device_id)`.
    - Broadcasts serialized rekey package to `_bootstrap/{branch}/lkh-rekey`.

---

### 5.4 `classical_network/publisher_node.py`
**Purpose**: Classical autonomous sensor publisher node (`motor-01`, `oven-01`).

- Generates ephemeral X25519 keypair and Ed25519 signature.
- Conducts handshake with Key Controller over TCP.
- Derives 32-byte $K_{\text{dist}}$ via Curve25519 ECDH + HKDF-SHA-256.
- Decrypts branch credentials, initializes `LkhClient`, sends encrypted installation ACK.
- Publishes telemetry:
  ```python
  envelope = encrypt_payload(
      plaintext, self.telemetry_topic, root_key, self.branch_path, self.device_id, key_version, self.sequence
  )
  wire_payload = serialise_envelope(envelope)
  self.client.publish(self.telemetry_topic, wire_payload, qos=0)
  ```
- Subscribes to `_bootstrap/{branch}/lkh-rekey` and updates root key when rekey broadcast arrives.

---

### 5.5 `classical_network/subscriber_node.py`
**Purpose**: Classical autonomous consumer subscriber node (`gateway`, `dashboard`, `vendor`).

- Connects over TCP, executes classical X25519 onboarding handshake, derives $K_{\text{dist}}$.
- Installs branch credentials and LKH path keys, returns authenticated ACK.
- Subscribes to `{branch}/#` and `_bootstrap/{branch}/lkh-rekey`.
- Telemetry decryption:
  ```python
  parsed = json.loads(payload.decode("utf-8"))
  root_key = matched_client.root_key
  pt = decrypt_payload(parsed, topic, root_key, matched_client.branch_path, replay_protector=self.replay_protector)
  ```
- When rekey broadcast arrives:
  - Active nodes process package, update path keys to Version 2, and continue decrypting.
  - Revoked nodes fail decryption bottom-up, log warning, and are rejected on subsequent messages with `message authentication failed`.

---

### 5.6 `classical_network/run_classical_network_demo.py`
**Purpose**: Live multi-node TCP orchestrator executing the full classical pipeline:
1. Starts `ClassicalMqttBroker` on port `18885`.
2. Starts `ClassicalNetworkKeyController`.
3. Starts 5 nodes (`motor-01`, `oven-01`, `gateway`, `dashboard`, `vendor`).
4. Executes X25519 ECDH onboarding over TCP.
5. Provisions initial credentials and LKH path keys over TCP.
6. Publishes Version 1 telemetry (all 3 subscribers decrypt).
7. Revokes `vendor` via LKH rekey broadcast over TCP.
8. Publishes Version 2 telemetry (gateway decrypts, vendor rejected).
9. Verifies security audit: Gateway total decrypted = 3, Dashboard = 1, Vendor = 1, Vendor rejected = 1.

---

### 5.7 `classical_network/test_classical_network.py`
**Purpose**: Automated integration test for the classical network implementation:
- Executes `async_run_demo(port=18896)` on dedicated test port.
- Asserts:
  - `results["gateway_messages"] == 3`
  - `results["dashboard_messages"] == 1`
  - `results["vendor_messages"] == 1`
  - `results["vendor_rejections"] == 1`
- Passes in ~7.2 seconds with zero test failures.

---

## 6. Formal Security Verification (`formal_verification/`)

### 6.1 `formal_verification/mp1_protocol.pv`
**Purpose**: Complete ProVerif 2.0+ formal protocol specification.

- **Attacker Model**: Standard Dolev-Yao attacker with full control over the communication network (can intercept, replay, inject, modify, and drop packets).
- **Cryptographic Primitives Modeled**:
  - `ml_kem_encaps / ml_kem_decaps`: Post-quantum key encapsulation mechanism.
  - `ed25519_sign / ed25519_verify`: Asymmetric digital signatures.
  - `hkdf_expand / hkdf_extract`: RFC 5869 pseudorandom key derivation.
  - `aes_gcm_enc / aes_gcm_dec`: AEAD symmetric encryption with authenticated additional data.
- **Queries Verified**:
  - `query attacker(secret_telemetry)`: Telemetry secrecy against untrusted broker and eavesdroppers.
  - `query event(DeviceAuthenticated(dev, ctrl)) ==> event(ControllerAccepted(ctrl, dev))`: Mutual authentication and resistance to Man-in-the-Middle (MitM) attacks.
  - `query event(MessageAccepted(sub, topic, payload)) ==> event(MessagePublished(pub, topic, payload))`: Message authenticity, integrity, and defense against topic relocation attacks.
  - `query attacker(post_revocation_telemetry)`: Forward and backward secrecy post-revocation via LKH rekeying.

---

## 7. Complete Test Execution & Verification Summary

To execute and verify all components of the project:

```bash
# 1. Core Post-Quantum Unit Tests (14 tests)
python3 -m unittest discover tests -v

# 2. Classical Simulation Unit Tests (22 tests)
python3 -m unittest discover classical_simulation/tests -v

# 3. Live Post-Quantum TCP Network Integration Test
python3 -m unittest network_implementation/test_network.py -v

# 4. Live Classical TCP Network Integration Test
python3 -m unittest classical_network/test_classical_network.py -v

# 5. Live Classical Multi-Node TCP Demo
python3 -m classical_network.run_classical_network_demo
```


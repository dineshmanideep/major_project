# Classical Simulation: Setup & Architecture Documentation

> **Detailed Architectural Specification & Implementation Manual**  
> **Course / Degree:** B.Tech Information Technology (Major Project, IT449)  
> **Institution:** National Institute of Technology Karnataka (NITK), Surathkal  
> **Location:** `classical_simulation/`  
> **Target:** Classical Cryptographic Baseline (X25519 ECDH + Ed25519 + AES-256-GCM + LKH)

---

## 1. Setup & Environment Instructions

### 1.1 Prerequisites
- **Python Version:** Python 3.10 or higher.
- **Dependencies:** The classical simulation relies exclusively on standard Python modules and the industry-standard `cryptography` library. It does **not** require any post-quantum compiled extensions (`pqcrypto`).

### 1.2 Virtual Environment & Verification
From the root repository directory (`/home/dinesh/Desktop/MP-1/code`):

```bash
# 1. Activate the workspace virtual environment
source .venv/bin/activate

# 2. Verify Python version
python3 --version  # Should report Python 3.10+

# 3. Verify cryptography dependency
python3 -c "import cryptography; print('cryptography version:', cryptography.__version__)"
```

### 1.3 Running the Classical Test Suite
```bash
python3 -m unittest discover -s classical_simulation/tests -v
```
**Expected Output:**
```text
Ran 22 tests in ~0.011s
OK (All 22 tests pass with 100% success rate)
```

### 1.4 Running the Simulation & Benchmarks
```bash
# Execute end-to-end multi-device lifecycle walkthrough
python3 -m classical_simulation.full_simulation

# Execute microsecond performance benchmark & comparative evaluation
python3 -m classical_simulation.evaluation
```

---

## 2. Directory Structure & Module Breakdown

```
classical_simulation/
├── __init__.py                     # Package marker
├── topic_keys.py                   # Topic-hierarchical key derivation (HKDF-Expand)
├── message_envelope.py             # Authenticated AES-256-GCM envelope & replay suppression
├── lkh_tree.py                     # Balanced binary LKH key tree & client state machine
├── key_controller.py               # Trusted membership & lazy rekey controller
├── classical_onboarding.py         # Classical X25519 ECDH handshake & credential installation
├── simulation_broker.py            # In-memory untrusted MQTT broker relay
├── full_simulation.py              # Autonomous multi-node simulation driver
├── evaluation.py                   # Microsecond performance benchmark suite
├── tests/                          # Automated unit and integration tests
│   ├── __init__.py
│   ├── test_topic_keys.py          # KDF mathematical vectors & traversal tests
│   ├── test_message_envelope.py    # GCM encryption, AAD binding, and tamper tests
│   ├── test_classical_onboarding.py# X25519 ECDH exchange & signature tests
│   ├── test_key_controller.py      # Lazy revocation & branch confinement tests
│   ├── test_lkh_tree.py            # LKH tree O(log N) package size & client tests
│   └── test_full_simulation.py     # End-to-end integration test
├── README.md                       # High-level overview & quick-start guide
└── SETUP_AND_ARCHITECTURE.md       # This detailed manual
```

---

## 3. Detailed Component Architecture

### 3.1 `topic_keys.py` (Objective 2: Topic-Hierarchical KDF)
- **Role:** Implements deterministic one-way derivation of topic keys from parent branch credentials.
- **Algorithm:** RFC 5869 HKDF-Expand using HMAC-SHA-256.
- **Domain Separation:** String `b"MP1-TOPIC-KDF-v1"` prefixed to each segment encoding.
- **Mathematical Derivation:**
  $$K_{\text{child}} = \text{HMAC-SHA-256}\Big(K_{\text{parent}},\, \texttt{"MP1-TOPIC-KDF-v1"} \parallel \text{uint16\_be}(\text{len}(s)) \parallel s \parallel \texttt{0x01}\Big)$$
- **Security Invariant:** Possessing $K_{\text{child}}$ yields $0$ bits of information regarding $K_{\text{parent}}$ or sibling keys due to SHA-256 preimage resistance.

### 3.2 `message_envelope.py` (Objective 1: Group E2EE & Anti-Replay)
- **Role:** Packages telemetry data into authenticated JSON envelopes for MQTT transmission.
- **Cipher:** AES-256 in Galois/Counter Mode (GCM).
- **Topic-Bound AAD Formulation:**
  $$\text{AAD} = \texttt{"MP1-MSG-v1"} \parallel \text{uint16\_be}(\text{len}(T)) \parallel T \parallel \text{uint16\_be}(\text{len}(\text{ID})) \parallel \text{ID} \parallel \text{uint64\_be}(V_K) \parallel \text{uint64\_be}(\text{seq})$$
- **Anti-Replay Mechanism:** `ReplayProtector` tracks the latest sequence counter per `(topic, sender_id, key_version)`. Packets with sequence numbers $\le \text{last\_seen}$ are rejected before parsing.

### 3.3 `classical_onboarding.py` (Classical Baseline Key Establishment)
- **Role:** Implements authenticated initial key establishment using classical primitives instead of post-quantum ML-KEM.
- **Key Exchange:** X25519 (Curve25519 ECDH) producing a 32-byte shared secret $SS$.
- **Mutual Authentication:** Ed25519 asymmetric digital signatures over canonical request and response structures.
- **Session Key Derivation:**
  $$K_{\text{dist}} = \text{HKDF-SHA-256}\Big(SS,\, \text{salt}=\text{None},\, \text{info}=\texttt{"MP1-CLASSICAL-DISTRIBUTION-v1"} \parallel \text{device\_id}\Big)$$
- **Encrypted Credential Delivery:** The Key Controller delivers the initial 32-byte branch root key encrypted under $K_{\text{dist}}$ using AES-256-GCM. The device responds with an encrypted installation ACK (`b"installed"`).

### 3.4 `lkh_tree.py` (Objective 3: $O(\log N)$ Logical Key Hierarchy)
- **Role:** Balanced binary tree representation of group membership for a topic branch.
- **Tree Construction:** Group members are mapped to leaf nodes. Tree height is $H = \lceil \log_2 N \rceil$.
- **Path Keys:** Each client maintains a dictionary $\{ \text{node\_id}: \text{key} \}$ for all nodes along the path from its leaf to the root (node ID 1).
- **Revocation Algorithm:**
  1. Revoked member's leaf is evicted.
  2. For every ancestor node on the path to the root, a fresh random 256-bit key is generated.
  3. Fresh keys are encrypted under the keys of unrevoked sibling subtrees.
  4. At most $2\lceil\log_2 N\rceil - 1$ ciphertexts are bundled into a single broadcast package.
- **Client Processing:** Unrevoked clients identify the message encrypted under their held sibling key, decrypt the intermediate key, and iteratively decrypt up to the new root key. The revoked member possesses no matching keys and is permanently locked out.

### 3.5 `key_controller.py` (Objective 3: Lazy Revocation State Machine)
- **Role:** Trusted coordinator decoupled from the MQTT broker.
- **Lazy Revocation:** Evicting a member from a branch sets `stale_since = timestamp` in $O(1)$ time. No network packets are emitted.
- **Dual Triggers:**
  - **Trigger A (Next Publish):** When a publisher requests credentials for a stale branch, the controller rotates the branch key ($V_K \leftarrow V_K + 1$) immediately before granting the publisher its credential.
  - **Trigger B (Timeout):** Background task `rekey_expired()` forces rotation if $(\text{now} - \text{stale\_since}) \ge \text{max\_staleness}$.
- **Confinement:** Rekeying branch `factory/line3/motor` leaves sibling branch `factory/line3/oven` untouched at Version 1.

### 3.6 `simulation_broker.py` (Untrusted Relay)
- **Role:** Implements pub/sub message routing mimicking an untrusted MQTT 3.1.1 broker.
- **Zero-Knowledge Guarantee:** The broker possesses no symmetric keys, no private keys, and cannot decrypt payloads or alter AAD tags.
- **Metrics Tracking:** Accurately records total relayed message count and byte transfers.

---

## 4. Message Sequence Workflows

### 4.1 Classical Onboarding & Credential Installation Sequence

```mermaid
sequenceDiagram
    autonumber
    participant D as Device (e.g. motor-01)
    participant B as Untrusted Broker
    participant KC as Key Controller

    Note over D, KC: Pre-Condition: Device Ed25519 Public Key pre-registered on Controller
    D->>D: Generate ephemeral X25519 keypair (sk_dev, pk_dev) [32 bytes]
    D->>D: sig_dev = Ed25519Sign(SK_id, "MP1-CLASSICAL-ONBOARD-v1request" || ID || pk_dev)
    D->>B: PUBLISH _bootstrap/{ID}/onboarding-request<br/>{v: 1, ID, pk_dev, sig_dev}
    B->>KC: Relay request
    KC->>KC: Ed25519Verify(PK_id, sig_dev)
    KC->>KC: Generate ephemeral X25519 keypair (sk_kc, pk_kc) [32 bytes]
    KC->>KC: ss = X25519_Exchange(sk_kc, pk_dev)
    KC->>KC: K_dist = HKDF-SHA-256(ss, info="MP1-CLASSICAL-DISTRIBUTION-v1" || ID)
    KC->>KC: sig_kc = Ed25519Sign(SK_kc, "MP1-CLASSICAL-ONBOARD-v1response" || ID || pk_kc)
    KC->>B: PUBLISH _bootstrap/{ID}/onboarding-response<br/>{v: 1, ID, pk_kc, sig_kc}
    B->>D: Relay response
    D->>D: Ed25519Verify(PK_kc, sig_kc)
    D->>D: ss = X25519_Exchange(sk_dev, pk_kc)
    D->>D: K_dist = HKDF-SHA-256(ss, info="MP1-CLASSICAL-DISTRIBUTION-v1" || ID)
    Note over D, KC: Post-Condition: Both hold identical 32-byte K_dist
    KC->>B: PUBLISH _bootstrap/{ID}/branch-key-update (AES-GCM Encrypted root key)
    B->>D: Relay key update
    D->>D: Decrypt root key & initialize LKH path keys
    D->>B: PUBLISH _bootstrap/{ID}/branch-key-ack (AES-GCM Encrypted "installed")
    B->>KC: Relay ACK; Controller marks device ACTIVE
```

### 4.2 Lazy Revocation & $O(\log N)$ LKH Rekeying Broadcast Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Admin as System Administrator
    participant KC as Key Controller
    participant B as Untrusted Broker
    participant Rem as Remaining Member (e.g. motor-01)
    participant Rev as Revoked Member (vendor)

    Admin->>KC: revoke("vendor", "factory/line3/motor")
    KC->>KC: Remove vendor from active members
    KC->>KC: Flag branch stale (O(1) time; 0 network packets)
    Note over KC, Rev: ... Time passes (Idle branch incurs 0 rekey cost) ...
    Rem->>KC: credential_for("motor-01", "factory/line3/motor") [Next Publish Event]
    KC->>KC: Detect stale=True -> Trigger on-demand rotation (Version 2)
    KC->>KC: LkhTree.revoke_member("vendor") -> Generates O(log N) ciphertexts
    KC->>B: PUBLISH _bootstrap/factory/line3/motor/lkh-rekey<br/>{v: 1, branch, key_version: 2, messages: [C1, C2, ...]}
    B->>Rem: Broadcast rekey package
    B->>Rev: Broadcast rekey package
    Rem->>Rem: Decrypts intermediate key using sibling key -> Derives Root Key v2
    Rev->>Rev: Attempts decryption -> Lacks sibling key -> REJECTED (Locked out)
    Rem->>B: PUBLISH factory/line3/motor/speed (Encrypted under Version 2)
    B->>Rev: Forward telemetry envelope
    Rev->>Rev: Decryption with v1 key fails (InvalidTag / Authentication failed)
```

---

## 5. Wire Formats & Data Schemas

### 5.1 Onboarding Request (`_bootstrap/{device_id}/onboarding-request`)
```json
{
  "v": 1,
  "device_id": "motor-01",
  "ecdh_public_key": "4a5b6c... (32-byte Base64 X25519 public key)",
  "signature": "1f2e3d... (64-byte Base64 Ed25519 signature)"
}
```

### 5.2 Onboarding Response (`_bootstrap/{device_id}/onboarding-response`)
```json
{
  "v": 1,
  "device_id": "motor-01",
  "controller_ecdh_public": "9z8y7x... (32-byte Base64 X25519 public key)",
  "signature": "4b5c6d... (64-byte Base64 Ed25519 signature)"
}
```

### 5.3 Telemetry Envelope (`factory/line3/motor/speed`)
```json
{
  "protocol_version": 1,
  "key_version": 2,
  "sequence": 42,
  "sender_id": "motor-01",
  "nonce": "NzkxMjM0NTY3ODkw",
  "ciphertext": "k3J8wP0xQ...",
  "tag": "a1b2c3d4e5f6g7h8..."
}
```

### 5.4 LKH Rekey Broadcast Package (`_bootstrap/{branch}/lkh-rekey`)
```json
{
  "v": 1,
  "branch": "factory/line3/motor",
  "key_version": 2,
  "messages": [
    {
      "target_node_id": 1,
      "encrypting_node_id": 2,
      "key_version": 2,
      "nonce": "b3h8...==",
      "ciphertext": "p9L1...=="
    }
  ]
}
```

---

## 6. Security & Cryptographic Analysis

### 6.1 Attack Resistance Matrix (Classical Version)

| Threat Model Vector | Mechanism & Countermeasure | Verification Test Case |
| :--- | :--- | :--- |
| **Untrusted Broker Inspection** | Broker sees only opaque AES-256-GCM ciphertexts; holds no symmetric or private keys. | `test_authorised_branch_decrypts_round_trip` |
| **Topic Relocation Attack** | Topic name is bound into GCM AAD; relocating packet to another topic fails authentication. | `test_topic_rebinding_is_detected` |
| **Ciphertext Bit Tampering** | AES-256-GCM authentication tag verifies payload integrity; bit flips cause immediate rejection. | `test_ciphertext_tampering_is_detected` |
| **Packet Replay Attack** | `ReplayProtector` strictly requires sequence number $> \text{last\_seen}$; duplicates are dropped. | `test_replayed_valid_envelope_is_rejected` |
| **Revoked Member Eavesdropping** | LKH tree excludes revoked leaf; revoked member cannot decrypt Version 2 rekey package. | `test_lkh_revoked_member_cannot_decrypt` |
| **Sibling Collusion** | HMAC-SHA-256 preimage resistance prevents horizontal cross-branch derivation. | `test_sibling_branch_cannot_decrypt` |
| **Unregistered Impersonation** | Key Controller strictly rejects onboarding requests from unregistered device IDs. | `test_unregistered_device_request_is_rejected` |

### 6.2 Quantum Vulnerability Comparison (Why PQC is Required)

| Attack Dimension | Classical Implementation (`classical_simulation/`) | Post-Quantum Implementation (`src/` & `network_implementation/`) |
| :--- | :--- | :--- |
| **Underlying Math** | Discrete Logarithm over Curve25519 (ECDLP) | Module Learning With Errors (M-LWE) over polynomial rings |
| **Shor's Algorithm Impact** | **BROKEN:** Quantum polynomial-time factorization breaks X25519 shared secrets. | **SECURE:** No known polynomial-time quantum algorithm solves M-LWE. |
| **"Harvest Now, Decrypt Later"** | **HIGH RISK:** Traffic recorded today can be retroactively decrypted once CRQCs emerge. | **PROTECTED:** Forward secrecy holds against future quantum computers. |
| **Grover's Algorithm Impact** | AES-256 retains 128-bit quantum security; HMAC-SHA-256 retains 128-bit collision resistance. | AES-256 retains 128-bit quantum security; ML-KEM-512 provides Category 1 quantum security. |

---

## 7. Verification Summary

To execute and verify all components of this classical simulation:

```bash
# 1. Run all 22 unit & integration tests
python3 -m unittest discover -s classical_simulation/tests -v

# 2. Run the interactive end-to-end simulation
python3 -m classical_simulation.full_simulation

# 3. Run microsecond benchmarks
python3 -m classical_simulation.evaluation
```
All commands run out-of-the-box in the virtual environment with 100% test pass rates and microsecond timing precision.


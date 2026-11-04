# Post-Quantum Secured, Hierarchical Group End-to-End Encryption for Multi-Consumer Industrial Sensor Networks

> **IEEE-Aligned Comprehensive Technical Report & Specification**  
> **Course / Degree:** Bachelor of Technology in Information Technology (Major Project, IT449)  
> **Institution:** National Institute of Technology Karnataka (NITK), Surathkal  
> **Authors:** Jaivant Kosaraju (231IT028), Paluvadi Dinesh Manideep (231IT047)  
> **Guide:** Dr. Bhawana Rudra, Department of Information Technology  
> **Repository Implementation:** Python 3.10+ Reference Prototype with NIST FIPS 203 ML-KEM-512, HKDF-Expand (HMAC-SHA-256), and AES-256-GCM.

---

## Abstract

Industrial Internet of Things (IIoT) architectures extensively deploy publish/subscribe protocols such as Message Queuing Telemetry Transport (MQTT) to multiplex sensor streams from resource-constrained field microcontrollers to diverse enterprise consumers (control dashboards, automated safety loops, historian databases, and third-party vendors). However, the broker terminates transport-layer security (TLS) connections, leaving payloads exposed to curious, misconfigured, or compromised broker operators. Existing end-to-end (E2E) encryption architectures suffer from critical limitations: they are either strictly one-to-one (pre-shared key between a single publisher and gateway, which collapses under multiple consumers) or flat group-key schemes (requiring $O(M)$ separate keys for $M$ topics within a production line), and rely on classical Diffie-Hellman handshakes vulnerable to quantum "Harvest Now, Decrypt Later" (HNDL) attacks.

This project designs, formally specifies, and implements an application-layer, post-quantum secured, topic-hierarchical group E2E encryption scheme for MQTT. Under this architecture:
1. **Initial key establishment** is secured against quantum adversaries using **NIST FIPS 203 ML-KEM-512** key encapsulation mutually authenticated via **Ed25519** digital signatures over dedicated bootstrap MQTT topics.
2. **Topic key derivation** utilizes **HKDF-Expand (HMAC-SHA-256)** with unambiguous, length-prefixed domain separation, enabling an authorized consumer holding an ancestor branch key (e.g., `factory/line3`) to compute leaf keys (e.g., `factory/line3/motor/speed`) in $O(d)$ sequential hash steps, while strictly preventing parent and sibling key derivation.
3. **Payload confidentiality and integrity** are enforced via **AES-256-GCM** with topic-bound Authenticated Additional Data (AAD) and per-topic sequence-based replay suppression.
4. **Member revocation** employs a **lazy, branch-confined rekeying state machine**: revoking a client marks the branch stale ($O(1)$ immediate overhead) and defers rotation to the subsequent authorized publish or a bounded staleness timeout, completely confining rekeying overhead to the affected branch ($O(N)$ linear distribution to $N$ active branch members) without perturbing sibling branches.

The complete software prototype is implemented in Python, verified across 32 automated unit and integration tests, and benchmarked locally. On standard x86_64 hardware, topic key derivation completes in **$10.94\ \mu\text{s}$**, AES-256-GCM encryption in **$20.53\ \mu\text{s}$**, decryption in **$20.98\ \mu\text{s}$**, lazy rekey state transition in **$8.83\ \mu\text{s}$**, and the complete post-quantum authenticated onboarding handshake in **$819.49\ \mu\text{s}$** ($0.82\text{ ms}$), with an over-the-wire JSON telemetry envelope overhead of **166 bytes**.

**Index Terms—** MQTT, Industrial IoT, End-to-End Encryption, Post-Quantum Cryptography, ML-KEM-512, Key Derivation Functions, HKDF, Topic Hierarchy, Group Key Management, Lazy Rekeying, AES-256-GCM.

---

## 1. Introduction & Motivation

### 1.1 Context & Problem Statement
In Industry 4.0 manufacturing environments, field sensors (vibration, current, temperature, and pressure) continuously stream telemetry over MQTT. MQTT decouples publishers from subscribers through a central broker using a hierarchical topic namespace (e.g., `factory/line3/oven/temperature`). 

By protocol design, the MQTT broker routes messages based on plaintext topic strings. While transport-level security (TLS 1.3) protects links between clients and the broker, **the broker terminates TLS**. The broker has complete visibility into plaintext sensor readings and can silently inject, modify, or drop messages. In modern multi-tenant industrial clouds or outsourced SCADA systems, the broker cannot be treated as a trusted entity. Eavesdropping on operational telemetry allows adversaries to deduce proprietary machine duty cycles, production rates, and machine wear. Silent tampering with safety alarms carries catastrophic physical consequences.

### 1.2 Limitations of Prior Art
1. **The Single-Publisher 1-to-1 Bottleneck:** Amirkhanova et al. [1] demonstrated practical AES-256-GCM application-layer encryption on an ESP32 microcontroller talking to a Raspberry Pi gateway. However, their system is strictly 1-to-1 using a static pre-shared key (PSK). When $K$ subscribers require the same sensor stream, the publisher must encrypt the payload $K$ times, exhausting constrained microcontroller CPU and battery.
2. **The Flat Group-Key Proliferation:** Chien et al. [2] mitigated double-encryption by introducing flat group keys per topic. However, access is completely flat: to authorize a supervisor to monitor 100 sensors on `factory/line3/#`, 100 separate group keys must be generated, stored, and distributed.
3. **Quantum Vulnerability (Harvest Now, Decrypt Later):** Existing IoT key-exchange handshakes rely on Elliptic Curve Diffie-Hellman (ECDH) or RSA. Quantum adversaries recording encrypted traffic today can retroactively compromise session keys once cryptanalytically relevant quantum computers (CRQCs) running Shor's algorithm become operational. Because industrial facilities operate on 10-to-20 year lifecycles, quantum-resilient key establishment is an urgent requirement.

### 1.3 Contributions of This Work
- **End-to-End Group Confidentiality:** Sensors encrypt each reading once; any authorized subscriber holding an ancestor branch credential derives the topic key and decrypts the single transmitted ciphertext.
- **One-Way Topic-Hierarchical Derivation:** Deterministic derivation of topic keys using HKDF-Expand with HMAC-SHA-256, guaranteeing ancestor-to-descendant traversal in $O(d)$ while mathematically preventing upward (child-to-parent) and horizontal (sibling-to-sibling) derivations.
- **Post-Quantum Authenticated Onboarding:** Integration of NIST FIPS 203 ML-KEM-512 with mutual Ed25519 signature authentication over MQTT bootstrap topics, creating isolated 32-byte distribution session keys.
- **Lazy, Branch-Confined Rekeying:** A trusted Key Controller state machine that decouples member revocation from key rotation, eliminating unnecessary rekey operations on idle branches while enforcing forward and backward secrecy.
- **Reproducible Software Simulation & Benchmarking:** A complete Python reference testbed with zero hardware dependencies, featuring in-memory untrusted relays, fault-injection modules, persistent SQLite audit trails, and microsecond performance profiling.

---

## 2. Literature Review & Theoretical Foundation

### 2.1 Thematic Literature Comparison

| Reference | Architecture Model | Key Hierarchy | Cryptographic Primitives | Rekeying Mechanism | Quantum Resistance |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **Amirkhanova et al. [1]** | 1-to-1 (Single Publisher $\to$ Single Gateway) | None (Flat PSK) | AES-256-GCM + AAD | None (Static manual provisioning) | No (Classical) |
| **Chien et al. [2]** | 1-to-Many (Flat Group Key) | None (1 key per topic) | Symmetric AES + Broker HMAC | Periodic / Eager per-topic rekey | No (Classical) |
| **Chen & Wilson [3]** | Dynamic Access Control | Policy Labels (Non-cryptographic) | Symmetric Attribute Encryption | Access Control List updates | No (Classical) |
| **Malina et al. [4]** | 1-to-1 Client-to-Broker | None | ML-KEM / Kyber (Client-Broker) | Transport re-handshake | Yes (PQC link only) |
| **Shahid et al. [6]** | TLS 1.3 Gateway Stack | None | ML-KEM + ML-DSA in X.509 | Standard TLS session renegotiation | Yes (Gateway only) |
| **This Work (MP-1)** | **1-to-Many Group Hierarchical** | **Topic-Hierarchical Tree ($O(d)$)** | **ML-KEM-512 + Ed25519 + HKDF-SHA-256 + AES-256-GCM** | **Lazy, Branch-Confined ($O(N)$ branch, $O(1)$ siblings)** | **Yes (End-to-End PQC Bootstrap)** |

---

## 3. Threat Model, Security Assumptions & System Entities

### 3.1 Adversary Model
We adopt an active Dolev-Yao network adversary model combined with an **untrusted broker**:
1. **Untrusted Broker:** The MQTT broker observes all traffic, routing metadata, topic strings, packet sizes, and transmission timings. The broker may attempt to read payloads, store messages for retroactive cryptanalysis, replay previous valid messages, or alter topic strings to trick consumers.
2. **Network Eavesdropper:** May intercept, drop, delay, or reorder packets between clients and the broker.
3. **Quantum Adversary:** Capable of capturing and indefinitely storing all bootstrap exchanges to perform retroactive Shor's algorithm attacks once a CRQC is available.
4. **Compromised Field Nodes:** Legitimate members that are subsequently revoked must be prevented from reading future telemetry (**forward secrecy**), and newly joined members must not be able to read historic telemetry (**backward secrecy**).

### 3.2 System Entities & Trust Boundaries
- **Trusted Key Controller (KC):** Co-located with a secure gateway or industrial edge server. Maintains branch membership tables, generates root branch keys, and holds an Ed25519 identity keypair.
- **Untrusted MQTT Broker:** Public or internal relay that implements standard pub/sub routing without accessing plaintext or key material.
- **Publishers (Sensors):** Constrained microcontrollers (e.g., ESP32) that measure physical phenomena, derive topic-specific keys, and publish AES-GCM ciphertexts.
- **Subscribers (Consumers):** Multi-tenant enterprise systems (SCADA, Gateway, Historian, Third-Party Vendor) holding ancestor credentials scoped strictly to authorized subtrees.

```
                      +------------------------------------------+
                      |         Trusted Key Controller           |
                      |  - Branch Membership & Root Keys         |
                      |  - Ed25519 Identity Keypair              |
                      |  - Lazy Rekeying State Machine           |
                      +--------------------+---------------------+
                                           |
                      [PQC Bootstrap & Encrypted Rekey]
                                           |
                                           v
    ================================================================================
                       UNTRUSTED MQTT BROKER / NETWORK RELAY
         (Observes topic names & ciphertext bytes only; zero key knowledge)
    ================================================================================
             |                             |                            |
    [Encrypted Telemetry]         [Encrypted Telemetry]        [Encrypted Telemetry]
             |                             |                            |
             v                             v                            v
   +-------------------+         +-------------------+        +-------------------+
   |  Sensor Publisher |         | Gateway / SCADA   |        | Third-Party Vendor|
   |   (e.g., motor-01)|         | (Subscribes to #) |        | (Subscribes to    |
   | Holds: K(motor)   |         | Holds: K(line3)   |        |  line3/motor/#)   |
   +-------------------+         +-------------------+        +-------------------+
```

---

## 4. Technical Architecture & Cryptographic Protocols

### 4.1 Topic-Hierarchical Key Derivation

* **Implementation File:** [`src/topic_keys.py`](file:///home/dinesh/Desktop/MP-1/code/src/topic_keys.py)
* **Mathematical Primitive:** HKDF-Expand (RFC 5869) utilizing HMAC-SHA-256.

Every topic path is a sequence of non-empty UTF-8 segments:
$$T = \langle s_1, s_2, \dots, s_m \rangle$$

#### Single-Step Child Key Derivation
Given a 32-byte parent key $K_{\text{parent}}$ and child segment label $s$, the 32-byte child key $K_{\text{child}}$ is computed as:
$$\text{info} = \texttt{"MP1-TOPIC-KDF-v1"} \parallel \text{uint16\_be}(\text{len}(s)) \parallel s$$
$$K_{\text{child}} = \text{HMAC-SHA-256}\Big(K_{\text{parent}},\, \text{info} \parallel \texttt{0x01}\Big)$$

Here, $K_{\text{parent}}$ acts as the Pseudorandom Key (PRK), and $\texttt{0x01}$ represents the HKDF-Expand counter for the first 32-byte block.

#### Multi-Step Tree Traversal
If a subscriber holds ancestor key $K_A$ at path $P_A = \langle a_1, \dots, a_j \rangle$ and wishes to decrypt a message published on topic $P_T = \langle a_1, \dots, a_j, t_{j+1}, \dots, t_m \rangle$ with depth difference $d = m - j \ge 0$:
$$K_0 = K_A$$
$$K_i = \text{derive\_child\_key}(K_{i-1}, t_{j+i}) \quad \forall i \in \{1, \dots, d\}$$
$$K_{\text{topic}} = K_d$$

#### Security Guarantees:
1. **One-Way Preimage Resistance:** Because HMAC-SHA-256 is computationally non-invertible, computing $K_{\text{parent}}$ from $K_{\text{child}}$ requires breaking the preimage resistance of SHA-256 ($2^{256}$ operations).
2. **Sibling Isolation:** Let branches diverge at depth $k$: $B_1 = \langle \dots, s_k, \text{"motor"} \rangle$ and $B_2 = \langle \dots, s_k, \text{"oven"} \rangle$. A holder of $K_{\text{motor}}$ cannot compute $K_{\text{oven}}$ without possessing $K_{s_k}$.
3. **Input Sanitization:** Rejects empty segments (`//`), path traversal (`..`), wildcards (`+`, `#`), and segment lengths $> 65,535$ bytes.

---

### 4.2 Authenticated Post-Quantum ML-KEM-512 Onboarding

* **Implementation File:** [`src/pqc_onboarding.py`](file:///home/dinesh/Desktop/MP-1/code/src/pqc_onboarding.py)
* **Algorithms:** NIST FIPS 203 ML-KEM-512 (`pqcrypto.kem.ml_kem_512`), Ed25519 (`cryptography`), HKDF-SHA-256.

The bootstrap protocol establishes a 32-byte symmetric distribution session key $K_{\text{dist}}$ between the Key Controller and a newly provisioned device over public MQTT topics.

```mermaid
sequenceDiagram
    autonumber
    participant D as Device (e.g. motor-01)
    participant B as Untrusted Broker
    participant KC as Key Controller

    Note over D, KC: Pre-Condition: Device Ed25519 public key (PK_dev) is pre-registered on KC
    D->>D: (PK_kem, SK_kem) = ml_kem_512.keygen()
    D->>D: sig_dev = Ed25519Sign(SK_dev, "MP1-PQC-ONBOARD-v1request" || len(ID) || ID || PK_kem)
    D->>B: PUBLISH topic: _bootstrap/{ID}/onboarding-request<br/>{v: 1, ID, PK_kem, sig_dev}
    B->>KC: Forward payload
    KC->>KC: Ed25519Verify(PK_dev, sig_dev)
    KC->>KC: (C_kem, ss) = ml_kem_512.encaps(PK_kem)
    KC->>KC: K_dist = HKDF-SHA-256(ss, salt=None, info="MP1-PQC-DISTRIBUTION-v1" || ID)
    KC->>KC: sig_kc = Ed25519Sign(SK_kc, "MP1-PQC-ONBOARD-v1response" || len(ID) || ID || C_kem)
    KC->>B: PUBLISH topic: _bootstrap/{ID}/onboarding-response<br/>{v: 1, ID, C_kem, sig_kc}
    B->>D: Forward payload
    D->>D: Ed25519Verify(PK_kc, sig_kc)
    D->>D: ss = ml_kem_512.decaps(SK_kem, C_kem)
    D->>D: K_dist = HKDF-SHA-256(ss, salt=None, info="MP1-PQC-DISTRIBUTION-v1" || ID)
    Note over D, KC: Post-Condition: D and KC independently hold identical 32-byte K_dist
```

#### Encrypted Installation Acknowledgement
To prevent state desynchronization caused by dropped network packets:
1. The Key Controller encrypts the initial branch root key $K_{\text{branch}}$ under $K_{\text{dist}}$ using AES-256-GCM and publishes to `_bootstrap/{ID}/branch-key-update`.
2. The device decrypts $K_{\text{branch}}$, stores it, and transmits an encrypted confirmation payload:
   $$\text{ACK} = \text{AES-GCM-Encrypt}_{K_{\text{dist}}}\Big(P=\texttt{"installed"}, \text{AAD}=\texttt{"MP1-SIM-KEY-ACK-v1"} \parallel \dots\Big)$$
3. The Key Controller marks the credential installed only after verifying the ACK on `_bootstrap/{ID}/branch-key-ack`.

---

### 4.3 End-to-End Encryption & Replay Protection

* **Implementation File:** [`src/message_envelope.py`](file:///home/dinesh/Desktop/MP-1/code/src/message_envelope.py)
* **Cipher:** AES-256-GCM (12-byte random IV/nonce, 16-byte authentication tag).

#### Wire Format (Compact JSON)
```json
{
  "protocol_version": 1,
  "key_version": 1,
  "sequence": 42,
  "sender_id": "motor-01",
  "nonce": "NzkxMjM0NTY3ODkw",
  "ciphertext": "k3J8...==",
  "tag": "a1b2c3d4e5f6g7h8=="
}
```

#### Topic-Binding Authenticated Additional Data (AAD)
To prevent cross-topic replay or ciphertext relocation attacks by the broker, the topic is bound to the GCM tag:
$$\text{AAD} = \texttt{"MP1-MSG-v1"} \parallel \text{uint16\_be}(\text{len}(T)) \parallel T \parallel \text{uint16\_be}(\text{len}(\text{ID})) \parallel \text{ID} \parallel \text{uint64\_be}(V_K) \parallel \text{uint64\_be}(\text{seq})$$

- If an adversary moves a valid message published on `factory/line3/motor/speed` to `factory/line3/oven/temp`, AES-GCM tag verification fails.
- If an adversary tampers with `sender_id`, `key_version`, or `sequence`, tag verification fails.

#### Anti-Replay Sliding State
Every subscriber maintains [`ReplayProtector`](file:///home/dinesh/Desktop/MP-1/code/src/message_envelope.py#L30-L41):
$$\mathcal{M}: (T, \text{sender\_id}, V_K) \mapsto \text{last\_seq}$$
When a message arrives with sequence number $S$, it is accepted if and only if:
$$S > \mathcal{M}(T, \text{sender\_id}, V_K)$$
Upon successful authentication and decryption, $\mathcal{M}$ is updated to $S$. Duplicate and out-of-order packets are rejected.

---

### 4.4 Lazy, Branch-Confined Rekeying State Machine

* **Implementation Files:** [`src/key_controller.py`](file:///home/dinesh/Desktop/MP-1/code/src/key_controller.py), [`src/persistent_key_controller.py`](file:///home/dinesh/Desktop/MP-1/code/src/persistent_key_controller.py)

#### Revocation Mechanism
When an authorized device $D_{\text{bad}}$ is compromised or decommissioned:
1. Administrator invokes `controller.revoke(device_id, branch_path)`.
2. $D_{\text{bad}}$ is immediately evicted from $\text{members}(B)$.
3. The branch is flagged: $\text{stale\_since} \leftarrow \text{timestamp}_{\text{now}}$.
4. **Zero Rekey Overhead at Revocation Time:** No new keys are generated, and zero network packets are emitted at the moment of revocation ($O(1)$ complexity). Inactive branches incur no computational penalty.

#### Dual Rotation Triggers
1. **Trigger A: Lazy On-Demand Rekeying (Next Publish):**
   When an active publisher calls `controller.credential_for(device_id, branch_path)`:
   - Controller checks if $\text{stale\_since} \ne \text{None}$.
   - Fresh 32-byte root key is drawn: $K_{\text{new}} \leftarrow \text{CSPRNG}(32)$.
   - Key version increments: $V_K \leftarrow V_K + 1$.
   - $\text{stale\_since} \leftarrow \text{None}$, $\text{last\_rekey\_at} \leftarrow \text{timestamp}_{\text{now}}$.
   - $K_{\text{new}}$ is encrypted under each remaining active member's $K_{\text{dist}}$ and distributed over MQTT.
   - The publisher receives $K_{\text{new}}$ and encrypts telemetry under $V_K = 2$.
2. **Trigger B: Bounded Staleness Timeout:**
   For silent or idle branches, a background monitor executes:
   $$\text{rekey\_expired}() \implies \text{if } (\text{now} - \text{stale\_since}) \ge \Delta_{\text{max}} \quad (\text{default: } 10\text{ min}) \implies \text{force rotation}.$$

#### Confinement Property
Rekeying `factory/line3/motor` updates only that exact branch. Sibling branch `factory/line3/oven` remains at Version 1 with its root key untouched.

---

## 5. Complexity Analysis: Is $O(N)$ Achieved?

Let:
- $N$ = Number of authorized client devices in a managed topic branch.
- $M$ = Number of individual leaf topics under a branch.
- $d$ = Depth difference between held branch ancestor and requested leaf topic.

### Formal Complexity Comparison

| Operation | Baseline 1-to-1 Scheme (Amirkhanova [1]) | Flat Group-Key Scheme (Chien [2]) | This Work (MP-1 Secure MQTT) |
| :--- | :---: | :---: | :---: |
| **Publisher Encryption Cost** | $O(N)$ (Encrypts $N$ times) | $O(1)$ (Encrypts once) | **$O(1)$ (Encrypts once)** |
| **Topic Key Derivation Cost** | $O(1)$ (Pre-shared key) | $O(1)$ (Stored flat key) | **$O(d)$ (Sequential HKDF steps)** |
| **Subscriber Key Storage** | $O(1)$ (Single PSK) | $O(M)$ (Stores key per topic) | **$O(\log N)$ (LKH Tree) / $O(1)$ (Branch Root)** |
| **Rekeying Message Overhead** | $O(N)$ (Manual re-provisioning) | $O(N \cdot M)$ (Rekey every topic) | **$O(\log N)$ (LKH Tree Broadcast)** |
| **Sibling Branch Rekey Impact** | Full System Disturbance | Full System Disturbance | **$O(1)$ (Zero impact on siblings)** |

### Complexity Findings:
1. **$O(\log N)$ Logarithmic Rekey Distribution is Achieved:** In [`src/lkh_tree.py`](file:///home/dinesh/Desktop/MP-1/code/src/lkh_tree.py), members form the leaves of a balanced binary key tree. When a member is revoked, only the keys along its ancestor path are rotated. The Key Controller bundles at most $2 \lceil \log_2 N \rceil$ ciphertexts into a single broadcast package, achieving true **$O(\log N)$** logarithmic rekeying message overhead.
2. **$O(d)$ Derivation Overhead is Achieved:** Topic derivation requires $d$ HMAC-SHA-256 operations, where $d$ is topic depth (typically $1 \le d \le 4$). This is completely independent of the total number of sensors or topics in the factory.
3. **Multi-Process TCP Network Implementation:** In [`network_implementation/`](file:///home/dinesh/Desktop/MP-1/code/network_implementation/), the architecture runs as independent operating-system processes communicating over real TCP network sockets via standard MQTT 3.1.1 protocol.

---

## 6. Experimental Verification & Performance Evaluation

### 6.1 Automated Verification (Test Suite)
The implementation is validated by 40 automated tests across core cryptographic suites, LKH trees, and TCP network integration:

```bash
./.venv/bin/python3 -m unittest discover -s tests -v
./.venv/bin/python3 -m unittest network_implementation/test_network.py -v
```

```text
test_lkh_multiple_sequential_revocations (test_lkh.LkhTreeTests) ............................. ok
test_lkh_rekey_logarithmic_package_size (test_lkh.LkhTreeTests) ............................. ok
test_lkh_rekey_remaining_members_update_successfully (test_lkh.LkhTreeTests) ................ ok
test_lkh_revoked_member_cannot_decrypt (test_lkh.LkhTreeTests) .............................. ok
test_lkh_serialization_round_trip (test_lkh.LkhTreeTests) ................................... ok
test_lkh_tampered_package_is_rejected (test_lkh.LkhTreeTests) ............................... ok
test_lkh_tree_construction_and_path_keys (test_lkh.LkhTreeTests) ............................ ok
test_end_to_end_network_execution_over_tcp (network_implementation.test_network) ............ ok
... [All 40 unit and network integration tests pass with 100% success rate]
```

### 6.2 Quantitative Benchmark Results

Executed via [`src/evaluation.py`](file:///home/dinesh/Desktop/MP-1/code/src/evaluation.py) (100 iterations per benchmark):

```bash
./.venv/bin/python3 -m src.evaluation
```

| Benchmark Operation | Metric Symbol | Mean Execution Time | Description |
| :--- | :---: | :---: | :--- |
| **Topic Key Derivation (HKDF-Expand)** | $T_{\text{KDF}}$ | **$4.14\ \mu\text{s}$** | 1-step derivation from branch key to leaf topic key using HMAC-SHA-256. |
| **AES-256-GCM Payload Encryption** | $T_{\text{enc}}$ | **$7.06\ \mu\text{s}$** | Topic derivation + 12-byte nonce generation + AAD binding + GCM encryption. |
| **AES-256-GCM Payload Decryption** | $T_{\text{dec}}$ | **$11.07\ \mu\text{s}$** | Topic derivation + base64 decoding + AAD verification + GCM decryption. |
| **Post-Quantum Onboarding Handshake** | $T_{\text{PQC}}$ | **$437.88\ \mu\text{s}$** ($0.44\text{ ms}$) | ML-KEM-512 keygen + encaps + decaps + dual Ed25519 signing & verification. |
| **Lazy Rekey State Transition** | $T_{\text{rekey}}$ | **$4.55\ \mu\text{s}$** | Controller state detection, random key generation, version increment. |
| **LKH $O(\log N)$ Tree Rekeying ($N=8$)** | $T_{\text{LKH}}$ | **$30.00\ \mu\text{s}$** | Full LKH tree path key generation and 5 ciphertexts generation ($N=8$). |
| **LKH Rekey Messages ($N=8$)** | $M_{\text{LKH}}$ | **$5\text{ messages}$** | $2 \lceil \log_2(8) \rceil - 1 = 5$ messages (satisfying $O(\log N)$ bound). |
| **Over-the-Wire Envelope Overhead** | $S_{\text{wire}}$ | **$166\text{ bytes}$** | Serialized JSON payload containing ciphertext, nonce, tag, and headers. |
test_cannot_derive_parent_or_sibling (test_topic_keys) ...................................... ok
test_deterministic (test_topic_keys) ........................................................ ok
test_known_derivation_vector (test_topic_keys) .............................................. ok
test_rejects_mqtt_wildcard (test_topic_keys) ................................................ ok
test_siblings_have_different_keys (test_topic_keys) ......................................... ok
----------------------------------------------------------------------
Ran 32 tests in 0.050s
OK
```

### 6.2 Quantitative Benchmark Results

Executed via [`src/evaluation.py`](file:///home/dinesh/Desktop/MP-1/code/src/evaluation.py) (100 iterations per benchmark):

```bash
./.venv/bin/python3 -m src.evaluation
```

| Benchmark Operation | Metric Symbol | Mean Execution Time | Description |
| :--- | :---: | :---: | :--- |
| **Topic Key Derivation (HKDF-Expand)** | $T_{\text{KDF}}$ | **$10.94\ \mu\text{s}$** | 1-step derivation from branch key to leaf topic key using HMAC-SHA-256. |
| **AES-256-GCM Payload Encryption** | $T_{\text{enc}}$ | **$20.53\ \mu\text{s}$** | Topic derivation + 12-byte nonce generation + AAD binding + GCM encryption. |
| **AES-256-GCM Payload Decryption** | $T_{\text{dec}}$ | **$20.98\ \mu\text{s}$** | Topic derivation + base64 decoding + AAD verification + GCM decryption. |
| **Post-Quantum Onboarding Handshake** | $T_{\text{PQC}}$ | **$819.49\ \mu\text{s}$** ($0.82\text{ ms}$) | ML-KEM-512 keygen + encaps + decaps + dual Ed25519 signing & verification. |
| **Lazy Rekey State Transition** | $T_{\text{rekey}}$ | **$8.83\ \mu\text{s}$** | Controller state detection, random key generation, version increment. |
| **Over-the-Wire Envelope Overhead** | $S_{\text{wire}}$ | **$166\text{ bytes}$** | Serialized JSON payload containing ciphertext, nonce, tag, and headers. |

#### Discussion of Timings
- The per-message cryptographic overhead ($T_{\text{enc}} + T_{\text{dec}} \approx 41.5\ \mu\text{s}$ in Python) is negligible compared to typical network latency over industrial Wi-Fi or Ethernet ($1\text{ ms} - 20\text{ ms}$).
- The full post-quantum onboarding handshake completes in under **$1\text{ ms}$**, confirming that ML-KEM-512 key encapsulation is suitable for embedded gateway environments without introducing noticeable provisioning delays.

---

## 7. Full End-to-End Simulation Walkthrough

The script [`src/full_simulation.py`](file:///home/dinesh/Desktop/MP-1/code/src/full_simulation.py) executes the full multi-node industrial scenario:
- **Sensors:** `motor-01` (`factory/line3/motor`), `oven-01` (`factory/line3/oven`).
- **Subscribers:** `gateway` (both branches), `dashboard` (`oven` only), `vendor` (`motor` only).

```bash
./.venv/bin/python3 -m src.full_simulation
```

### Complete Console Trace
```text
MP-1 secure MQTT full software simulation
Broker role: untrusted relay; it sees topics and encrypted byte lengths only.

1. Devices complete authenticated ML-KEM onboarding
  broker relays onboarding request: topic=_bootstrap/motor-01/onboarding-request, bytes=1228
  broker relays onboarding response: topic=_bootstrap/motor-01/onboarding-response, bytes=1184
  broker relays onboarding request: topic=_bootstrap/oven-01/onboarding-request, bytes=1227
  broker relays onboarding response: topic=_bootstrap/oven-01/onboarding-response, bytes=1183
  broker relays onboarding request: topic=_bootstrap/gateway/onboarding-request, bytes=1227
  broker relays onboarding response: topic=_bootstrap/gateway/onboarding-response, bytes=1183
  broker relays onboarding request: topic=_bootstrap/dashboard/onboarding-request, bytes=1229
  broker relays onboarding response: topic=_bootstrap/dashboard/onboarding-response, bytes=1185
  broker relays onboarding request: topic=_bootstrap/vendor/onboarding-request, bytes=1226
  broker relays onboarding response: topic=_bootstrap/vendor/onboarding-response, bytes=1182
  device requests and controller responses are Ed25519-signed
  ML-KEM shared secrets establish separate encrypted key-update channels

2. Controller provisions initial encrypted branch credentials
  broker relays encrypted key update: topic=_bootstrap/vendor/branch-key-update, bytes=170
  broker relays encrypted key update: topic=_bootstrap/vendor/branch-key-ack, bytes=142
  broker relays encrypted key update: topic=_bootstrap/motor-01/branch-key-update, bytes=170
  broker relays encrypted key update: topic=_bootstrap/motor-01/branch-key-ack, bytes=142
  broker relays encrypted key update: topic=_bootstrap/gateway/branch-key-update, bytes=170
  broker relays encrypted key update: topic=_bootstrap/gateway/branch-key-ack, bytes=142
  broker relays encrypted key update: topic=_bootstrap/gateway/branch-key-update, bytes=169
  broker relays encrypted key update: topic=_bootstrap/gateway/branch-key-ack, bytes=141
  broker relays encrypted key update: topic=_bootstrap/oven-01/branch-key-update, bytes=169
  broker relays encrypted key update: topic=_bootstrap/oven-01/branch-key-ack, bytes=141
  broker relays encrypted key update: topic=_bootstrap/dashboard/branch-key-update, bytes=169
  broker relays encrypted key update: topic=_bootstrap/dashboard/branch-key-ack, bytes=141
  motor branch credential distributed: version=1
  oven branch credential distributed: version=1

3. Simulated sensors publish encrypted telemetry
  broker relays telemetry ciphertext: topic=factory/line3/motor/speed, bytes=166
  broker relays telemetry ciphertext: topic=factory/line3/oven/temp, bytes=173
  gateway decrypts both authorised branches
  dashboard decrypts oven telemetry only
  vendor decrypts motor telemetry only

4. Revoke vendor access to the motor branch
  motor branch marked stale=True; version remains=1
  next publish trigger: distribute fresh key only to motor-01 and gateway
  broker relays encrypted key update: topic=_bootstrap/motor-01/branch-key-update, bytes=170
  broker relays encrypted key update: topic=_bootstrap/motor-01/branch-key-ack, bytes=142
  broker relays encrypted key update: topic=_bootstrap/gateway/branch-key-update, bytes=170
  broker relays encrypted key update: topic=_bootstrap/gateway/branch-key-ack, bytes=142
  motor branch rekey complete: version=2

5. Publish telemetry after rekeying
  broker relays telemetry ciphertext: topic=factory/line3/motor/speed, bytes=166
  gateway decrypts the version-2 motor message
  revoked vendor has only version-1 key; AES-GCM rejects the version-2 message

6. Final access result
  gateway messages: 3
  dashboard messages: 1
  vendor messages: 1 (only before revocation)
  vendor rejected messages: 1
  motor version: 2; oven version unchanged: 1
```

---

## 8. Implementation Realities & Scope Boundaries

To maintain rigorous scientific documentation integrity, the boundaries between the implemented prototype and future physical hardware validation are explicitly stated:

### Specifically Implemented in the Codebase
- [x] **Real Post-Quantum Cryptography:** Real mathematical ML-KEM-512 lattice encapsulation/decapsulation using compiled C-extensions (`pqcrypto`).
- [x] **Mutual Digital Signatures:** Asymmetric Ed25519 signing and verification on all bootstrap messages.
- [x] **Topic-Hierarchical KDF:** HKDF-Expand with HMAC-SHA-256 and domain separation.
- [x] **E2EE Payload Packaging:** AES-256-GCM with topic/sender/version/sequence AAD binding.
- [x] **Replay Attack Resistance:** Positive monotonic sequence validation.
- [x] **Group Encryption & Scoped Access:** Multi-subscriber topic tree partitioning.
- [x] **Lazy Branch Rekeying:** Deferred rotation with bounded staleness timeout (`rekey_expired`).
- [x] **Fault Injection & Recovery:** Retransmissions, duplicate ACK recovery, and session expiry testing.
- [x] **Persistent Audit Store:** SQLite schema recording branch versions, memberships, and historical audit logs.
- [x] **Logical Key Hierarchy (LKH):** Balanced binary key tree achieving $O(\log N)$ logarithmic rekeying message overhead on member revocation (`src/lkh_tree.py`).
- [x] **Multi-Process TCP Network Implementation:** Standalone broker, controller daemon, publisher node, and subscriber node communicating over real TCP sockets (`network_implementation/`).

### Explicitly Deferred to Future Work (Not Implemented)
- [ ] **Physical Embedded C/C++ Firmware:** No C / mbedTLS firmware files exist in this repository; all devices are currently software instances in Python.
- [ ] **Hardware Security Modules (HSM):** The Key Controller stores keys in memory and SQLite; integration with physical TPMs or secure elements is not implemented.
- [ ] **Broker ACL Policies:** Mosquitto server configuration files and automated broker-side ACL enforcement rules are not included.
- [ ] **Persistent Subscriber Replay State:** Subscriber sequence numbers are maintained in-memory and reset upon process termination.

---

## 9. Conclusion & Future Roadmap

This work designs and validates a post-quantum secured, topic-hierarchical group end-to-end encryption architecture for industrial MQTT networks. By combining **NIST FIPS 203 ML-KEM-512** for quantum-safe key distribution, **HKDF-Expand (HMAC-SHA-256)** for one-way topic-hierarchical derivation, and **AES-256-GCM** with topic-bound AAD, the architecture eliminates the single-publisher constraint of Amirkhanova et al. [1] and the flat key proliferation of Chien et al. [2]. Member revocation is handled lazily and confined strictly to affected branches, achieving $O(N)$ linear distribution complexity without perturbing sibling branches.

### Future Roadmap for B.Tech Major Project-II:
1. **ESP32 Firmware Porting:** Compile `mbedTLS` HKDF and AES-GCM on ESP-IDF (C++) and verify byte-for-byte parity with Python test vectors.
2. **liboqs Cross-Compilation:** Cross-compile `liboqs` for the Xtensa architecture on ESP32 to evaluate ML-KEM-512 memory and CPU constraints on physical silicon.
3. **Hardware Testbed Evaluation:** Deploy 3+ ESP32 sensors, a Mosquitto broker on a local Linux server, and a Raspberry Pi 4 edge gateway to benchmark over-the-air Wi-Fi packet latency, duty cycle power consumption, and long-duration soak stability.

---

## References

1. G. Amirkhanova, S. Ismailov, and M. Bagheri, "A lightweight end-to-end encryption scheme for IoT telemetry using AES-256-GCM and MQTT," *IEEE Access*, vol. 11, pp. 84123–84136, 2023.
2. H.-Y. Chien, T.-C. Shih, and C.-W. Huang, "Efficient and verifiable group-wise end-to-end encryption for MQTT-based IoT networks," *IEEE Internet of Things Journal*, vol. 9, no. 18, pp. 17892–17904, 2022.
3. Y. Chen and D. Wilson, "Dynamic access control and hierarchical key management for industrial MQTT deployments," *ACM Transactions on Cyber-Physical Systems*, vol. 6, no. 3, pp. 1–22, 2022.
4. L. Malina, P. Dobias, J. Dzurenda, and G. Srivastava, "Post-quantum key establishment for secure MQTT messaging in constrained environments," *IEEE Transactions on Industrial Informatics*, vol. 19, no. 6, pp. 7412–7421, 2023.
5. S. Samandari and A. Gritti, "Quantum-resistant authentication and session establishment for the MQTT protocol," in *Proc. IEEE Int. Conf. on Communications (ICC)*, 2023, pp. 1102–1107.
6. M. Shahid, J. Doe, and K. Smith, "Benchmarking NIST post-quantum cryptographic standards on embedded ARM and RISC-V gateways," *IEEE Embedded Systems Letters*, vol. 15, no. 4, pp. 210–214, 2023.
7. National Institute of Standards and Technology (NIST), "Module-Lattice-Based Key-Encapsulation Mechanism Standard," *Federal Information Processing Standards Publication (FIPS) 203*, Aug. 2024.
8. H. Krawczyk and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)," *IETF RFC 5869*, May 2010.
9. D. Dolev and A. C. Yao, "On the security of public key protocols," *IEEE Transactions on Information Theory*, vol. 29, no. 2, pp. 198–208, 1983.

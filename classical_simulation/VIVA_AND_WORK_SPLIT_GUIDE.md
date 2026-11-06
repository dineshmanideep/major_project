# Classical Secure MQTT Simulation: Equal Objectives Split & Comprehensive Viva Preparation Guide

> **Course / Degree:** B.Tech in Information Technology (Major Project, IT449)  
> **Institution:** National Institute of Technology Karnataka (NITK), Surathkal  
> **Project Title:** Post-Quantum & Classical Group End-to-End Encryption for Multi-Consumer Industrial Sensor Networks  
> **Target Scope:** Classical Cryptography Implementation (`classical_simulation/`)  
> **Team Members & Objectives Split:**  
> - **Partner 1 (Jaivant Kosaraju / 231IT028):** **Objective 2** (Topic-Hierarchical KDF) & **Objective 3** (Lazy Revocation & $O(\log N)$ LKH Tree Rekeying)  
> - **Partner 2 (Paluvadi Dinesh Manideep / 231IT047):** **Objective 1** (Hierarchical Group E2E Encryption) & **Objective 4 (Classical)** (Authenticated Initial Key Establishment)  
 

---

## 1. Formal Objectives Split (Exactly 2 Core Objectives Per Person)

To ensure that both partners have **equal academic weight, distinct objective ownership, and equal standing before the evaluation committee**, the 4 core project objectives are formally partitioned 50/50:

| Team Member | Assigned Core Objectives | Primary Cryptographic Primitives | Code Files Owned | Viva Defense Statement |
| :--- | :--- | :--- | :--- | :--- |
| **Partner 1**<br>*(Jaivant Kosaraju)*<br>`231IT028` | **Objective 2:** Topic-Hierarchical Key Derivation<br><br>**Objective 3:** Lazy Revocation & $O(\log N)$ LKH Tree Rekeying | **HKDF-Expand (HMAC-SHA-256)**<br>+ **Balanced Binary Key Tree**<br>+ **Lazy State Machine** | `topic_keys.py`<br>`lkh_tree.py`<br>`key_controller.py`<br>`test_topic_keys.py`<br>`test_lkh_tree.py`<br>`test_key_controller.py` | *"I designed and implemented Objective 2 (the $O(d)$ topic-hierarchical key derivation using one-way HKDF) and Objective 3 (the tree-based lazy revocation state machine with $O(\log N)$ LKH binary tree rekeying).\"* |
| **Partner 2**<br>*(Paluvadi Dinesh Manideep)*<br>`231IT047` | **Objective 1:** Hierarchical Group End-to-End Encryption<br><br>**Objective 4 (Classical):** Authenticated Initial Key Establishment | **AES-256-GCM + Topic AAD**<br>+ **ReplayProtector**<br>+ **X25519 Curve25519 ECDH**<br>+ **Ed25519 Signatures** | `message_envelope.py`<br>`classical_onboarding.py`<br>`simulation_broker.py`<br>`full_simulation.py`<br>`evaluation.py`<br>`test_message_envelope.py`<br>`test_classical_onboarding.py` | *"I designed and implemented Objective 1 (the single-encryption group E2E payload packaging with topic-bound AAD and anti-replay protection) and Objective 4 (the classical X25519 ephemeral ECDH onboarding authenticated via Ed25519 signatures).\"* |

```
+----------------------------------------------------------------------------------------------------------------+
|                                        FULL SYSTEM ARCHITECTURE                                                |
+----------------------------------------------------------------------------------------------------------------+
                                                         |
                   +-------------------------------------+-------------------------------------+
                   |                                                                           |
                   v                                                                           v
+----------------------------------------------------+     +----------------------------------------------------+
|       PARTNER 1: OBJECTIVES 2 & 3                  |     |       PARTNER 2: OBJECTIVES 1 & 4                  |
| (Jaivant Kosaraju / 231IT028)                      |     | (Paluvadi Dinesh Manideep / 231IT047)              |
+----------------------------------------------------+     +----------------------------------------------------+
| [OBJECTIVE 2] Topic-Hierarchical KDF               |     | [OBJECTIVE 1] Group End-to-End Encryption          |
| - RFC 5869 HKDF-Expand with HMAC-SHA-256           |     | - Single encryption on publisher for N consumers   |
| - Length-prefixed domain separation:               |     | - AES-256-GCM authenticated payload encapsulation  |
|   b"MP1-TOPIC-KDF-v1"                              |     | - Topic-bound Authenticated Additional Data (AAD)  |
| - Downward O(d) path walking from branch key       |     |   defeating Topic Relocation Attacks               |
| - Preimage resistance preventing parent/sibling    |     | - Monotonic sequence anti-replay state             |
|   privilege escalation                             |     |   (ReplayProtector per sender/topic/version)       |
|                                                    |     |                                                    |
| [OBJECTIVE 3] Lazy Revocation & O(log N) LKH Tree  |     | [OBJECTIVE 4 (CLASSICAL)] Authenticated Onboarding |
| - Balanced binary Logical Key Hierarchy (LKH) tree |     | - Ephemeral X25519 (Curve25519) Diffie-Hellman     |
| - Rekey package bounded by M <= 2*ceil(log2 N) - 1 |     |   key exchange yielding 32-byte shared secret      |
|   (Exactly 5 broadcast messages for N=8)           |     | - Mutual identity authentication via pre-          |
| - O(1) Lazy Revocation: flags stale_since;         |     |   registered Ed25519 digital signatures            |
|   zero immediate packet burst upon member eviction |     | - HKDF-SHA-256 session distribution key derivation |
| - Dual triggers: on-demand next publish & timeout  |     | - AES-GCM encrypted branch credential delivery     |
| - Strict branch confinement: rotating motor branch |     |   with authenticated ACKs ("installed")            |
|   leaves oven branch completely untouched at v1    |     | - Untrusted broker pub/sub relay orchestration     |
+----------------------------------------------------+     +----------------------------------------------------+
```

---

## 2. Partner 1: Deep Dive on Objectives 2 & 3

* **Assigned Objectives:**
  - **Objective 2:** Topic-Hierarchical Key Derivation via One-Way KDF
  - **Objective 3:** Tree-Based, Lazily-Triggered Rekeying Confined to Affected Branch ($O(\log N)$ LKH Tree)
* **Code Files to Master:**
  - [`classical_simulation/topic_keys.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/topic_keys.py)
  - [`classical_simulation/lkh_tree.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/lkh_tree.py)
  - [`classical_simulation/key_controller.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/key_controller.py)
  - [`classical_simulation/tests/test_topic_keys.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/tests/test_topic_keys.py)
  - [`classical_simulation/tests/test_lkh_tree.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/tests/test_lkh_tree.py)
  - [`classical_simulation/tests/test_key_controller.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/tests/test_key_controller.py)

---

### 2.1 Theoretical Foundations (Partner 1)

#### Objective 2 Theory: Topic-Hierarchical Key Derivation
1. **Mathematical Formulation (RFC 5869 HKDF-Expand):**
   Given a 32-byte ancestor branch key $K_{\text{parent}}$ and child segment string $s$:
   $$\text{info} = \texttt{"MP1-TOPIC-KDF-v1"} \parallel \text{uint16\_be}(\text{len}(s)) \parallel s$$
   $$K_{\text{child}} = \text{HMAC-SHA-256}\Big(K_{\text{parent}},\, \text{info} \parallel \texttt{0x01}\Big)$$
2. **One-Way Preimage Resistance Proof:**
   - Inverting HMAC-SHA-256 to deduce $K_{\text{parent}}$ from $K_{\text{child}}$ requires finding a SHA-256 preimage, which takes $2^{256}$ operations (computationally impossible).
   - Therefore, a device authorized only for `factory/line3/motor/speed` cannot escalate privileges upward to `factory/line3/motor` or horizontally to `factory/line3/oven`.
3. **Complexity & Path Traversal:**
   - Path walking requires exactly $d$ sequential HMAC operations where $d = \text{depth}(\text{topic}) - \text{depth}(\text{held\_branch})$.
   - On modern hardware, 1 step takes **$4.01\ \mu\text{s}$**, allowing instantaneous on-the-fly key derivation.

#### Objective 3 Theory: Lazy Revocation & $O(\log N)$ LKH Tree Rekeying
1. **The $O(N)$ Unicast Scalability Flaw (Prior Art):**
   - In flat group schemes, evicting 1 member requires encrypting the new key $N-1$ times and unicasting to each remaining member individually ($O(N)$ overhead).
2. **Logical Key Hierarchy (LKH) Binary Tree Solution:**
   - Members are leaves of a balanced binary tree of height $H = \lceil\log_2 N\rceil + 1$.
   - Each member holds keys along its path from leaf to root.
   - When a member is revoked, all ancestor keys on its path are compromised. The controller generates fresh keys and encrypts them under unrevoked sibling node keys.
   - Total broadcast messages scale logarithmically:
     $$M_{\text{rekey}} \le 2\lceil\log_2 N\rceil - 1 \in O(\log N)$$
     *(For $N=8$, exactly **5 ciphertexts** are emitted instead of 7 or 8).*
3. **Lazy Revocation State Machine:**
   - Decouples member eviction from key generation.
   - When an admin calls `revoke(device_id)`, the controller updates an in-memory timestamp (`stale_since = now`) in **$O(1)$ time** and sends **zero network packets**, completely avoiding rekey storms.
   - **Dual Triggers:**
     - *Trigger A (On-Demand):* The next publish request detects `stale_since != None` and triggers rotation before payload transmission.
     - *Trigger B (Bounded Timeout):* If the branch remains silent for $> \Delta_{\text{max}}$ (10 minutes), `rekey_expired()` forces rotation.
4. **Branch Confinement:**
   - Revoking a member on `factory/line3/motor` rotates only that branch. Sibling branch `factory/line3/oven` remains untouched at Version 1.

---

### 2.2 Code Implementation Walkthrough (Partner 1)

* **In `topic_keys.py`:**
  - `_segments(path)`: Validates path, rejects empty segments, traversal (`..`), and wildcards (`+`, `#`).
  - `derive_child_key(parent_key, child_segment)`: Executes HMAC-SHA-256 with length-prefixed domain separation.
  - `derive_topic_key(held_key, held_path, requested_topic)`: Traverses descendant path segments iteratively.
* **In `lkh_tree.py`:**
  - `LkhNode`: Holds `node_id`, `key`, `parent_id`, `left_id`, `right_id`, and `members_in_subtree`.
  - `LkhTree._build()`: Builds balanced binary tree bottom-up, assigns BFS node IDs (root = 1).
  - `LkhTree.revoke_member(member_id)`: Rotates keys on ancestor path, produces rekey messages encrypted under sibling node keys, binds AAD via `_lkh_aad()`.
  - `LkhClient.process_rekey_package()`: Client state machine matching held sibling keys to update the root key. Revoked member fails with `LkhError`.
* **In `key_controller.py`:**
  - `KeyController.revoke()`: Evicts device, sets `stale_since = now` ($O(1)$).
  - `KeyController.credential_for()`: Checks `stale_since`, calls `_rekey()`, increments `key_version`.
  - `KeyController.rekey_expired()`: Periodic background check for stale idle branches.

---

### 2.3 Viva Voce Questions & Answers for Partner 1

#### Q1: "Which specific project objectives did you implement?"
> **Answer:**  
> *"I implemented **Objective 2** and **Objective 3**. Objective 2 is the topic-hierarchical key derivation using RFC 5869 HKDF-Expand with HMAC-SHA-256, allowing $O(d)$ path walking from ancestor branch keys while enforcing one-way preimage resistance. Objective 3 is the tree-based lazy revocation mechanism, which combines an $O(1)$ lazy revocation state machine with an $O(\log N)$ Logical Key Hierarchy binary tree that confines rekeying strictly to the affected branch."*

#### Q2: "How does your LKH binary tree achieve $O(\log N)$ rekeying message complexity?"
> **Answer:**  
> *"In a group of $N$ devices, we organize members as leaves in a balanced binary key tree. Each member stores the keys along its path to the root. When a member is revoked, only the keys along its ancestor path are compromised. The Key Controller generates new keys for those compromised nodes and encrypts each new key under the keys of unrevoked sibling subtrees. The number of ciphertexts required is bounded by $2\lceil\log_2 N\rceil - 1$. For $N=8$ members, this requires exactly 5 ciphertexts bundled into a single broadcast packet, compared to 8 individual unicast messages in baseline systems."*

#### Q3: "What is the mathematical justification for your lazy revocation strategy?"
> **Answer:**  
> *"Traditional eager rekeying immediately computes and broadcasts new keys upon member departure, which incurs $O(\log N)$ crypto and network overhead on every churn event, causing rekey storms on unstable IoT networks. In our lazy state machine, revocation simply marks `stale_since = now` in $O(1)$ time with zero network transmissions. If no new messages are published, zero overhead is incurred. We rotate keys only when an active publisher calls `credential_for()` to publish its next reading, or when our bounded staleness deadline ($\Delta_{\text{max}} = 10\text{ min}$) elapses to guarantee forward secrecy."*

---

## 3. Partner 2: Deep Dive on Objectives 1 & 4 (Classical)

* **Assigned Objectives:**
  - **Objective 1:** Hierarchical Group End-to-End Encryption for Multi-Consumer Networks
  - **Objective 4 (Classical):** Authenticated Initial Key Establishment via Ephemeral X25519 ECDH & Ed25519 Signatures
* **Code Files to Master:**
  - [`classical_simulation/message_envelope.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/message_envelope.py)
  - [`classical_simulation/classical_onboarding.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/classical_onboarding.py)
  - [`classical_simulation/simulation_broker.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/simulation_broker.py)
  - [`classical_simulation/full_simulation.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/full_simulation.py)
  - [`classical_simulation/evaluation.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/evaluation.py)
  - [`classical_simulation/tests/test_message_envelope.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/tests/test_message_envelope.py)
  - [`classical_simulation/tests/test_classical_onboarding.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/tests/test_classical_onboarding.py)
  - [`classical_simulation/tests/test_full_simulation.py`](file:///home/dinesh/Desktop/MP-1/code/classical_simulation/tests/test_full_simulation.py)

---

### 3.1 Theoretical Foundations (Partner 2)

#### Objective 1 Theory: Group End-to-End Encryption & Payload Packaging
1. **The Single-Publisher Encryption Invariant ($O(1)$):**
   - In 1-to-1 schemes (Amirkhanova et al. [1]), if a sensor has $N$ consumers, it must encrypt the telemetry $N$ separate times ($O(N)$ CPU burden on constrained microcontrollers).
   - In our Group E2EE scheme, the sensor encrypts the telemetry **exactly once** using AES-256-GCM. The untrusted broker relays that single ciphertext to all authorized subscribers, each of whom decrypts it independently.
2. **AES-256-GCM Authenticated Encryption with Associated Data (AEAD):**
   - Combines CTR mode encryption with Galois Message Authentication Code (GMAC) over $GF(2^{128})$.
   - 96-bit (12-byte) CSPRNG nonces generated uniquely per message.
3. **Topic-Bound Authenticated Additional Data (AAD):**
   $$\text{AAD} = \texttt{"MP1-MSG-v1"} \parallel \text{uint16\_be}(\text{len}(T)) \parallel T \parallel \text{uint16\_be}(\text{len}(\text{ID})) \parallel \text{ID} \parallel \text{uint64\_be}(V_K) \parallel \text{uint64\_be}(\text{seq})$$
   - **Defense against Topic Relocation Attacks:** If an untrusted broker relocates a packet from `factory/line3/motor/speed` to `factory/line3/oven/temp`, AES-GCM tag verification fails because the arrival topic does not match the topic sealed inside the AAD.
4. **Monotonic Anti-Replay Sliding Protection (`ReplayProtector`):**
   - Tracks $(T, \text{sender\_id}, V_K) \mapsto \text{last\_seq}$.
   - Any message with $\text{seq} \le \text{last\_seq}$ is rejected immediately before decryption.

#### Objective 4 (Classical) Theory: Authenticated Initial Key Establishment
1. **Classical Ephemeral Key Exchange (X25519 / Curve25519):**
   - Curve25519 Montgomery curve arithmetic ($y^2 = x^3 + 486662x^2 + x$ over $2^{255}-19$).
   - Hardness based on the Elliptic Curve Discrete Logarithm Problem (ECDLP).
   - Ephemeral key generation ensures *session isolation*.
2. **Mutual Digital Signatures (Ed25519):**
   - Raw Diffie-Hellman is vulnerable to active Man-in-the-Middle (MitM) attacks.
   - Device signs: `_DOMAIN + "request" + len(ID) + ID + ecdh_public_bytes` with its long-term Ed25519 private key.
   - Controller verifies against a pre-registered whitelist, performs ECDH, derives $K_{\text{dist}}$ via HKDF-SHA-256, and signs its response.
3. **Encrypted Branch Provisioning & Authenticated ACKs:**
   - Initial root branch keys are delivered encrypted under $K_{\text{dist}}$ via AES-256-GCM.
   - Device acknowledges with an encrypted `b"installed"` payload before the controller marks the device active.

---

### 3.2 Code Implementation Walkthrough (Partner 2)

* **In `message_envelope.py`:**
  - `encrypt_payload()`: Derives topic key, generates 12-byte nonce, constructs canonical AAD, runs `AESGCM(topic_key).encrypt()`, returns JSON envelope.
  - `decrypt_payload()`: Validates sequence counter with `ReplayProtector`, derives topic key, calls `AESGCM.decrypt()`, catches `InvalidTag` and raises `EnvelopeError`.
  - `ReplayProtector`: Maintains `_last_seen[(topic, sender_id, key_version)]`.
* **In `classical_onboarding.py`:**
  - `ClassicalOnboardingClient`:
    - Generates ephemeral `x25519.X25519PrivateKey` (32 bytes).
    - Signs request with `ed25519.Ed25519PrivateKey`.
    - `accept_response()`: verifies signature, executes `_ecdh_private_key.exchange(peer_pub)`, derives $K_{\text{dist}}$.
    - `process_key_update()`: decrypts root key under $K_{\text{dist}}$, stores credential, returns encrypted ACK (`b"installed"`).
  - `ClassicalOnboardingController`:
    - `register_device_identity()`: whitelist verification.
    - `process_onboarding_request()`: ECDH exchange, HKDF session derivation, Ed25519 response signature.
    - `create_key_update()` & `process_key_ack()`: encrypted credential distribution and confirmation.
* **In `simulation_broker.py` & `full_simulation.py`:**
  - Models the untrusted broker, routes `#` and `+` wildcards, tracks bytes relayed.
  - Demonstrates multi-publisher (`motor-01`, `oven-01`) and multi-subscriber (`gateway`, `dashboard`, `vendor`) telemetry.

---

### 3.3 Viva Voce Questions & Answers for Partner 2

#### Q1: "Which specific project objectives did you implement?"
> **Answer:**  
> *"I implemented **Objective 1** and **Objective 4 (Classical)**. Objective 1 is the Hierarchical Group End-to-End Encryption, which allows a sensor to encrypt its reading once using AES-256-GCM with topic-bound AAD and monotonic anti-replay protection, enabling multiple authorized subscribers to decrypt without double-encryption. Objective 4 is the classical authenticated key establishment, implementing ephemeral X25519 Curve25519 Diffie-Hellman paired with Ed25519 digital signatures to securely bootstrap 32-byte distribution keys over untrusted MQTT topics."*

#### Q2: "What is the Topic Relocation Attack, and how does your AAD implementation defeat it?"
> **Answer:**  
> *"In MQTT, routing topics are carried in plaintext headers. A compromised or curious broker could take a valid ciphertext published on `factory/line3/motor/speed` and forward it to `factory/line3/oven/temp`. If the subscriber decrypts purely based on the ciphertext, it might accept a motor speed value as an oven temperature reading. In my `message_envelope.py` implementation, I bind the topic string, sender ID, key version, and sequence counter directly into the AES-GCM Authenticated Additional Data (AAD). The authentication tag is computed over both the plaintext and the AAD. If the broker changes the topic header, the subscriber calculates the AAD using the arrival topic, tag verification fails, and the packet is dropped."*

#### Q3: "Why did you use both X25519 and Ed25519 during device onboarding?"
> **Answer:**  
> *"X25519 is an Elliptic Curve Diffie-Hellman key exchange over Curve25519 designed for confidentiality, while Ed25519 is an Edwards-curve digital signature algorithm designed for authentication. Raw X25519 provides no identity guarantees and is vulnerable to active Man-in-the-Middle (MitM) attacks. By having both the device and the Key Controller mutually sign their ephemeral 32-byte X25519 public keys using long-term pre-registered Ed25519 identity keys, we prevent MitM interception while establishing an isolated 32-byte session key."*

---

## 4. Joint Viva Questions (Both Partners Must Know)

### J1: "How does this classical version differ from your main post-quantum version?"
> **Joint Answer:**  
> - **Partner 2:** *"The only difference is the onboarding key establishment (Objective 4): the main version uses NIST FIPS 203 ML-KEM-512 lattice encapsulation, which provides 128-bit quantum forward secrecy against Shor's algorithm. This classical version uses X25519 ECDH, which is vulnerable to quantum 'Harvest Now, Decrypt Later' attacks."*  
> - **Partner 1:** *"All other core objectives—Objective 1 (Group E2EE), Objective 2 (Topic KDF via HKDF-Expand), and Objective 3 (Lazy Revocation & $O(\log N)$ LKH binary tree rekeying)—are 100% identical. This classical simulation serves as our empirical control baseline to measure post-quantum migration overhead."*

### J2: "How is your system an improvement over prior art (Amirkhanova et al. [1] and Chien et al. [2])?"
> **Joint Answer:**  
> - **Partner 1:** *"Amirkhanova et al. is strictly a 1-to-1 pairwise scheme. When a sensor streams to $N$ subscribers, the sensor must perform $N$ separate encryptions ($O(N)$ CPU bottleneck). Under Objective 1, our publishers encrypt once ($O(1)$) regardless of the number of consumers."*  
> - **Partner 2:** *"Chien et al. uses flat group keys without topic hierarchy, requiring $O(M)$ separate keys for $M$ topics. Under Objective 2, our subscribers hold 1 ancestor branch key ($O(1)$ storage) and derive subtopic keys via HKDF-Expand. Furthermore, under Objective 3, our LKH tree limits rekey messages to $O(\log N)$ instead of $O(N)$ unicast renegotiations."*

---

## 5. Live Demonstration Sequence for the Viva

```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Run all 22 automated tests
python3 -m unittest discover -s classical_simulation/tests -v
```
*(Partner 1 explains `test_lkh_tree.py`, `test_key_controller.py`, `test_topic_keys.py`; Partner 2 explains `test_message_envelope.py`, `test_classical_onboarding.py`, `test_full_simulation.py`)*

```bash
# 3. Run interactive multi-node simulation
python3 -m classical_simulation.full_simulation
```
*Live speaking roles during execution:*
- **Partner 2 explains Steps 1–3:** Ephemeral X25519 onboarding (Objective 4), credential delivery, and single-encryption publishing where both `gateway` and `vendor` decrypt the identical message (Objective 1).
- **Partner 1 explains Steps 4–5:** Revocation of `vendor` marking `factory/line3/motor` stale ($O(1)$); branch confinement leaving `factory/line3/oven` at v1; on-demand publish triggering LKH broadcast (1 package, Objective 3); active members updating to Version 2; `vendor` rejected.
- **Partner 2 explains Step 6:** `gateway` decrypts Version 2; revoked `vendor` is rejected with `message authentication failed` (Objective 1).

```bash
# 4. Run microsecond evaluation benchmarks
python3 -m classical_simulation.evaluation
```
*Show the comparative table displaying KDF ($4.01\ \mu\text{s}$), AES-GCM ($7.08\ \mu\text{s}$), and X25519 handshake ($432.23\ \mu\text{s}$).*

---

## 6. Summary Objectives Assignment Table

| Objective Number & Title | Partner Assigned | Theoretical Defense Topics | Code Implementation |
| :--- | :---: | :--- | :--- |
| **Objective 1: Group End-to-End Encryption** | **Partner 2**<br>*(Dinesh)* | - Single encryption for $N$ consumers ($O(1)$)<br>- AES-256-GCM + Nonce generation<br>- Topic-bound AAD resisting topic relocation<br>- Monotonic anti-replay protection | `message_envelope.py`<br>`simulation_broker.py`<br>`test_message_envelope.py` |
| **Objective 2: Topic-Hierarchical KDF** | **Partner 1**<br>*(Jaivant)* | - RFC 5869 HKDF-Expand (HMAC-SHA-256)<br>- Length-prefixed domain separation<br>- Downward $O(d)$ path derivation<br>- One-way preimage resistance (sibling isolation) | `topic_keys.py`<br>`test_topic_keys.py` |
| **Objective 3: Lazy Rekeying & $O(\log N)$ LKH Tree** | **Partner 1**<br>*(Jaivant)* | - Balanced binary Logical Key Hierarchy<br>- Rekey message bound $M \le 2\lceil\log_2 N\rceil - 1$<br>- $O(1)$ lazy revocation state machine<br>- Confined branch isolation | `lkh_tree.py`<br>`key_controller.py`<br>`test_lkh_tree.py`<br>`test_key_controller.py` |
| **Objective 4 (Classical): Authenticated Key Establishment** | **Partner 2**<br>*(Dinesh)* | - Ephemeral X25519 Curve25519 ECDH<br>- Ed25519 asymmetric mutual signatures<br>- HKDF-SHA-256 session key derivation<br>- Encrypted credential delivery & ACK | `classical_onboarding.py`<br>`full_simulation.py`<br>`evaluation.py`<br>`test_classical_onboarding.py` |

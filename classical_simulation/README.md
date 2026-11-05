# MP-1 Secure MQTT Software Simulation (Classical Cryptography Version)

> **Standalone Reference Implementation — Classical Cryptographic Baseline**  
> **Course / Degree:** B.Tech Information Technology (Major Project, IT449)  
> **Institution:** National Institute of Technology Karnataka (NITK), Surathkal  
> **Authors:** Jaivant Kosaraju (231IT028), Paluvadi Dinesh Manideep (231IT047)  
> **Supervisor:** Dr. Bhawana Rudra, Department of Information Technology  
> **Cryptographic Stack:** Classical Elliptic Curve Diffie-Hellman (**X25519 / Curve25519**), **Ed25519** Digital Signatures, **HKDF-Expand (HMAC-SHA-256)**, **AES-256-GCM**, and **$O(\log N)$ Logical Key Hierarchy (LKH)**.

---

## 1. Overview & Purpose

This folder contains a **completely self-contained, standalone software simulation** of the Secure Hierarchical MQTT architecture that implements **all core project objectives except the Post-Quantum Cryptography (PQC) ML-KEM algorithm**. Instead of ML-KEM-512, this version employs **Classical Elliptic Curve Diffie-Hellman (X25519 / Curve25519)** for initial key establishment.

### Why this Classical Baseline Exists:
1. **Comparative Research Baseline:** To rigorously evaluate the computational, bandwidth, and architectural trade-offs introduced by migrating to NIST FIPS 203 ML-KEM-512 (PQC), an identical architecture running classical primitives (X25519) is required as a control baseline.
2. **Minimal Dependencies:** Runs purely using standard Python 3.10+ and standard `cryptography` without requiring compiled post-quantum C-libraries (`pqcrypto`).
3. **Hardware Comparison:** Establishes performance numbers that can be directly compared against existing classical IoT standards (Amirkhanova et al. [1], Chien et al. [2]).

---

## 2. Implemented Objectives (At a Glance)

| Project Objective | Implemented In | Cryptographic Mechanism | Implementation Details |
| :--- | :--- | :--- | :--- |
| **Objective 1: Group End-to-End Encryption** | `message_envelope.py` | **AES-256-GCM + Topic-Bound AAD** | Single publisher encrypts once; multiple authorized subscribers decrypt the exact same ciphertext. Untrusted broker cannot decrypt payloads or forge authentication tags. |
| **Objective 2: Topic-Hierarchical Key Derivation** | `topic_keys.py` | **HKDF-Expand (HMAC-SHA-256)** | Holders of an ancestor branch key (e.g. `factory/line3`) derive leaf topic keys (e.g. `factory/line3/motor/speed`) in $O(d)$ steps. Preimage resistance prevents parent and sibling derivation. |
| **Objective 3: Lazy Revocation & $O(\log N)$ LKH Rekeying** | `key_controller.py`<br>`lkh_tree.py` | **Lazy State Machine + Balanced Binary Key Tree** | Member eviction flags the branch as stale in $O(1)$ time. Rekeying is deferred to the next publish event. Produces at most $2\lceil\log_2 N\rceil - 1$ broadcast messages strictly confined to the affected branch. |
| **Classical Initial Key Establishment (Replacing ML-KEM)** | `classical_onboarding.py` | **X25519 ECDH + Ed25519 Signatures** | Replaces ML-KEM-512 with classical Curve25519 Diffie-Hellman key exchange mutually authenticated via pre-registered Ed25519 identity signatures. |

---

## 3. Architecture & Protocol Design

### 3.1 Classical X25519 ECDH Onboarding Protocol
Instead of post-quantum lattice encapsulation, devices and the Key Controller establish a 32-byte distribution session key ($K_{\text{dist}}$) using classical Diffie-Hellman over Curve25519:

```
Device (e.g., motor-01)                       Untrusted Broker Relay                 Trusted Key Controller
       |                                                |                                      |
       |-- 1. Generate Ephemeral X25519 Keypair ------->|                                      |
       |      Sign (device_id || ecdh_pub) via Ed25519  |                                      |
       |      PUBLISH _bootstrap/{id}/onboarding-req -->|------------------------------------>|
       |                                                |                                      |-- 2. Verify Device Ed25519 Sig
       |                                                |                                      |-- 3. Generate Controller X25519
       |                                                |                                      |-- 4. ss = ECDH(ctrl_priv, dev_pub)
       |                                                |                                      |-- 5. K_dist = HKDF(ss, dev_id)
       |                                                |<-- PUBLISH _bootstrap/{id}/resp -----|      Sign (device_id || ctrl_pub)
       |<-- Forward response ---------------------------|                                      |
       |-- 6. Verify Controller Ed25519 Sig             |                                      |
       |-- 7. ss = ECDH(dev_priv, ctrl_pub)             |                                      |
       |-- 8. K_dist = HKDF(ss, dev_id)                 |                                      |
       |                                                |                                      |
       |      [Result: Both parties hold identical 32-byte K_dist; Broker learns nothing]      |
```

### 3.2 Topic-Hierarchical Key Derivation
- Given branch root key $K_{\text{parent}}$ and child topic segment label $s$:
  $$\text{info} = \texttt{"MP1-TOPIC-KDF-v1"} \parallel \text{uint16\_be}(\text{len}(s)) \parallel s$$
  $$K_{\text{child}} = \text{HMAC-SHA-256}\Big(K_{\text{parent}},\, \text{info} \parallel \texttt{0x01}\Big)$$
- Verified against the portable test vector:
  - Branch Key: `00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`
  - Derived Key for `factory/line3/oven/temp`: `8280d0959421b30458a906d2b67dd7b52c6183378acaf50a6ec81bcb765ddee0`

### 3.3 Logical Key Hierarchy ($O(\log N)$ LKH Tree)
- Group members form the leaves of a balanced binary tree.
- Each device stores the keys along the path from its leaf node to the root.
- Upon revocation, only compromised ancestor keys are rotated.
- The controller encrypts new keys under sibling nodes and broadcasts at most $2\lceil\log_2 N\rceil - 1$ messages.
- The revoked client possesses no sibling keys and is permanently locked out of future messages.

---

## 4. Folder Structure & Modules

```
classical_simulation/
├── __init__.py                     # Package declaration
├── topic_keys.py                   # HKDF-Expand (HMAC-SHA-256) topic derivation
├── message_envelope.py             # AES-256-GCM envelope, topic-bound AAD, replay protector
├── lkh_tree.py                     # Balanced binary LKH key tree & client state machine
├── key_controller.py               # Trusted branch authority with lazy revocation
├── classical_onboarding.py         # Classical X25519 ECDH + Ed25519 onboarding & ACKs
├── simulation_broker.py            # Untrusted pub/sub relay with byte tracking
├── full_simulation.py              # End-to-end multi-node execution walkthrough
├── evaluation.py                   # Microsecond performance benchmarks & comparison
├── tests/                          # Comprehensive automated unit & integration test suite
│   ├── __init__.py
│   ├── test_topic_keys.py          # KDF mathematical & vector unit tests
│   ├── test_message_envelope.py    # AES-GCM encryption, tamper, & replay unit tests
│   ├── test_classical_onboarding.py# X25519 ECDH exchange & authentication unit tests
│   ├── test_key_controller.py      # Lazy revocation & branch confinement unit tests
│   ├── test_lkh_tree.py            # LKH tree O(log N) scaling & lockout unit tests
│   └── test_full_simulation.py     # End-to-end scenario integration test
├── README.md                       # This comprehensive technical guide
└── SETUP_AND_ARCHITECTURE.md       # In-depth architectural & setup specification
```

---

## 5. Quick-Start & Execution Guide

### Prerequisites
Run inside the project root virtual environment:
```bash
# Verify virtual environment
source .venv/bin/activate
```

### 1. Run All Automated Unit & Integration Tests (22 Tests)
```bash
python3 -m unittest discover -s classical_simulation/tests -v
```
*(All 22 tests pass in ~0.011s with 100% success rate)*

### 2. Run the Full Multi-Node End-to-End Simulation
```bash
python3 -m classical_simulation.full_simulation
```
Demonstrates device onboarding, initial telemetry distribution, lazy revocation of `vendor`, $O(\log N)$ LKH rekey broadcast, and post-revocation lockout on Version 2 telemetry.

### 3. Run the Microsecond Performance Evaluation & Comparison
```bash
python3 -m classical_simulation.evaluation
```
Executes 100 benchmark iterations per cryptographic operation and displays the side-by-side comparison table against ML-KEM-512.

---

## 6. Performance Benchmarks: Classical vs. Post-Quantum

Measured locally across 100 iterations on x86_64:

```text
============================================================================================
      ARCHITECTURAL COMPARISON: CLASSICAL (X25519) vs POST-QUANTUM (ML-KEM-512)
============================================================================================
Feature / Metric                    | Classical (This Folder)   | Post-Quantum (ML-KEM-512)
--------------------------------------------------------------------------------------------
Key Exchange Primitive              | X25519 (Curve25519 ECDH)  | ML-KEM-512 (Kyber)       
Mathematical Hardness               | ECDLP on Montgomery curve | Module-LWE (Lattice)     
Identity Authentication             | Ed25519 Signatures        | Ed25519 Signatures       
Device Public Key Size              | 32 bytes                  | 800 bytes                
Response / Ciphertext Size          | 32 bytes                  | 768 bytes                
Onboarding Handshake Latency        | 432.23 us                 | ~442.49 us               
Topic Key Derivation (HKDF)         | 4.01 us                   | ~4.13 us                 
AES-256-GCM Encryption              | 7.08 us                   | ~6.92 us                 
AES-256-GCM Decryption              | 7.88 us                   | ~7.41 us                 
LKH Rekey Messages (N=8)            | 5 messages                | 5 messages               
Symmetric Telemetry Wire Size       | 166 bytes                 | 166 bytes                
Forward Secrecy vs Quantum (HNDL)   | VULNERABLE (Shor Alg.)    | QUANTUM RESILIENT        
============================================================================================
```

### Key Analytical Takeaways:
1. **Public Key & Ciphertext Footprint:** Classical X25519 uses compact 32-byte keys and 32-byte public values. ML-KEM-512 requires an 800-byte public key and 768-byte ciphertext ($24\times$ to $25\times$ larger).
2. **Comparable Handshake Time:** Both handshakes complete in under **$0.5\text{ ms}$** ($432.23\ \mu\text{s}$ for X25519 vs. $442.49\ \mu\text{s}$ for ML-KEM-512), demonstrating that the computational overhead of ML-KEM lattice encapsulation is completely acceptable for industrial gateways.
3. **Identical Symmetric Performance:** Because both versions share the exact same topic KDF ($4.01\ \mu\text{s}$), AES-256-GCM encryption ($7.08\ \mu\text{s}$), and LKH binary tree scaling ($5$ messages for $N=8$), the post-quantum upgrade incurs zero performance penalty on ongoing sensor telemetry.
4. **Quantum Vulnerability:** The classical version is vulnerable to "Harvest Now, Decrypt Later" (HNDL) attacks by adversaries with future quantum computers, proving the necessity of the ML-KEM-512 implementation in the root project.


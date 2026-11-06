# Classical Network Implementation (MP-1 Secure MQTT)

This directory provides a **standalone, live TCP network deployment** of the Classical Baseline for the MP-1 project:
- **Key Establishment**: Classical X25519 (Curve25519) Ephemeral Diffie-Hellman Key Exchange + Ed25519 Digital Signatures.
- **Relay Broker**: Pure-Python `asyncio` MQTT 3.1.1 broker communicating over OS TCP sockets.
- **Network Clients**: Autonomous device processes using `paho-mqtt` over standard TCP.
- **Group Security**: AES-256-GCM authenticated payloads with topic-bound Authenticated Additional Data (AAD), deterministic topic-hierarchical key derivation (HKDF-SHA-256), and $O(\log N)$ Logical Key Hierarchy (LKH) binary tree rekeying.

---

## Directory Architecture

```
classical_network/
├── __init__.py                     # Package definition
├── config.py                       # Network endpoints, port 18885, topic branches & memberships
├── broker_service.py               # Pure-Python asyncio MQTT 3.1.1 TCP broker
├── controller_service.py           # Trusted Key Controller daemon (X25519 ECDH + LKH trees)
├── publisher_node.py               # Autonomous sensor publisher process (motor-01, oven-01)
├── subscriber_node.py              # Autonomous subscriber process (gateway, dashboard, vendor)
├── run_classical_network_demo.py   # Multi-process TCP orchestrator running full live demo
├── test_classical_network.py       # Automated integration test over real TCP sockets
└── README.md                       # Architecture and usage documentation
```

---

## How It Works Over Live TCP

1. **Untrusted MQTT Broker (`broker_service.py`)**:
   - Listens on TCP `127.0.0.1:18885` (or dynamic test port `18896`).
   - Relays opaque binary packets without knowing plaintext or session keys.

2. **Autonomous Classical Handshake (`controller_service.py` & nodes)**:
   - Device generates ephemeral X25519 keypair and signs its public key with its pre-registered Ed25519 private key.
   - Controller verifies device signature against whitelist, generates its own ephemeral X25519 keypair, derives $K_{\text{dist}}$ via HKDF-SHA-256, signs its response, and replies.
   - Device verifies controller signature, computes Curve25519 shared secret, and derives identical 32-byte $K_{\text{dist}}$.

3. **Encrypted Branch & LKH Distribution**:
   - Controller distributes branch root key and individual LKH binary tree path keys encrypted with AES-256-GCM under $K_{\text{dist}}$.
   - Devices install path keys and return authenticated installation ACKs.

4. **Group Telemetry Publishing**:
   - Sensor encrypts telemetry with AES-256-GCM using topic key derived via HKDF-SHA-256 from branch root key.
   - Topic and sequence number are cryptographically sealed in AAD.

5. **$O(\log N)$ LKH Rekey Broadcast**:
   - Revoking a member rotates only the keys on its leaf-to-root path.
   - Controller broadcasts encrypted rekey package on `_bootstrap/{branch}/lkh-rekey`.
   - Active members decrypt bottom-up to update to Version 2; revoked client is unable to decrypt and is permanently excluded.

---

## Running the Classical Network Implementation

### 1. Run Automated TCP Integration Tests
```bash
python3 -m unittest classical_network/test_classical_network.py -v
```

### 2. Run the Live Multi-Node TCP Demo
```bash
python3 -m classical_network.run_classical_network_demo
```

### 3. Run Standalone Daemons Individually
- **Broker**:
  ```bash
  python3 -m classical_network.broker_service --port 18885
  ```
- **Controller**:
  ```bash
  python3 -m classical_network.controller_service --port 18885
  ```
- **Publisher**:
  ```bash
  python3 -m classical_network.publisher_node --device-id motor-01 --branch factory/line3/motor --topic factory/line3/motor/speed --port 18885
  ```
- **Subscriber**:
  ```bash
  python3 -m classical_network.subscriber_node --device-id gateway --branches factory/line3/motor factory/line3/oven --port 18885
  ```


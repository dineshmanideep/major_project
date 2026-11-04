# MP-1 Secure MQTT: Standalone TCP Network Implementation

This directory contains a complete, multi-process network implementation of the post-quantum secured, topic-hierarchical, group end-to-end encrypted MQTT industrial telemetry system.

Unlike the in-memory simulation in `src/`, every entity in this directory runs as an **independent program communicating over standard TCP network sockets** using the MQTT 3.1.1 protocol.

---

## 1. Network Topology & Architecture

```
                          +------------------------------------------+
                          |   network_implementation/                |
                          |   controller_service.py                  |
                          |   (Trusted Key Controller Daemon)        |
                          +--------------------+---------------------+
                                               |
                                     TCP Socket Connection
                                               |
                                               v
    ========================================================================================
                             network_implementation/broker_service.py
                           (Untrusted Standalone MQTT TCP Broker Relay)
                                Listen Port: 18883 (or Mosquitto 1883)
    ========================================================================================
             |                                 |                                 |
       TCP Connection                    TCP Connection                    TCP Connection
             |                                 |                                 |
             v                                 v                                 v
   +-------------------+             +-------------------+             +-------------------+
   | publisher_node.py |             | subscriber_node.py|             | subscriber_node.py|
   | (e.g., motor-01)  |             | (e.g., gateway)   |             | (e.g., vendor)    |
   | Sensor Publisher  |             | Multi-Branch Sub  |             | Scoped Sub (Motor)|
   +-------------------+             +-------------------+             +-------------------+
```

### Protocol Pipeline Over Real TCP Sockets:
1. **TCP Connection Establishment:** Every node connects over TCP sockets to the broker using `paho.mqtt.client`.
2. **Post-Quantum Onboarding Handshake:** Nodes execute mutual Ed25519-signed **ML-KEM-512** key encapsulation over topics `_bootstrap/{device_id}/onboarding-request` and `_bootstrap/{device_id}/onboarding-response`.
3. **Encrypted Branch Provisioning & ACKs:** The Key Controller delivers AES-256-GCM encrypted branch credentials (including initial LKH path keys) and receives encrypted ACKs (`b"installed"`).
4. **End-to-End Encrypted Telemetry:** Publishers derive leaf topic keys via HKDF-Expand (HMAC-SHA-256), encrypt readings with AES-256-GCM + topic-bound AAD, and publish over TCP.
5. **$O(\log N)$ Logical Key Hierarchy (LKH) Rekeying:** When a member is revoked, the Key Controller rotates the compromised path keys, bundles at most $2 \lceil \log_2 N \rceil$ ciphertexts into an LKH rekey package, and broadcasts it over TCP on `_bootstrap/{branch}/lkh-rekey`.
6. **Access Enforcement:** Remaining nodes decrypt the LKH broadcast and update their root keys; the revoked client cannot decrypt any ciphertext, retains obsolete keys, and is permanently rejected by AES-GCM tag verification.

---

## 2. Directory Structure

```
network_implementation/
├── config.py             # Network host, port, branch and topic settings
├── broker_service.py     # Standalone asyncio pure-Python MQTT TCP broker (no sudo needed)
├── controller_service.py # Standalone Key Controller daemon (ML-KEM, LKH rekeying)
├── publisher_node.py     # Standalone sensor publisher client process
├── subscriber_node.py    # Standalone subscriber consumer client process
├── run_network_demo.py   # Multi-process end-to-end orchestrator script
├── test_network.py       # Automated TCP integration test
├── requirements.txt      # Python dependencies
└── README.md             # This setup and operational guide
```

---

## 3. Installation & Setup

Ensure the root virtual environment is active:

```bash
# From the repository root
source .venv/bin/activate
pip install -r network_implementation/requirements.txt
```

---

## 4. How to Run the Network Implementation

### Option A: Automated Multi-Process Orchestrator (Recommended)

Run the complete multi-process lifecycle with one command. This starts the TCP broker, launches all nodes, performs the PQC handshake, publishes telemetry, executes $O(\log N)$ LKH rekeying, and audits access control:

```bash
python3 -m network_implementation.run_network_demo
```

### Option B: Automated Network Integration Tests

Execute the automated test suite verifying the multi-process TCP network pipeline:

```bash
python3 -m unittest network_implementation/test_network.py -v
```

### Option C: Manual Execution in Separate Terminal Windows

You can run each component as an independent program in separate terminal sessions:

#### Terminal 1: Start the Untrusted MQTT Broker Relay
```bash
python3 -m network_implementation.broker_service --port 18883
```
*(Alternatively, if you have Eclipse Mosquitto installed, run `mosquitto -p 18883`)*

#### Terminal 2: Start the Trusted Key Controller Service
```bash
python3 -m network_implementation.controller_service --port 18883
```

#### Terminal 3: Run the Multi-Branch Gateway Subscriber
```bash
python3 -m network_implementation.subscriber_node --device-id gateway --branch factory/line3/motor --port 18883
```

#### Terminal 4: Run the Sensor Publisher
```bash
python3 -m network_implementation.publisher_node --device-id motor-01 --branch factory/line3/motor --topic factory/line3/motor/speed --port 18883
```

---

## 5. Technical Specifications & Wire Formats

### Post-Quantum Onboarding Wire Format (JSON over TCP)
- **Request (`_bootstrap/{device_id}/onboarding-request`):**
  ```json
  {
    "v": 1,
    "device_id": "motor-01",
    "kem_public_key": "<base64-ML-KEM-512-public-key>",
    "signature": "<base64-Ed25519-signature>"
  }
  ```
- **Response (`_bootstrap/{device_id}/onboarding-response`):**
  ```json
  {
    "v": 1,
    "device_id": "motor-01",
    "kem_ciphertext": "<base64-ML-KEM-512-ciphertext>",
    "signature": "<base64-controller-Ed25519-signature>"
  }
  ```

### Logical Key Hierarchy (LKH) Rekey Broadcast (`_bootstrap/{branch}/lkh-rekey`)
Contains $O(\log N)$ encrypted key update envelopes:
```json
[
  {
    "target_node_id": 2,
    "encrypting_node_id": 5,
    "key_version": 2,
    "nonce": "<base64-12-bytes>",
    "ciphertext": "<base64-encrypted-32-byte-key>"
  },
  {
    "target_node_id": 1,
    "encrypting_node_id": 2,
    "key_version": 2,
    "nonce": "<base64-12-bytes>",
    "ciphertext": "<base64-encrypted-root-key>"
  }
]
```

### Telemetry Payload Envelope (`factory/line3/motor/speed`)
```json
{
  "protocol_version": 1,
  "key_version": 2,
  "sequence": 1,
  "sender_id": "motor-01",
  "nonce": "<base64-12-bytes>",
  "ciphertext": "<base64-ciphertext>",
  "tag": "<base64-16-bytes>"
}
```
Authenticated Additional Data (AAD) strictly binds:
$$\text{AAD} = \texttt{"MP1-MSG-v1"} \parallel \text{len}(topic) \parallel topic \parallel \text{len}(sender) \parallel sender \parallel key\_version \parallel sequence$$


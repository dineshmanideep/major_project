# MP-1 Implementation

Implemented components:

- `src/topic_keys.py`: reference topic-hierarchical key derivation.
- `src/message_envelope.py`: MQTT-ready AES-256-GCM message envelopes. The MQTT
  topic, sender ID, and key version are authenticated as additional data, while the
  sensor payload is encrypted.
- `src/mqtt_prototype.py`: encrypted publisher and subscriber components. They can
  run against an in-memory untrusted relay for testing or a Mosquitto-compatible
  broker through `PahoMqttTransport`.

Install the required dependency in your virtual environment:

```bash
python3 -m pip install -r requirements.txt
```

Run its checks from this directory:

```bash
python3 -m unittest discover -s tests -v
```

## End-to-end prototype

`EncryptedPublisher` encrypts the sensor bytes once, then the broker relays only
the MQTT topic and serialised ciphertext envelope. Each `EncryptedSubscriber`
holds an authorised ancestor key, subscribes only to that branch, and decrypts
locally. `tests/test_mqtt_prototype.py` demonstrates two independently
authorised subscribers decrypting the same publish, while a motor-only subscriber
cannot receive or derive an oven key.

For a live Mosquitto broker, construct `PahoMqttTransport(host, port, client_id)`
for the publisher/subscriber and run its MQTT network loop after subscribing.

It derives a 32-byte AES-256 key for each MQTT topic, beginning with a securely
provisioned ancestor key. A holder of `factory/line3` can derive keys below that
branch, but the module refuses requests for parents and sibling branches. The message
envelope tests also verify that tampering with ciphertext, sender metadata, or the
MQTT topic causes AES-GCM authentication to fail.

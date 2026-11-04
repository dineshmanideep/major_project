"""Standalone Sensor Publisher Node.

Connects to the MQTT broker over standard TCP as an autonomous device process.
Completes post-quantum ML-KEM-512 onboarding, decrypts and installs branch
credentials, listens for LKH rekey updates, and periodically publishes
AES-256-GCM encrypted sensor telemetry with topic-bound Authenticated Additional Data.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import time
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import paho.mqtt.client as mqtt
from pqcrypto.kem import ml_kem_512

from network_implementation.config import (
    BOOTSTRAP_PREFIX,
    DEFAULT_BROKER_HOST,
    DEFAULT_BROKER_PORT,
    MOTOR_BRANCH,
    MOTOR_TELEMETRY_TOPIC,
)
from src.lkh_tree import LkhClient, parse_rekey_package
from src.message_envelope import encrypt_payload, serialise_envelope
from src.simulated_key_distribution import _aad as update_aad, _ack_aad, _ack_topic, _UPDATE_VERSION
from src.topic_keys import KEY_LENGTH


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s")


class NetworkPublisherNode:
    """Autonomous publisher process managing PQC onboarding and telemetry publishing over TCP."""

    def __init__(
        self,
        device_id: str,
        branch_path: str,
        telemetry_topic: str,
        controller_public_key: Ed25519PublicKey,
        host: str = DEFAULT_BROKER_HOST,
        port: int = DEFAULT_BROKER_PORT,
    ) -> None:
        self.device_id = device_id
        self.branch_path = branch_path
        self.telemetry_topic = telemetry_topic
        self.controller_public_key = controller_public_key
        self.host = host
        self.port = port
        self.logger = logging.getLogger(f"Publisher:{device_id}")

        self.identity_private_key = Ed25519PrivateKey.generate()
        self.identity_public_key = self.identity_private_key.public_key()
        self._kem_public_key, self._kem_secret_key = ml_kem_512.keygen()

        self.distribution_session_key: bytes | None = None
        self.lkh_client: LkhClient | None = None
        self.sequence = 0
        self.onboarded = False
        self.provisioned = False

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"pub-{device_id}")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def connect(self) -> None:
        self.logger.info("Connecting to broker at tcp://%s:%d...", self.host, self.port)
        self.client.connect(self.host, self.port)
        self.client.loop_start()

    def disconnect(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()
        self.logger.info("Disconnected from broker.")

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags: Any, rc: Any, props: Any = None) -> None:
        self.logger.info("Connected to broker.")
        # Subscribe to onboarding response, branch key update, and LKH rekey broadcast
        client.subscribe(f"{BOOTSTRAP_PREFIX}/{self.device_id}/onboarding-response", qos=1)
        client.subscribe(f"{BOOTSTRAP_PREFIX}/{self.device_id}/branch-key-update", qos=1)
        client.subscribe(f"{BOOTSTRAP_PREFIX}/{self.branch_path}/lkh-rekey", qos=1)

        # Initiate ML-KEM-512 onboarding handshake
        self.initiate_onboarding()

    def initiate_onboarding(self) -> None:
        """Send authenticated ML-KEM-512 onboarding request to the Key Controller."""
        canonical_req = (
            b"MP1-PQC-ONBOARD-v1request"
            + len(self.device_id.encode("utf-8")).to_bytes(2, "big")
            + self.device_id.encode("utf-8")
            + self._kem_public_key
        )
        sig = self.identity_private_key.sign(canonical_req)

        req_payload = json.dumps({
            "v": 1,
            "device_id": self.device_id,
            "kem_public_key": base64.b64encode(self._kem_public_key).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii"),
        }, sort_keys=True).encode("utf-8")

        topic = f"{BOOTSTRAP_PREFIX}/{self.device_id}/onboarding-request"
        self.client.publish(topic, req_payload, qos=1)
        self.logger.info("Published ML-KEM-512 onboarding request on topic %s", topic)

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
        topic = msg.topic
        payload = msg.payload

        if topic == f"{BOOTSTRAP_PREFIX}/{self.device_id}/onboarding-response":
            self._handle_onboarding_response(payload)
        elif topic == f"{BOOTSTRAP_PREFIX}/{self.device_id}/branch-key-update":
            self._handle_branch_key_update(payload)
        elif topic == f"{BOOTSTRAP_PREFIX}/{self.branch_path}/lkh-rekey":
            self._handle_lkh_rekey(payload)

    def _handle_onboarding_response(self, payload: bytes) -> None:
        try:
            data = json.loads(payload.decode("utf-8"))
            if data.get("v") != 1 or data.get("device_id") != self.device_id:
                return

            ciphertext = base64.b64decode(data["kem_ciphertext"])
            signature = base64.b64decode(data["signature"])

            # Verify controller Ed25519 signature
            canonical_resp = (
                b"MP1-PQC-ONBOARD-v1response"
                + len(self.device_id.encode("utf-8")).to_bytes(2, "big")
                + self.device_id.encode("utf-8")
                + ciphertext
            )
            self.controller_public_key.verify(signature, canonical_resp)

            # ML-KEM-512 decapsulation
            shared_secret = ml_kem_512.decaps(self._kem_secret_key, ciphertext)
            self.distribution_session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=KEY_LENGTH,
                salt=None,
                info=b"MP1-PQC-DISTRIBUTION-v1" + self.device_id.encode("utf-8"),
            ).derive(shared_secret)

            self.onboarded = True
            self.logger.info("Verified controller response & derived 32-byte distribution session key.")
        except Exception as exc:
            self.logger.error("Failed to verify onboarding response: %s", exc)

    def _handle_branch_key_update(self, payload: bytes) -> None:
        if not self.distribution_session_key:
            return
        try:
            message = json.loads(payload.decode("utf-8"))
            if message.get("v") != _UPDATE_VERSION or message.get("branch") != self.branch_path:
                return

            version = message["key_version"]
            nonce = base64.b64decode(message["nonce"])
            ciphertext = base64.b64decode(message["ciphertext"])

            raw_bytes = AESGCM(self.distribution_session_key).decrypt(
                nonce, ciphertext, update_aad(self.device_id, self.branch_path, version)
            )
            payload_data = json.loads(raw_bytes.decode("utf-8"))
            root_key = base64.b64decode(payload_data["root_key"])
            path_keys = {int(nid): base64.b64decode(k) for nid, k in payload_data["path_keys"].items()}

            self.lkh_client = LkhClient(self.device_id, self.branch_path, path_keys, version)
            self.provisioned = True
            self.logger.info("Installed branch credential for %s (Version %d, LKH root key installed)", self.branch_path, version)

            # Send encrypted ACK
            ack_nonce = os.urandom(12)
            ack_ct = AESGCM(self.distribution_session_key).encrypt(
                ack_nonce, b"installed", _ack_aad(self.device_id, self.branch_path, version)
            )
            ack_envelope = {
                "v": _UPDATE_VERSION,
                "branch": self.branch_path,
                "key_version": version,
                "nonce": base64.b64encode(ack_nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ack_ct).decode("ascii"),
            }
            self.client.publish(_ack_topic(self.device_id), json.dumps(ack_envelope, sort_keys=True).encode("utf-8"), qos=1)
            self.logger.info("Sent encrypted installation ACK to Key Controller.")
        except Exception as exc:
            self.logger.error("Failed to install branch update: %s", exc)

    def _handle_lkh_rekey(self, payload: bytes) -> None:
        if not self.lkh_client:
            return
        try:
            pkg = parse_rekey_package(payload)
            target_version = self.lkh_client.key_version + 1
            new_root = self.lkh_client.process_rekey_package(pkg, target_version)
            self.logger.info("Processed LKH rekey broadcast! Updated to Version %d (New root key: %s...)", target_version, new_root[:4].hex())
        except Exception as exc:
            self.logger.warning("Could not process LKH rekey: %s", exc)

    def publish_telemetry(self, plaintext: bytes) -> None:
        """Derive topic key from held branch root key, encrypt with AES-256-GCM, and publish."""
        if not self.lkh_client:
            self.logger.warning("Cannot publish: branch credential not provisioned yet")
            return

        self.sequence += 1
        root_key = self.lkh_client.root_key
        key_version = self.lkh_client.key_version

        envelope = encrypt_payload(
            plaintext,
            self.telemetry_topic,
            root_key,
            self.branch_path,
            self.device_id,
            key_version,
            self.sequence,
        )
        wire_payload = serialise_envelope(envelope)
        self.client.publish(self.telemetry_topic, wire_payload, qos=0)
        self.logger.info(
            "Published telemetry: topic=%s bytes=%d seq=%d v=%d plaintext=%s",
            self.telemetry_topic,
            len(wire_payload),
            self.sequence,
            key_version,
            plaintext.decode("utf-8", errors="replace"),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="MP-1 Standalone Sensor Publisher Node")
    parser.add_argument("--device-id", default="motor-01", help="Device identifier")
    parser.add_argument("--branch", default=MOTOR_BRANCH, help="Authorized branch path")
    parser.add_argument("--topic", default=MOTOR_TELEMETRY_TOPIC, help="Publish topic")
    parser.add_argument("--host", default=DEFAULT_BROKER_HOST, help="Broker host")
    parser.add_argument("--port", type=int, default=DEFAULT_BROKER_PORT, help="Broker port")
    args = parser.parse_args()

    # In a real environment, the controller public key is provisioned at manufacturing
    # For CLI demo, we expect a pre-shared key or run via orchestrator
    print(f"Publisher node {args.device_id} started. Use run_network_demo.py for orchestrated execution.")


if __name__ == "__main__":
    main()


"""Standalone Subscriber Consumer Node.

Connects to the MQTT broker over standard TCP as an autonomous consumer process
(e.g., Gateway, Dashboard, or Third-Party Vendor).
Performs post-quantum ML-KEM-512 onboarding, installs branch credentials,
processes O(log N) LKH rekey broadcasts, and decrypts live telemetry in real-time.
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
)
from src.lkh_tree import LkhClient, LkhError, parse_rekey_package
from src.message_envelope import decrypt_payload, EnvelopeError, parse_envelope, ReplayProtector
from src.simulated_key_distribution import _aad as update_aad, _ack_aad, _ack_topic, _UPDATE_VERSION
from src.topic_keys import KEY_LENGTH


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s")


class NetworkSubscriberNode:
    """Autonomous consumer process managing PQC onboarding and telemetry decryption over TCP."""

    def __init__(
        self,
        device_id: str,
        branch_paths: list[str] | str,
        controller_public_key: Ed25519PublicKey,
        host: str = DEFAULT_BROKER_HOST,
        port: int = DEFAULT_BROKER_PORT,
    ) -> None:
        self.device_id = device_id
        self.branch_paths = [branch_paths] if isinstance(branch_paths, str) else list(branch_paths)
        self.controller_public_key = controller_public_key
        self.host = host
        self.port = port
        self.logger = logging.getLogger(f"Subscriber:{device_id}")

        self.identity_private_key = Ed25519PrivateKey.generate()
        self.identity_public_key = self.identity_private_key.public_key()
        self._kem_public_key, self._kem_secret_key = ml_kem_512.keygen()

        self.distribution_session_key: bytes | None = None
        self.lkh_clients: dict[str, LkhClient] = {}
        self.replay_protector = ReplayProtector()
        self.received_messages: list[tuple[str, bytes]] = []
        self.rejected_messages: list[tuple[str, str]] = []
        self.onboarded = False

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"sub-{device_id}")
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
        # Subscribe to onboarding response & branch key updates
        client.subscribe(f"{BOOTSTRAP_PREFIX}/{self.device_id}/onboarding-response", qos=1)
        client.subscribe(f"{BOOTSTRAP_PREFIX}/{self.device_id}/branch-key-update", qos=1)

        for branch in self.branch_paths:
            client.subscribe(f"{BOOTSTRAP_PREFIX}/{branch}/lkh-rekey", qos=1)
            client.subscribe(f"{branch}/#", qos=0)

        # Initiate ML-KEM-512 onboarding handshake
        self.initiate_onboarding()

    def initiate_onboarding(self) -> None:
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
        elif topic.endswith("/lkh-rekey"):
            self._handle_lkh_rekey(topic, payload)
        else:
            self._handle_telemetry(topic, payload)

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
            if message.get("v") != _UPDATE_VERSION:
                return

            branch = message["branch"]
            version = message["key_version"]
            nonce = base64.b64decode(message["nonce"])
            ciphertext = base64.b64decode(message["ciphertext"])

            raw_bytes = AESGCM(self.distribution_session_key).decrypt(
                nonce, ciphertext, update_aad(self.device_id, branch, version)
            )
            payload_data = json.loads(raw_bytes.decode("utf-8"))
            root_key = base64.b64decode(payload_data["root_key"])
            path_keys = {int(nid): base64.b64decode(k) for nid, k in payload_data["path_keys"].items()}

            self.lkh_clients[branch] = LkhClient(self.device_id, branch, path_keys, version)
            self.logger.info("Installed branch credential for %s (Version %d, LKH root key installed)", branch, version)

            # Send encrypted ACK
            ack_nonce = os.urandom(12)
            ack_ct = AESGCM(self.distribution_session_key).encrypt(
                ack_nonce, b"installed", _ack_aad(self.device_id, branch, version)
            )
            ack_envelope = {
                "v": _UPDATE_VERSION,
                "branch": branch,
                "key_version": version,
                "nonce": base64.b64encode(ack_nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ack_ct).decode("ascii"),
            }
            self.client.publish(_ack_topic(self.device_id), json.dumps(ack_envelope, sort_keys=True).encode("utf-8"), qos=1)
            self.logger.info("Sent encrypted installation ACK to Key Controller for %s.", branch)
        except Exception as exc:
            self.logger.error("Failed to install branch update: %s", exc)

    def _handle_lkh_rekey(self, topic: str, payload: bytes) -> None:
        branch = topic[len(f"{BOOTSTRAP_PREFIX}/") : -len("/lkh-rekey")]
        client = self.lkh_clients.get(branch)
        if not client:
            return
        try:
            pkg = parse_rekey_package(payload)
            target_version = client.key_version + 1
            new_root = client.process_rekey_package(pkg, target_version)
            self.logger.info("Processed LKH rekey broadcast on %s! Updated to Version %d (Root key: %s...)", branch, target_version, new_root[:4].hex())
        except LkhError as exc:
            self.logger.warning("Could not process LKH rekey on %s (Device likely revoked): %s", branch, exc)

    def _handle_telemetry(self, topic: str, payload: bytes) -> None:
        # Match topic against held branch clients
        matched_client: LkhClient | None = None
        for branch, client in self.lkh_clients.items():
            if topic.startswith(f"{branch}/"):
                matched_client = client
                break

        if not matched_client:
            return

        try:
            envelope = parse_envelope(payload)
            root_key = matched_client.root_key
            plaintext = decrypt_payload(envelope, topic, root_key, matched_client.branch_path)

            self.replay_protector.accept(
                topic, envelope["sender_id"], envelope["key_version"], envelope["sequence"]
            )
            self.received_messages.append((topic, plaintext))
            self.logger.info(
                "DECRYPT SUCCESS: topic=%s sender=%s v=%d seq=%d payload=%s",
                topic,
                envelope["sender_id"],
                envelope["key_version"],
                envelope["sequence"],
                plaintext.decode("utf-8", errors="replace"),
            )
        except (EnvelopeError, Exception) as exc:
            self.rejected_messages.append((topic, str(exc)))
            self.logger.warning("DECRYPT REJECTED on topic=%s: %s", topic, exc)


def main() -> None:
    parser = argparse.ArgumentParser(description="MP-1 Standalone Subscriber Consumer Node")
    parser.add_argument("--device-id", default="gateway", help="Device identifier")
    parser.add_argument("--branch", default=MOTOR_BRANCH, help="Authorized branch path")
    parser.add_argument("--host", default=DEFAULT_BROKER_HOST, help="Broker host")
    parser.add_argument("--port", type=int, default=DEFAULT_BROKER_PORT, help="Broker port")
    args = parser.parse_args()

    print(f"Subscriber node {args.device_id} started. Use run_network_demo.py for orchestrated execution.")


if __name__ == "__main__":
    main()


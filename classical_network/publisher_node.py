"""Standalone Classical Sensor Publisher Node.

Connects to the MQTT broker over standard TCP as an autonomous device process.
Completes classical X25519 ECDH + Ed25519 onboarding, decrypts and installs branch
credentials with LKH path keys, listens for LKH rekey updates, and periodically
publishes AES-256-GCM encrypted sensor telemetry with topic-bound Authenticated Additional Data.
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
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import paho.mqtt.client as mqtt

from classical_network.config import (
    BOOTSTRAP_PREFIX,
    DEFAULT_BROKER_HOST,
    DEFAULT_BROKER_PORT,
    MOTOR_BRANCH,
    MOTOR_TELEMETRY_TOPIC,
    REKEY_TOPIC_SUFFIX,
)
from classical_simulation.lkh_tree import LkhClient
from src.lkh_tree import parse_rekey_package
from classical_simulation.message_envelope import encrypt_payload, serialise_envelope
from classical_simulation.topic_keys import KEY_LENGTH


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s")

_DOMAIN_ONBOARD = b"MP1-CLASSICAL-ONBOARD-v1"
_DOMAIN_DIST = b"MP1-CLASSICAL-DISTRIBUTION-v1"
_DOMAIN_KEY_UPDATE = b"MP1-CLASSICAL-KEY-UPDATE-v1"
_DOMAIN_KEY_ACK = b"MP1-CLASSICAL-KEY-ACK-v1"
_UPDATE_VERSION = 1
NONCE_LENGTH = 12


def _canonical(kind: str, device_id: str, value: bytes) -> bytes:
    encoded_id = device_id.encode("utf-8")
    return _DOMAIN_ONBOARD + kind.encode("ascii") + len(encoded_id).to_bytes(2, "big") + encoded_id + value


def _update_aad(device_id: str, branch_path: str, key_version: int) -> bytes:
    fields = (device_id, branch_path)
    encoded = []
    for value in fields:
        raw = value.encode("utf-8")
        encoded.append(len(raw).to_bytes(2, "big") + raw)
    return _DOMAIN_KEY_UPDATE + b"".join(encoded) + key_version.to_bytes(8, "big")


def _ack_aad(device_id: str, branch_path: str, key_version: int) -> bytes:
    return _DOMAIN_KEY_ACK + _update_aad(device_id, branch_path, key_version)


class ClassicalNetworkPublisherNode:
    """Autonomous publisher process managing Classical X25519 onboarding and telemetry publishing over TCP."""

    def __init__(
        self,
        device_id: str,
        branch_path: str,
        telemetry_topic: str,
        controller_public_key: ed25519.Ed25519PublicKey,
        host: str = DEFAULT_BROKER_HOST,
        port: int = DEFAULT_BROKER_PORT,
    ) -> None:
        self.device_id = device_id
        self.branch_path = branch_path
        self.telemetry_topic = telemetry_topic
        self.controller_public_key = controller_public_key
        self.host = host
        self.port = port
        self.logger = logging.getLogger(f"ClassicalPub:{device_id}")

        self.identity_private_key = ed25519.Ed25519PrivateKey.generate()
        self.identity_public_key = self.identity_private_key.public_key()
        self._ecdh_private_key = x25519.X25519PrivateKey.generate()
        self._ecdh_public_bytes = self._ecdh_private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

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
        client.subscribe(f"{BOOTSTRAP_PREFIX}/{self.branch_path}/{REKEY_TOPIC_SUFFIX}", qos=1)

        # Initiate Classical X25519 onboarding handshake
        self.initiate_onboarding()

    def initiate_onboarding(self) -> None:
        """Send authenticated Classical X25519 onboarding request to the Key Controller."""
        sig = self.identity_private_key.sign(
            _canonical("request", self.device_id, self._ecdh_public_bytes)
        )

        req_payload = json.dumps({
            "v": 1,
            "device_id": self.device_id,
            "ecdh_public_key": base64.b64encode(self._ecdh_public_bytes).decode("ascii"),
            "signature": base64.b64encode(sig).decode("ascii"),
        }, sort_keys=True).encode("utf-8")

        topic = f"{BOOTSTRAP_PREFIX}/{self.device_id}/onboarding-request"
        self.client.publish(topic, req_payload, qos=1)
        self.logger.info("Published Classical X25519 onboarding request on topic %s", topic)

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
        topic = msg.topic
        payload = msg.payload

        if topic == f"{BOOTSTRAP_PREFIX}/{self.device_id}/onboarding-response":
            self._handle_onboarding_response(payload)
        elif topic == f"{BOOTSTRAP_PREFIX}/{self.device_id}/branch-key-update":
            self._handle_branch_key_update(payload)
        elif topic == f"{BOOTSTRAP_PREFIX}/{self.branch_path}/{REKEY_TOPIC_SUFFIX}":
            self._handle_lkh_rekey(payload)

    def _handle_onboarding_response(self, payload: bytes) -> None:
        try:
            data = json.loads(payload.decode("utf-8"))
            if data.get("v") != 1 or data.get("device_id") != self.device_id:
                return

            controller_ecdh_bytes = base64.b64decode(data["controller_ecdh_public"])
            signature = base64.b64decode(data["signature"])

            # Verify controller Ed25519 signature
            self.controller_public_key.verify(
                signature, _canonical("response", self.device_id, controller_ecdh_bytes)
            )

            # Curve25519 ECDH exchange
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(controller_ecdh_bytes)
            shared_secret = self._ecdh_private_key.exchange(peer_public_key)

            # HKDF derivation of 32-byte distribution session key
            self.distribution_session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=KEY_LENGTH,
                salt=None,
                info=_DOMAIN_DIST + self.device_id.encode("utf-8"),
            ).derive(shared_secret)

            self.onboarded = True
            self.logger.info("Verified controller response & derived 32-byte distribution session key via X25519 ECDH.")
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
                nonce, ciphertext, _update_aad(self.device_id, self.branch_path, version)
            )
            payload_data = json.loads(raw_bytes.decode("utf-8"))
            root_key = base64.b64decode(payload_data["root_key"])
            path_keys = {int(nid): base64.b64decode(k) for nid, k in payload_data["path_keys"].items()}

            self.lkh_client = LkhClient(self.device_id, self.branch_path, path_keys, version)
            self.provisioned = True
            self.logger.info("Installed branch credential for %s (Version %d, LKH root key installed)", self.branch_path, version)

            # Send encrypted ACK
            ack_nonce = os.urandom(NONCE_LENGTH)
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
            ack_topic = f"{BOOTSTRAP_PREFIX}/{self.device_id}/branch-key-ack"
            self.client.publish(ack_topic, json.dumps(ack_envelope, sort_keys=True).encode("utf-8"), qos=1)
            self.logger.info("Sent encrypted installation ACK to Classical Key Controller.")
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
    parser = argparse.ArgumentParser(description="Classical MP-1 Standalone Sensor Publisher Node")
    parser.add_argument("--device-id", default="motor-01", help="Device identifier")
    parser.add_argument("--branch", default=MOTOR_BRANCH, help="Authorized branch path")
    parser.add_argument("--topic", default=MOTOR_TELEMETRY_TOPIC, help="Publish topic")
    parser.add_argument("--host", default=DEFAULT_BROKER_HOST, help="Broker host")
    parser.add_argument("--port", type=int, default=DEFAULT_BROKER_PORT, help="Broker port")
    args = parser.parse_args()

    print(f"Publisher node {args.device_id} started. Use run_classical_network_demo.py for orchestrated execution.")


if __name__ == "__main__":
    main()


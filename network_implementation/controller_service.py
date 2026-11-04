"""Standalone Trusted Key Controller Network Service.

Connects to the MQTT broker over standard TCP. Handles post-quantum ML-KEM-512
bootstrap exchanges, provisions encrypted branch credentials, and executes
O(log N) Logical Key Hierarchy (LKH) tree rekeying on member revocation.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import time
from typing import Any, Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import paho.mqtt.client as mqtt
from pqcrypto.kem import ml_kem_512

from network_implementation.config import (
    BOOTSTRAP_PREFIX,
    BRANCH_MEMBERS,
    DEFAULT_BROKER_HOST,
    DEFAULT_BROKER_PORT,
    MOTOR_BRANCH,
    OVEN_BRANCH,
)
from src.lkh_tree import LkhTree, serialise_rekey_package
from src.simulated_key_distribution import _aad as update_aad, _ack_aad, _UPDATE_VERSION
from src.topic_keys import KEY_LENGTH


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (KeyController) %(message)s")
logger = logging.getLogger("KeyController")


def _session_kdf(shared_secret: bytes, device_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=b"MP1-PQC-DISTRIBUTION-v1" + device_id.encode("utf-8"),
    ).derive(shared_secret)


class NetworkKeyController:
    """Standalone controller managing PQC onboarding, branch keys, and LKH rekeying over TCP."""

    def __init__(self, host: str = DEFAULT_BROKER_HOST, port: int = DEFAULT_BROKER_PORT) -> None:
        self.host = host
        self.port = port
        self.identity_private_key = Ed25519PrivateKey.generate()
        self.identity_public_key = self.identity_private_key.public_key()

        self.device_public_keys: dict[str, Ed25519PublicKey] = {}
        self.session_keys: dict[str, bytes] = {}
        self.branch_lkh_trees: dict[str, LkhTree] = {}
        self.acknowledgements: set[tuple[str, str, int]] = set()

        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="trusted-key-controller")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

        # Initialize LKH trees for managed branches
        self.branch_lkh_trees[MOTOR_BRANCH] = LkhTree(MOTOR_BRANCH, BRANCH_MEMBERS[MOTOR_BRANCH])
        self.branch_lkh_trees[OVEN_BRANCH] = LkhTree(OVEN_BRANCH, BRANCH_MEMBERS[OVEN_BRANCH])

    def register_device_identity(self, device_id: str, public_key: Ed25519PublicKey) -> None:
        self.device_public_keys[device_id] = public_key
        logger.info("Registered identity key for device: %s", device_id)

    def connect(self) -> None:
        logger.info("Connecting to broker at tcp://%s:%d...", self.host, self.port)
        self.client.connect(self.host, self.port)
        self.client.loop_start()

    def disconnect(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()
        logger.info("Disconnected from broker.")

    def _on_connect(self, client: mqtt.Client, userdata: Any, flags: Any, rc: Any, props: Any = None) -> None:
        logger.info("Connected to broker successfully.")
        # Subscribe to onboarding requests and acknowledgements
        client.subscribe(f"{BOOTSTRAP_PREFIX}/+/onboarding-request", qos=1)
        client.subscribe(f"{BOOTSTRAP_PREFIX}/+/branch-key-ack", qos=1)
        client.subscribe("_admin/+", qos=1)

    def _on_message(self, client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
        topic = msg.topic
        payload = msg.payload

        if topic.endswith("/onboarding-request"):
            self._handle_onboarding_request(topic, payload)
        elif topic.endswith("/branch-key-ack"):
            self._handle_ack(topic, payload)
        elif topic.startswith("_admin/"):
            self._handle_admin(topic, payload)

    def _handle_onboarding_request(self, topic: str, payload: bytes) -> None:
        try:
            device_id = topic.split("/")[1]
            data = json.loads(payload.decode("utf-8"))
            if data.get("v") != 1 or data.get("device_id") != device_id:
                return

            if device_id not in self.device_public_keys:
                logger.warning("Rejected onboarding: device %s not pre-registered", device_id)
                return

            kem_pub_bytes = base64.b64decode(data["kem_public_key"])
            signature = base64.b64decode(data["signature"])

            # Verify device signature
            canonical_req = (
                b"MP1-PQC-ONBOARD-v1request"
                + len(device_id.encode("utf-8")).to_bytes(2, "big")
                + device_id.encode("utf-8")
                + kem_pub_bytes
            )
            self.device_public_keys[device_id].verify(signature, canonical_req)

            # ML-KEM-512 Encapsulation
            ciphertext, shared_secret = ml_kem_512.encaps(kem_pub_bytes)
            session_key = _session_kdf(shared_secret, device_id)
            self.session_keys[device_id] = session_key

            # Sign response
            canonical_resp = (
                b"MP1-PQC-ONBOARD-v1response"
                + len(device_id.encode("utf-8")).to_bytes(2, "big")
                + device_id.encode("utf-8")
                + ciphertext
            )
            resp_sig = self.identity_private_key.sign(canonical_resp)

            response_payload = json.dumps({
                "v": 1,
                "device_id": device_id,
                "kem_ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "signature": base64.b64encode(resp_sig).decode("ascii"),
            }, sort_keys=True).encode("utf-8")

            resp_topic = f"{BOOTSTRAP_PREFIX}/{device_id}/onboarding-response"
            self.client.publish(resp_topic, response_payload, qos=1)
            logger.info("Completed ML-KEM-512 handshake with %s (Derived 32-byte session key)", device_id)

        except Exception as exc:
            logger.error("Error processing onboarding request: %s", exc)

    def _handle_ack(self, topic: str, payload: bytes) -> None:
        try:
            device_id = topic.split("/")[1]
            if device_id not in self.session_keys:
                return
            data = json.loads(payload.decode("utf-8"))
            branch = data["branch"]
            version = data["key_version"]
            nonce = base64.b64decode(data["nonce"])
            ct = base64.b64decode(data["ciphertext"])

            pt = AESGCM(self.session_keys[device_id]).decrypt(
                nonce, ct, _ack_aad(device_id, branch, version)
            )
            if pt == b"installed":
                self.acknowledgements.add((device_id, branch, version))
                logger.info("Received authenticated installation ACK from %s for %s v%d", device_id, branch, version)
        except Exception:
            pass

    def distribute_branch_credentials(self, branch_path: str) -> None:
        """Distribute initial LKH path keys & root key to each authorized member."""
        tree = self.branch_lkh_trees.get(branch_path)
        if not tree:
            return
        root_key = tree.get_root_key()

        for member_id in tree.members:
            if member_id not in self.session_keys:
                logger.warning("Cannot distribute to %s: no active PQC session", member_id)
                continue
            path_keys = tree.get_path_keys(member_id)
            # Encode path keys: dict of node_id -> base64 key
            payload_data = {
                "root_key": base64.b64encode(root_key).decode("ascii"),
                "path_keys": {str(nid): base64.b64encode(k).decode("ascii") for nid, k in path_keys.items()},
            }
            raw_bytes = json.dumps(payload_data, sort_keys=True).encode("utf-8")

            nonce = os.urandom(12)
            aad = update_aad(member_id, branch_path, tree.key_version)
            ct = AESGCM(self.session_keys[member_id]).encrypt(nonce, raw_bytes, aad)

            update_envelope = {
                "v": _UPDATE_VERSION,
                "branch": branch_path,
                "key_version": tree.key_version,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ct).decode("ascii"),
            }
            topic = f"{BOOTSTRAP_PREFIX}/{member_id}/branch-key-update"
            self.client.publish(topic, json.dumps(update_envelope, sort_keys=True).encode("utf-8"), qos=1)
            logger.info("Published initial branch credentials to %s for %s (Version %d)", member_id, branch_path, tree.key_version)

    def revoke_and_rekey_lkh(self, branch_path: str, revoked_device_id: str) -> None:
        """Execute O(log N) LKH rekeying and broadcast rekey package."""
        tree = self.branch_lkh_trees.get(branch_path)
        if not tree:
            logger.error("Branch %s not found", branch_path)
            return

        logger.info("Executing LKH revocation for %s on branch %s...", revoked_device_id, branch_path)
        new_root, rekey_package = tree.revoke_member(revoked_device_id)

        # Broadcast LKH rekey package on MQTT
        rekey_topic = f"{BOOTSTRAP_PREFIX}/{branch_path}/lkh-rekey"
        serialized = serialise_rekey_package(rekey_package)
        self.client.publish(rekey_topic, serialized, qos=1)
        logger.info(
            "Broadcast LKH rekey package: %d messages (O(log N)) on topic %s (Version %d)",
            len(rekey_package),
            rekey_topic,
            tree.key_version,
        )

    def _handle_admin(self, topic: str, payload: bytes) -> None:
        if topic == "_admin/revoke":
            try:
                cmd = json.loads(payload.decode("utf-8"))
                self.revoke_and_rekey_lkh(cmd["branch"], cmd["device_id"])
            except Exception as e:
                logger.error("Admin revoke failed: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(description="MP-1 Standalone Key Controller Service")
    parser.add_argument("--host", default=DEFAULT_BROKER_HOST, help="MQTT broker host")
    parser.add_argument("--port", type=int, default=DEFAULT_BROKER_PORT, help="MQTT broker port")
    args = parser.parse_args()

    controller = NetworkKeyController(args.host, args.port)
    controller.connect()
    logger.info("Key Controller service running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        controller.disconnect()


if __name__ == "__main__":
    main()


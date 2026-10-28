"""Authenticated ML-KEM-512 onboarding for the software-only simulation.

MQTT bootstrap messages are relayed through the untrusted transport. ML-KEM
provides the shared secret; pre-provisioned Ed25519 public keys authenticate
both the device request and the Key Controller response.
"""

from __future__ import annotations

import base64
import json

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_512

from src.mqtt_prototype import MqttTransport
from src.simulated_key_distribution import _ack_aad, _ack_topic, SimulatedDevice
from src.topic_keys import KEY_LENGTH


def _canonical(kind: str, device_id: str, value: bytes) -> bytes:
    encoded_id = device_id.encode("utf-8")
    return b"MP1-PQC-ONBOARD-v1" + kind.encode("ascii") + len(encoded_id).to_bytes(2, "big") + encoded_id + value


def _session_key(shared_secret: bytes, device_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_LENGTH, salt=None,
        info=b"MP1-PQC-DISTRIBUTION-v1" + device_id.encode("utf-8"),
    ).derive(shared_secret)


class OnboardingError(ValueError):
    """Raised when an onboarding message lacks identity or PQC validity."""


class MlKemOnboardingClient:
    """Device-side ML-KEM request generation and authenticated response handling."""

    def __init__(self, device: SimulatedDevice, controller_public_key: Ed25519PublicKey) -> None:
        self.device = device
        self._controller_public_key = controller_public_key
        self._identity_private_key = Ed25519PrivateKey.generate()
        self._kem_public_key, self._kem_secret_key = ml_kem_512.keygen()

    @property
    def identity_public_key(self) -> Ed25519PublicKey:
        return self._identity_private_key.public_key()

    def request(self) -> bytes:
        signature = self._identity_private_key.sign(
            _canonical("request", self.device.device_id, self._kem_public_key)
        )
        return json.dumps({
            "v": 1,
            "device_id": self.device.device_id,
            "kem_public_key": base64.b64encode(self._kem_public_key).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }, sort_keys=True).encode("utf-8")

    def accept_response(self, payload: bytes) -> None:
        try:
            data = json.loads(payload.decode("utf-8"))
            if set(data) != {"v", "device_id", "kem_ciphertext", "signature"} or data["v"] != 1:
                raise OnboardingError("invalid controller response")
            if data["device_id"] != self.device.device_id:
                raise OnboardingError("controller response targets another device")
            ciphertext = base64.b64decode(data["kem_ciphertext"], validate=True)
            signature = base64.b64decode(data["signature"], validate=True)
            self._controller_public_key.verify(
                signature, _canonical("response", self.device.device_id, ciphertext)
            )
            self.device.distribution_key = _session_key(
                ml_kem_512.decaps(self._kem_secret_key, ciphertext), self.device.device_id
            )
        except (ValueError, KeyError, InvalidSignature, OnboardingError) as exc:
            raise OnboardingError("invalid or unauthenticated onboarding response") from exc


class MlKemOnboardingController:
    """Trusted controller-side identity verification and ML-KEM encapsulation."""

    def __init__(self, transport: MqttTransport) -> None:
        self.transport = transport
        self._identity_private_key = Ed25519PrivateKey.generate()
        self._device_public_keys: dict[str, Ed25519PublicKey] = {}
        self._session_keys: dict[str, bytes] = {}
        self._acknowledgements: set[tuple[str, str, int]] = set()
        self.transport.subscribe("#", self._receive_broker_message)

    @property
    def identity_public_key(self) -> Ed25519PublicKey:
        return self._identity_private_key.public_key()

    def register_device_identity(self, client: MlKemOnboardingClient) -> None:
        self._device_public_keys[client.device.device_id] = client.identity_public_key

    def session_key_for(self, device_id: str) -> bytes:
        """Return controller-owned session state, never device object state."""
        try:
            return self._session_keys[device_id]
        except KeyError as exc:
            raise OnboardingError("device has no active ML-KEM session") from exc

    def acknowledged(self, device_id: str, branch_path: str, key_version: int) -> bool:
        return (device_id, branch_path, key_version) in self._acknowledgements

    def expire_session(self, device_id: str) -> None:
        """Invalidate controller session state; a device must onboard again."""
        self._session_keys.pop(device_id, None)
        self._acknowledgements = {entry for entry in self._acknowledgements if entry[0] != device_id}

    def onboard(self, client: MlKemOnboardingClient) -> None:
        """Relay and process a complete authenticated bootstrap exchange."""
        request = client.request()
        self.transport.publish(f"_bootstrap/{client.device.device_id}/onboarding-request", request)
        response = self._handle_request(request)
        self.transport.publish(f"_bootstrap/{client.device.device_id}/onboarding-response", response)
        client.accept_response(response)

    def _handle_request(self, payload: bytes) -> bytes:
        try:
            data = json.loads(payload.decode("utf-8"))
            if set(data) != {"v", "device_id", "kem_public_key", "signature"} or data["v"] != 1:
                raise OnboardingError("invalid device request")
            device_id = data["device_id"]
            public_key = base64.b64decode(data["kem_public_key"], validate=True)
            signature = base64.b64decode(data["signature"], validate=True)
            self._device_public_keys[device_id].verify(signature, _canonical("request", device_id, public_key))
            ciphertext, shared_secret = ml_kem_512.encaps(public_key)
            self._session_keys[device_id] = _session_key(shared_secret, device_id)
            response_signature = self._identity_private_key.sign(
                _canonical("response", device_id, ciphertext)
            )
            return json.dumps({
                "v": 1,
                "device_id": device_id,
                "kem_ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "signature": base64.b64encode(response_signature).decode("ascii"),
            }, sort_keys=True).encode("utf-8")
        except (ValueError, KeyError, InvalidSignature, OnboardingError) as exc:
            raise OnboardingError("invalid or unauthenticated onboarding request") from exc

    def _receive_broker_message(self, topic: str, payload: bytes) -> None:
        """Accept only authenticated installation acknowledgements from devices."""
        if not topic.startswith("_bootstrap/") or not topic.endswith("/branch-key-ack"):
            return
        try:
            device_id = topic.split("/")[1]
            data = json.loads(payload.decode("utf-8"))
            if set(data) != {"v", "branch", "key_version", "nonce", "ciphertext"} or data["v"] != 1:
                return
            branch = data["branch"]
            version = data["key_version"]
            nonce = base64.b64decode(data["nonce"], validate=True)
            ciphertext = base64.b64decode(data["ciphertext"], validate=True)
            if not isinstance(branch, str) or not isinstance(version, int) or len(nonce) != 12:
                return
            installed = AESGCM(self.session_key_for(device_id)).decrypt(
                nonce, ciphertext, _ack_aad(device_id, branch, version)
            )
            if installed == b"installed":
                self._acknowledgements.add((device_id, branch, version))
        except (ValueError, KeyError, InvalidTag, OnboardingError):
            return

"""Classical Key Establishment (X25519 ECDH + Ed25519 Authentication) for MQTT Onboarding.

This module replaces the post-quantum ML-KEM-512 lattice mechanism with classical
Elliptic Curve Diffie-Hellman (X25519 / Curve25519) combined with Ed25519 digital signatures.
It provides the comparative classical baseline for evaluating post-quantum transition costs.

Handshake Overview:
1. Device generates ephemeral X25519 keypair (32-byte public key) and signs it using its
   pre-registered Ed25519 identity key.
2. Device publishes the request to:
   _bootstrap/{device_id}/onboarding-request
3. Trusted Controller verifies the Ed25519 signature, generates an ephemeral X25519 keypair,
   computes the 32-byte ECDH shared secret, derives K_dist via HKDF-SHA-256, signs its
   response, and publishes to:
   _bootstrap/{device_id}/onboarding-response
4. Device verifies Controller's Ed25519 signature, computes ECDH shared secret, derives
   the exact same 32-byte K_dist, and confirms session establishment.
5. Controller distributes initial branch credentials encrypted under K_dist via AES-256-GCM.
6. Device responds with an authenticated ACK.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from classical_simulation.key_controller import BranchCredential
from classical_simulation.topic_keys import KEY_LENGTH


_DOMAIN_ONBOARD = b"MP1-CLASSICAL-ONBOARD-v1"
_DOMAIN_DIST = b"MP1-CLASSICAL-DISTRIBUTION-v1"
_DOMAIN_KEY_UPDATE = b"MP1-CLASSICAL-KEY-UPDATE-v1"
_DOMAIN_KEY_ACK = b"MP1-CLASSICAL-KEY-ACK-v1"

NONCE_LENGTH = 12
_UPDATE_VERSION = 1


class ClassicalOnboardingError(ValueError):
    """Raised when classical onboarding or key distribution fails."""


def _canonical(kind: str, device_id: str, value: bytes) -> bytes:
    encoded_id = device_id.encode("utf-8")
    return _DOMAIN_ONBOARD + kind.encode("ascii") + len(encoded_id).to_bytes(2, "big") + encoded_id + value


def _session_key(shared_secret: bytes, device_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=None,
        info=_DOMAIN_DIST + device_id.encode("utf-8"),
    ).derive(shared_secret)


def _update_topic(device_id: str) -> str:
    return f"_bootstrap/{device_id}/branch-key-update"


def _ack_topic(device_id: str) -> str:
    return f"_bootstrap/{device_id}/branch-key-ack"


def _update_aad(device_id: str, branch_path: str, key_version: int) -> bytes:
    fields = (device_id, branch_path)
    encoded = []
    for value in fields:
        raw = value.encode("utf-8")
        if len(raw) > 65535:
            raise ClassicalOnboardingError("field is too long")
        encoded.append(len(raw).to_bytes(2, "big") + raw)
    return _DOMAIN_KEY_UPDATE + b"".join(encoded) + key_version.to_bytes(8, "big")


def _ack_aad(device_id: str, branch_path: str, key_version: int) -> bytes:
    return _DOMAIN_KEY_ACK + _update_aad(device_id, branch_path, key_version)


@dataclass
class SimulatedClassicalDevice:
    """Software-only device holding local credentials and session state."""

    device_id: str
    distribution_key: bytes | None = None
    credentials: dict[str, BranchCredential] = field(default_factory=dict)
    rejected_updates: list[str] = field(default_factory=list)

    def credential_for(self, branch_path: str) -> BranchCredential:
        try:
            return self.credentials[branch_path]
        except KeyError as exc:
            raise ClassicalOnboardingError(f"device has no credential for branch {branch_path}") from exc


class ClassicalOnboardingClient:
    """Device-side classical X25519 ECDH onboarding and credential installation."""

    def __init__(
        self,
        device: SimulatedClassicalDevice,
        controller_identity_public_key: ed25519.Ed25519PublicKey,
    ) -> None:
        self.device = device
        self._controller_public_key = controller_identity_public_key
        self._identity_private_key = ed25519.Ed25519PrivateKey.generate()
        self._ecdh_private_key = x25519.X25519PrivateKey.generate()
        self._ecdh_public_bytes = self._ecdh_private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    @property
    def identity_public_key(self) -> ed25519.Ed25519PublicKey:
        return self._identity_private_key.public_key()

    def generate_request(self) -> bytes:
        """Create signed classical onboarding request with ephemeral X25519 public key."""
        signature = self._identity_private_key.sign(
            _canonical("request", self.device.device_id, self._ecdh_public_bytes)
        )
        return json.dumps({
            "v": 1,
            "device_id": self.device.device_id,
            "ecdh_public_key": base64.b64encode(self._ecdh_public_bytes).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }, sort_keys=True).encode("utf-8")

    def accept_response(self, payload: bytes) -> None:
        """Verify controller response, complete ECDH exchange, and derive K_dist."""
        try:
            data = json.loads(payload.decode("utf-8"))
            if set(data) != {"v", "device_id", "controller_ecdh_public", "signature"} or data["v"] != 1:
                raise ClassicalOnboardingError("invalid controller response format")
            if data["device_id"] != self.device.device_id:
                raise ClassicalOnboardingError("controller response target mismatch")

            controller_ecdh_bytes = base64.b64decode(data["controller_ecdh_public"], validate=True)
            signature = base64.b64decode(data["signature"], validate=True)

            self._controller_public_key.verify(
                signature, _canonical("response", self.device.device_id, controller_ecdh_bytes)
            )

            # Perform classical Curve25519 Diffie-Hellman exchange
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(controller_ecdh_bytes)
            shared_secret = self._ecdh_private_key.exchange(peer_public_key)

            # Derive 32-byte distribution session key
            self.device.distribution_key = _session_key(shared_secret, self.device.device_id)
        except (ValueError, KeyError, InvalidSignature, ClassicalOnboardingError) as exc:
            raise ClassicalOnboardingError("invalid or unauthentic classical response") from exc

    def process_key_update(self, payload: bytes) -> bytes:
        """Decrypt and install branch credential under K_dist, returning encrypted ACK."""
        if self.device.distribution_key is None:
            raise ClassicalOnboardingError("device has not completed classical onboarding")

        try:
            message = json.loads(payload.decode("utf-8"))
            required = {"v", "branch", "key_version", "nonce", "ciphertext"}
            if not isinstance(message, dict) or set(message) != required or message["v"] != _UPDATE_VERSION:
                raise ClassicalOnboardingError("invalid key-update envelope")

            branch = message["branch"]
            version = message["key_version"]
            nonce = base64.b64decode(message["nonce"], validate=True)
            ciphertext = base64.b64decode(message["ciphertext"], validate=True)

            if len(nonce) != NONCE_LENGTH:
                raise ClassicalOnboardingError("invalid nonce length")

            aad = _update_aad(self.device.device_id, branch, version)
            plaintext = AESGCM(self.device.distribution_key).decrypt(nonce, ciphertext, aad)

            if len(plaintext) != KEY_LENGTH:
                raise ClassicalOnboardingError("invalid branch root key length")

            self.device.credentials[branch] = BranchCredential(branch, plaintext, version)

            # Build encrypted ACK
            ack_nonce = os.urandom(NONCE_LENGTH)
            ack_aad_val = _ack_aad(self.device.device_id, branch, version)
            ack_cipher = AESGCM(self.device.distribution_key).encrypt(ack_nonce, b"installed", ack_aad_val)

            return json.dumps({
                "v": _UPDATE_VERSION,
                "device_id": self.device.device_id,
                "branch": branch,
                "key_version": version,
                "nonce": base64.b64encode(ack_nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ack_cipher).decode("ascii"),
            }, sort_keys=True).encode("utf-8")

        except (ValueError, KeyError, InvalidTag, ClassicalOnboardingError) as exc:
            self.device.rejected_updates.append(str(exc))
            raise ClassicalOnboardingError("key-update decryption failed") from exc


class ClassicalOnboardingController:
    """Controller-side identity verification, X25519 ECDH exchange, and credential distribution."""

    def __init__(self) -> None:
        self._identity_private_key = ed25519.Ed25519PrivateKey.generate()
        self._device_identities: dict[str, ed25519.Ed25519PublicKey] = {}
        self._session_keys: dict[str, bytes] = {}
        self._acknowledgements: set[tuple[str, str, int]] = set()

    @property
    def identity_public_key(self) -> ed25519.Ed25519PublicKey:
        return self._identity_private_key.public_key()

    def register_device_identity(self, device_id: str, identity_public_key: ed25519.Ed25519PublicKey) -> None:
        """Pre-register trusted device Ed25519 public key."""
        if not device_id or not isinstance(device_id, str):
            raise ClassicalOnboardingError("device_id must be a non-empty string")
        self._device_identities[device_id] = identity_public_key

    def process_onboarding_request(self, request_payload: bytes) -> bytes:
        """Verify device request, generate ephemeral X25519 keypair, derive K_dist, and return signed response."""
        try:
            data = json.loads(request_payload.decode("utf-8"))
            if set(data) != {"v", "device_id", "ecdh_public_key", "signature"} or data["v"] != 1:
                raise ClassicalOnboardingError("malformed onboarding request")

            device_id = data["device_id"]
            if device_id not in self._device_identities:
                raise ClassicalOnboardingError(f"unregistered device ID: {device_id}")

            device_ecdh_bytes = base64.b64decode(data["ecdh_public_key"], validate=True)
            signature = base64.b64decode(data["signature"], validate=True)

            # Verify device signature using pre-registered identity key
            device_identity_key = self._device_identities[device_id]
            device_identity_key.verify(signature, _canonical("request", device_id, device_ecdh_bytes))

            # Ephemeral X25519 keypair on controller
            controller_ecdh_priv = x25519.X25519PrivateKey.generate()
            controller_ecdh_pub_bytes = controller_ecdh_priv.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )

            # Compute classical Curve25519 shared secret
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(device_ecdh_bytes)
            shared_secret = controller_ecdh_priv.exchange(peer_public_key)

            # Derive session key and store
            session_key = _session_key(shared_secret, device_id)
            self._session_keys[device_id] = session_key

            # Controller signs response
            sig = self._identity_private_key.sign(
                _canonical("response", device_id, controller_ecdh_pub_bytes)
            )

            return json.dumps({
                "v": 1,
                "device_id": device_id,
                "controller_ecdh_public": base64.b64encode(controller_ecdh_pub_bytes).decode("ascii"),
                "signature": base64.b64encode(sig).decode("ascii"),
            }, sort_keys=True).encode("utf-8")

        except (ValueError, KeyError, InvalidSignature, ClassicalOnboardingError) as exc:
            raise ClassicalOnboardingError("invalid onboarding request") from exc

    def get_session_key(self, device_id: str) -> bytes:
        try:
            return self._session_keys[device_id]
        except KeyError as exc:
            raise ClassicalOnboardingError(f"no session key established for {device_id}") from exc

    def create_key_update(self, device_id: str, branch_path: str, root_key: bytes, key_version: int) -> bytes:
        """Encrypt a branch credential under device's K_dist."""
        session_key = self.get_session_key(device_id)
        nonce = os.urandom(NONCE_LENGTH)
        aad = _update_aad(device_id, branch_path, key_version)
        ciphertext = AESGCM(session_key).encrypt(nonce, root_key, aad)

        return json.dumps({
            "v": _UPDATE_VERSION,
            "branch": branch_path,
            "key_version": key_version,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }, sort_keys=True).encode("utf-8")

    def process_key_ack(self, ack_payload: bytes) -> bool:
        """Authenticate and verify an installation ACK from a device."""
        try:
            data = json.loads(ack_payload.decode("utf-8"))
            device_id = data["device_id"]
            branch = data["branch"]
            version = data["key_version"]
            nonce = base64.b64decode(data["nonce"], validate=True)
            ciphertext = base64.b64decode(data["ciphertext"], validate=True)

            session_key = self.get_session_key(device_id)
            aad = _ack_aad(device_id, branch, version)
            plaintext = AESGCM(session_key).decrypt(nonce, ciphertext, aad)

            if plaintext != b"installed":
                return False

            self._acknowledgements.add((device_id, branch, version))
            return True
        except (ValueError, KeyError, InvalidTag, ClassicalOnboardingError):
            return False

    def is_key_acknowledged(self, device_id: str, branch_path: str, key_version: int) -> bool:
        return (device_id, branch_path, key_version) in self._acknowledgements


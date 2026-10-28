"""Hardware-free simulation of encrypted branch-key distribution.

This module models the channel that will eventually be established by
authenticated ML-KEM onboarding.  A simulated device is provisioned with a
unique 256-bit controller-to-device distribution key.  The controller uses it
to AES-GCM encrypt a branch credential and sends the opaque update through the
untrusted MQTT relay.  It is a simulation transport, not an ML-KEM
implementation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.key_controller import BranchCredential, KeyController, KeyControllerError
from src.message_envelope import EnvelopeError, ReplayProtector, decrypt_payload, encrypt_payload, parse_envelope, serialise_envelope
from src.mqtt_prototype import MqttTransport
from src.topic_keys import KEY_LENGTH


_UPDATE_VERSION = 1
_NONCE_LENGTH = 12
_UPDATE_PREFIX = "_bootstrap"


class KeyUpdateError(ValueError):
    """Raised when a simulated key-update message is malformed or unauthentic."""


def _topic(device_id: str) -> str:
    return f"{_UPDATE_PREFIX}/{device_id}/branch-key-update"


def _aad(device_id: str, branch_path: str, key_version: int) -> bytes:
    fields = (device_id, branch_path)
    encoded = []
    for value in fields:
        raw = value.encode("utf-8")
        if len(raw) > 65535:
            raise KeyUpdateError("key-update field is too long")
        encoded.append(len(raw).to_bytes(2, "big") + raw)
    return b"MP1-SIM-KEY-UPDATE-v1" + b"".join(encoded) + key_version.to_bytes(8, "big")


@dataclass
class SimulatedDevice:
    """Software-only device holding a simulated secure controller channel."""

    device_id: str
    transport: MqttTransport
    distribution_key: bytes = field(default_factory=lambda: os.urandom(KEY_LENGTH))
    credentials: dict[str, BranchCredential] = field(default_factory=dict)
    rejected_updates: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.device_id:
            raise KeyUpdateError("device ID must be non-empty")
        if len(self.distribution_key) != KEY_LENGTH:
            raise KeyUpdateError("distribution key must be exactly 32 bytes")

    def subscribe_for_key_updates(self) -> None:
        self.transport.subscribe(_topic(self.device_id), self._receive_update)

    def credential_for(self, branch_path: str) -> BranchCredential:
        try:
            return self.credentials[branch_path]
        except KeyError as exc:
            raise KeyUpdateError("device has no credential for this branch") from exc

    def _receive_update(self, topic: str, payload: bytes) -> None:
        if topic != _topic(self.device_id):
            return
        try:
            message = json.loads(payload.decode("utf-8"))
            required = {"v", "branch", "key_version", "nonce", "ciphertext"}
            if not isinstance(message, dict) or set(message) != required or message["v"] != _UPDATE_VERSION:
                raise KeyUpdateError("invalid key-update envelope")
            branch = message["branch"]
            version = message["key_version"]
            if not isinstance(branch, str) or not isinstance(version, int) or version < 1:
                raise KeyUpdateError("invalid key-update metadata")
            nonce = base64.b64decode(message["nonce"], validate=True)
            ciphertext = base64.b64decode(message["ciphertext"], validate=True)
            if len(nonce) != _NONCE_LENGTH:
                raise KeyUpdateError("invalid key-update nonce")
            root_key = AESGCM(self.distribution_key).decrypt(
                nonce, ciphertext, _aad(self.device_id, branch, version)
            )
            if len(root_key) != KEY_LENGTH:
                raise KeyUpdateError("invalid branch root key")
            old = self.credentials.get(branch)
            if old is not None and version <= old.key_version:
                raise KeyUpdateError("key-update version is not newer")
            self.credentials[branch] = BranchCredential(branch, root_key, version)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, InvalidTag, KeyUpdateError) as exc:
            self.rejected_updates.append(str(exc))


@dataclass
class SimulatedKeyDistributor:
    """Controller-side encrypted distribution of credentials to simulated devices."""

    controller: KeyController
    transport: MqttTransport
    devices: dict[str, SimulatedDevice] = field(default_factory=dict)

    def register_device(self, device: SimulatedDevice) -> None:
        if device.device_id in self.devices:
            raise KeyUpdateError("device is already registered")
        self.devices[device.device_id] = device

    def distribute_branch(self, branch_path: str) -> BranchCredential:
        """Deliver the current credential to every remaining authorised member.

        Obtaining the first credential triggers a lazy rekey if the branch is
        stale.  Every recipient then receives exactly that same fresh branch
        key, wrapped separately under its own distribution key.
        """
        status = self.controller.branch_status(branch_path)
        members = status["members"]
        if not members:
            raise KeyUpdateError("cannot distribute a branch with no members")
        credentials: list[tuple[SimulatedDevice, BranchCredential]] = []
        for device_id in members:
            try:
                device = self.devices[device_id]
            except KeyError as exc:
                raise KeyUpdateError(f"no simulated device registered for {device_id}") from exc
            credentials.append((device, self.controller.credential_for(device_id, branch_path)))
        credential = credentials[0][1]
        for device, device_credential in credentials:
            if device_credential != credential:
                raise KeyUpdateError("controller returned inconsistent branch credentials")
            self._send_update(device, credential)
        return credential

    def _send_update(self, device: SimulatedDevice, credential: BranchCredential) -> None:
        nonce = os.urandom(_NONCE_LENGTH)
        ciphertext = AESGCM(device.distribution_key).encrypt(
            nonce,
            credential.root_key,
            _aad(device.device_id, credential.branch_path, credential.key_version),
        )
        envelope = {
            "v": _UPDATE_VERSION,
            "branch": credential.branch_path,
            "key_version": credential.key_version,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        self.transport.publish(_topic(device.device_id), json.dumps(envelope, sort_keys=True).encode("utf-8"))


@dataclass
class SimulatedManagedPublisher:
    """A software-only publisher that uses locally received branch credentials."""

    device: SimulatedDevice
    branch_path: str
    _sequences: dict[str, int] = field(default_factory=dict)

    def publish(self, topic: str, plaintext: bytes) -> dict[str, Any]:
        credential = self.device.credential_for(self.branch_path)
        sequence = self._sequences.get(topic, 0) + 1
        envelope = encrypt_payload(
            plaintext, topic, credential.root_key, credential.branch_path,
            self.device.device_id, credential.key_version, sequence,
        )
        self._sequences[topic] = sequence
        self.device.transport.publish(topic, serialise_envelope(envelope))
        return envelope


@dataclass
class SimulatedManagedSubscriber:
    """A software-only consumer that decrypts with locally stored credentials."""

    device: SimulatedDevice
    branch_path: str
    received: list[tuple[str, bytes]] = field(default_factory=list)
    rejected: list[str] = field(default_factory=list)
    replay_protector: ReplayProtector = field(default_factory=ReplayProtector)

    def subscribe(self) -> None:
        self.device.transport.subscribe(f"{self.branch_path}/#", self._receive)

    def _receive(self, topic: str, payload: bytes) -> None:
        try:
            credential = self.device.credential_for(self.branch_path)
            envelope = parse_envelope(payload)
            plaintext = decrypt_payload(envelope, topic, credential.root_key, credential.branch_path)
            self.replay_protector.accept(
                topic, envelope["sender_id"], envelope["key_version"], envelope["sequence"]
            )
        except (KeyUpdateError, EnvelopeError) as exc:
            self.rejected.append(str(exc))
            return
        self.received.append((topic, plaintext))

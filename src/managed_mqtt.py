"""MQTT endpoint helpers that obtain branch credentials from ``KeyController``."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.key_controller import KeyController, KeyControllerError
from src.message_envelope import EnvelopeError, ReplayProtector, decrypt_payload, encrypt_payload, parse_envelope, serialise_envelope
from src.mqtt_prototype import MqttTransport


@dataclass
class ControllerManagedPublisher:
    """Publisher that obtains a fresh credential before every encrypted publish."""

    transport: MqttTransport
    controller: KeyController
    device_id: str
    branch_path: str
    _sequences: dict[str, int] = field(default_factory=dict)

    def publish(self, topic: str, plaintext: bytes) -> dict[str, object]:
        credential = self.controller.credential_for(self.device_id, self.branch_path)
        sequence = self._sequences.get(topic, 0) + 1
        envelope = encrypt_payload(
            plaintext, topic, credential.root_key, credential.branch_path, self.device_id, credential.key_version, sequence
        )
        self._sequences[topic] = sequence
        self.transport.publish(topic, serialise_envelope(envelope))
        return envelope


@dataclass
class ControllerManagedSubscriber:
    """Subscriber that refreshes its controller credential before decrypting."""

    transport: MqttTransport
    controller: KeyController
    device_id: str
    branch_path: str
    received: list[tuple[str, bytes]] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)
    replay_protector: ReplayProtector = field(default_factory=ReplayProtector)

    def subscribe(self) -> None:
        self.transport.subscribe(f"{self.branch_path}/#", self._handle_message)

    def _handle_message(self, topic: str, payload: bytes) -> None:
        try:
            credential = self.controller.credential_for(self.device_id, self.branch_path)
            envelope = parse_envelope(payload)
            plaintext = decrypt_payload(envelope, topic, credential.root_key, credential.branch_path)
            self.replay_protector.accept(
                topic, envelope["sender_id"], envelope["key_version"], envelope["sequence"]
            )
        except KeyControllerError:
            # A revoked endpoint may still have an MQTT subscription, but it
            # can no longer obtain the rotated branch credential.
            return
        except EnvelopeError as exc:
            self.rejected.append((topic, str(exc)))
            return
        self.received.append((topic, plaintext))

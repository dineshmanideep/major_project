"""Encrypted MQTT publisher/subscriber components for the Python prototype.

The cryptographic payload format lives in :mod:`src.message_envelope`.  This
module connects it to an MQTT-shaped transport while deliberately keeping the
broker unable to inspect plaintext or keys.  ``InMemoryBroker`` is useful for
repeatable tests; ``PahoMqttTransport`` connects the same components to a
Mosquitto-compatible broker.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from src.message_envelope import (
    EnvelopeError,
    decrypt_payload,
    encrypt_payload,
    parse_envelope,
    ReplayProtector,
    serialise_envelope,
)
from src.topic_keys import TopicKeyError, derive_topic_key


MessageHandler = Callable[[str, bytes], None]


class MqttTransport(Protocol):
    """The small transport surface required by the encrypted components."""

    def publish(self, topic: str, payload: bytes) -> None:
        """Publish opaque bytes to a topic."""

    def subscribe(self, topic_filter: str, handler: MessageHandler) -> None:
        """Deliver messages matching ``topic_filter`` to ``handler``."""


def _matches(topic_filter: str, topic: str) -> bool:
    """Match exact topic filters and the MQTT multi-level ``#`` wildcard."""
    filter_parts = topic_filter.split("/")
    topic_parts = topic.split("/")
    if not topic_filter or any(not part for part in filter_parts):
        raise ValueError("topic filter must not contain empty segments")
    if filter_parts[-1:] == ["#"]:
        if any(part in {"#", "+"} for part in filter_parts[:-1]):
            raise ValueError("only a trailing # wildcard is supported")
        return topic_parts[: len(filter_parts) - 1] == filter_parts[:-1]
    if any(part in {"#", "+"} for part in filter_parts):
        raise ValueError("only a trailing # wildcard is supported")
    return filter_parts == topic_parts


@dataclass
class InMemoryBroker:
    """An untrusted relay simulation: it stores only topic names and bytes."""

    subscriptions: list[tuple[str, MessageHandler]] = field(default_factory=list)

    def publish(self, topic: str, payload: bytes) -> None:
        for topic_filter, handler in tuple(self.subscriptions):
            if _matches(topic_filter, topic):
                handler(topic, payload)

    def subscribe(self, topic_filter: str, handler: MessageHandler) -> None:
        _matches(topic_filter, "_validation") if topic_filter == "#" else _matches(topic_filter, topic_filter.rstrip("/#") or "_")
        self.subscriptions.append((topic_filter, handler))


@dataclass
class FaultInjectingBroker(InMemoryBroker):
    """In-memory relay that can drop selected publishes to test recovery paths."""

    drop_once_topics: set[str] = field(default_factory=set)

    def drop_next(self, topic: str) -> None:
        self.drop_once_topics.add(topic)

    def publish(self, topic: str, payload: bytes) -> None:
        if topic in self.drop_once_topics:
            self.drop_once_topics.remove(topic)
            return
        super().publish(topic, payload)


@dataclass
class EncryptedPublisher:
    """Encrypt sensor bytes once and publish only the resulting envelope."""

    transport: MqttTransport
    sender_id: str
    held_key: bytes
    held_path: str
    key_version: int
    _sequences: dict[str, int] = field(default_factory=dict)

    def publish(self, topic: str, plaintext: bytes) -> dict[str, Any]:
        sequence = self._sequences.get(topic, 0) + 1
        envelope = encrypt_payload(
            plaintext,
            topic,
            self.held_key,
            self.held_path,
            self.sender_id,
            self.key_version,
            sequence,
        )
        self._sequences[topic] = sequence
        self.transport.publish(topic, serialise_envelope(envelope))
        return envelope


@dataclass
class EncryptedSubscriber:
    """Subscribe to an authorised branch and decrypt messages locally."""

    transport: MqttTransport
    held_key: bytes
    held_path: str
    received: list[tuple[str, bytes]] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)
    replay_protector: ReplayProtector = field(default_factory=ReplayProtector)

    def subscribe(self) -> None:
        """Subscribe exactly to the subtree represented by the held key."""
        self.transport.subscribe(f"{self.held_path}/#", self._handle_message)

    def _handle_message(self, topic: str, payload: bytes) -> None:
        try:
            envelope = parse_envelope(payload)
            plaintext = decrypt_payload(envelope, topic, self.held_key, self.held_path)
            self.replay_protector.accept(
                topic, envelope["sender_id"], envelope["key_version"], envelope["sequence"]
            )
        except EnvelopeError as exc:
            self.rejected.append((topic, str(exc)))
            return
        self.received.append((topic, plaintext))

    def can_decrypt(self, topic: str) -> bool:
        """Return whether the subscriber's ancestor key authorises ``topic``."""
        try:
            derive_topic_key(self.held_key, self.held_path, topic)
        except TopicKeyError:
            return False
        return True


class PahoMqttTransport:
    """Mosquitto-compatible transport adapter, imported only when used.

    Call ``loop_forever`` (or access ``client`` and manage its network loop)
    after registering subscribers.
    """

    def __init__(self, host: str = "localhost", port: int = 1883, client_id: str = "") -> None:
        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:  # pragma: no cover - depends on optional runtime package
            raise RuntimeError("install paho-mqtt to use a live MQTT broker") from exc
        self._handlers: list[tuple[str, MessageHandler]] = []
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        self.client.on_message = self._on_message
        self.client.connect(host, port)

    def publish(self, topic: str, payload: bytes) -> None:
        result = self.client.publish(topic, payload=payload, qos=1)
        result.wait_for_publish()

    def subscribe(self, topic_filter: str, handler: MessageHandler) -> None:
        self._handlers.append((topic_filter, handler))
        result, _ = self.client.subscribe(topic_filter, qos=1)
        if result != 0:
            raise RuntimeError(f"MQTT subscription failed with result code {result}")

    def loop_forever(self) -> None:
        self.client.loop_forever()

    def _on_message(self, _client: Any, _userdata: Any, message: Any) -> None:
        for topic_filter, handler in tuple(self._handlers):
            if _matches(topic_filter, message.topic):
                handler(message.topic, message.payload)

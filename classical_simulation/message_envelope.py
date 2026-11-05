"""AES-256-GCM authenticated envelopes for MQTT payloads (Classical Module).

The MQTT topic is cryptographically bound into the Authenticated Additional Data (AAD)
of AES-256-GCM without exposing raw plaintext in the JSON envelope. This ensures
that an untrusted broker cannot relocate messages across topics or alter sequence numbers
without causing immediate authentication tag validation failure.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from classical_simulation.topic_keys import TopicKeyError, derive_topic_key


PROTOCOL_VERSION = 1
NONCE_LENGTH = 12
TAG_LENGTH = 16


class EnvelopeError(ValueError):
    """Raised when an encrypted MQTT message is malformed or unauthentic."""


class ReplayProtector:
    """Track the newest accepted sequence for each sender/topic/version tuple."""

    def __init__(self) -> None:
        self._last_seen: dict[tuple[str, str, int], int] = {}

    def accept(self, topic: str, sender_id: str, key_version: int, sequence: int) -> None:
        previous = self._last_seen.get((topic, sender_id, key_version), 0)
        if sequence <= previous:
            raise EnvelopeError("replayed or out-of-order message")
        self._last_seen[(topic, sender_id, key_version)] = sequence


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: Any, field: str) -> bytes:
    if not isinstance(value, str):
        raise EnvelopeError(f"{field} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, UnicodeEncodeError) as exc:
        raise EnvelopeError(f"{field} is not valid base64") from exc


def _aad(topic: str, sender_id: str, key_version: int, sequence: int) -> bytes:
    """Canonical data that must stay bound to an encrypted MQTT message."""
    if not isinstance(sender_id, str) or not sender_id:
        raise EnvelopeError("sender_id must be a non-empty string")
    if not isinstance(key_version, int) or key_version < 1:
        raise EnvelopeError("key_version must be a positive integer")
    if not isinstance(sequence, int) or sequence < 1:
        raise EnvelopeError("sequence must be a positive integer")
    try:
        topic_bytes = topic.encode("utf-8")
        sender_bytes = sender_id.encode("utf-8")
    except (AttributeError, UnicodeEncodeError) as exc:
        raise EnvelopeError("topic and sender_id must be UTF-8 strings") from exc
    if len(topic_bytes) > 65535 or len(sender_bytes) > 65535:
        raise EnvelopeError("topic or sender_id is too long")
    return (
        b"MP1-MSG-v1"
        + len(topic_bytes).to_bytes(2, "big")
        + topic_bytes
        + len(sender_bytes).to_bytes(2, "big")
        + sender_bytes
        + key_version.to_bytes(8, "big")
        + sequence.to_bytes(8, "big")
    )


def encrypt_payload(
    plaintext: bytes,
    topic: str,
    held_key: bytes,
    held_path: str,
    sender_id: str,
    key_version: int,
    sequence: int = 1,
) -> dict[str, Any]:
    """Encrypt one payload under the leaf key derived for ``topic``."""
    if not isinstance(plaintext, bytes):
        raise EnvelopeError("plaintext must be bytes")
    try:
        topic_key = derive_topic_key(held_key, held_path, topic)
    except TopicKeyError as exc:
        raise EnvelopeError(str(exc)) from exc

    nonce = os.urandom(NONCE_LENGTH)
    aad = _aad(topic, sender_id, key_version, sequence)
    cipher_and_tag = AESGCM(topic_key).encrypt(nonce, plaintext, aad)
    ciphertext = cipher_and_tag[:-TAG_LENGTH]
    tag = cipher_and_tag[-TAG_LENGTH:]

    return {
        "protocol_version": PROTOCOL_VERSION,
        "key_version": key_version,
        "sequence": sequence,
        "sender_id": sender_id,
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
        "tag": _b64encode(tag),
    }


def parse_envelope(envelope: Mapping[str, Any]) -> tuple[int, int, str, bytes, bytes, bytes]:
    """Validate the schema of a received MQTT JSON envelope."""
    required = {"protocol_version", "key_version", "sequence", "sender_id", "nonce", "ciphertext", "tag"}
    if not isinstance(envelope, Mapping) or set(envelope) != required:
        raise EnvelopeError("envelope must contain exactly the expected fields")

    protocol_version = envelope["protocol_version"]
    key_version = envelope["key_version"]
    sequence = envelope["sequence"]
    sender_id = envelope["sender_id"]

    if protocol_version != PROTOCOL_VERSION:
        raise EnvelopeError("unsupported protocol version")
    if not isinstance(key_version, int) or key_version < 1:
        raise EnvelopeError("key_version must be a positive integer")
    if not isinstance(sequence, int) or sequence < 1:
        raise EnvelopeError("sequence must be a positive integer")
    if not isinstance(sender_id, str) or not sender_id:
        raise EnvelopeError("sender_id must be a non-empty string")

    nonce = _b64decode(envelope["nonce"], "nonce")
    ciphertext = _b64decode(envelope["ciphertext"], "ciphertext")
    tag = _b64decode(envelope["tag"], "tag")

    if len(nonce) != NONCE_LENGTH:
        raise EnvelopeError("nonce must be 12 bytes")
    if len(tag) != TAG_LENGTH:
        raise EnvelopeError("tag must be 16 bytes")

    return key_version, sequence, sender_id, nonce, ciphertext, tag


def decrypt_payload(
    envelope: Mapping[str, Any],
    topic: str,
    held_key: bytes,
    held_path: str,
    replay_protector: ReplayProtector | None = None,
) -> bytes:
    """Decrypt and authenticate a received message envelope."""
    key_version, sequence, sender_id, nonce, ciphertext, tag = parse_envelope(envelope)
    try:
        topic_key = derive_topic_key(held_key, held_path, topic)
    except TopicKeyError as exc:
        raise EnvelopeError(str(exc)) from exc

    if replay_protector is not None:
        replay_protector.accept(topic, sender_id, key_version, sequence)

    aad = _aad(topic, sender_id, key_version, sequence)
    try:
        return AESGCM(topic_key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise EnvelopeError("message authentication failed") from exc


def serialise_envelope(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")


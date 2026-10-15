"""Deterministic, one-way topic-hierarchical key derivation.

This is a dependency-free reference implementation intended to match an
ESP32/mbedTLS HKDF-Expand implementation byte-for-byte.  It does not perform
key distribution: callers must provision an authorised ancestor key securely.
"""

from __future__ import annotations

import hashlib
import hmac


KEY_LENGTH = 32  # AES-256 key size
_DOMAIN = b"MP1-TOPIC-KDF-v1"


class TopicKeyError(ValueError):
    """Raised when a topic path is malformed or outside an authority scope."""


def _segments(path: str) -> tuple[str, ...]:
    """Return a validated canonical MQTT topic path as individual segments."""
    if not isinstance(path, str) or not path:
        raise TopicKeyError("topic path must be a non-empty string")
    parts = tuple(path.split("/"))
    if any(not part for part in parts):
        raise TopicKeyError("topic path must not contain empty segments")
    if any("+" in part or "#" in part for part in parts):
        raise TopicKeyError("wildcards are not valid cryptographic topic paths")
    return parts


def _encode_info(segment: str) -> bytes:
    """Use an unambiguous, versioned HKDF info encoding for one segment."""
    encoded = segment.encode("utf-8")
    if len(encoded) > 65535:
        raise TopicKeyError("topic segment is too long")
    return _DOMAIN + len(encoded).to_bytes(2, "big") + encoded


def derive_child_key(parent_key: bytes, child_segment: str) -> bytes:
    """Derive a 32-byte child key using one block of HKDF-Expand/SHA-256.

    ``parent_key`` is treated as the 32-byte HKDF pseudorandom key (PRK).
    The byte ``0x01`` is HKDF-Expand's counter for its first output block.
    """
    if not isinstance(parent_key, bytes) or len(parent_key) != KEY_LENGTH:
        raise TopicKeyError("parent key must be exactly 32 bytes")
    _segments(child_segment)  # applies the same segment validation rules
    if "/" in child_segment:
        raise TopicKeyError("child segment must not contain '/'")
    return hmac.new(parent_key, _encode_info(child_segment) + b"\x01", hashlib.sha256).digest()


def derive_topic_key(held_key: bytes, held_path: str, requested_topic: str) -> bytes:
    """Derive a descendant's key, rejecting parent and sibling access attempts."""
    ancestor = _segments(held_path)
    target = _segments(requested_topic)
    if len(target) < len(ancestor) or target[: len(ancestor)] != ancestor:
        raise TopicKeyError("requested topic is outside the held branch")

    key = held_key
    for segment in target[len(ancestor) :]:
        key = derive_child_key(key, segment)
    return key

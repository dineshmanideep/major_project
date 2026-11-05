"""Untrusted MQTT broker simulation relay (Classical Module).

Acts as an honest-but-curious or untrusted broker that routes messages
purely based on topic strings. Holds zero cryptographic keys and cannot
inspect or forge payload contents.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Callable


Callback = Callable[[str, bytes], None]


def _match_topic(sub_filter: str, topic: str) -> bool:
    """Check if an MQTT topic matches a subscription filter with '+' and '#' wildcards."""
    if sub_filter == "#":
        return True
    sub_parts = sub_filter.split("/")
    topic_parts = topic.split("/")

    for i, part in enumerate(sub_parts):
        if part == "#":
            return True
        if i >= len(topic_parts):
            return False
        if part == "+":
            continue
        if part != topic_parts[i]:
            return False

    return len(sub_parts) == len(topic_parts)


class SimulationBroker:
    """In-memory pub/sub broker simulating an untrusted MQTT relay."""

    def __init__(self) -> None:
        self._subscriptions: list[tuple[str, Callback]] = []
        self.relayed_messages: list[tuple[str, int]] = []  # (topic, byte_len)

    def subscribe(self, topic_filter: str, callback: Callback) -> None:
        self._subscriptions.append((topic_filter, callback))

    def publish(self, topic: str, payload: bytes) -> None:
        self.relayed_messages.append((topic, len(payload)))
        for topic_filter, callback in self._subscriptions:
            if _match_topic(topic_filter, topic):
                callback(topic, payload)

    @property
    def total_bytes_relayed(self) -> int:
        return sum(length for _, length in self.relayed_messages)

    @property
    def total_messages_relayed(self) -> int:
        return len(self.relayed_messages)


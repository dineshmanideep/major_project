"""Tests for topic-hierarchical key derivation in the classical simulation."""

from __future__ import annotations

import unittest

from classical_simulation.topic_keys import (
    KEY_LENGTH,
    TopicKeyError,
    derive_child_key,
    derive_topic_key,
)


class TopicKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.branch_key = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
        self.branch_path = "factory/line3"

    def test_deterministic(self) -> None:
        key_a = derive_topic_key(self.branch_key, self.branch_path, "factory/line3/motor/speed")
        key_b = derive_topic_key(self.branch_key, self.branch_path, "factory/line3/motor/speed")
        self.assertEqual(key_a, key_b)
        self.assertEqual(len(key_a), KEY_LENGTH)

    def test_known_derivation_vector(self) -> None:
        result = derive_topic_key(self.branch_key, self.branch_path, "factory/line3/oven/temp")
        expected_hex = "8280d0959421b30458a906d2b67dd7b52c6183378acaf50a6ec81bcb765ddee0"
        self.assertEqual(result.hex(), expected_hex)

    def test_rejects_mqtt_wildcard(self) -> None:
        with self.assertRaises(TopicKeyError):
            derive_topic_key(self.branch_key, self.branch_path, "factory/line3/+")
        with self.assertRaises(TopicKeyError):
            derive_topic_key(self.branch_key, self.branch_path, "factory/line3/#")

    def test_siblings_have_different_keys(self) -> None:
        motor_key = derive_topic_key(self.branch_key, self.branch_path, "factory/line3/motor")
        oven_key = derive_topic_key(self.branch_key, self.branch_path, "factory/line3/oven")
        self.assertNotEqual(motor_key, oven_key)

    def test_cannot_derive_parent_or_sibling(self) -> None:
        motor_key = derive_topic_key(self.branch_key, self.branch_path, "factory/line3/motor")
        with self.assertRaises(TopicKeyError):
            derive_topic_key(motor_key, "factory/line3/motor", "factory/line3")
        with self.assertRaises(TopicKeyError):
            derive_topic_key(motor_key, "factory/line3/motor", "factory/line3/oven")


if __name__ == "__main__":
    unittest.main()

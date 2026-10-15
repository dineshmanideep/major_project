"""Cross-platform contract tests for the topic key derivation module."""

import unittest

from src.topic_keys import TopicKeyError, derive_child_key, derive_topic_key


ROOT_KEY = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
LINE3 = "factory/line3"


class TopicKeyTests(unittest.TestCase):
    def test_known_derivation_vector(self):
        """This expected value is the portable ESP32/Raspberry Pi test vector."""
        result = derive_topic_key(ROOT_KEY, LINE3, "factory/line3/oven/temp")
        self.assertEqual(
            result.hex(),
            "8280d0959421b30458a906d2b67dd7b52c6183378acaf50a6ec81bcb765ddee0",
        )

    def test_deterministic(self):
        first = derive_topic_key(ROOT_KEY, LINE3, "factory/line3/motor/speed")
        second = derive_topic_key(ROOT_KEY, LINE3, "factory/line3/motor/speed")
        self.assertEqual(first, second)

    def test_siblings_have_different_keys(self):
        oven = derive_child_key(ROOT_KEY, "oven")
        motor = derive_child_key(ROOT_KEY, "motor")
        self.assertNotEqual(oven, motor)

    def test_cannot_derive_parent_or_sibling(self):
        with self.assertRaises(TopicKeyError):
            derive_topic_key(ROOT_KEY, "factory/line3/oven", "factory/line3")
        with self.assertRaises(TopicKeyError):
            derive_topic_key(ROOT_KEY, "factory/line3/oven", "factory/line3/motor/speed")

    def test_rejects_mqtt_wildcard(self):
        with self.assertRaises(TopicKeyError):
            derive_topic_key(ROOT_KEY, LINE3, "factory/line3/+")


if __name__ == "__main__":
    unittest.main()

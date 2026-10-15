"""End-to-end tests for the encrypted MQTT prototype."""

import unittest

from src.mqtt_prototype import EncryptedPublisher, EncryptedSubscriber, InMemoryBroker
from src.topic_keys import derive_topic_key


ROOT_KEY = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
LINE3 = "factory/line3"
OVEN_TEMP = "factory/line3/oven/temp"
MOTOR_SPEED = "factory/line3/motor/speed"


class EncryptedMqttPrototypeTests(unittest.TestCase):
    def setUp(self):
        self.broker = InMemoryBroker()
        self.publisher = EncryptedPublisher(
            self.broker, "esp32-oven-01", ROOT_KEY, LINE3, key_version=1
        )

    def test_two_authorised_subscribers_decrypt_same_ciphertext(self):
        dashboard = EncryptedSubscriber(self.broker, ROOT_KEY, LINE3)
        historian = EncryptedSubscriber(self.broker, ROOT_KEY, LINE3)
        dashboard.subscribe()
        historian.subscribe()

        envelope = self.publisher.publish(OVEN_TEMP, b'{"celsius":182.4}')

        self.assertEqual(dashboard.received, [(OVEN_TEMP, b'{"celsius":182.4}')])
        self.assertEqual(historian.received, [(OVEN_TEMP, b'{"celsius":182.4}')])
        self.assertNotIn(b"celsius", str(envelope).encode())

    def test_subscriber_is_confined_to_its_authorised_branch(self):
        motor_key = derive_topic_key(ROOT_KEY, LINE3, "factory/line3/motor")
        vendor = EncryptedSubscriber(self.broker, motor_key, "factory/line3/motor")
        vendor.subscribe()

        self.publisher.publish(OVEN_TEMP, b"182.4")
        self.publisher.publish(MOTOR_SPEED, b"1500")

        self.assertEqual(vendor.received, [(MOTOR_SPEED, b"1500")])
        self.assertFalse(vendor.can_decrypt(OVEN_TEMP))

    def test_tampered_payload_is_rejected_by_each_subscriber(self):
        subscriber = EncryptedSubscriber(self.broker, ROOT_KEY, LINE3)
        subscriber.subscribe()
        self.broker.publish(OVEN_TEMP, b'{"not":"an encrypted envelope"}')

        self.assertEqual(subscriber.received, [])
        self.assertEqual(len(subscriber.rejected), 1)


if __name__ == "__main__":
    unittest.main()

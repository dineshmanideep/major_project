"""Tests for lazy, branch-confined revocation rekeying."""

from datetime import datetime, timedelta, timezone
import unittest

from src.key_controller import KeyController, KeyControllerError
from src.managed_mqtt import ControllerManagedPublisher, ControllerManagedSubscriber
from src.message_envelope import EnvelopeError, decrypt_payload
from src.mqtt_prototype import InMemoryBroker


MOTOR = "factory/line3/motor"
OVEN = "factory/line3/oven"
MOTOR_SPEED = f"{MOTOR}/speed"
OVEN_TEMP = f"{OVEN}/temp"
START = datetime(2026, 1, 1, tzinfo=timezone.utc)


class KeyControllerTests(unittest.TestCase):
    def setUp(self):
        self.controller = KeyController(max_staleness=timedelta(minutes=5))
        self.controller.create_branch(MOTOR, {"motor-01", "gateway", "vendor"}, b"m" * 32)
        self.controller.create_branch(OVEN, {"oven-01", "gateway"}, b"o" * 32)

    def test_revocation_is_lazy_then_rekeys_before_next_publish(self):
        before = self.controller.credential_for("motor-01", MOTOR)
        self.controller.revoke("vendor", MOTOR, now=START)
        self.assertTrue(self.controller.branch_status(MOTOR)["stale"])
        self.assertEqual(self.controller.branch_status(MOTOR)["key_version"], 1)

        after = self.controller.credential_for("motor-01", MOTOR, now=START + timedelta(seconds=1))
        self.assertEqual(after.key_version, 2)
        self.assertNotEqual(after.root_key, before.root_key)
        self.assertFalse(self.controller.branch_status(MOTOR)["stale"])
        with self.assertRaises(KeyControllerError):
            self.controller.credential_for("vendor", MOTOR)

    def test_rekey_is_confined_to_revoked_branch(self):
        oven_before = self.controller.credential_for("oven-01", OVEN)
        self.controller.revoke("vendor", MOTOR, now=START)
        self.controller.credential_for("motor-01", MOTOR, now=START + timedelta(seconds=1))
        oven_after = self.controller.credential_for("oven-01", OVEN)

        self.assertEqual(oven_after, oven_before)
        self.assertEqual(self.controller.branch_status(OVEN)["key_version"], 1)

    def test_idle_stale_branch_rekeys_at_deadline(self):
        self.controller.revoke("vendor", MOTOR, now=START)
        self.assertEqual(self.controller.rekey_expired(now=START + timedelta(minutes=4)), [])
        self.assertEqual(self.controller.rekey_expired(now=START + timedelta(minutes=5)), [MOTOR])
        self.assertEqual(self.controller.branch_status(MOTOR)["key_version"], 2)

    def test_managed_publish_rekeys_before_ciphertext_reaches_consumer(self):
        broker = InMemoryBroker()
        publisher = ControllerManagedPublisher(broker, self.controller, "motor-01", MOTOR)
        gateway = ControllerManagedSubscriber(broker, self.controller, "gateway", MOTOR)
        vendor = ControllerManagedSubscriber(broker, self.controller, "vendor", MOTOR)
        gateway.subscribe()
        vendor.subscribe()

        publisher.publish(MOTOR_SPEED, b"1500")
        revoked_credential = self.controller.credential_for("vendor", MOTOR)
        self.controller.revoke("vendor", MOTOR)
        envelope = publisher.publish(MOTOR_SPEED, b"1600")

        self.assertEqual(gateway.received, [(MOTOR_SPEED, b"1500"), (MOTOR_SPEED, b"1600")])
        self.assertEqual(vendor.received, [(MOTOR_SPEED, b"1500")])
        with self.assertRaises(EnvelopeError):
            decrypt_payload(
                envelope, MOTOR_SPEED, revoked_credential.root_key, revoked_credential.branch_path
            )

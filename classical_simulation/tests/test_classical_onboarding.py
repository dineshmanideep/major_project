"""Tests for Classical X25519 ECDH Onboarding and Credential Distribution."""

from __future__ import annotations

import json
import unittest

from classical_simulation.classical_onboarding import (
    ClassicalOnboardingClient,
    ClassicalOnboardingController,
    ClassicalOnboardingError,
    SimulatedClassicalDevice,
)


class ClassicalOnboardingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = ClassicalOnboardingController()
        self.device = SimulatedClassicalDevice("motor-01")
        self.client = ClassicalOnboardingClient(self.device, self.controller.identity_public_key)
        self.controller.register_device_identity("motor-01", self.client.identity_public_key)

    def test_authenticated_x25519_onboarding_succeeds(self) -> None:
        req = self.client.generate_request()
        resp = self.controller.process_onboarding_request(req)
        self.client.accept_response(resp)

        dev_key = self.device.distribution_key
        ctrl_key = self.controller.get_session_key("motor-01")

        self.assertIsNotNone(dev_key)
        self.assertEqual(len(dev_key), 32)
        self.assertEqual(dev_key, ctrl_key)

    def test_unregistered_device_request_is_rejected(self) -> None:
        unregistered_dev = SimulatedClassicalDevice("rogue-device")
        rogue_client = ClassicalOnboardingClient(unregistered_dev, self.controller.identity_public_key)
        req = rogue_client.generate_request()

        with self.assertRaises(ClassicalOnboardingError):
            self.controller.process_onboarding_request(req)

    def test_tampered_controller_response_is_rejected(self) -> None:
        req = self.client.generate_request()
        resp = self.controller.process_onboarding_request(req)

        data = json.loads(resp.decode("utf-8"))
        data["controller_ecdh_public"] = "A" * 44  # Tamper with public key
        tampered_resp = json.dumps(data).encode("utf-8")

        with self.assertRaises(ClassicalOnboardingError):
            self.client.accept_response(tampered_resp)

    def test_key_update_and_ack_roundtrip(self) -> None:
        req = self.client.generate_request()
        resp = self.controller.process_onboarding_request(req)
        self.client.accept_response(resp)

        branch = "factory/line3/motor"
        root_key = b"r" * 32
        update_bytes = self.controller.create_key_update("motor-01", branch, root_key, key_version=1)

        ack_bytes = self.client.process_key_update(update_bytes)
        ack_success = self.controller.process_key_ack(ack_bytes)

        self.assertTrue(ack_success)
        self.assertTrue(self.controller.is_key_acknowledged("motor-01", branch, 1))
        self.assertEqual(self.device.credential_for(branch).root_key, root_key)


if __name__ == "__main__":
    unittest.main()


"""ML-KEM and mutual identity authentication tests for software onboarding."""

import json
import unittest

from src.mqtt_prototype import InMemoryBroker
from src.pqc_onboarding import MlKemOnboardingClient, MlKemOnboardingController, OnboardingError
from src.simulated_key_distribution import SimulatedDevice


class PqcOnboardingTests(unittest.TestCase):
    def setUp(self):
        self.broker = InMemoryBroker()
        self.controller = MlKemOnboardingController(self.broker)
        self.device = SimulatedDevice("motor-01", self.broker, b"x" * 32)
        self.client = MlKemOnboardingClient(self.device, self.controller.identity_public_key)
        self.controller.register_device_identity(self.client)

    def test_authenticated_ml_kem_onboarding_replaces_placeholder_key(self):
        before = self.device.distribution_key
        self.controller.onboard(self.client)
        self.assertNotEqual(self.device.distribution_key, before)
        self.assertEqual(len(self.device.distribution_key), 32)

    def test_unregistered_device_request_is_rejected(self):
        stranger = MlKemOnboardingClient(
            SimulatedDevice("attacker", self.broker), self.controller.identity_public_key
        )
        with self.assertRaises(OnboardingError):
            self.controller.onboard(stranger)

    def test_tampered_controller_response_is_rejected(self):
        response = self.controller._handle_request(self.client.request())
        data = json.loads(response)
        data["device_id"] = "attacker"
        with self.assertRaises(OnboardingError):
            self.client.accept_response(json.dumps(data).encode("utf-8"))

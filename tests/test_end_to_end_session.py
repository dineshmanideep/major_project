"""Protocol-level session, acknowledgement, retry, and expiry tests."""

import unittest

from src.key_controller import KeyController
from src.mqtt_prototype import FaultInjectingBroker
from src.pqc_onboarding import MlKemOnboardingClient, MlKemOnboardingController, OnboardingError
from src.simulated_key_distribution import _ack_topic, _topic, SimulatedDevice, SimulatedKeyDistributor


BRANCH = "factory/line3/motor"


class EndToEndSessionTests(unittest.TestCase):
    def setUp(self):
        self.broker = FaultInjectingBroker()
        self.key_controller = KeyController()
        self.key_controller.create_branch(BRANCH, {"motor-01"})
        self.device = SimulatedDevice("motor-01", self.broker)
        self.device.subscribe_for_key_updates()
        self.session_controller = MlKemOnboardingController(self.broker)
        self.client = MlKemOnboardingClient(self.device, self.session_controller.identity_public_key)
        self.session_controller.register_device_identity(self.client)
        self.session_controller.onboard(self.client)
        self.distributor = SimulatedKeyDistributor(
            self.key_controller, self.broker,
            session_key_for=self.session_controller.session_key_for,
            acknowledgement_received=self.session_controller.acknowledged,
        )
        self.distributor.register_device(self.device)

    def test_controller_and_device_independently_hold_same_ml_kem_session(self):
        self.assertEqual(self.session_controller.session_key_for("motor-01"), self.device.distribution_key)
        self.distributor.distribute_branch(BRANCH)
        self.assertTrue(self.session_controller.acknowledged("motor-01", BRANCH, 1))

    def test_dropped_key_update_is_retried_until_authenticated_ack(self):
        self.broker.drop_next(_topic("motor-01"))
        credential = self.distributor.distribute_branch(BRANCH, max_attempts=2)
        self.assertEqual(self.device.credential_for(BRANCH), credential)
        self.assertTrue(self.session_controller.acknowledged("motor-01", BRANCH, 1))

    def test_dropped_ack_is_recovered_by_duplicate_update(self):
        self.broker.drop_next(_ack_topic("motor-01"))
        self.distributor.distribute_branch(BRANCH, max_attempts=2)
        self.assertTrue(self.session_controller.acknowledged("motor-01", BRANCH, 1))

    def test_expired_controller_session_requires_fresh_onboarding(self):
        self.session_controller.expire_session("motor-01")
        with self.assertRaises(OnboardingError):
            self.distributor.distribute_branch(BRANCH)
        self.session_controller.onboard(self.client)
        self.distributor.distribute_branch(BRANCH)
        self.assertTrue(self.session_controller.acknowledged("motor-01", BRANCH, 1))

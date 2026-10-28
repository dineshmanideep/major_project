"""Hardware-free simulation of encrypted branch-key delivery and revocation."""

import unittest

from src.key_controller import KeyController
from src.mqtt_prototype import InMemoryBroker
from src.simulated_key_distribution import (
    SimulatedDevice,
    SimulatedKeyDistributor,
    SimulatedManagedPublisher,
    SimulatedManagedSubscriber,
)


BRANCH = "factory/line3/motor"
TOPIC = f"{BRANCH}/speed"


class SimulatedKeyDistributionTests(unittest.TestCase):
    def setUp(self):
        self.broker = InMemoryBroker()
        self.controller = KeyController()
        self.controller.create_branch(BRANCH, {"motor-01", "gateway", "vendor"}, b"m" * 32)
        self.distributor = SimulatedKeyDistributor(self.controller, self.broker)
        self.devices = {
            device_id: SimulatedDevice(device_id, self.broker)
            for device_id in ("motor-01", "gateway", "vendor")
        }
        for device in self.devices.values():
            device.subscribe_for_key_updates()
            self.distributor.register_device(device)

    def test_authorised_devices_receive_individually_encrypted_initial_key(self):
        initial = self.distributor.distribute_branch(BRANCH)

        self.assertEqual(self.devices["motor-01"].credential_for(BRANCH), initial)
        self.assertEqual(self.devices["gateway"].credential_for(BRANCH), initial)
        self.assertEqual(self.devices["vendor"].credential_for(BRANCH), initial)

    def test_rekey_update_reaches_remaining_members_not_revoked_device(self):
        initial = self.distributor.distribute_branch(BRANCH)
        self.controller.revoke("vendor", BRANCH)
        rotated = self.distributor.distribute_branch(BRANCH)

        self.assertEqual(rotated.key_version, initial.key_version + 1)
        self.assertNotEqual(rotated.root_key, initial.root_key)
        self.assertEqual(self.devices["motor-01"].credential_for(BRANCH), rotated)
        self.assertEqual(self.devices["gateway"].credential_for(BRANCH), rotated)
        self.assertEqual(self.devices["vendor"].credential_for(BRANCH), initial)

    def test_end_to_end_telemetry_uses_locally_received_rotated_credential(self):
        self.distributor.distribute_branch(BRANCH)
        publisher = SimulatedManagedPublisher(self.devices["motor-01"], BRANCH)
        gateway = SimulatedManagedSubscriber(self.devices["gateway"], BRANCH)
        vendor = SimulatedManagedSubscriber(self.devices["vendor"], BRANCH)
        gateway.subscribe()
        vendor.subscribe()

        publisher.publish(TOPIC, b"1500")
        self.controller.revoke("vendor", BRANCH)
        self.distributor.distribute_branch(BRANCH)
        publisher.publish(TOPIC, b"1600")

        self.assertEqual(gateway.received, [(TOPIC, b"1500"), (TOPIC, b"1600")])
        self.assertEqual(vendor.received, [(TOPIC, b"1500")])
        self.assertEqual(len(vendor.rejected), 1)

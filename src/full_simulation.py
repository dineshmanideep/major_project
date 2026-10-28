"""Runnable software-only demonstration of the complete secure MQTT workflow.

Run from the repository root with ``python3 -m src.full_simulation``.  The
trace deliberately shows metadata and outcomes, never plaintext key material.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from src.key_controller import KeyController
from src.mqtt_prototype import InMemoryBroker
from src.pqc_onboarding import MlKemOnboardingClient, MlKemOnboardingController
from src.simulated_key_distribution import (
    SimulatedDevice,
    SimulatedKeyDistributor,
    SimulatedManagedPublisher,
    SimulatedManagedSubscriber,
)


MOTOR_BRANCH = "factory/line3/motor"
OVEN_BRANCH = "factory/line3/oven"
MOTOR_TOPIC = f"{MOTOR_BRANCH}/speed"
OVEN_TOPIC = f"{OVEN_BRANCH}/temp"


@dataclass(frozen=True)
class SimulationReport:
    """Outcome summary returned by :func:`run_demo` for tests or UI adapters."""

    motor_key_version: int
    oven_key_version: int
    gateway_messages: int
    dashboard_messages: int
    vendor_messages: int
    vendor_rejections: int
    revoked_vendor_has_old_motor_key: bool


class TracingBroker(InMemoryBroker):
    """Untrusted relay that reports only public routing metadata for the demo."""

    def __init__(self, emit: Callable[[str], None]) -> None:
        super().__init__()
        self._emit = emit

    def publish(self, topic: str, payload: bytes) -> None:
        if topic.endswith("onboarding-request"):
            kind = "onboarding request"
        elif topic.endswith("onboarding-response"):
            kind = "onboarding response"
        elif topic.startswith("_bootstrap/"):
            kind = "encrypted key update"
        else:
            kind = "telemetry ciphertext"
        self._emit(f"  broker relays {kind}: topic={topic}, bytes={len(payload)}")
        super().publish(topic, payload)


def run_demo(emit: Callable[[str], None] = print) -> SimulationReport:
    """Execute the complete no-hardware simulation and return its results."""
    emit("MP-1 secure MQTT full software simulation")
    emit("Broker role: untrusted relay; it sees topics and encrypted byte lengths only.\n")

    broker = TracingBroker(emit)
    controller = KeyController()
    controller.create_branch(MOTOR_BRANCH, {"motor-01", "gateway", "vendor"})
    controller.create_branch(OVEN_BRANCH, {"oven-01", "gateway", "dashboard"})
    distributor = SimulatedKeyDistributor(controller, broker)

    device_ids = ("motor-01", "oven-01", "gateway", "dashboard", "vendor")
    devices = {device_id: SimulatedDevice(device_id, broker) for device_id in device_ids}
    onboarding_controller = MlKemOnboardingController(broker)
    onboarding_clients = {
        device_id: MlKemOnboardingClient(device, onboarding_controller.identity_public_key)
        for device_id, device in devices.items()
    }
    for device in devices.values():
        device.subscribe_for_key_updates()
        distributor.register_device(device)

    emit("1. Devices complete authenticated ML-KEM onboarding")
    for client in onboarding_clients.values():
        onboarding_controller.register_device_identity(client)
        onboarding_controller.onboard(client)
    distributor.session_key_for = onboarding_controller.session_key_for
    distributor.acknowledgement_received = onboarding_controller.acknowledged
    emit("  device requests and controller responses are Ed25519-signed")
    emit("  ML-KEM shared secrets establish separate encrypted key-update channels\n")

    emit("2. Controller provisions initial encrypted branch credentials")
    motor_v1 = distributor.distribute_branch(MOTOR_BRANCH)
    oven_v1 = distributor.distribute_branch(OVEN_BRANCH)
    emit(f"  motor branch credential distributed: version={motor_v1.key_version}")
    emit(f"  oven branch credential distributed: version={oven_v1.key_version}\n")

    motor_publisher = SimulatedManagedPublisher(devices["motor-01"], MOTOR_BRANCH)
    oven_publisher = SimulatedManagedPublisher(devices["oven-01"], OVEN_BRANCH)
    gateway_motor = SimulatedManagedSubscriber(devices["gateway"], MOTOR_BRANCH)
    gateway_oven = SimulatedManagedSubscriber(devices["gateway"], OVEN_BRANCH)
    dashboard = SimulatedManagedSubscriber(devices["dashboard"], OVEN_BRANCH)
    vendor = SimulatedManagedSubscriber(devices["vendor"], MOTOR_BRANCH)
    for subscriber in (gateway_motor, gateway_oven, dashboard, vendor):
        subscriber.subscribe()

    emit("3. Simulated sensors publish encrypted telemetry")
    motor_publisher.publish(MOTOR_TOPIC, b'{"rpm":1500}')
    oven_publisher.publish(OVEN_TOPIC, b'{"celsius":182.4}')
    emit("  gateway decrypts both authorised branches")
    emit("  dashboard decrypts oven telemetry only")
    emit("  vendor decrypts motor telemetry only\n")

    emit("4. Revoke vendor access to the motor branch")
    controller.revoke("vendor", MOTOR_BRANCH)
    stale_status = controller.branch_status(MOTOR_BRANCH)
    emit(f"  motor branch marked stale={stale_status['stale']}; version remains={stale_status['key_version']}")
    emit("  next publish trigger: distribute fresh key only to motor-01 and gateway")
    motor_v2 = distributor.distribute_branch(MOTOR_BRANCH)
    emit(f"  motor branch rekey complete: version={motor_v2.key_version}\n")

    emit("5. Publish telemetry after rekeying")
    motor_publisher.publish(MOTOR_TOPIC, b'{"rpm":1600}')
    emit("  gateway decrypts the version-2 motor message")
    emit("  revoked vendor has only version-1 key; AES-GCM rejects the version-2 message\n")

    motor_status = controller.branch_status(MOTOR_BRANCH)
    oven_status = controller.branch_status(OVEN_BRANCH)
    emit("6. Final access result")
    emit(f"  gateway messages: {len(gateway_motor.received) + len(gateway_oven.received)}")
    emit(f"  dashboard messages: {len(dashboard.received)}")
    emit(f"  vendor messages: {len(vendor.received)} (only before revocation)")
    emit(f"  vendor rejected messages: {len(vendor.rejected)}")
    emit(f"  motor version: {motor_status['key_version']}; oven version unchanged: {oven_status['key_version']}")

    return SimulationReport(
        motor_key_version=int(motor_status["key_version"]),
        oven_key_version=int(oven_status["key_version"]),
        gateway_messages=len(gateway_motor.received) + len(gateway_oven.received),
        dashboard_messages=len(dashboard.received),
        vendor_messages=len(vendor.received),
        vendor_rejections=len(vendor.rejected),
        revoked_vendor_has_old_motor_key=devices["vendor"].credential_for(MOTOR_BRANCH).key_version == 1,
    )


def main() -> None:
    run_demo()


if __name__ == "__main__":
    main()

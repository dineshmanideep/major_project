"""Small repeatable performance evaluation for the software-only prototype."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from statistics import mean
from time import perf_counter_ns

from src.key_controller import KeyController
from src.lkh_tree import LkhTree
from src.message_envelope import decrypt_payload, encrypt_payload
from src.mqtt_prototype import InMemoryBroker
from src.pqc_onboarding import MlKemOnboardingClient, MlKemOnboardingController
from src.simulated_key_distribution import SimulatedDevice
from src.topic_keys import derive_topic_key


ROOT_KEY = b"r" * 32
BRANCH = "factory/line3/motor"
TOPIC = f"{BRANCH}/speed"


@dataclass(frozen=True)
class EvaluationMetrics:
    """Mean local execution times; not a hardware or network benchmark."""

    iterations: int
    kdf_us: float
    encrypt_us: float
    decrypt_us: float
    ml_kem_onboarding_us: float
    lazy_rekey_us: float
    lkh_rekey_us: float
    lkh_rekey_messages: int
    telemetry_envelope_bytes: int

    def as_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def _mean_us(operation, iterations: int) -> float:  # type: ignore[no-untyped-def]
    samples = []
    for _ in range(iterations):
        started = perf_counter_ns()
        operation()
        samples.append((perf_counter_ns() - started) / 1_000)
    return round(mean(samples), 2)


def measure(iterations: int = 100) -> EvaluationMetrics:
    """Collect local process timings using the implemented cryptographic code."""
    if iterations < 1:
        raise ValueError("iterations must be positive")

    kdf_us = _mean_us(lambda: derive_topic_key(ROOT_KEY, BRANCH, TOPIC), iterations)
    envelope = encrypt_payload(b'{"rpm":1500}', TOPIC, ROOT_KEY, BRANCH, "motor-01", 1, 1)
    encrypt_us = _mean_us(
        lambda: encrypt_payload(b'{"rpm":1500}', TOPIC, ROOT_KEY, BRANCH, "motor-01", 1, 1), iterations
    )
    decrypt_us = _mean_us(lambda: decrypt_payload(envelope, TOPIC, ROOT_KEY, BRANCH), iterations)

    def onboard() -> None:
        broker = InMemoryBroker()
        controller = MlKemOnboardingController(broker)
        device = SimulatedDevice("motor-01", broker)
        client = MlKemOnboardingClient(device, controller.identity_public_key)
        controller.register_device_identity(client)
        controller.onboard(client)

    def rekey() -> None:
        controller = KeyController()
        controller.create_branch(BRANCH, {"motor-01", "vendor"})
        controller.revoke("vendor", BRANCH)
        controller.credential_for("motor-01", BRANCH)

    def lkh_rekey() -> None:
        members = [f"dev_{i}" for i in range(8)]
        tree = LkhTree(BRANCH, members)
        tree.revoke_member("dev_0")

    tree8 = LkhTree(BRANCH, [f"dev_{i}" for i in range(8)])
    _, pkg8 = tree8.revoke_member("dev_0")

    return EvaluationMetrics(
        iterations=iterations,
        kdf_us=kdf_us,
        encrypt_us=encrypt_us,
        decrypt_us=decrypt_us,
        ml_kem_onboarding_us=_mean_us(onboard, iterations),
        lazy_rekey_us=_mean_us(rekey, iterations),
        lkh_rekey_us=_mean_us(lkh_rekey, iterations),
        lkh_rekey_messages=len(pkg8),
        telemetry_envelope_bytes=len(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")),
    )


def main() -> None:
    print(measure().as_json())


if __name__ == "__main__":
    main()

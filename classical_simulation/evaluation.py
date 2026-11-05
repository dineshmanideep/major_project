"""Performance evaluation and benchmarking for the Classical Cryptography simulation.

Measures:
- Classical X25519 ECDH Onboarding Handshake Time
- Topic Key Derivation Time (HKDF-Expand HMAC-SHA-256)
- AES-256-GCM Payload Encryption & Decryption Times
- Lazy Rekey State Transition Time
- LKH Binary Tree Rekeying Time and Message Scaling (N=8)
- Over-the-Wire JSON Envelope Byte Size

Provides a formal comparative analysis against the Post-Quantum (ML-KEM-512) implementation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from statistics import mean
from time import perf_counter_ns

from classical_simulation.classical_onboarding import (
    ClassicalOnboardingClient,
    ClassicalOnboardingController,
    SimulatedClassicalDevice,
)
from classical_simulation.key_controller import KeyController
from classical_simulation.lkh_tree import LkhTree
from classical_simulation.message_envelope import decrypt_payload, encrypt_payload
from classical_simulation.simulation_broker import SimulationBroker
from classical_simulation.topic_keys import derive_topic_key


ROOT_KEY = b"c" * 32
BRANCH = "factory/line3/motor"
TOPIC = f"{BRANCH}/speed"


@dataclass(frozen=True)
class ClassicalEvaluationMetrics:
    """Mean execution timings for the classical cryptography simulation."""

    iterations: int
    ecdh_onboarding_us: float
    kdf_us: float
    encrypt_us: float
    decrypt_us: float
    lazy_rekey_us: float
    lkh_rekey_us: float
    lkh_rekey_messages: int
    telemetry_envelope_bytes: int

    def as_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def _mean_us(operation, iterations: int) -> float:
    samples = []
    for _ in range(iterations):
        started = perf_counter_ns()
        operation()
        samples.append((perf_counter_ns() - started) / 1_000)
    return round(mean(samples), 2)


def measure_classical(iterations: int = 100) -> ClassicalEvaluationMetrics:
    """Collect microsecond timings for classical operations."""
    if iterations < 1:
        raise ValueError("iterations must be positive")

    # 1. KDF Derivation
    kdf_us = _mean_us(lambda: derive_topic_key(ROOT_KEY, BRANCH, TOPIC), iterations)

    # 2. AES-256-GCM Encrypt & Decrypt
    envelope = encrypt_payload(b'{"rpm":1500}', TOPIC, ROOT_KEY, BRANCH, "motor-01", 1, 1)
    encrypt_us = _mean_us(
        lambda: encrypt_payload(b'{"rpm":1500}', TOPIC, ROOT_KEY, BRANCH, "motor-01", 1, 1), iterations
    )
    decrypt_us = _mean_us(lambda: decrypt_payload(envelope, TOPIC, ROOT_KEY, BRANCH), iterations)

    # 3. Classical X25519 ECDH + Ed25519 Onboarding Handshake
    def onboard() -> None:
        ctrl = ClassicalOnboardingController()
        dev = SimulatedClassicalDevice("motor-01")
        cl = ClassicalOnboardingClient(dev, ctrl.identity_public_key)
        ctrl.register_device_identity("motor-01", cl.identity_public_key)
        req = cl.generate_request()
        resp = ctrl.process_onboarding_request(req)
        cl.accept_response(resp)

    ecdh_onboarding_us = _mean_us(onboard, iterations)

    # 4. Lazy Rekey Transition
    def lazy_rekey() -> None:
        controller = KeyController()
        controller.create_branch(BRANCH, {"motor-01", "vendor"})
        controller.revoke("vendor", BRANCH)
        controller.credential_for("motor-01", BRANCH)

    lazy_rekey_us = _mean_us(lazy_rekey, iterations)

    # 5. LKH Tree Rekeying for N=8
    def lkh_rekey_run() -> None:
        members = [f"dev_{i}" for i in range(8)]
        tree = LkhTree(BRANCH, members)
        tree.revoke_member("dev_0")

    lkh_rekey_us = _mean_us(lkh_rekey_run, iterations)

    tree8 = LkhTree(BRANCH, [f"dev_{i}" for i in range(8)])
    _, pkg8 = tree8.revoke_member("dev_0")

    return ClassicalEvaluationMetrics(
        iterations=iterations,
        ecdh_onboarding_us=ecdh_onboarding_us,
        kdf_us=kdf_us,
        encrypt_us=encrypt_us,
        decrypt_us=decrypt_us,
        lazy_rekey_us=lazy_rekey_us,
        lkh_rekey_us=lkh_rekey_us,
        lkh_rekey_messages=len(pkg8),
        telemetry_envelope_bytes=len(json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")),
    )


def print_comparison_table(metrics: ClassicalEvaluationMetrics) -> None:
    """Print comparative table between Classical (X25519) and Post-Quantum (ML-KEM-512)."""
    print("\n" + "=" * 92)
    print("      ARCHITECTURAL COMPARISON: CLASSICAL (X25519) vs POST-QUANTUM (ML-KEM-512)")
    print("=" * 92)
    print(f"{'Feature / Metric':<35} | {'Classical (This Folder)':<25} | {'Post-Quantum (ML-KEM-512)':<25}")
    print("-" * 92)
    print(f"{'Key Exchange Primitive':<35} | {'X25519 (Curve25519 ECDH)':<25} | {'ML-KEM-512 (Kyber)':<25}")
    print(f"{'Mathematical Hardness':<35} | {'ECDLP on Montgomery curve':<25} | {'Module-LWE (Lattice)':<25}")
    print(f"{'Identity Authentication':<35} | {'Ed25519 Signatures':<25} | {'Ed25519 Signatures':<25}")
    print(f"{'Device Public Key Size':<35} | {'32 bytes':<25} | {'800 bytes':<25}")
    print(f"{'Response / Ciphertext Size':<35} | {'32 bytes':<25} | {'768 bytes':<25}")
    print(f"{'Onboarding Handshake Latency':<35} | {f'{metrics.ecdh_onboarding_us:.2f} us':<25} | {'~442.49 us':<25}")
    print(f"{'Topic Key Derivation (HKDF)':<35} | {f'{metrics.kdf_us:.2f} us':<25} | {'~4.13 us':<25}")
    print(f"{'AES-256-GCM Encryption':<35} | {f'{metrics.encrypt_us:.2f} us':<25} | {'~6.92 us':<25}")
    print(f"{'AES-256-GCM Decryption':<35} | {f'{metrics.decrypt_us:.2f} us':<25} | {'~7.41 us':<25}")
    print(f"{'LKH Rekey Messages (N=8)':<35} | {f'{metrics.lkh_rekey_messages} messages':<25} | {'5 messages':<25}")
    print(f"{'Symmetric Telemetry Wire Size':<35} | {f'{metrics.telemetry_envelope_bytes} bytes':<25} | {'166 bytes':<25}")
    print(f"{'Forward Secrecy vs Quantum (HNDL)':<35} | {'VULNERABLE (Shor Alg.)':<25} | {'QUANTUM RESILIENT':<25}")
    print("=" * 92)


if __name__ == "__main__":
    m = measure_classical()
    print("\nRaw JSON Metrics:")
    print(m.as_json())
    print_comparison_table(m)


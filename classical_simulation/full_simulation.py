"""Full software simulation using Classical Cryptography (X25519 ECDH).

Demonstrates:
1. Device onboarding via Classical X25519 ECDH + Ed25519 mutual authentication.
2. Initial branch credential provisioning and LKH tree setup.
3. Multi-publisher sensor telemetry over untrusted broker relay.
4. Multi-subscriber authorized decryption across topic branches.
5. Lazy member revocation and confined branch isolation.
6. O(log N) LKH binary tree rekey broadcast on next publish.
7. Complete lockout of the revoked member on Version 2 telemetry.
"""

from __future__ import annotations

import json
from typing import Any

from classical_simulation.classical_onboarding import (
    ClassicalOnboardingClient,
    ClassicalOnboardingController,
    SimulatedClassicalDevice,
)
from classical_simulation.key_controller import BranchCredential, KeyController
from classical_simulation.lkh_tree import LkhClient, LkhError, LkhTree
from classical_simulation.message_envelope import (
    EnvelopeError,
    ReplayProtector,
    decrypt_payload,
    encrypt_payload,
    serialise_envelope,
)
from classical_simulation.simulation_broker import SimulationBroker


BRANCH_MOTOR = "factory/line3/motor"
BRANCH_OVEN = "factory/line3/oven"
TOPIC_MOTOR_SPEED = f"{BRANCH_MOTOR}/speed"
TOPIC_OVEN_TEMP = f"{BRANCH_OVEN}/temp"


def run_classical_simulation(verbose: bool = True) -> dict[str, Any]:
    """Execute the full classical end-to-end simulation scenario."""
    log = print if verbose else (lambda *args, **kwargs: None)

    log("=" * 80)
    log("  MP-1 SECURE MQTT SIMULATION (CLASSICAL X25519 ECDH VERSION)")
    log("  Objectives: Group E2EE + Topic KDF + Lazy Revocation + O(log N) LKH Rekeying")
    log("  Key Establishment: Classical X25519 (Curve25519) + Ed25519 Signatures")
    log("=" * 80)

    # Step 0: Setup Broker and Controllers
    broker = SimulationBroker()
    key_controller = KeyController()
    onboard_controller = ClassicalOnboardingController()

    key_controller.create_branch(BRANCH_MOTOR, {"motor-01", "gateway", "vendor"})
    key_controller.create_branch(BRANCH_OVEN, {"oven-01", "gateway", "dashboard"})

    # Step 1: Create Simulated Devices
    devices = {
        "motor-01": SimulatedClassicalDevice("motor-01"),
        "oven-01": SimulatedClassicalDevice("oven-01"),
        "gateway": SimulatedClassicalDevice("gateway"),
        "dashboard": SimulatedClassicalDevice("dashboard"),
        "vendor": SimulatedClassicalDevice("vendor"),
    }

    # Step 2: Classical X25519 Onboarding
    log("\n[STEP 1] Devices perform Classical X25519 ECDH Onboarding...")
    clients: dict[str, ClassicalOnboardingClient] = {}

    for dev_id, dev in devices.items():
        client = ClassicalOnboardingClient(dev, onboard_controller.identity_public_key)
        clients[dev_id] = client

        # Pre-register trusted device Ed25519 identity key
        onboard_controller.register_device_identity(dev_id, client.identity_public_key)

        # Device generates request
        req_bytes = client.generate_request()
        broker.publish(f"_bootstrap/{dev_id}/onboarding-request", req_bytes)

        # Controller processes request & returns signed response
        resp_bytes = onboard_controller.process_onboarding_request(req_bytes)
        broker.publish(f"_bootstrap/{dev_id}/onboarding-response", resp_bytes)

        # Device accepts response & completes ECDH exchange
        client.accept_response(resp_bytes)
        log(f"  -> {dev_id:10s} completed X25519 ECDH handshake; derived 32-byte distribution key.")

    # Step 3: Provision Initial Branch Credentials & LKH Trees
    log("\n[STEP 2] Controller provisions initial branch credentials and LKH trees...")
    lkh_trees: dict[str, LkhTree] = {
        BRANCH_MOTOR: LkhTree(BRANCH_MOTOR, ["motor-01", "gateway", "vendor"]),
        BRANCH_OVEN: LkhTree(BRANCH_OVEN, ["oven-01", "gateway", "dashboard"]),
    }

    lkh_clients: dict[tuple[str, str], LkhClient] = {}

    # Distribute motor branch credentials
    for dev_id in ["motor-01", "gateway", "vendor"]:
        cred = key_controller.credential_for(dev_id, BRANCH_MOTOR)
        update_bytes = onboard_controller.create_key_update(dev_id, BRANCH_MOTOR, cred.root_key, cred.key_version)
        broker.publish(f"_bootstrap/{dev_id}/branch-key-update", update_bytes)

        ack_bytes = clients[dev_id].process_key_update(update_bytes)
        broker.publish(f"_bootstrap/{dev_id}/branch-key-ack", ack_bytes)
        assert onboard_controller.process_key_ack(ack_bytes)

        # Provision LKH client path keys
        path_keys = lkh_trees[BRANCH_MOTOR].get_path_keys(dev_id)
        lkh_clients[(dev_id, BRANCH_MOTOR)] = LkhClient(dev_id, BRANCH_MOTOR, path_keys, cred.key_version)
        log(f"  -> Distributed {BRANCH_MOTOR} (v{cred.key_version}) to {dev_id} with LKH path keys.")

    # Distribute oven branch credentials
    for dev_id in ["oven-01", "gateway", "dashboard"]:
        cred = key_controller.credential_for(dev_id, BRANCH_OVEN)
        update_bytes = onboard_controller.create_key_update(dev_id, BRANCH_OVEN, cred.root_key, cred.key_version)
        broker.publish(f"_bootstrap/{dev_id}/branch-key-update", update_bytes)

        ack_bytes = clients[dev_id].process_key_update(update_bytes)
        broker.publish(f"_bootstrap/{dev_id}/branch-key-ack", ack_bytes)
        assert onboard_controller.process_key_ack(ack_bytes)

        path_keys = lkh_trees[BRANCH_OVEN].get_path_keys(dev_id)
        lkh_clients[(dev_id, BRANCH_OVEN)] = LkhClient(dev_id, BRANCH_OVEN, path_keys, cred.key_version)
        log(f"  -> Distributed {BRANCH_OVEN} (v{cred.key_version}) to {dev_id} with LKH path keys.")

    # Step 4: Publish Initial Telemetry
    log("\n[STEP 3] Sensor nodes publish initial encrypted telemetry (Version 1)...")
    replay_protectors = {
        "gateway": ReplayProtector(),
        "dashboard": ReplayProtector(),
        "vendor": ReplayProtector(),
    }

    decrypted_records: dict[str, list[dict[str, Any]]] = {
        "gateway": [],
        "dashboard": [],
        "vendor": [],
    }
    rejected_records: dict[str, list[str]] = {
        "gateway": [],
        "dashboard": [],
        "vendor": [],
    }

    # Motor Telemetry (v1)
    motor_cred = devices["motor-01"].credential_for(BRANCH_MOTOR)
    motor_payload = b'{"rpm": 1500, "status": "nominal"}'
    motor_env = encrypt_payload(
        motor_payload, TOPIC_MOTOR_SPEED, motor_cred.root_key, BRANCH_MOTOR, "motor-01", motor_cred.key_version, sequence=1
    )
    motor_env_bytes = serialise_envelope(motor_env)
    broker.publish(TOPIC_MOTOR_SPEED, motor_env_bytes)
    log(f"  [PUBLISH] motor-01 -> {TOPIC_MOTOR_SPEED} (v1, seq 1, {len(motor_env_bytes)} bytes)")

    # Oven Telemetry (v1)
    oven_cred = devices["oven-01"].credential_for(BRANCH_OVEN)
    oven_payload = b'{"temp_c": 182.5, "status": "nominal"}'
    oven_env = encrypt_payload(
        oven_payload, TOPIC_OVEN_TEMP, oven_cred.root_key, BRANCH_OVEN, "oven-01", oven_cred.key_version, sequence=1
    )
    oven_env_bytes = serialise_envelope(oven_env)
    broker.publish(TOPIC_OVEN_TEMP, oven_env_bytes)
    log(f"  [PUBLISH] oven-01  -> {TOPIC_OVEN_TEMP} (v1, seq 1, {len(oven_env_bytes)} bytes)")

    # Process subscribers for v1
    # Gateway (subscribed to both)
    for env, top, branch in [(motor_env, TOPIC_MOTOR_SPEED, BRANCH_MOTOR), (oven_env, TOPIC_OVEN_TEMP, BRANCH_OVEN)]:
        k = devices["gateway"].credential_for(branch).root_key
        pt = decrypt_payload(env, top, k, branch, replay_protectors["gateway"])
        decrypted_records["gateway"].append({"topic": top, "payload": pt.decode()})
        log(f"  [DECRYPT] gateway   successfully decrypted: {top} -> {pt.decode()}")

    # Dashboard (subscribed to oven only)
    oven_k = devices["dashboard"].credential_for(BRANCH_OVEN).root_key
    pt = decrypt_payload(oven_env, TOPIC_OVEN_TEMP, oven_k, BRANCH_OVEN, replay_protectors["dashboard"])
    decrypted_records["dashboard"].append({"topic": TOPIC_OVEN_TEMP, "payload": pt.decode()})
    log(f"  [DECRYPT] dashboard successfully decrypted: {TOPIC_OVEN_TEMP} -> {pt.decode()}")

    # Vendor (subscribed to motor only)
    motor_k = devices["vendor"].credential_for(BRANCH_MOTOR).root_key
    pt = decrypt_payload(motor_env, TOPIC_MOTOR_SPEED, motor_k, BRANCH_MOTOR, replay_protectors["vendor"])
    decrypted_records["vendor"].append({"topic": TOPIC_MOTOR_SPEED, "payload": pt.decode()})
    log(f"  [DECRYPT] vendor    successfully decrypted: {TOPIC_MOTOR_SPEED} -> {pt.decode()}")

    # Step 5: Lazy Revocation of Vendor from Motor Branch
    log("\n[STEP 4] Revoking 'vendor' from 'factory/line3/motor'...")
    key_controller.revoke("vendor", BRANCH_MOTOR)
    log(f"  -> Branch '{BRANCH_MOTOR}' marked stale (O(1) operation; zero immediate rekey traffic).")
    log(f"  -> Sibling branch '{BRANCH_OVEN}' remains stale=False (confined rekeying property).")

    # Step 6: Next Publish Triggers O(log N) LKH Rekeying
    log("\n[STEP 5] Next publish triggers LKH rekey rotation before payload transmission...")
    fresh_motor_cred = key_controller.credential_for("motor-01", BRANCH_MOTOR)
    assert fresh_motor_cred.key_version == 2
    log(f"  -> Key Controller rotated '{BRANCH_MOTOR}' to Version 2.")

    # LKH Tree revocation on motor branch
    tree = lkh_trees[BRANCH_MOTOR]
    new_root, rekey_messages = tree.revoke_member("vendor")
    rekey_pkg_bytes = tree.serialize_rekey_package(rekey_messages)
    log(f"  -> LKH Binary Tree broadcast package generated: {len(rekey_messages)} messages (O(log N)).")
    broker.publish(f"_bootstrap/{BRANCH_MOTOR}/lkh-rekey", rekey_pkg_bytes)

    # Active members update LKH state
    for active_dev in ["motor-01", "gateway"]:
        lkh_cl = lkh_clients[(active_dev, BRANCH_MOTOR)]
        updated_root = lkh_cl.process_rekey_package(rekey_pkg_bytes)
        devices[active_dev].credentials[BRANCH_MOTOR] = BranchCredential(BRANCH_MOTOR, updated_root, fresh_motor_cred.key_version)
        log(f"  -> Active member '{active_dev}' updated LKH root key to Version 2.")

    # Revoked vendor attempts to process rekey package
    vendor_lkh = lkh_clients[("vendor", BRANCH_MOTOR)]
    try:
        vendor_lkh.process_rekey_package(rekey_pkg_bytes)
    except LkhError as exc:
        log(f"  -> Revoked member 'vendor' rejected by LKH package: {exc}")

    # Step 7: Publish Telemetry Post-Rekeying (Version 2)
    log("\n[STEP 6] Publishing telemetry under Version 2...")
    motor_payload_v2 = b'{"rpm": 1650, "status": "accelerating"}'
    motor_env_v2 = encrypt_payload(
        motor_payload_v2, TOPIC_MOTOR_SPEED, devices["motor-01"].credential_for(BRANCH_MOTOR).root_key,
        BRANCH_MOTOR, "motor-01", 2, sequence=2
    )
    motor_env_v2_bytes = serialise_envelope(motor_env_v2)
    broker.publish(TOPIC_MOTOR_SPEED, motor_env_v2_bytes)
    log(f"  [PUBLISH] motor-01 -> {TOPIC_MOTOR_SPEED} (v2, seq 2, {len(motor_env_v2_bytes)} bytes)")

    # Gateway decrypts v2
    gw_k_v2 = devices["gateway"].credential_for(BRANCH_MOTOR).root_key
    pt_v2 = decrypt_payload(motor_env_v2, TOPIC_MOTOR_SPEED, gw_k_v2, BRANCH_MOTOR, replay_protectors["gateway"])
    decrypted_records["gateway"].append({"topic": TOPIC_MOTOR_SPEED, "payload": pt_v2.decode()})
    log(f"  [DECRYPT] gateway   successfully decrypted Version 2 payload: {pt_v2.decode()}")

    # Revoked vendor attempts to decrypt v2 with its stale v1 key
    vendor_stale_k = devices["vendor"].credential_for(BRANCH_MOTOR).root_key
    try:
        decrypt_payload(motor_env_v2, TOPIC_MOTOR_SPEED, vendor_stale_k, BRANCH_MOTOR, replay_protectors["vendor"])
    except EnvelopeError as exc:
        rejected_records["vendor"].append(str(exc))
        log(f"  [REJECTED] vendor    failed to decrypt Version 2 payload: {exc}")

    # Step 8: Final Summary
    log("\n" + "=" * 80)
    log("  FINAL SECURITY & ACCESS AUDIT SUMMARY")
    log("=" * 80)
    log(f"  Gateway total decrypted messages:  {len(decrypted_records['gateway'])} (v1 motor, v1 oven, v2 motor)")
    log(f"  Dashboard total decrypted messages:{len(decrypted_records['dashboard'])} (v1 oven only)")
    log(f"  Vendor total decrypted messages:   {len(decrypted_records['vendor'])} (v1 motor only)")
    log(f"  Vendor total rejected messages:    {len(rejected_records['vendor'])} (v2 motor rejected post-revocation)")
    log(f"  Total bytes relayed by broker:     {broker.total_bytes_relayed} bytes across {broker.total_messages_relayed} messages")
    log("=" * 80 + "\n")

    return {
        "decrypted_records": decrypted_records,
        "rejected_records": rejected_records,
        "total_relayed_messages": broker.total_messages_relayed,
        "total_relayed_bytes": broker.total_bytes_relayed,
        "lkh_rekey_messages_count": len(rekey_messages),
    }


if __name__ == "__main__":
    run_classical_simulation(verbose=True)

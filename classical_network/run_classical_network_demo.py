"""End-to-End Multi-Process Network Orchestrator for MP-1 Secure MQTT (Classical Baseline).

Demonstrates the complete classical X25519 ECDH secured, topic-hierarchical,
group-encrypted industrial telemetry pipeline over real TCP network sockets:
1. Runs an untrusted MQTT relay broker on TCP.
2. Performs mutual Ed25519-signed classical X25519 ECDH onboarding over TCP.
3. Provisions initial LKH tree credentials and verifies encrypted ACKs over TCP.
4. Publishes AES-256-GCM telemetry with topic-bound Authenticated Additional Data (AAD).
5. Executes O(log N) LKH rekey broadcast on member revocation.
6. Verifies that remaining nodes update and continue decrypting,
   while the revoked client is permanently excluded.
"""

from __future__ import annotations

import asyncio
import logging
import time

from classical_network.broker_service import ClassicalMqttBroker
from classical_network.config import (
    DEFAULT_BROKER_HOST,
    DEFAULT_BROKER_PORT,
    MOTOR_BRANCH,
    MOTOR_TELEMETRY_TOPIC,
    OVEN_BRANCH,
    OVEN_TELEMETRY_TOPIC,
)
from classical_network.controller_service import ClassicalNetworkKeyController
from classical_network.publisher_node import ClassicalNetworkPublisherNode
from classical_network.subscriber_node import ClassicalNetworkSubscriberNode


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ClassicalNetworkDemo")


async def async_run_demo(port: int = DEFAULT_BROKER_PORT) -> dict[str, int]:
    logger.info("================================================================================")
    logger.info("   MP-1 SECURE MQTT: CLASSICAL TCP NETWORK DEMONSTRATION")
    logger.info("   Classical X25519 ECDH + Ed25519 Signatures + Topic KDF + O(log N) LKH Rekeying")
    logger.info("================================================================================")

    # 1. Start Broker
    logger.info("STEP 1: Starting untrusted TCP MQTT Broker on port %d...", port)
    broker = ClassicalMqttBroker(host=DEFAULT_BROKER_HOST, port=port)
    await broker.start()

    # 2. Start Key Controller
    logger.info("STEP 2: Initializing Classical Key Controller service...")
    controller = ClassicalNetworkKeyController(host=DEFAULT_BROKER_HOST, port=port)

    # 3. Create Publishers and Subscribers
    logger.info("STEP 3: Creating Network Nodes...")
    motor_pub = ClassicalNetworkPublisherNode(
        "motor-01", MOTOR_BRANCH, MOTOR_TELEMETRY_TOPIC, controller.identity_public_key, port=port
    )
    oven_pub = ClassicalNetworkPublisherNode(
        "oven-01", OVEN_BRANCH, OVEN_TELEMETRY_TOPIC, controller.identity_public_key, port=port
    )

    gateway_sub = ClassicalNetworkSubscriberNode(
        "gateway", [MOTOR_BRANCH, OVEN_BRANCH], controller.identity_public_key, port=port
    )
    dashboard_sub = ClassicalNetworkSubscriberNode(
        "dashboard", OVEN_BRANCH, controller.identity_public_key, port=port
    )
    vendor_sub = ClassicalNetworkSubscriberNode(
        "vendor", MOTOR_BRANCH, controller.identity_public_key, port=port
    )

    nodes = [motor_pub, oven_pub, gateway_sub, dashboard_sub, vendor_sub]

    # Pre-register device identities on Controller
    for node in nodes:
        controller.register_device_identity(node.device_id, node.identity_public_key)

    # Connect controller and all nodes over TCP
    controller.connect()
    await asyncio.sleep(0.3)

    for node in nodes:
        node.connect()
        await asyncio.sleep(0.1)

    # Allow Classical X25519 onboarding exchanges to complete
    logger.info("STEP 4: Executing Classical X25519 ECDH Onboarding over TCP...")
    await asyncio.sleep(0.8)

    # Distribute initial LKH credentials
    logger.info("STEP 5: Provisioning initial branch credentials & LKH trees over TCP...")
    controller.distribute_branch_credentials(MOTOR_BRANCH)
    controller.distribute_branch_credentials(OVEN_BRANCH)
    await asyncio.sleep(0.8)

    # Verify initial telemetry publish
    logger.info("STEP 6: Publishing initial encrypted telemetry (Version 1)...")
    motor_pub.publish_telemetry(b'{"rpm": 1500, "status": "nominal"}')
    oven_pub.publish_telemetry(b'{"celsius": 182.5, "status": "nominal"}')
    await asyncio.sleep(0.8)

    logger.info("--- Initial Telemetry Verification ---")
    logger.info("Gateway received: %d messages", len(gateway_sub.received_messages))
    logger.info("Dashboard received: %d messages", len(dashboard_sub.received_messages))
    logger.info("Vendor received: %d messages", len(vendor_sub.received_messages))

    # Revoke vendor using O(log N) LKH
    logger.info("STEP 7: Revoking vendor from '%s' via O(log N) LKH Rekeying...", MOTOR_BRANCH)
    controller.revoke_and_rekey_lkh(MOTOR_BRANCH, "vendor")
    await asyncio.sleep(0.8)

    # Publish telemetry after rekeying
    logger.info("STEP 8: Publishing telemetry post-rekeying (Version 2)...")
    motor_pub.publish_telemetry(b'{"rpm": 1650, "status": "accelerating"}')
    await asyncio.sleep(0.8)

    logger.info("================================================================================")
    logger.info("   FINAL ACCESS & SECURITY AUDIT SUMMARY (CLASSICAL NETWORK)")
    logger.info("================================================================================")
    logger.info("Gateway total decrypted messages: %d (Both branches, v1 and v2)", len(gateway_sub.received_messages))
    logger.info("Dashboard total decrypted messages: %d (Oven only)", len(dashboard_sub.received_messages))
    logger.info("Vendor total decrypted messages: %d (Motor v1 only before revocation)", len(vendor_sub.received_messages))
    logger.info("Vendor rejected messages: %d (Rejected v2 post-revocation)", len(vendor_sub.rejected_messages))

    results = {
        "gateway_messages": len(gateway_sub.received_messages),
        "dashboard_messages": len(dashboard_sub.received_messages),
        "vendor_messages": len(vendor_sub.received_messages),
        "vendor_rejections": len(vendor_sub.rejected_messages),
    }

    # Teardown
    for node in nodes:
        node.disconnect()
    controller.disconnect()
    await broker.stop()

    return results


def main() -> None:
    asyncio.run(async_run_demo())


if __name__ == "__main__":
    main()


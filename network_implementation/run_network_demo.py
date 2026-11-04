"""End-to-End Multi-Process Network Orchestrator for MP-1 Secure MQTT.

Demonstrates the complete post-quantum secured, topic-hierarchical,
group-encrypted industrial telemetry pipeline over real TCP network sockets:
1. Runs an untrusted MQTT relay broker on TCP.
2. Performs mutual Ed25519-signed ML-KEM-512 onboarding over TCP.
3. Provisions initial LKH tree credentials and verifies encrypted ACKs over TCP.
4. Publishes AES-256-GCM telemetry with topic-bound AAD.
5. Executes O(log N) LKH rekey broadcast on member revocation.
6. Verifies that remaining nodes update and continue decrypting,
   while the revoked client is permanently excluded.
"""

from __future__ import annotations

import asyncio
import logging
import time

from network_implementation.broker_service import MiniMqttBroker
from network_implementation.config import (
    DEFAULT_BROKER_HOST,
    DEFAULT_BROKER_PORT,
    MOTOR_BRANCH,
    MOTOR_TELEMETRY_TOPIC,
    OVEN_BRANCH,
    OVEN_TELEMETRY_TOPIC,
)
from network_implementation.controller_service import NetworkKeyController
from network_implementation.publisher_node import NetworkPublisherNode
from network_implementation.subscriber_node import NetworkSubscriberNode


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("NetworkDemo")


async def async_run_demo(port: int = DEFAULT_BROKER_PORT) -> dict[str, int]:
    logger.info("================================================================================")
    logger.info("   MP-1 SECURE MQTT: MULTI-PROCESS TCP NETWORK DEMONSTRATION")
    logger.info("   Post-Quantum ML-KEM-512 + Topic Hierarchy + O(log N) LKH Rekeying")
    logger.info("================================================================================")

    # 1. Start Broker
    logger.info("STEP 1: Starting untrusted TCP MQTT Broker...")
    broker = MiniMqttBroker(host=DEFAULT_BROKER_HOST, port=port)
    await broker.start()

    # 2. Start Key Controller
    logger.info("STEP 2: Initializing Key Controller service...")
    controller = NetworkKeyController(host=DEFAULT_BROKER_HOST, port=port)

    # 3. Create Publishers and Subscribers
    logger.info("STEP 3: Creating Network Nodes...")
    motor_pub = NetworkPublisherNode(
        "motor-01", MOTOR_BRANCH, MOTOR_TELEMETRY_TOPIC, controller.identity_public_key, port=port
    )
    oven_pub = NetworkPublisherNode(
        "oven-01", OVEN_BRANCH, OVEN_TELEMETRY_TOPIC, controller.identity_public_key, port=port
    )

    gateway_sub = NetworkSubscriberNode(
        "gateway", [MOTOR_BRANCH, OVEN_BRANCH], controller.identity_public_key, port=port
    )
    dashboard_sub = NetworkSubscriberNode(
        "dashboard", OVEN_BRANCH, controller.identity_public_key, port=port
    )
    vendor_sub = NetworkSubscriberNode(
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

    # Allow ML-KEM-512 onboarding exchanges to complete
    logger.info("STEP 4: Executing Post-Quantum ML-KEM-512 Onboarding over TCP...")
    await asyncio.sleep(0.8)

    # Distribute initial LKH credentials
    logger.info("STEP 5: Provisioning initial branch credentials & LKH trees over TCP...")
    controller.distribute_branch_credentials(MOTOR_BRANCH)
    controller.distribute_branch_credentials(OVEN_BRANCH)
    await asyncio.sleep(0.8)

    # Verify initial telemetry publish
    logger.info("STEP 6: Publishing initial encrypted telemetry...")
    motor_pub.publish_telemetry(b'{"rpm": 1500, "status": "nominal"}')
    oven_pub.publish_telemetry(b'{"celsius": 185.2, "status": "nominal"}')
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
    logger.info("   FINAL ACCESS & SECURITY AUDIT SUMMARY")
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

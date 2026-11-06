"""Network deployment configuration for the Classical MP-1 secure MQTT testbed.

Contains broker connection endpoints, topic prefixes, managed branches,
and identity configuration for classical X25519 ECDH + Ed25519 operation.
"""

from __future__ import annotations

import os

# Classical Network Endpoints (Port 18885 avoids conflict with PQC port 18883)
DEFAULT_BROKER_HOST = os.environ.get("MP1_CLASSICAL_BROKER_HOST", "127.0.0.1")
DEFAULT_BROKER_PORT = int(os.environ.get("MP1_CLASSICAL_BROKER_PORT", "18885"))

# Topic prefixes
BOOTSTRAP_PREFIX = "_bootstrap"
REKEY_TOPIC_SUFFIX = "lkh-rekey"

# Managed topic branches and default devices
MOTOR_BRANCH = "factory/line3/motor"
OVEN_BRANCH = "factory/line3/oven"

MOTOR_TELEMETRY_TOPIC = f"{MOTOR_BRANCH}/speed"
OVEN_TELEMETRY_TOPIC = f"{OVEN_BRANCH}/temp"

# Device roles & branch membership
BRANCH_MEMBERS = {
    MOTOR_BRANCH: ["motor-01", "gateway", "vendor"],
    OVEN_BRANCH: ["oven-01", "gateway", "dashboard"],
}


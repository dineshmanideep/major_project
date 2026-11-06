"""Automated test suite for the Classical Multi-Process TCP Network Implementation."""

import asyncio
import unittest

from classical_network.run_classical_network_demo import async_run_demo


class ClassicalNetworkImplementationTests(unittest.TestCase):
    def test_end_to_end_classical_network_execution_over_tcp(self):
        # Run demo on dynamic test port 18896
        results = asyncio.run(async_run_demo(port=18896))

        self.assertEqual(results["gateway_messages"], 3, "Gateway should decrypt all 3 valid telemetry messages")
        self.assertEqual(results["dashboard_messages"], 1, "Dashboard should decrypt 1 oven message")
        self.assertEqual(results["vendor_messages"], 1, "Vendor should decrypt 1 motor message before revocation")
        self.assertEqual(results["vendor_rejections"], 1, "Vendor should reject 1 motor message after revocation")


if __name__ == "__main__":
    unittest.main()


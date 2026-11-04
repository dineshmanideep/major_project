"""Automated test suite for the multi-process TCP network implementation."""

import asyncio
import unittest

from network_implementation.run_network_demo import async_run_demo


class NetworkImplementationTests(unittest.TestCase):
    def test_end_to_end_network_execution_over_tcp(self):
        # Run demo on dynamic test port 18895
        results = asyncio.run(async_run_demo(port=18895))

        self.assertEqual(results["gateway_messages"], 3, "Gateway should decrypt all 3 valid telemetry messages")
        self.assertEqual(results["dashboard_messages"], 1, "Dashboard should decrypt 1 oven message")
        self.assertEqual(results["vendor_messages"], 1, "Vendor should decrypt 1 motor message before revocation")
        self.assertEqual(results["vendor_rejections"], 1, "Vendor should reject 1 motor message after revocation")


if __name__ == "__main__":
    unittest.main()


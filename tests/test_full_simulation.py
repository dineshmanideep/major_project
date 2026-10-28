"""Checks the complete software-only demonstration scenario."""

import unittest

from src.full_simulation import run_demo


class FullSimulationTests(unittest.TestCase):
    def test_demo_covers_branch_access_revocation_and_rekeying(self):
        lines: list[str] = []
        report = run_demo(lines.append)

        self.assertEqual(report.motor_key_version, 2)
        self.assertEqual(report.oven_key_version, 1)
        self.assertEqual(report.gateway_messages, 3)
        self.assertEqual(report.dashboard_messages, 1)
        self.assertEqual(report.vendor_messages, 1)
        self.assertEqual(report.vendor_rejections, 1)
        self.assertTrue(report.revoked_vendor_has_old_motor_key)
        self.assertTrue(any("Revoke vendor" in line for line in lines))

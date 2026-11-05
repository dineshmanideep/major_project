"""Integration test for the full classical software simulation scenario."""

from __future__ import annotations

import unittest

from classical_simulation.full_simulation import run_classical_simulation


class FullSimulationTests(unittest.TestCase):
    def test_classical_simulation_runs_to_completion(self) -> None:
        result = run_classical_simulation(verbose=False)

        self.assertIn("decrypted_records", result)
        self.assertIn("rejected_records", result)

        # Gateway receives 3 messages (v1 motor, v1 oven, v2 motor)
        self.assertEqual(len(result["decrypted_records"]["gateway"]), 3)

        # Dashboard receives 1 message (v1 oven)
        self.assertEqual(len(result["decrypted_records"]["dashboard"]), 1)

        # Vendor receives 1 message before revocation
        self.assertEqual(len(result["decrypted_records"]["vendor"]), 1)

        # Vendor rejects 1 message post-revocation
        self.assertEqual(len(result["rejected_records"]["vendor"]), 1)

        # Broker successfully relayed all messages
        self.assertGreater(result["total_relayed_messages"], 10)
        self.assertGreater(result["total_relayed_bytes"], 1000)


if __name__ == "__main__":
    unittest.main()


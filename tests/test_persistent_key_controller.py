"""Persistence and audit coverage for the simulated Key Controller."""

from datetime import datetime, timezone
import tempfile
import unittest

from src.persistent_key_controller import PersistentKeyController


BRANCH = "factory/line3/motor"


class PersistentKeyControllerTests(unittest.TestCase):
    def test_branch_membership_and_rekey_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            db = f"{directory}/controller.sqlite3"
            first = PersistentKeyController(db)
            first.create_branch(BRANCH, {"motor-01", "vendor"}, b"m" * 32)
            first.revoke("vendor", BRANCH, now=datetime(2026, 1, 1, tzinfo=timezone.utc))
            rotated = first.credential_for("motor-01", BRANCH)
            first.close()

            restarted = PersistentKeyController(db)
            status = restarted.branch_status(BRANCH)
            restored = restarted.credential_for("motor-01", BRANCH)
            self.assertEqual(status["members"], frozenset({"motor-01"}))
            self.assertFalse(status["stale"])
            self.assertEqual(restored, rotated)
            self.assertIn("branch_rekeyed", [event["event"] for event in restarted.audit_events()])
            restarted.close()

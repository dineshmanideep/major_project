"""Tests for the Key Controller and lazy revocation state machine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from classical_simulation.key_controller import KeyController, KeyControllerError


class KeyControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = KeyController(max_staleness=timedelta(minutes=10))
        self.branch = "factory/line3/motor"
        self.sibling_branch = "factory/line3/oven"
        self.controller.create_branch(self.branch, {"motor-01", "gateway", "vendor"})
        self.controller.create_branch(self.sibling_branch, {"oven-01", "gateway", "dashboard"})

    def test_revocation_is_lazy_then_rekeys_before_next_publish(self) -> None:
        t0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.controller.revoke("vendor", self.branch, now=t0)

        # Branch marked stale, but version remains 1 until next request
        self.assertTrue(self.controller.is_stale(self.branch))
        self.assertNotIn("vendor", self.controller.branch_members(self.branch))

        # Next publish triggers rotation
        t1 = t0 + timedelta(minutes=1)
        cred = self.controller.credential_for("motor-01", self.branch, now=t1)
        self.assertEqual(cred.key_version, 2)
        self.assertFalse(self.controller.is_stale(self.branch))

    def test_rekey_is_confined_to_revoked_branch(self) -> None:
        self.controller.revoke("vendor", self.branch)
        cred_motor = self.controller.credential_for("motor-01", self.branch)
        cred_oven = self.controller.credential_for("oven-01", self.sibling_branch)

        # Motor branch is rotated to v2; oven branch remains at v1
        self.assertEqual(cred_motor.key_version, 2)
        self.assertEqual(cred_oven.key_version, 1)

    def test_idle_stale_branch_rekeys_at_deadline(self) -> None:
        t0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.controller.revoke("vendor", self.branch, now=t0)

        t_before = t0 + timedelta(minutes=9)
        self.assertEqual(self.controller.rekey_expired(now=t_before), [])

        t_after = t0 + timedelta(minutes=11)
        rekeyed = self.controller.rekey_expired(now=t_after)
        self.assertEqual(rekeyed, [self.branch])
        self.assertFalse(self.controller.is_stale(self.branch))


if __name__ == "__main__":
    unittest.main()


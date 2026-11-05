"""Tests for Logical Key Hierarchy (LKH) binary key tree."""

from __future__ import annotations

import unittest

from classical_simulation.lkh_tree import LkhClient, LkhError, LkhTree


class LkhTreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.branch = "factory/line3/motor"
        self.members = [f"dev_{i}" for i in range(8)]
        self.tree = LkhTree(self.branch, self.members)

    def test_lkh_tree_construction_and_path_keys(self) -> None:
        self.assertEqual(len(self.tree.members), 8)
        self.assertEqual(self.tree.key_version, 1)

        for m in self.members:
            path_keys = self.tree.get_path_keys(m)
            self.assertIn(1, path_keys)  # Root key
            self.assertEqual(len(path_keys[1]), 32)

    def test_lkh_rekey_logarithmic_package_size(self) -> None:
        # For N=8, tree height is ceil(log2 8) = 3.
        # Max ciphertexts: 2 * 3 - 1 = 5
        new_root, rekey_messages = self.tree.revoke_member("dev_0")
        self.assertEqual(self.tree.key_version, 2)
        self.assertLessEqual(len(rekey_messages), 5)
        self.assertEqual(len(new_root), 32)

    def test_lkh_rekey_remaining_members_update_successfully(self) -> None:
        clients = {
            m: LkhClient(m, self.branch, self.tree.get_path_keys(m), key_version=1)
            for m in self.members
        }

        new_root, rekey_messages = self.tree.revoke_member("dev_0")
        package_bytes = self.tree.serialize_rekey_package(rekey_messages)

        # Remaining 7 members must successfully update to new root key
        for m in self.members[1:]:
            updated_root = clients[m].process_rekey_package(package_bytes)
            self.assertEqual(updated_root, new_root)
            self.assertEqual(clients[m].key_version, 2)

    def test_lkh_revoked_member_cannot_decrypt(self) -> None:
        dev0_client = LkhClient("dev_0", self.branch, self.tree.get_path_keys("dev_0"), key_version=1)
        _, rekey_messages = self.tree.revoke_member("dev_0")
        package_bytes = self.tree.serialize_rekey_package(rekey_messages)

        with self.assertRaises(LkhError):
            dev0_client.process_rekey_package(package_bytes)


if __name__ == "__main__":
    unittest.main()


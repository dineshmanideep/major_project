"""Unit tests for Logical Key Hierarchy (LKH) O(log N) tree-based rekeying."""

import math
import unittest

from src.lkh_tree import (
    LkhClient,
    LkhError,
    LkhTree,
    parse_rekey_package,
    serialise_rekey_package,
)


BRANCH = "factory/line3/motor"


class LkhTreeTests(unittest.TestCase):
    def test_lkh_tree_construction_and_path_keys(self):
        members = ["dev1", "dev2", "dev3", "dev4"]
        tree = LkhTree(BRANCH, members)
        self.assertEqual(tree.members, set(members))
        self.assertEqual(tree.key_version, 1)

        root_key = tree.get_root_key()
        self.assertEqual(len(root_key), 32)

        for m in members:
            path_keys = tree.get_path_keys(m)
            # For 4 members in balanced binary tree, depth is 2 (3 nodes on path: leaf, parent, root)
            self.assertEqual(len(path_keys), 3)
            self.assertIn(1, path_keys)
            self.assertEqual(path_keys[1], root_key)

    def test_lkh_rekey_logarithmic_package_size(self):
        for n in [4, 8, 16, 32]:
            members = [f"dev_{i}" for i in range(n)]
            tree = LkhTree(BRANCH, members)
            new_root, pkg = tree.revoke_member("dev_0")

            max_allowed = 2 * math.ceil(math.log2(n))
            self.assertLessEqual(len(pkg), max_allowed, f"LKH rekey messages {len(pkg)} exceeded bound {max_allowed} for N={n}")
            self.assertEqual(len(new_root), 32)

    def test_lkh_rekey_remaining_members_update_successfully(self):
        members = ["m0", "m1", "m2", "m3", "m4", "m5", "m6", "m7"]
        tree = LkhTree(BRANCH, members)
        clients = {m: LkhClient(m, BRANCH, tree.get_path_keys(m)) for m in members}

        orig_root = tree.get_root_key()
        for c in clients.values():
            self.assertEqual(c.root_key, orig_root)

        # Revoke m0
        new_root, pkg = tree.revoke_member("m0")
        self.assertNotEqual(new_root, orig_root)

        # All remaining members m1..m7 must update to new_root
        for m in members[1:]:
            res = clients[m].process_rekey_package(pkg, 2)
            self.assertEqual(res, new_root)
            self.assertEqual(clients[m].root_key, new_root)
            self.assertEqual(clients[m].key_version, 2)

    def test_lkh_revoked_member_cannot_decrypt(self):
        members = ["m0", "m1", "m2", "m3"]
        tree = LkhTree(BRANCH, members)
        clients = {m: LkhClient(m, BRANCH, tree.get_path_keys(m)) for m in members}

        new_root, pkg = tree.revoke_member("m0")

        with self.assertRaises(LkhError):
            clients["m0"].process_rekey_package(pkg, 2)

        # Revoked member still holds only old root key
        self.assertNotEqual(clients["m0"].root_key, new_root)

    def test_lkh_multiple_sequential_revocations(self):
        members = ["dev0", "dev1", "dev2", "dev3", "dev4"]
        tree = LkhTree(BRANCH, members)
        clients = {m: LkhClient(m, BRANCH, tree.get_path_keys(m)) for m in members}

        # Step 1: Revoke dev0
        root_v2, pkg_v2 = tree.revoke_member("dev0")
        for m in ["dev1", "dev2", "dev3", "dev4"]:
            self.assertEqual(clients[m].process_rekey_package(pkg_v2, 2), root_v2)

        # Step 2: Revoke dev1
        root_v3, pkg_v3 = tree.revoke_member("dev1")
        for m in ["dev2", "dev3", "dev4"]:
            self.assertEqual(clients[m].process_rekey_package(pkg_v3, 3), root_v3)

        # Both dev0 and dev1 fail
        with self.assertRaises(LkhError):
            clients["dev0"].process_rekey_package(pkg_v3, 3)
        with self.assertRaises(LkhError):
            clients["dev1"].process_rekey_package(pkg_v3, 3)

    def test_lkh_tampered_package_is_rejected(self):
        members = ["dev0", "dev1", "dev2", "dev3"]
        tree = LkhTree(BRANCH, members)
        client = LkhClient("dev1", BRANCH, tree.get_path_keys("dev1"))

        _, pkg = tree.revoke_member("dev0")

        # Tamper with the ciphertext of first item
        tampered_pkg = [dict(item) for item in pkg]
        tampered_pkg[0]["ciphertext"] = "YWJjZA=="  # corrupted base64

        with self.assertRaises(LkhError):
            client.process_rekey_package(tampered_pkg, 2)

    def test_lkh_serialization_round_trip(self):
        members = ["dev0", "dev1", "dev2", "dev3"]
        tree = LkhTree(BRANCH, members)
        _, pkg = tree.revoke_member("dev0")

        serialized = serialise_rekey_package(pkg)
        self.assertIsInstance(serialized, bytes)

        parsed = parse_rekey_package(serialized)
        self.assertEqual(parsed, pkg)


if __name__ == "__main__":
    unittest.main()


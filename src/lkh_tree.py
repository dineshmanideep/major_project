"""Logical Key Hierarchy (LKH) tree implementation for O(log N) group rekeying.

This module implements a balanced binary key tree for topic branches.
When a group member is revoked, only the keys along the path from the revoked
leaf to the root are rotated. The Key Controller bundles O(log N) encrypted
key updates into a single broadcast package, enabling all remaining members
to derive the fresh branch root key while permanently excluding the revoked client.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import json
import os
from typing import Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.topic_keys import KEY_LENGTH


NONCE_LENGTH = 12
_LKH_DOMAIN = b"MP1-LKH-REKEY-v1"


class LkhError(ValueError):
    """Raised when an LKH tree or client operation is invalid or fails."""


def _lkh_aad(branch_path: str, target_node_id: int, encrypting_node_id: int, key_version: int) -> bytes:
    """Deterministic Authenticated Additional Data for LKH rekey messages."""
    branch_bytes = branch_path.encode("utf-8")
    return (
        _LKH_DOMAIN
        + len(branch_bytes).to_bytes(2, "big")
        + branch_bytes
        + target_node_id.to_bytes(4, "big")
        + encrypting_node_id.to_bytes(4, "big")
        + key_version.to_bytes(8, "big")
    )


@dataclass
class LkhNode:
    """A node in the Logical Key Hierarchy binary tree."""

    node_id: int
    key: bytes
    parent_id: Optional[int] = None
    left_id: Optional[int] = None
    right_id: Optional[int] = None
    member_id: Optional[str] = None
    members_in_subtree: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.member_id:
            self.members_in_subtree.add(self.member_id)


class LkhTree:
    """Logical Key Hierarchy binary tree maintained by the Key Controller.

    For a group of N members, the tree height is ceil(log2 N). On revocation,
    rekeying generates at most 2 * ceil(log2 N) ciphertexts, achieving O(log N)
    rekey distribution overhead.
    """

    def __init__(self, branch_path: str, members: list[str] | set[str]) -> None:
        if not branch_path:
            raise LkhError("branch_path must be a non-empty string")
        self.branch_path = branch_path
        self.nodes: dict[int, LkhNode] = {}
        self.member_leaf: dict[str, int] = {}
        self.key_version: int = 1
        self.root_id: int = 1
        self._build(list(members))

    @property
    def members(self) -> set[str]:
        return set(self.member_leaf.keys())

    def _build(self, members: list[str]) -> None:
        clean_members = sorted(list(set(members)))
        if len(clean_members) < 2:
            raise LkhError("LKH tree requires at least 2 members")

        curr_nodes: list[LkhNode] = []
        for m in clean_members:
            if not isinstance(m, str) or not m:
                raise LkhError("member ID must be a non-empty string")
            node = LkhNode(node_id=-1, key=os.urandom(KEY_LENGTH), member_id=m)
            curr_nodes.append(node)

        # Build balanced binary tree bottom-up
        level = curr_nodes
        while len(level) > 1:
            next_level: list[LkhNode] = []
            for i in range(0, len(level), 2):
                if i + 1 < len(level):
                    left = level[i]
                    right = level[i + 1]
                    parent = LkhNode(node_id=-1, key=os.urandom(KEY_LENGTH))
                    parent.members_in_subtree = left.members_in_subtree | right.members_in_subtree
                    parent._left_child = left  # type: ignore[attr-defined]
                    parent._right_child = right  # type: ignore[attr-defined]
                    next_level.append(parent)
                else:
                    next_level.append(level[i])
            level = next_level

        root = level[0]
        # Assign canonical node IDs via BFS traversal
        queue = [(root, 1)]
        root.node_id = 1
        self.nodes[1] = root
        next_node_id = 2

        while queue:
            curr, cid = queue.pop(0)
            curr.node_id = cid
            self.nodes[cid] = curr
            if curr.member_id:
                self.member_leaf[curr.member_id] = cid

            left = getattr(curr, "_left_child", None)
            right = getattr(curr, "_right_child", None)
            if left:
                lid = next_node_id
                next_node_id += 1
                curr.left_id = lid
                left.parent_id = cid
                queue.append((left, lid))
            if right:
                rid = next_node_id
                next_node_id += 1
                curr.right_id = rid
                right.parent_id = cid
                queue.append((right, rid))

    def get_path_keys(self, member_id: str) -> dict[int, bytes]:
        """Return the dictionary of {node_id: key} along the path from member's leaf to root."""
        if member_id not in self.member_leaf:
            raise LkhError(f"member {member_id} is not in the LKH tree")
        leaf_id = self.member_leaf[member_id]
        keys: dict[int, bytes] = {}
        curr_id: Optional[int] = leaf_id
        while curr_id is not None:
            keys[curr_id] = self.nodes[curr_id].key
            curr_id = self.nodes[curr_id].parent_id
        return keys

    def get_root_key(self) -> bytes:
        """Return the current branch root key."""
        return self.nodes[self.root_id].key

    def revoke_member(self, member_id: str) -> tuple[bytes, list[dict[str, Any]]]:
        """Revoke a member, rotate all compromised keys along its path, and return rekey package.

        The rekey package contains at most 2 * ceil(log2 N) ciphertexts, achieving
        O(log N) rekey distribution overhead.
        """
        if member_id not in self.member_leaf:
            raise LkhError(f"member {member_id} is not in the LKH tree")
        if len(self.member_leaf) <= 2:
            raise LkhError("cannot revoke below 2 members; minimum group size is 2")

        leaf_id = self.member_leaf[member_id]
        self.key_version += 1
        new_version = self.key_version

        # Path from leaf's parent up to root
        path_to_root: list[int] = []
        curr_id: Optional[int] = self.nodes[leaf_id].parent_id
        while curr_id is not None:
            path_to_root.append(curr_id)
            curr_id = self.nodes[curr_id].parent_id

        # Generate fresh keys for compromised nodes
        new_keys: dict[int, bytes] = {nid: os.urandom(KEY_LENGTH) for nid in path_to_root}
        rekey_package: list[dict[str, Any]] = []

        # Process bottom-up
        for nid in path_to_root:
            node = self.nodes[nid]
            new_key = new_keys[nid]
            left = self.nodes[node.left_id]  # type: ignore[index]
            right = self.nodes[node.right_id] if node.right_id else None

            if right is None:
                continue

            if member_id in left.members_in_subtree:
                revoked_child = left
                sibling_child = right
            else:
                revoked_child = right
                sibling_child = left

            # 1. Encrypt new_key under sibling_child's key if it contains active members
            if sibling_child.members_in_subtree:
                sibling_key = new_keys.get(sibling_child.node_id, sibling_child.key)
                nonce = os.urandom(NONCE_LENGTH)
                aad = _lkh_aad(self.branch_path, nid, sibling_child.node_id, new_version)
                ct = AESGCM(sibling_key).encrypt(nonce, new_key, aad)
                rekey_package.append({
                    "target_node_id": nid,
                    "encrypting_node_id": sibling_child.node_id,
                    "key_version": new_version,
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "ciphertext": base64.b64encode(ct).decode("ascii"),
                })

            # 2. If revoked_child is an internal node with other active members
            remaining_in_revoked_subtree = revoked_child.members_in_subtree - {member_id}
            if remaining_in_revoked_subtree:
                child_new_key = new_keys[revoked_child.node_id]
                nonce = os.urandom(NONCE_LENGTH)
                aad = _lkh_aad(self.branch_path, nid, revoked_child.node_id, new_version)
                ct = AESGCM(child_new_key).encrypt(nonce, new_key, aad)
                rekey_package.append({
                    "target_node_id": nid,
                    "encrypting_node_id": revoked_child.node_id,
                    "key_version": new_version,
                    "nonce": base64.b64encode(nonce).decode("ascii"),
                    "ciphertext": base64.b64encode(ct).decode("ascii"),
                })

        # Apply fresh keys and evict revoked member
        for nid, nkey in new_keys.items():
            self.nodes[nid].key = nkey
            self.nodes[nid].members_in_subtree.discard(member_id)

        # Mark leaf as revoked
        self.nodes[leaf_id].member_id = None
        self.nodes[leaf_id].members_in_subtree.discard(member_id)
        del self.member_leaf[member_id]

        return self.get_root_key(), rekey_package


class LkhClient:
    """Client-side LKH state machine holding path keys from leaf to root."""

    def __init__(
        self,
        device_id: str,
        branch_path: str,
        path_keys: dict[int, bytes],
        key_version: int = 1,
    ) -> None:
        self.device_id = device_id
        self.branch_path = branch_path
        self.path_keys = dict(path_keys)
        self.key_version = key_version

    @property
    def root_key(self) -> bytes:
        if 1 not in self.path_keys:
            raise LkhError("client holds no root key")
        return self.path_keys[1]

    def process_rekey_package(self, package: list[dict[str, Any]], expected_version: int) -> bytes:
        """Process broadcast rekey package, decrypting updated keys bottom-up.

        Raises LkhError if the client is revoked or lacks required keys.
        """
        updated_nodes: set[int] = set()
        current_keys = dict(self.path_keys)
        progress = True

        while progress:
            progress = False
            for item in package:
                target_id = item["target_node_id"]
                enc_id = item["encrypting_node_id"]
                if target_id in updated_nodes:
                    continue
                if enc_id in current_keys:
                    key = current_keys[enc_id]
                    nonce = base64.b64decode(item["nonce"])
                    ct = base64.b64decode(item["ciphertext"])
                    aad = _lkh_aad(self.branch_path, target_id, enc_id, expected_version)
                    try:
                        decrypted_key = AESGCM(key).decrypt(nonce, ct, aad)
                        current_keys[target_id] = decrypted_key
                        updated_nodes.add(target_id)
                        progress = True
                    except (InvalidTag, ValueError):
                        pass

        if not updated_nodes:
            raise LkhError(f"client {self.device_id} could not decrypt any key in the LKH rekey package")

        self.path_keys = current_keys
        self.key_version = expected_version
        return self.root_key


def serialise_rekey_package(package: list[dict[str, Any]]) -> bytes:
    """Serialise an LKH rekey package to UTF-8 JSON bytes for MQTT broadcast."""
    return json.dumps(package, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_rekey_package(payload: bytes) -> list[dict[str, Any]]:
    """Parse JSON bytes into an LKH rekey package structure."""
    try:
        data = json.loads(payload.decode("utf-8"))
        if not isinstance(data, list):
            raise LkhError("rekey package must be a JSON array")
        return data
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LkhError("invalid LKH rekey package JSON payload") from exc

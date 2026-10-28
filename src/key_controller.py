"""Trusted membership and lazy-rekey controller for encrypted MQTT branches.

The controller is deliberately separate from the MQTT relay.  It retains branch
root keys and supplies them only to members authorised for that exact branch.
When a member is revoked, the branch becomes stale.  The next authorised
publisher requesting credentials causes a rekey *before* it encrypts a new
message; idle stale branches can also be rekeyed by ``rekey_expired``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import secrets

from src.topic_keys import KEY_LENGTH, TopicKeyError, derive_topic_key


class KeyControllerError(ValueError):
    """Raised for invalid branch state or unauthorised controller requests."""


@dataclass(frozen=True)
class BranchCredential:
    """Key material supplied to one currently authorised branch member."""

    branch_path: str
    root_key: bytes
    key_version: int


@dataclass
class _BranchState:
    root_key: bytes
    key_version: int = 1
    members: set[str] = field(default_factory=set)
    stale_since: datetime | None = None
    last_rekey_at: datetime | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_branch_path(path: str) -> None:
    """Reuse cryptographic-topic validation without treating a root as a key."""
    try:
        derive_topic_key(b"\0" * KEY_LENGTH, path, path)
    except TopicKeyError as exc:
        raise KeyControllerError(str(exc)) from exc


class KeyController:
    """Trusted authority for branch membership, versions, and lazy rekeying."""

    def __init__(self, max_staleness: timedelta = timedelta(minutes=10)) -> None:
        if max_staleness <= timedelta(0):
            raise KeyControllerError("max_staleness must be positive")
        self.max_staleness = max_staleness
        self._branches: dict[str, _BranchState] = {}

    def create_branch(
        self, branch_path: str, members: set[str] | None = None, root_key: bytes | None = None
    ) -> None:
        """Create a managed branch with an initial random 256-bit root key."""
        _validate_branch_path(branch_path)
        if branch_path in self._branches:
            raise KeyControllerError("branch already exists")
        if root_key is not None and (not isinstance(root_key, bytes) or len(root_key) != KEY_LENGTH):
            raise KeyControllerError("root key must be exactly 32 bytes")
        authorised_members = set() if members is None else set(members)
        if any(not isinstance(member, str) or not member for member in authorised_members):
            raise KeyControllerError("member IDs must be non-empty strings")
        self._branches[branch_path] = _BranchState(root_key or secrets.token_bytes(KEY_LENGTH), members=authorised_members)

    def add_member(self, device_id: str, branch_path: str) -> None:
        """Authorise a device or consumer to receive this branch's credential."""
        if not isinstance(device_id, str) or not device_id:
            raise KeyControllerError("device ID must be a non-empty string")
        self._state(branch_path).members.add(device_id)

    def revoke(self, device_id: str, branch_path: str, *, now: datetime | None = None) -> None:
        """Remove a member and mark only its branch stale, without immediate rekey."""
        state = self._state(branch_path)
        if device_id not in state.members:
            raise KeyControllerError("device is not authorised for this branch")
        state.members.remove(device_id)
        state.stale_since = now or _now()

    def credential_for(self, device_id: str, branch_path: str, *, now: datetime | None = None) -> BranchCredential:
        """Get a current credential, lazily rekeying a stale branch first."""
        state = self._state(branch_path)
        if device_id not in state.members:
            raise KeyControllerError("device is not authorised for this branch")
        if state.stale_since is not None:
            self._rekey(state, now or _now())
        return BranchCredential(branch_path, state.root_key, state.key_version)

    def rekey_expired(self, *, now: datetime | None = None) -> list[str]:
        """Rekey stale idle branches whose bounded-staleness deadline elapsed."""
        current_time = now or _now()
        rekeyed: list[str] = []
        for path, state in self._branches.items():
            if state.stale_since is not None and current_time - state.stale_since >= self.max_staleness:
                self._rekey(state, current_time)
                rekeyed.append(path)
        return rekeyed

    def branch_status(self, branch_path: str) -> dict[str, object]:
        """Return safe operational metadata without exposing the root key."""
        state = self._state(branch_path)
        return {
            "key_version": state.key_version,
            "stale": state.stale_since is not None,
            "members": frozenset(state.members),
            "last_rekey_at": state.last_rekey_at,
        }

    def _state(self, branch_path: str) -> _BranchState:
        try:
            return self._branches[branch_path]
        except KeyError as exc:
            raise KeyControllerError("unknown branch") from exc

    @staticmethod
    def _rekey(state: _BranchState, at: datetime) -> None:
        state.root_key = secrets.token_bytes(KEY_LENGTH)
        state.key_version += 1
        state.stale_since = None
        state.last_rekey_at = at

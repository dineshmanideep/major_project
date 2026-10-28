"""SQLite-backed Key Controller state for the software simulation.

The database is a local simulation artifact.  In production, its root-key
column must be protected by an operating-system keystore or HSM; plaintext
SQLite storage is deliberately not presented as production key protection.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import json
from pathlib import Path
import sqlite3

from src.key_controller import BranchCredential, KeyController, _BranchState, _now


def _encode_time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _decode_time(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


class PersistentKeyController(KeyController):
    """A Key Controller whose branch state and audit events survive restarts."""

    def __init__(self, database_path: str | Path, max_staleness: timedelta = timedelta(minutes=10)) -> None:
        self.database_path = Path(database_path)
        self._connection = sqlite3.connect(self.database_path)
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()
        super().__init__(max_staleness=max_staleness)
        self._load()

    def close(self) -> None:
        self._connection.close()

    def create_branch(self, branch_path: str, members: set[str] | None = None, root_key: bytes | None = None) -> None:
        super().create_branch(branch_path, members, root_key)
        self._save("branch_created", branch_path, None)

    def add_member(self, device_id: str, branch_path: str) -> None:
        super().add_member(device_id, branch_path)
        self._save("member_added", branch_path, device_id)

    def revoke(self, device_id: str, branch_path: str, *, now: datetime | None = None) -> None:
        super().revoke(device_id, branch_path, now=now)
        self._save("member_revoked", branch_path, device_id)

    def credential_for(self, device_id: str, branch_path: str, *, now: datetime | None = None) -> BranchCredential:
        previous_version = self.branch_status(branch_path)["key_version"]
        credential = super().credential_for(device_id, branch_path, now=now)
        event = "branch_rekeyed" if credential.key_version != previous_version else "credential_requested"
        self._save(event, branch_path, device_id)
        return credential

    def rekey_expired(self, *, now: datetime | None = None) -> list[str]:
        rekeyed = super().rekey_expired(now=now)
        if rekeyed:
            self._save("expired_branches_rekeyed", ",".join(rekeyed), None)
        return rekeyed

    def audit_events(self) -> list[dict[str, str | None]]:
        rows = self._connection.execute(
            "SELECT event, branch_path, device_id, occurred_at FROM audit_events ORDER BY id"
        ).fetchall()
        return [
            {"event": row[0], "branch_path": row[1], "device_id": row[2], "occurred_at": row[3]}
            for row in rows
        ]

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS branches (
                branch_path TEXT PRIMARY KEY,
                root_key BLOB NOT NULL,
                key_version INTEGER NOT NULL,
                members_json TEXT NOT NULL,
                stale_since TEXT,
                last_rekey_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                branch_path TEXT NOT NULL,
                device_id TEXT,
                occurred_at TEXT NOT NULL
            );
            """
        )
        self._connection.commit()

    def _load(self) -> None:
        for row in self._connection.execute(
            "SELECT branch_path, root_key, key_version, members_json, stale_since, last_rekey_at FROM branches"
        ):
            self._branches[row[0]] = _BranchState(
                root_key=row[1], key_version=row[2], members=set(json.loads(row[3])),
                stale_since=_decode_time(row[4]), last_rekey_at=_decode_time(row[5]),
            )

    def _save(self, event: str, branch_path: str, device_id: str | None) -> None:
        self._connection.execute("DELETE FROM branches")
        self._connection.executemany(
            "INSERT INTO branches VALUES (?, ?, ?, ?, ?, ?)",
            [
                (path, state.root_key, state.key_version, json.dumps(sorted(state.members)),
                 _encode_time(state.stale_since), _encode_time(state.last_rekey_at))
                for path, state in self._branches.items()
            ],
        )
        self._connection.execute(
            "INSERT INTO audit_events(event, branch_path, device_id, occurred_at) VALUES (?, ?, ?, ?)",
            (event, branch_path, device_id, _now().isoformat()),
        )
        self._connection.commit()

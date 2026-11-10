"""SQLite store for the web UI: domains, the authorization acknowledgment, scans, and the audit log.

Kept under the gitignored output directory. A second in-memory instance holds demo scans,
so demo data never mixes with real history.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    name TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    kind TEXT NOT NULL,
    port INTEGER,
    token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    method TEXT
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    verification_method TEXT,
    grade TEXT,
    total INTEGER,
    counts TEXT,
    error TEXT,
    result TEXT,
    report_html TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event TEXT NOT NULL,
    target TEXT,
    verification_method TEXT,
    status TEXT NOT NULL,
    summary TEXT
);
"""

SCAN_COLUMNS = (
    "id", "target", "mode", "scan_type", "status", "started_at", "finished_at", "verification_method", "grade",
    "total", "counts", "error",
)


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path | None) -> None:
        """``path=None`` keeps everything in memory (used for demo scans and tests)."""
        if path is not None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path) if path else ":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)

    def _run(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock, self._conn:
            return self._conn.execute(sql, params).fetchall()

    # ------------------------------------------------------------------ acknowledgment

    def acknowledged_at(self) -> str | None:
        rows = self._run("SELECT value FROM meta WHERE key = 'authorization_acknowledged_at'")
        return rows[0]["value"] if rows else None

    def acknowledge(self) -> str:
        existing = self.acknowledged_at()
        if existing:
            return existing
        stamp = now_iso()
        self._run("INSERT INTO meta (key, value) VALUES ('authorization_acknowledged_at', ?)", (stamp,))
        self.audit("authorization_acknowledged", status="ok", summary="User confirmed ownership or written permission")
        return stamp

    # ------------------------------------------------------------------ domains

    def list_domains(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._run("SELECT * FROM domains ORDER BY created_at DESC, name")]

    def get_domain(self, name: str) -> dict[str, Any] | None:
        rows = self._run("SELECT * FROM domains WHERE name = ?", (name,))
        return dict(rows[0]) if rows else None

    def add_domain(self, name: str, host: str, kind: str, port: int | None, token: str) -> dict[str, Any]:
        self._run(
            "INSERT OR IGNORE INTO domains (name, host, kind, port, token, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, host, kind, port, token, now_iso()),
        )
        return self.get_domain(name) or {}

    def mark_verified(self, name: str, method: str, when: str | None = None) -> None:
        self._run("UPDATE domains SET verified_at = ?, method = ? WHERE name = ?", (when or now_iso(), method, name))

    def delete_domain(self, name: str) -> bool:
        existed = self.get_domain(name) is not None
        self._run("DELETE FROM domains WHERE name = ?", (name,))
        return existed

    # ------------------------------------------------------------------ scans

    def save_scan(self, record: dict[str, Any]) -> None:
        self._run(
            "INSERT OR REPLACE INTO scans (id, target, mode, scan_type, status, started_at, finished_at, "
            "verification_method, grade, total, counts, error, result, report_html) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["id"], record["target"], record["mode"], record["scan_type"], record["status"],
                record["started_at"], record.get("finished_at"), record.get("verification_method"),
                record.get("grade"), record.get("total"),
                json.dumps(record["counts"]) if record.get("counts") is not None else None,
                record.get("error"),
                json.dumps(record["result"]) if record.get("result") is not None else None,
                record.get("report_html"),
            ),
        )

    @staticmethod
    def _scan(row: sqlite3.Row, full: bool) -> dict[str, Any]:
        data = {key: row[key] for key in SCAN_COLUMNS}
        data["counts"] = json.loads(data["counts"]) if data["counts"] else None
        if full:
            data["result"] = json.loads(row["result"]) if row["result"] else None
        return data

    def list_scans(self, limit: int = 200) -> list[dict[str, Any]]:
        columns = ", ".join(SCAN_COLUMNS)
        rows = self._run(f"SELECT {columns} FROM scans ORDER BY started_at DESC, rowid DESC LIMIT ?", (limit,))  # noqa: S608 - fixed column list
        return [self._scan(r, full=False) for r in rows]

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        rows = self._run("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return self._scan(rows[0], full=True) if rows else None

    def get_report_html(self, scan_id: str) -> str | None:
        rows = self._run("SELECT report_html FROM scans WHERE id = ?", (scan_id,))
        return rows[0]["report_html"] if rows else None

    # ------------------------------------------------------------------ audit

    def audit(
        self, event: str, *, target: str | None = None, verification_method: str | None = None, status: str = "ok",
        summary: str | None = None,
    ) -> None:
        self._run(
            "INSERT INTO audit (timestamp, event, target, verification_method, status, summary) VALUES (?, ?, ?, ?, ?, ?)",
            (now_iso(), event, target, verification_method, status, summary),
        )

    def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        return [dict(r) for r in self._run("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]

"""Persistent local scan history for the optional dashboard."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class ScanHistory:
    """Small thread-safe SQLite store for serialised scan results."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        if path != ":memory:":
            resolved = Path(path).expanduser()
            resolved.parent.mkdir(parents=True, exist_ok=True)
            path = resolved
        self._connection = sqlite3.connect(str(path), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._connection:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    report TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT ''
                )
                """
            )

    def add(self, report: dict[str, Any], summary: str = "") -> int:
        """Store a report and return its numeric history ID."""
        payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"))
        created_at = datetime.now(UTC).isoformat()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                "INSERT INTO scans (created_at, report, summary) VALUES (?, ?, ?)",
                (created_at, payload, summary),
            )
        if cursor.lastrowid is None:  # pragma: no cover - SQLite always assigns it
            raise RuntimeError("failed to allocate scan history id")
        return int(cursor.lastrowid)

    def list(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return newest-first metadata without returning full findings."""
        safe_limit = max(1, min(limit, 500))
        with self._lock:
            rows = self._connection.execute(
                "SELECT id, created_at, report, summary FROM scans "
                "ORDER BY id DESC LIMIT ?",
                (safe_limit,),
            ).fetchall()
        return [self._metadata(row) for row in rows]

    def get(self, scan_id: int) -> dict[str, Any] | None:
        """Return one stored result, or ``None`` when it does not exist."""
        with self._lock:
            row = self._connection.execute(
                "SELECT id, created_at, report, summary FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "report": json.loads(row["report"]),
            "summary": row["summary"],
        }

    def delete(self, scan_id: int) -> bool:
        """Delete one scan and report whether a row was removed."""
        with self._lock, self._connection:
            cursor = self._connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0

    @staticmethod
    def _metadata(row: sqlite3.Row) -> dict[str, Any]:
        report = json.loads(row["report"])
        targets = report.get("targets", [])
        severities = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
        for target in targets:
            for finding in target.get("findings", []):
                severity = finding.get("severity", "info")
                if severity in severities:
                    severities[severity] += 1
        return {
            "id": row["id"],
            "created_at": row["created_at"],
            "scan_started": report.get("scan_started", ""),
            "scan_finished": report.get("scan_finished", ""),
            "total_findings": report.get("total_findings", 0),
            "target_count": len(targets),
            "target": targets[0].get("target", "") if targets else "",
            "severities": severities,
            "has_summary": bool(row["summary"]),
        }

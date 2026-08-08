"""Tests for the local dashboard history store."""
from __future__ import annotations

from pathlib import Path

from webscan.history import ScanHistory


def _report(target: str = "https://example.com") -> dict[str, object]:
    return {
        "scan_started": "2026-01-01T00:00:00+00:00",
        "scan_finished": "2026-01-01T00:00:01+00:00",
        "total_findings": 1,
        "targets": [{
            "target": target,
            "findings": [{"severity": "high", "plugin": "headers"}],
        }],
    }


def test_history_round_trip_and_metadata(tmp_path: Path) -> None:
    history = ScanHistory(tmp_path / "history.db")
    scan_id = history.add(_report(), "Review HSTS first.")

    rows = history.list()
    assert rows[0]["id"] == scan_id
    assert rows[0]["target"] == "https://example.com"
    assert rows[0]["severities"]["high"] == 1

    item = history.get(scan_id)
    assert item is not None
    assert item["summary"] == "Review HSTS first."
    assert item["report"]["total_findings"] == 1


def test_history_delete_is_idempotently_reported(tmp_path: Path) -> None:
    history = ScanHistory(tmp_path / "history.db")
    scan_id = history.add(_report())
    assert history.delete(scan_id) is True
    assert history.get(scan_id) is None
    assert history.delete(scan_id) is False

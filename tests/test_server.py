"""Tests for the optional HTTP backend (webscan.server).

The whole module is skipped when the ``serve`` extra (fastapi) is absent, so the
core test suite stays dependency-light. When fastapi *is* installed, we drive
the app with FastAPI's TestClient and a monkeypatched scan engine — no network.
"""
from __future__ import annotations

from typing import Any

import pytest

from webscan.models import Finding, ScanReport, Severity, TargetResult
from webscan.server import run_scan, server_available

pytestmark = pytest.mark.skipif(
    not server_available(), reason="serve extra (fastapi) not installed"
)


def _fake_report() -> ScanReport:
    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[Finding("headers", "Missing CSP", Severity.HIGH, "d", "u")],
            scanned_at="t0",
        )
    )
    report.total_findings = 1
    return report


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Any:  # noqa: ANN401 - TestClient
    from fastapi.testclient import TestClient

    from webscan import server

    async def _fake_scan(targets: Any, **kwargs: Any) -> ScanReport:  # noqa: ANN401 - shim
        assert targets, "scan must receive at least one target"
        return _fake_report()

    monkeypatch.setattr(server, "scan", _fake_scan)
    # Keep AI off regardless of the host environment so the report is unannotated.
    monkeypatch.setattr(server, "ai_available", lambda *a, **k: False)
    monkeypatch.setattr(
        server.AIAssistant, "available", property(lambda self: False)
    )
    return TestClient(server.create_app())


def test_health(client) -> None:  # noqa: ANN001
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["ai"] is False


def test_scan_happy_path(client) -> None:  # noqa: ANN001
    resp = client.post("/scan", json={"targets": ["https://example.com"]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"] == ""
    assert body["report"]["total_findings"] == 1
    assert body["report"]["targets"][0]["findings"][0]["title"] == "Missing CSP"


def test_scan_requires_target(client) -> None:  # noqa: ANN001
    # Empty targets list is rejected by run_scan's validation -> 400.
    resp = client.post("/scan", json={"targets": []})
    assert resp.status_code == 400


def test_scan_rejects_non_object_body(client) -> None:  # noqa: ANN001
    resp = client.post("/scan", json=["not", "an", "object"])
    assert resp.status_code == 400


async def test_run_scan_rejects_empty_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    # run_scan is the framework-agnostic core; it raises ValueError on no targets.
    with pytest.raises(ValueError, match="at least one target"):
        await run_scan({"targets": []})


async def test_run_scan_returns_report(monkeypatch: pytest.MonkeyPatch) -> None:
    from webscan import server

    async def _fake_scan(targets: Any, **kwargs: Any) -> ScanReport:  # noqa: ANN401 - shim
        return _fake_report()

    monkeypatch.setattr(server, "scan", _fake_scan)
    monkeypatch.setattr(
        server.AIAssistant, "available", property(lambda self: False)
    )
    out = await run_scan({"targets": ["https://example.com"], "ai_summary": True})
    # AI unavailable -> summary stays empty, report still present.
    assert out["summary"] == ""
    assert out["report"]["total_findings"] == 1


async def test_run_scan_with_ai_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the AI layer is available, triage runs and the summary flows through."""
    from webscan import server

    async def _fake_scan(targets: Any, **kwargs: Any) -> ScanReport:  # noqa: ANN401 - shim
        return _fake_report()

    class _FakeAssistant:
        available = True

        def __init__(self, *a: Any, **k: Any) -> None:  # noqa: ANN401 - shim
            self.triaged = False

        async def triage_report(self, report: ScanReport) -> ScanReport:
            self.triaged = True
            return report

        async def summarize_report(self, report: ScanReport) -> str:
            return "Looks fine overall."

    monkeypatch.setattr(server, "scan", _fake_scan)
    monkeypatch.setattr(server, "AIAssistant", _FakeAssistant)

    out = await run_scan(
        {"targets": ["https://example.com"], "ai_triage": True, "ai_summary": True}
    )
    assert out["summary"] == "Looks fine overall."
    assert out["report"]["total_findings"] == 1

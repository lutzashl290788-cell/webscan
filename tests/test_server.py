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


# ---------------------------------------------------------------------------
# Hardening tests (v2.5.1) — body-size cap, validation, edge cases
# ---------------------------------------------------------------------------


def test_scan_rejects_too_many_targets(client) -> None:  # noqa: ANN001
    """run_scan caps targets at _MAX_TARGETS (50) to prevent resource abuse."""
    from webscan.server import _MAX_TARGETS

    payload = {"targets": [f"https://example.com/{i}" for i in range(_MAX_TARGETS + 1)]}
    resp = client.post("/scan", json=payload)
    assert resp.status_code == 400
    assert "too many targets" in resp.json()["detail"]


def test_scan_rejects_non_list_targets(client) -> None:  # noqa: ANN001
    """targets must be a list — a string is rejected with 400."""
    resp = client.post("/scan", json={"targets": "https://example.com"})
    assert resp.status_code == 400
    assert "targets must be a list" in resp.json()["detail"]


def test_scan_rejects_bad_timeout_type(client) -> None:  # noqa: ANN001
    """timeout must be int — a string is rejected with 400."""
    resp = client.post(
        "/scan", json={"targets": ["https://example.com"], "timeout": "fast"}
    )
    assert resp.status_code == 400
    assert "must be integers" in resp.json()["detail"]


def test_scan_rejects_bad_plugins_type(client) -> None:  # noqa: ANN001
    """plugins must be a list — a string is rejected with 400."""
    resp = client.post(
        "/scan", json={"targets": ["https://example.com"], "plugins": "headers"}
    )
    assert resp.status_code == 400
    assert "plugins must be a list" in resp.json()["detail"]


def test_scan_rejects_oversized_body(client) -> None:  # noqa: ANN001
    """A body larger than _MAX_BODY_BYTES is rejected with 413 (CWE-400)."""
    from webscan.server import _MAX_BODY_BYTES

    # Build a payload that exceeds the cap by padding the URL list.
    pad = "x" * 1024
    targets = [f"https://example.com/{pad}/{i}" for i in range(_MAX_BODY_BYTES // 1024 + 5)]
    resp = client.post("/scan", json={"targets": targets})
    assert resp.status_code == 413
    assert "too large" in resp.json()["detail"]


def test_scan_rejects_malformed_json(client) -> None:  # noqa: ANN001
    """Invalid JSON body returns 400, not 500."""
    resp = client.post(
        "/scan",
        data=b"{not valid json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert "invalid JSON body" in resp.json()["detail"]


def test_create_app_raises_without_serve_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_app raises RuntimeError if the serve extra is not installed."""
    from webscan import server

    # Force server_available() to False to exercise the guard branch.
    monkeypatch.setattr(server, "server_available", lambda: False)
    with pytest.raises(RuntimeError, match="serve' extra is not installed"):
        server.create_app()


def test_run_server_raises_without_serve_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    """run_server raises RuntimeError if the serve extra is not installed."""
    from webscan import server

    monkeypatch.setattr(server, "server_available", lambda: False)
    with pytest.raises(RuntimeError, match="serve' extra is not installed"):
        server.run_server()


def test_confidence_from_str_handles_invalid_input() -> None:
    """_confidence_from_str returns None for unknown/invalid confidence names."""
    from webscan.server import _confidence_from_str

    # Empty / None => None.
    assert _confidence_from_str(None) is None
    assert _confidence_from_str("") is None
    # Unknown confidence name => None.
    assert _confidence_from_str("bogus") is None
    # Valid name => Confidence enum.
    assert _confidence_from_str("firm") is not None


async def test_run_scan_clamps_timeout_and_concurrency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_scan clamps absurd timeout/concurrency to safe bounds (CWE-770)."""
    from webscan import server

    captured: dict[str, Any] = {}

    async def _capture_scan(targets: Any, **kwargs: Any) -> ScanReport:  # noqa: ANN401 - shim
        captured.update(kwargs)
        return _fake_report()

    monkeypatch.setattr(server, "scan", _capture_scan)
    monkeypatch.setattr(
        server.AIAssistant, "available", property(lambda self: False)
    )

    # Request absurd values; run_scan should clamp to _MAX_TIMEOUT/_MAX_CONCURRENCY.
    await run_scan({
        "targets": ["https://example.com"],
        "timeout": 999999,
        "concurrency": 100000,
    })
    from webscan.server import _MAX_CONCURRENCY, _MAX_TIMEOUT

    assert captured["timeout"] == _MAX_TIMEOUT
    assert captured["concurrency"] == _MAX_CONCURRENCY

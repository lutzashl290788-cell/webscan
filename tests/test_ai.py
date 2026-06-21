"""Tests for the optional Claude AI layer (webscan.ai), using a fake client."""
from __future__ import annotations

import json
from typing import Any

import pytest

from webscan.ai import AIAssistant, AIConfig, ai_available
from webscan.models import Finding, ScanReport, Severity, TargetResult


class _Block:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _Resp:
    def __init__(self, text: str) -> None:
        self.content = [_Block(text)]


class _Messages:
    """Fake messages namespace; records calls and returns canned text."""

    def __init__(self, reply: str, boom: bool = False) -> None:
        self._reply = reply
        self._boom = boom
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> _Resp:  # noqa: ANN401 - fake SDK shim
        self.calls.append(kwargs)
        if self._boom:
            raise RuntimeError("simulated API failure")
        return _Resp(self._reply)


class _FakeClient:
    def __init__(self, reply: str = "{}", boom: bool = False) -> None:
        self.messages = _Messages(reply, boom)


def _report() -> ScanReport:
    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[
                Finding("headers", "Missing CSP", Severity.HIGH, "d", "u"),
                Finding("xss", "Reflected XSS", Severity.CRITICAL, "d", "u"),
            ],
            scanned_at="t0",
        )
    )
    report.total_findings = 2
    return report


def test_assistant_unavailable_without_client() -> None:
    a = AIAssistant(client=None)
    # With no anthropic SDK/key in the test env, a real build yields no client.
    # Explicitly passing None and no key keeps it unavailable.
    if a.available:
        pytest.skip("anthropic SDK + key present in environment")
    assert a.available is False


async def test_triage_unavailable_is_noop() -> None:
    report = _report()
    a = AIAssistant(client=None)
    if a.available:
        pytest.skip("anthropic configured in environment")
    out = await a.triage_report(report)
    assert out is report
    assert "ai_triage" not in report.targets[0].findings[0].evidence


async def test_triage_annotates_findings() -> None:
    reply = json.dumps(
        {
            "verdicts": [
                {"index": 0, "assessment": "likely_false_positive", "rationale": "weak"},
                {"index": 1, "assessment": "likely_true_positive", "rationale": "solid"},
            ]
        }
    )
    client = _FakeClient(reply=reply)
    a = AIAssistant(config=AIConfig(model="claude-opus-4-8"), client=client)
    assert a.available

    report = _report()
    await a.triage_report(report)

    f0, f1 = report.targets[0].findings
    assert f0.evidence["ai_triage"]["assessment"] == "likely_false_positive"
    assert f1.evidence["ai_triage"]["assessment"] == "likely_true_positive"
    # One request per target.
    assert len(client.messages.calls) == 1
    # Structured-output schema was requested.
    assert client.messages.calls[0]["output_config"]["format"]["type"] == "json_schema"


async def test_triage_ignores_out_of_range_index() -> None:
    reply = json.dumps(
        {"verdicts": [{"index": 99, "assessment": "uncertain", "rationale": "x"}]}
    )
    a = AIAssistant(client=_FakeClient(reply=reply))
    report = _report()
    await a.triage_report(report)
    assert "ai_triage" not in report.targets[0].findings[0].evidence


async def test_triage_survives_api_error() -> None:
    a = AIAssistant(client=_FakeClient(boom=True))
    report = _report()
    out = await a.triage_report(report)  # must not raise
    assert out is report
    assert "ai_triage" not in report.targets[0].findings[0].evidence


async def test_triage_survives_bad_json() -> None:
    a = AIAssistant(client=_FakeClient(reply="not json at all"))
    report = _report()
    await a.triage_report(report)
    assert "ai_triage" not in report.targets[0].findings[0].evidence


async def test_summary_returns_text() -> None:
    a = AIAssistant(client=_FakeClient(reply="Your site looks mostly fine."))
    summary = await a.summarize_report(_report())
    assert "mostly fine" in summary


async def test_summary_survives_api_error() -> None:
    a = AIAssistant(client=_FakeClient(boom=True))
    assert await a.summarize_report(_report()) == ""


def test_resolved_model_default() -> None:
    assert AIConfig().resolved_model() == "claude-opus-4-8"
    assert AIConfig(model="claude-haiku-4-5").resolved_model() == "claude-haiku-4-5"


def test_ai_available_false_without_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Without an explicit key and no env key, availability hinges on the key check
    # even if the SDK is installed.
    assert ai_available(AIConfig()) is False

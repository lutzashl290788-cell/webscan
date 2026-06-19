"""Tests for the ssti plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.ssti import SstiPlugin, _has_result, _has_syntax_reflection

_TARGET = "https://example.com/?name=test"


class _TwoResponseSession:
    """Returns baseline for first URL, probe for all others."""

    def __init__(self, baseline: FakeResponse, probe: FakeResponse) -> None:
        self._baseline = baseline
        self._probe = probe
        self._first = True

    def get(self, url: str, **_kw: object) -> FakeResponse:
        if self._first:
            self._first = False
            return self._baseline
        return self._probe


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


class TestHasResult:
    def test_standalone_number(self) -> None:
        assert _has_result("The answer is 49 here", "49") is True

    def test_number_in_phone(self) -> None:
        assert _has_result("Call 1492001234", "49") is False

    def test_at_start(self) -> None:
        assert _has_result("49 is the answer", "49") is True

    def test_at_end(self) -> None:
        assert _has_result("answer is 49", "49") is True

    def test_not_present(self) -> None:
        assert _has_result("nothing here", "49") is False

    def test_empty_expected(self) -> None:
        assert _has_result("anything", "") is False


class TestHasSyntaxReflection:
    def test_jinja2_braces(self) -> None:
        assert _has_syntax_reflection("hello {{7*7}} world", "{{7*7}}") is True

    def test_dollar_brace(self) -> None:
        assert _has_syntax_reflection("hello ${7*7} world", "${7*7}") is True

    def test_erb(self) -> None:
        assert _has_syntax_reflection("hello <%= 7*7 %> world", "<%= 7*7 %>") is True

    def test_ruby(self) -> None:
        assert _has_syntax_reflection("hello #{7*7} world", "#{7*7}") is True

    def test_no_reflection(self) -> None:
        assert _has_syntax_reflection("hello world", "{{7*7}}") is False


class TestPluginRun:
    async def test_no_params_no_findings(self) -> None:
        plugin = SstiPlugin()
        resp = FakeResponse(body="<html>no params</html>")
        findings = await plugin.run("https://example.com/page", FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_critical_when_result_evaluated(self) -> None:
        plugin = SstiPlugin()
        baseline = FakeResponse(body="<html>Hello test</html>", status=200)
        # Probe response contains 49 — the result of {{7*7}}
        probe = FakeResponse(body="<html>Hello 49</html>", status=200)
        session = _TwoResponseSession(baseline, probe)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

        critical = _findings_with(findings, title_contains="SSTI confirmed")
        assert len(critical) == 1
        assert critical[0].severity is Severity.CRITICAL
        assert critical[0].confidence is Confidence.FIRM

    async def test_medium_when_syntax_reflected_only(self) -> None:
        plugin = SstiPlugin()
        baseline = FakeResponse(body="<html>Hello test</html>", status=200)
        # Probe reflects the syntax but doesn't evaluate
        probe = FakeResponse(body="<html>Hello {{7*7}}</html>", status=200)
        session = _TwoResponseSession(baseline, probe)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

        tentative = _findings_with(findings, title_contains="Possible SSTI")
        assert len(tentative) == 1
        assert tentative[0].severity is Severity.MEDIUM
        assert tentative[0].confidence is Confidence.TENTATIVE

    async def test_no_finding_when_result_in_baseline(self) -> None:
        """If 49 is already in the baseline page, don't FP — try confirmation."""
        plugin = SstiPlugin()
        # Baseline already contains 49 (e.g. a price)
        baseline = FakeResponse(body="<html>Price: 49 USD</html>", status=200)
        # Probe also contains 49 (but from the baseline, not from evaluation)
        probe = FakeResponse(body="<html>Price: 49 USD</html>", status=200)
        session = _TwoResponseSession(baseline, probe)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        # Should not fire CRITICAL because 49 was in baseline and the
        # confirmation probe (343) won't match.
        critical = _findings_with(findings, title_contains="SSTI confirmed")
        assert critical == []

    async def test_network_error_returns_empty(self) -> None:
        plugin = SstiPlugin()

        class _BoomSession:
            def get(self, url: str, **_kw: object) -> _BoomResp:
                return _BoomResp()

        class _BoomResp:
            async def __aenter__(self) -> _BoomResp:
                raise _ClientError("boom")

            async def __aexit__(self, *_exc: object) -> bool:
                return False

        class _ClientError(Exception):
            pass

        import aiohttp

        orig = aiohttp.ClientError
        try:
            aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
            findings = await plugin.run(_TARGET, _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_evidence_includes_engine_and_payload(self) -> None:
        plugin = SstiPlugin()
        baseline = FakeResponse(body="<html>Hello test</html>", status=200)
        probe = FakeResponse(body="<html>Hello 49</html>", status=200)
        session = _TwoResponseSession(baseline, probe)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="SSTI confirmed")[0]
        ev = crit.evidence
        assert "engine" in ev
        assert "payload" in ev
        assert "expected_result" in ev
        assert ev["expected_result"] == "49"

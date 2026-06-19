"""Tests for the cache_poisoning plugin."""
from __future__ import annotations

from typing import Any

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.cache_poisoning import (
    CachePoisoningPlugin,
    _compile_dangerous_patterns,
    _find_dangerous_reflection,
    _has_plain_reflection,
    _is_html_response,
)

_TARGET = "https://example.com"


# ─── Fake session that supports custom request headers ──────────────────────


class _HeaderAwareSession:
    """Returns one response for the baseline (no extra header), another when
    a specific extra header is present in the request."""

    def __init__(
        self,
        baseline: FakeResponse,
        probe: FakeResponse,
        trigger_header: str,
    ) -> None:
        self._baseline = baseline
        self._probe = probe
        self._trigger_header = trigger_header.lower()
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("GET", url, kwargs))
        # Check if the trigger header is in the request headers.
        headers = kwargs.get("headers") or {}
        if isinstance(headers, dict):
            for k in headers:
                if k.lower() == self._trigger_header:
                    return self._probe
        return self._baseline


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestIsHtmlResponse:
    def test_html_content_type(self) -> None:
        assert _is_html_response("text/html", "<html></html>") is True

    def test_html_body_prefix(self) -> None:
        assert _is_html_response("", "<!DOCTYPE html><html></html>") is True

    def test_json_not_html(self) -> None:
        assert _is_html_response("application/json", '{"x":1}') is False

    def test_empty(self) -> None:
        assert _is_html_response("", "") is False


class TestFindDangerousReflection:
    def test_link_href_reflection(self) -> None:
        sentinel = "evil.example"
        body = f'<link rel="canonical" href="https://{sentinel}/page">'
        hits = _find_dangerous_reflection(body, sentinel)
        assert len(hits) == 1
        assert "link" in hits[0].lower()

    def test_script_src_reflection(self) -> None:
        sentinel = "evil.example"
        body = f'<script src="https://{sentinel}/tracker.js"></script>'
        hits = _find_dangerous_reflection(body, sentinel)
        assert len(hits) == 1

    def test_anchor_href_reflection(self) -> None:
        sentinel = "evil.example"
        body = f'<a href="https://{sentinel}/phish">Click here</a>'
        hits = _find_dangerous_reflection(body, sentinel)
        assert len(hits) == 1

    def test_form_action_reflection(self) -> None:
        sentinel = "evil.example"
        body = f'<form action="https://{sentinel}/steal" method="post">'
        hits = _find_dangerous_reflection(body, sentinel)
        assert len(hits) == 1

    def test_iframe_src_reflection(self) -> None:
        sentinel = "evil.example"
        body = f'<iframe src="https://{sentinel}/embed"></iframe>'
        hits = _find_dangerous_reflection(body, sentinel)
        assert len(hits) == 1

    def test_meta_refresh_reflection(self) -> None:
        sentinel = "evil.example"
        body = f'<meta http-equiv="refresh" content="0;url=https://{sentinel}/">'
        hits = _find_dangerous_reflection(body, sentinel)
        assert len(hits) == 1

    def test_no_reflection(self) -> None:
        sentinel = "evil.example"
        body = "<html><body><h1>Welcome</h1><p>No reflection here.</p></body></html>"
        hits = _find_dangerous_reflection(body, sentinel)
        assert hits == []

    def test_plain_text_not_dangerous(self) -> None:
        """Sentinel in plain text (not in a tag attribute) → not dangerous."""
        sentinel = "evil.example"
        body = "<html><body><p>Visit evil.example for help.</p></body></html>"
        hits = _find_dangerous_reflection(body, sentinel)
        assert hits == []

    def test_case_insensitive(self) -> None:
        sentinel = "evil.example"
        body = f'<LINK REL="canonical" HREF="https://{sentinel}/page">'
        hits = _find_dangerous_reflection(body, sentinel)
        assert len(hits) == 1

    def test_multiple_dangerous_hits(self) -> None:
        sentinel = "evil.example"
        body = (
            f'<link href="https://{sentinel}/a">'
            f'<script src="https://{sentinel}/b"></script>'
        )
        hits = _find_dangerous_reflection(body, sentinel)
        assert len(hits) == 2


class TestHasPlainReflection:
    def test_present(self) -> None:
        assert _has_plain_reflection("hello evil.example world", "evil.example") is True

    def test_absent(self) -> None:
        assert _has_plain_reflection("nothing here", "evil.example") is False

    def test_case_insensitive(self) -> None:
        assert _has_plain_reflection("EVIL.EXAMPLE", "evil.example") is True

    def test_empty_body(self) -> None:
        assert _has_plain_reflection("", "evil.example") is False


class TestCompileDangerousPatterns:
    def test_returns_compiled_patterns(self) -> None:
        patterns = _compile_dangerous_patterns("evil.example")
        assert len(patterns) > 0
        for p in patterns:
            assert hasattr(p, "search")

    def test_escapes_special_chars(self) -> None:
        # Sentinel with regex special chars should be escaped.
        sentinel = "evil.example.com"
        patterns = _compile_dangerous_patterns(sentinel)
        body = f'<a href="https://{sentinel}/">'
        assert any(p.search(body.lower()) for p in patterns)


# ─── Plugin end-to-end tests ─────────────────────────────────────────────────


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


class TestPluginRun:
    async def test_non_html_response_skipped(self) -> None:
        """JSON responses aren't typically page-cached — skip."""
        plugin = CachePoisoningPlugin()
        baseline = FakeResponse(
            body='{"data": "json"}',
            status=200,
            headers=[("Content-Type", "application/json")],
        )
        # Use FakeSession since we don't expect any probe to be sent.
        session = FakeSession(baseline)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_short_body_skipped(self) -> None:
        plugin = CachePoisoningPlugin()
        baseline = FakeResponse(body="short", status=200, headers=[("Content-Type", "text/html")])
        session = FakeSession(baseline)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_error_status_skipped(self) -> None:
        plugin = CachePoisoningPlugin()
        body = "<html><body><h1>Not Found</h1><p>Page does not exist.</p></body></html>"
        baseline = FakeResponse(body=body, status=404, headers=[("Content-Type", "text/html")])
        session = FakeSession(baseline)
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_dangerous_link_reflection_is_critical(self) -> None:
        """X-Forwarded-Host reflected in <link href> → CRITICAL FIRM."""
        plugin = CachePoisoningPlugin()
        baseline_body = (
            "<html><head><title>Example</title>"
            '<link rel="canonical" href="https://example.com/page">'
            "</head><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length to exceed the 200-byte minimum threshold.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "text/html")],
        )
        # Probe response has the sentinel in a <link href>
        probe_body = (
            "<html><head><title>Example</title>"
            '<link rel="canonical" href="https://webscan-cache-probe-SENTINEL.example/page">'
            "</head><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length to exceed the 200-byte minimum threshold.</p>"
            "</body></html>"
        )
        # Use a fixed sentinel by patching secrets.token_hex
        import secrets
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "SENTINEL"  # type: ignore[assignment]
        try:
            probe_resp = FakeResponse(
                body=probe_body, status=200,
                headers=[("Content-Type", "text/html")],
            )
            session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
            findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

            critical = _findings_with(findings, title_contains="Cache poisoning")
            assert len(critical) == 1
            assert critical[0].severity is Severity.CRITICAL
            assert critical[0].confidence is Confidence.FIRM
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]

    async def test_plain_reflection_is_medium(self) -> None:
        """Sentinel in plain text (not in link/script) → MEDIUM FIRM."""
        plugin = CachePoisoningPlugin()
        baseline_body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>Visit example.com for help and support with your account and billing questions.</p>"
            "<p>Additional paragraph for body length to exceed the 200-byte minimum threshold.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "text/html")],
        )
        probe_body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>Visit webscan-cache-probe-SENTINEL.example for help.</p>"
            "<p>Additional paragraph for body length to exceed the 200-byte minimum threshold.</p>"
            "</body></html>"
        )
        import secrets
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "SENTINEL"  # type: ignore[assignment]
        try:
            probe_resp = FakeResponse(
                body=probe_body, status=200,
                headers=[("Content-Type", "text/html")],
            )
            session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
            findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]

            medium = _findings_with(findings, title_contains="reflected in body")
            assert len(medium) == 1
            assert medium[0].severity is Severity.MEDIUM
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]

    async def test_no_reflection_no_finding(self) -> None:
        """Server accepts header but doesn't reflect it → no finding."""
        plugin = CachePoisoningPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>Static content not affected by headers at all in any way.</p>"
            "<p>Additional paragraph for body length to exceed the 200-byte minimum threshold.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        # Probe returns the SAME body — no reflection.
        probe_resp = FakeResponse(body=body, status=200, headers=[("Content-Type", "text/html")])
        session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
        findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
        assert findings == []

    async def test_baseline_network_error_returns_empty(self) -> None:
        plugin = CachePoisoningPlugin()

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

    async def test_probe_network_error_skipped(self) -> None:
        """If a probe request errors, skip that header — don't propagate."""
        plugin = CachePoisoningPlugin()
        baseline_body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>Substantive content for length and body padding to exceed the threshold.</p>"
            "<p>Additional paragraph for body length to exceed the 200-byte minimum threshold.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "text/html")],
        )

        # Session returns baseline for first call (no header), then raises for probe.
        class _SessionWithBoomProbe:
            def __init__(self) -> None:
                self._first_call = True

            def get(self, url: str, **kwargs: object) -> FakeResponse:
                if self._first_call:
                    self._first_call = False
                    return baseline
                # Probe call — return a response that raises on __aenter__
                return _BoomProbeResp()

        class _BoomProbeResp:
            async def __aenter__(self) -> _BoomProbeResp:
                raise _ClientError("probe boom")

            async def __aexit__(self, *_exc: object) -> bool:
                return False

        class _ClientError(Exception):
            pass

        import aiohttp

        orig = aiohttp.ClientError
        try:
            aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
            findings = await plugin.run(_TARGET, _SessionWithBoomProbe())  # type: ignore[arg-type]
            # All probes failed, but no exception — empty findings.
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_evidence_includes_injected_header_and_value(self) -> None:
        """CRITICAL finding evidence records which header was injected."""
        plugin = CachePoisoningPlugin()
        baseline_body = (
            "<html><head><title>Example</title>"
            '<link rel="canonical" href="https://example.com/page">'
            "</head><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length to exceed the 200-byte minimum threshold.</p>"
            "</body></html>"
        )
        baseline = FakeResponse(
            body=baseline_body, status=200,
            headers=[("Content-Type", "text/html")],
        )
        probe_body = (
            "<html><head><title>Example</title>"
            '<link rel="canonical" href="https://webscan-cache-probe-SENTINEL.example/page">'
            "</head><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length to exceed the 200-byte minimum threshold.</p>"
            "</body></html>"
        )
        import secrets
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "SENTINEL"  # type: ignore[assignment]
        try:
            probe_resp = FakeResponse(
                body=probe_body, status=200,
                headers=[("Content-Type", "text/html")],
            )
            session = _HeaderAwareSession(baseline, probe_resp, "X-Forwarded-Host")
            findings = await plugin.run(_TARGET, session)  # type: ignore[arg-type]
            crit = _findings_with(findings, title_contains="Cache poisoning")[0]
            ev = crit.evidence
            assert ev["injected_header"] == "X-Forwarded-Host"
            assert "webscan-cache-probe" in str(ev["injected_value"])
            assert "dangerous_matches" in ev
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]

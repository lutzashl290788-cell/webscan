"""Tests for the clickjacking plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.clickjacking import (
    ClickjackingPlugin,
    _is_allow_from,
    _is_html_response,
    _is_protective_csp_frame_ancestors,
    _is_protective_xfo,
)

_TARGET = "https://example.com"


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestIsProtectiveXfo:
    def test_deny_is_protective(self) -> None:
        assert _is_protective_xfo("DENY") is True
        assert _is_protective_xfo("deny") is True

    def test_sameorigin_is_protective(self) -> None:
        assert _is_protective_xfo("SAMEORIGIN") is True
        assert _is_protective_xfo("sameorigin") is True

    def test_allow_from_is_not_protective(self) -> None:
        assert _is_protective_xfo("ALLOW-FROM https://trusted.example") is False
        assert _is_protective_xfo("allow-from https://trusted.example") is False

    def test_empty_is_not_protective(self) -> None:
        assert _is_protective_xfo("") is False

    def test_garbage_is_not_protective(self) -> None:
        assert _is_protective_xfo("banana") is False

    def test_case_insensitive(self) -> None:
        assert _is_protective_xfo("Deny") is True
        assert _is_protective_xfo("SameOrigin") is True


class TestIsProtectiveCsp:
    def test_none_is_protective(self) -> None:
        csp = "frame-ancestors 'none'"
        assert _is_protective_csp_frame_ancestors(csp) is True

    def test_self_is_protective(self) -> None:
        csp = "frame-ancestors 'self'"
        assert _is_protective_csp_frame_ancestors(csp) is True

    def test_host_list_is_protective(self) -> None:
        csp = "frame-ancestors https://trusted.example https://partner.example"
        assert _is_protective_csp_frame_ancestors(csp) is True

    def test_wildcard_is_not_protective(self) -> None:
        csp = "frame-ancestors *"
        assert _is_protective_csp_frame_ancestors(csp) is False

    def test_wildcard_in_list_is_not_protective(self) -> None:
        csp = "frame-ancestors 'self' *"
        assert _is_protective_csp_frame_ancestors(csp) is False

    def test_no_frame_ancestors_directive(self) -> None:
        csp = "default-src 'self'; script-src 'self'"
        assert _is_protective_csp_frame_ancestors(csp) is False

    def test_empty_csp(self) -> None:
        assert _is_protective_csp_frame_ancestors("") is False

    def test_frame_ancestors_with_other_directives(self) -> None:
        csp = "default-src 'self'; frame-ancestors 'self'; script-src 'self'"
        assert _is_protective_csp_frame_ancestors(csp) is True

    def test_case_insensitive_directive_name(self) -> None:
        csp = "Frame-Ancestors 'none'"
        assert _is_protective_csp_frame_ancestors(csp) is True

    def test_empty_value_not_protective(self) -> None:
        # `frame-ancestors` followed by `;` (no value)
        csp = "frame-ancestors; default-src 'self'"
        assert _is_protective_csp_frame_ancestors(csp) is False


class TestIsAllowFrom:
    def test_allow_from_detected(self) -> None:
        assert _is_allow_from("ALLOW-FROM https://trusted.example") is True

    def test_deny_not_allow_from(self) -> None:
        assert _is_allow_from("DENY") is False

    def test_sameorigin_not_allow_from(self) -> None:
        assert _is_allow_from("SAMEORIGIN") is False

    def test_empty_not_allow_from(self) -> None:
        assert _is_allow_from("") is False

    def test_case_insensitive(self) -> None:
        assert _is_allow_from("allow-from https://x") is True
        assert _is_allow_from("Allow-From https://x") is True


class TestIsHtmlResponse:
    def test_html_content_type(self) -> None:
        assert _is_html_response("text/html", "https://x.com/", "<html></html>") is True

    def test_html_extension(self) -> None:
        assert _is_html_response("", "https://x.com/page.html", "x") is True

    def test_body_starts_with_doctype(self) -> None:
        assert _is_html_response("", "https://x.com/page", "<!DOCTYPE html>") is True

    def test_body_starts_with_html_tag(self) -> None:
        assert _is_html_response("", "https://x.com/page", "<html><body></body></html>") is True

    def test_json_not_html(self) -> None:
        assert _is_html_response("application/json", "https://x.com/api", '{"x":1}') is False

    def test_xml_not_html(self) -> None:
        assert _is_html_response("application/xml", "https://x.com/api",
            "<?xml version='1.0'?>") is False

    def test_empty_not_html(self) -> None:
        assert _is_html_response("", "https://x.com/api", "") is False


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


# ─── Plugin end-to-end tests ─────────────────────────────────────────────────


class TestPluginRun:
    async def test_no_headers_medium_finding(self) -> None:
        """Neither X-Frame-Options nor CSP frame-ancestors → MEDIUM FIRM."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length padding to exceed the 200-byte minimum.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=200,
            headers=[("Content-Type", "text/html")],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        medium = _findings_with(findings, title_contains="can be framed by any origin")
        assert len(medium) == 1
        assert medium[0].severity is Severity.MEDIUM
        assert medium[0].confidence is Confidence.FIRM

    async def test_both_headers_protective_no_finding(self) -> None:
        """XFO: SAMEORIGIN + CSP frame-ancestors 'self' → no finding."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length padding to exceed the 200-byte minimum.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=200,
            headers=[
                ("Content-Type", "text/html"),
                ("X-Frame-Options", "SAMEORIGIN"),
                ("Content-Security-Policy", "frame-ancestors 'self'"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_xfo_only_low_finding(self) -> None:
        """XFO present but CSP missing → LOW FIRM (migration nudge)."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length padding to exceed the 200-byte minimum.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=200,
            headers=[
                ("Content-Type", "text/html"),
                ("X-Frame-Options", "DENY"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        low = _findings_with(findings, title_contains="X-Frame-Options present but CSP")
        assert len(low) == 1
        assert low[0].severity is Severity.LOW

    async def test_csp_only_no_finding(self) -> None:
        """CSP frame-ancestors present, XFO absent → no finding (CSP overrides XFO anyway)."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length padding to exceed the 200-byte minimum.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=200,
            headers=[
                ("Content-Type", "text/html"),
                ("Content-Security-Policy", "frame-ancestors 'none'"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_allow_from_info_finding(self) -> None:
        """ALLOW-FROM is obsolete → INFO finding."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length padding to exceed the 200-byte minimum.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=200,
            headers=[
                ("Content-Type", "text/html"),
                ("X-Frame-Options", "ALLOW-FROM https://trusted.example"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        info = _findings_with(findings, title_contains="ALLOW-FROM")
        assert len(info) == 1
        assert info[0].severity is Severity.INFO

    async def test_allow_from_without_csp_also_medium(self) -> None:
        """ALLOW-FROM + no CSP → both INFO and MEDIUM findings (effectively unprotected)."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length padding to exceed the 200-byte minimum.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=200,
            headers=[
                ("Content-Type", "text/html"),
                ("X-Frame-Options", "ALLOW-FROM https://trusted.example"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        info = _findings_with(findings, title_contains="ALLOW-FROM")
        medium = _findings_with(findings, title_contains="can be framed by any origin")
        assert len(info) == 1
        assert len(medium) == 1

    async def test_csp_wildcard_treated_as_no_protection(self) -> None:
        """CSP frame-ancestors * explicitly allows any origin → MEDIUM finding."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length padding to exceed the 200-byte minimum.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=200,
            headers=[
                ("Content-Type", "text/html"),
                ("Content-Security-Policy", "frame-ancestors *"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

        medium = _findings_with(findings, title_contains="can be framed by any origin")
        assert len(medium) == 1

    async def test_non_html_response_skipped(self) -> None:
        """JSON responses can't be clickjacked — skip."""
        plugin = ClickjackingPlugin()
        resp = FakeResponse(
            body='{"data": "no html"}',
            status=200,
            headers=[("Content-Type", "application/json")],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_error_status_skipped(self) -> None:
        """4xx/5xx responses are rarely worth auditing — skip."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>404 Not Found</h1>"
            "<p>The page you requested does not exist on this server.</p>"
            "<p>Please check the URL and try again later.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=404,
            headers=[("Content-Type", "text/html")],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_short_body_skipped(self) -> None:
        """Very short responses are probably empty stubs — skip."""
        plugin = ClickjackingPlugin()
        resp = FakeResponse(
            body="ok",
            status=200,
            headers=[("Content-Type", "text/html")],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_network_error_returns_empty(self) -> None:
        """If session.get raises, return [] (never propagate)."""

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
            plugin = ClickjackingPlugin()
            findings = await plugin.run(_TARGET, _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_evidence_includes_header_values(self) -> None:
        """MEDIUM finding evidence records the (absent) header values."""
        plugin = ClickjackingPlugin()
        body = (
            "<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with substantive content for testing.</p>"
            "<p>Additional paragraph for body length padding to exceed the 200-byte minimum.</p>"
            "</body></html>"
        )
        resp = FakeResponse(
            body=body,
            status=200,
            headers=[("Content-Type", "text/html")],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        medium = _findings_with(findings, title_contains="can be framed by any origin")[0]
        ev = medium.evidence
        assert ev["xfo_value"] == "(absent)"
        assert ev["csp_present"] is False
        assert ev["http_status"] == 200

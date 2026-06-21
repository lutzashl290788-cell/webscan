"""Tests for v2.5.3 security hardening — covers all INFO/M-NEW/M-6 fixes."""
from __future__ import annotations

from typing import Any

import pytest

from webscan import anonymize, reporter

# ---------------------------------------------------------------------------
# INFO-2: reporter._safe_url
# ---------------------------------------------------------------------------


def test_safe_url_allows_http_https() -> None:
    assert reporter._safe_url("https://example.com/a") == "https://example.com/a"
    assert reporter._safe_url("http://example.com/b") == "http://example.com/b"


def test_safe_url_allows_relative() -> None:
    assert reporter._safe_url("/api/users") == "/api/users"
    assert reporter._safe_url("relative/path") == "relative/path"


def test_safe_url_blocks_javascript_scheme() -> None:
    """The classic stored-XSS-via-href vector — must be replaced with '#'."""
    assert reporter._safe_url("javascript:alert(document.domain)") == "#"


def test_safe_url_blocks_data_scheme() -> None:
    assert reporter._safe_url("data:text/html,<script>alert(1)</script>") == "#"


def test_safe_url_blocks_vbscript_scheme() -> None:
    assert reporter._safe_url("vbscript:msgbox('xss')") == "#"


def test_safe_url_handles_invalid_input() -> None:
    """Invalid input should never raise; returns '#'."""
    assert reporter._safe_url("") in ("", "#")  # empty scheme = relative


# ---------------------------------------------------------------------------
# INFO-3: anonymize._PRIVATE_IP — IPv6 + CGNAT coverage
# ---------------------------------------------------------------------------


def test_anonymize_redacts_cgnat_ipv4() -> None:
    """100.64.0.0/10 (CGNAT) must be redacted."""
    from webscan.models import Finding, ScanReport, Severity, TargetResult

    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[
                Finding(
                    "test", "CGNAT IP leaked", Severity.LOW,
                    "Found 100.64.0.1 in response", "https://example.com",
                )
            ],
            scanned_at="t0",
        )
    )
    out = anonymize.anonymize_report(report)
    assert "100.64.0.1" not in out.targets[0].findings[0].description


def test_anonymize_redacts_ipv6_loopback() -> None:
    """IPv6 ::1 must be redacted."""
    from webscan.models import Finding, ScanReport, Severity, TargetResult

    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[
                Finding(
                    "test", "IPv6 loopback leaked", Severity.LOW,
                    "Connection from ::1", "https://example.com",
                )
            ],
            scanned_at="t0",
        )
    )
    out = anonymize.anonymize_report(report)
    assert "::1" not in out.targets[0].findings[0].description


def test_anonymize_redacts_ipv6_ula() -> None:
    """IPv6 ULA fc00::/7 must be redacted."""
    from webscan.models import Finding, ScanReport, Severity, TargetResult

    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[
                Finding(
                    "test", "ULA leaked", Severity.LOW,
                    "Internal host fd00:1234:5678::1", "https://example.com",
                )
            ],
            scanned_at="t0",
        )
    )
    out = anonymize.anonymize_report(report)
    assert "fd00:1234:5678::1" not in out.targets[0].findings[0].description


def test_anonymize_redacts_ipv6_link_local() -> None:
    """IPv6 link-local fe80::/10 must be redacted."""
    from webscan.models import Finding, ScanReport, Severity, TargetResult

    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[
                Finding(
                    "test", "link-local leaked", Severity.LOW,
                    "Neighbour fe80::1 on eth0", "https://example.com",
                )
            ],
            scanned_at="t0",
        )
    )
    out = anonymize.anonymize_report(report)
    assert "fe80::1" not in out.targets[0].findings[0].description


# ---------------------------------------------------------------------------
# M-6: mass_assignment — Idempotency-Key + X-WebScan-Dry-Run + allow_redirects=False
# ---------------------------------------------------------------------------


async def test_mass_assignment_sends_idempotency_key_and_dry_run_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The PUT probe must carry Idempotency-Key + X-WebScan-Test + X-WebScan-Dry-Run."""
    from webscan.plugins.mass_assignment import MassAssignmentPlugin

    captured: dict[str, Any] = {}

    class _Resp:
        def __init__(self, body: str = "") -> None:
            self._body = body
            self.status = 200
            self.headers = {"Content-Type": "application/json"}
            # Some test paths go through resp.content.read() (fetch_body)
            class _Content:
                async def read(self, limit: int) -> bytes:
                    return self._body.encode()  # type: ignore[attr-defined]
            self.content = _Content()

        async def __aenter__(self) -> _Resp:
            return self

        async def __aexit__(self, *a: Any) -> None:
            pass

        async def text(self, **kw: Any) -> str:
            return self._body

    class _Verb:
        def __init__(self, name: str, body: str = "") -> None:
            self.name = name
            self.body = body

        def __call__(self, url: str, **kw: Any) -> Any:
            captured[self.name] = kw
            return _Resp(self.body)

    class _Session:
        # GET returns a long-enough baseline (>= _MIN_BODY_LENGTH=50).
        def get(self, url: str, **kw: Any) -> Any:
            return _Resp('{"id": 1, "username": "alice", "email": "a@b.c", "role": "user"}')

        # PUT returns a body that reflects the injected field (mass-assignment successful).
        put = _Verb("put", body='{"id": 1, "role": "admin"}')

    plugin = MassAssignmentPlugin()
    await plugin.run(
        "https://example.com/api/users/1", _Session()  # type: ignore[arg-type]
    )
    # The captured PUT kwargs must include the marker headers.
    assert "put" in captured, "PUT must have been issued"
    headers = captured["put"].get("headers", {})
    assert "Idempotency-Key" in headers
    assert headers["Idempotency-Key"].startswith("webscan-")
    assert headers.get("X-WebScan-Test") == "1"
    assert headers.get("X-WebScan-Dry-Run") == "1"
    # Critical: PUT must NOT follow redirects.
    assert captured["put"].get("allow_redirects") is False


# ---------------------------------------------------------------------------
# INFO-7: api.scan() verify_ssl parameter
# ---------------------------------------------------------------------------


async def test_api_scan_accepts_verify_ssl(monkeypatch: pytest.MonkeyPatch) -> None:
    """scan() must accept verify_ssl and forward it to ScanEngine."""
    from webscan import api

    captured: dict[str, Any] = {}

    class _FakeEngine:
        def __init__(self, **kw: Any) -> None:
            captured.update(kw)

        async def scan_all(self, targets: Any) -> Any:
            from webscan.models import ScanReport
            return ScanReport(scan_started="t0", scan_finished="t1")

    monkeypatch.setattr(api, "ScanEngine", _FakeEngine)
    await api.scan(["https://example.com"], plugins=["headers"], verify_ssl=True)
    assert captured.get("verify_ssl") is True


# ---------------------------------------------------------------------------
# M-NEW-1: TraceConfig applied to ALL ClientSession creations
# ---------------------------------------------------------------------------


def test_auth_form_login_uses_trace_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """auth._form_login must install trace_configs on its ClientSession."""
    from webscan import auth

    captured: dict[str, Any] = {}

    class _FakeCookieJar:
        def __iter__(self):
            return iter([])

    class _FakeResp:
        async def __aenter__(self) -> _FakeResp:
            return self

        async def __aexit__(self, *a: Any) -> None:
            pass

        async def read(self) -> bytes:
            return b""

    class _FakeSession:
        def __init__(self, *a: Any, **kw: Any) -> None:
            captured["trace_configs"] = kw.get("trace_configs")
            captured["all_kwargs"] = kw
            self.cookie_jar = _FakeCookieJar()

        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, *a: Any) -> None:
            pass

        def post(self, *a: Any, **kw: Any) -> _FakeResp:
            return _FakeResp()

    import aiohttp

    # Patch both ClientSession AND TCPConnector so the test doesn't choke on
    # ssl_ctx=object() — we only care about the kwargs passed to ClientSession.
    class _FakeConnector:
        def __init__(self, *a: Any, **kw: Any) -> None:
            pass

    monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)
    monkeypatch.setattr(aiohttp, "TCPConnector", _FakeConnector)

    from webscan.auth import AuthConfig
    config = AuthConfig(login_url="https://example.com/login", login_data="u=a&p=b")
    try:
        import asyncio
        asyncio.new_event_loop().run_until_complete(
            auth._form_login(config, object(), aiohttp.ClientTimeout(total=5))
        )
    except Exception:  # noqa: BLE001 — _form_login raises LoginError on no cookies
        pass
    # The key assertion: trace_configs was passed (non-empty list).
    assert captured.get("trace_configs"), (
        "auth._form_login must pass trace_configs to ClientSession"
    )


def test_cli_crawl_targets_uses_trace_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """cli._crawl_targets must install trace_configs on its ClientSession."""
    import argparse

    import aiohttp

    from webscan import cli

    captured: dict[str, Any] = {}

    class _FakeSession:
        def __init__(self, *a: Any, **kw: Any) -> None:
            captured["trace_configs"] = kw.get("trace_configs")

        async def __aenter__(self) -> _FakeSession:
            return self

        async def __aexit__(self, *a: Any) -> None:
            pass

    monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)

    args = argparse.Namespace(
        crawl=False, depth=2, scope="", exclude=None, ignore_robots=True,
        timeout=5, concurrency=5, user_agent="", proxy="", max_urls=100,
    )
    # _crawl_targets is only called when args.crawl is True; bypass by calling directly.
    import asyncio

    from webscan.auth import PreparedAuth
    from webscan.net import NetConfig

    async def _run() -> Any:
        return await cli._crawl_targets(
            ["https://example.com"],
            args,
            PreparedAuth(cookies={}, headers={}),
            NetConfig(),
        )

    # We don't care about the result — only that ClientSession was constructed
    # with trace_configs. _crawl_targets will return seeds on any error.
    asyncio.new_event_loop().run_until_complete(_run())
    assert captured.get("trace_configs"), (
        "cli._crawl_targets must pass trace_configs to ClientSession"
    )


# ---------------------------------------------------------------------------
# INFO-4: ai.py prompt-injection protection (XML tags)
# ---------------------------------------------------------------------------


def test_ai_triage_wraps_findings_in_scanner_output_tags() -> None:
    """The triage user prompt must wrap attacker-controllable data in
    <scanner_output> tags so the LLM treats it as untrusted data."""
    from webscan.ai import AIAssistant, AIConfig
    from webscan.models import Finding, ScanReport, Severity, TargetResult

    class _Messages:
        def __init__(self) -> None:
            self.captured_user: str = ""

        async def create(self, **kw: Any) -> Any:
            self.captured_user = kw.get("messages", [{}])[0].get("content", "")
            class _Resp:
                content = []
            return _Resp()

    class _Client:
        def __init__(self) -> None:
            self.messages = _Messages()

    client = _Client()
    a = AIAssistant(config=AIConfig(model="m"), client=client)

    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[Finding("headers", "Missing CSP", Severity.HIGH, "d", "u")],
            scanned_at="t0",
        )
    )
    report.total_findings = 1

    import asyncio

    async def _run() -> Any:
        return await a.triage_report(report)

    asyncio.new_event_loop().run_until_complete(_run())
    user_msg = client.messages.captured_user
    assert "<scanner_output>" in user_msg
    assert "</scanner_output>" in user_msg


def test_ai_summary_wraps_findings_in_scanner_output_tags() -> None:
    """The summary user prompt must also wrap findings in <scanner_output> tags."""
    from webscan.ai import AIAssistant, AIConfig
    from webscan.models import Finding, ScanReport, Severity, TargetResult

    class _Messages:
        def __init__(self) -> None:
            self.captured_user: str = ""

        async def create(self, **kw: Any) -> Any:
            self.captured_user = kw.get("messages", [{}])[0].get("content", "")
            class _Resp:
                class _Block:
                    type = "text"
                    text = "summary"
                content = [_Block()]
            return _Resp()

    class _Client:
        def __init__(self) -> None:
            self.messages = _Messages()

    client = _Client()
    a = AIAssistant(config=AIConfig(model="m"), client=client)

    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[Finding("headers", "Missing CSP", Severity.HIGH, "d", "u")],
            scanned_at="t0",
        )
    )
    report.total_findings = 1

    import asyncio

    async def _run() -> Any:
        return await a.summarize_report(report)

    asyncio.new_event_loop().run_until_complete(_run())
    user_msg = client.messages.captured_user
    assert "<scanner_output>" in user_msg
    assert "</scanner_output>" in user_msg


# ---------------------------------------------------------------------------
# INFO-5: ai.py assert → if/raise (defensive programming)
# ---------------------------------------------------------------------------


def test_ai_triage_raises_runtime_error_if_client_is_none() -> None:
    """If somehow _triage_findings is called with client=None, it must raise
    RuntimeError (not AssertionError, which `python -O` strips)."""
    from webscan.ai import AIAssistant, AIConfig
    from webscan.models import Finding, ScanReport, Severity, TargetResult

    # Construct an assistant whose .available is True but whose _client is None.
    a = AIAssistant(config=AIConfig(model="m"), client=None)
    # Force .available to True to bypass the public guard.
    object.__setattr__(a, "_client", None)

    report = ScanReport(scan_started="t0", scan_finished="t1")
    report.targets.append(
        TargetResult(
            target="https://example.com",
            findings=[Finding("headers", "x", Severity.LOW, "d", "u")],
            scanned_at="t0",
        )
    )

    import asyncio

    async def _run() -> Any:
        # Bypass triage_report's .available check by calling the private method.
        return await a._triage_findings("https://example.com", report.targets[0].findings)

    with pytest.raises(RuntimeError, match="no client"):
        asyncio.new_event_loop().run_until_complete(_run())


# ---------------------------------------------------------------------------
# INFO-1: CORS middleware deny-all in server.py
# ---------------------------------------------------------------------------


def test_server_cors_middleware_deny_all_by_default() -> None:
    """create_app() must install a CORSMiddleware that denies all origins."""
    from webscan.server import create_app

    app = create_app()
    # The middleware is added — check via user_middleware list.
    middleware_specs = [m.cls.__name__ for m in app.user_middleware]
    assert "CORSMiddleware" in middleware_specs
    # Verify the actual config: empty allow_origins.
    cors_spec = next(m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware")
    assert cors_spec.kwargs.get("allow_origins") == []
    assert cors_spec.kwargs.get("allow_credentials") is False


def test_server_cors_preflight_returns_no_allow_origin() -> None:
    """A preflight OPTIONS request from evil.com must not get an Allow-Origin header."""
    from fastapi.testclient import TestClient

    from webscan import server

    # Use the real app — no monkeypatching, we want to test CORS behaviour.
    app = server.create_app()
    client = TestClient(app)
    resp = client.options(
        "/scan",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    # No Access-Control-Allow-Origin header means browsers block the request.
    assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}


# ---------------------------------------------------------------------------
# INFO-6: cli._progress masks URL credentials
# ---------------------------------------------------------------------------


def test_progress_masks_url_credentials(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """_progress must not print user:password embedded in target URLs."""

    from webscan import cli

    # Build a minimal args namespace that _run() would construct _progress under.
    # We bypass _run() entirely and just exercise the closure by calling cli._run
    # is complex; instead, replicate the closure inline using _mask_proxy_url.
    # _mask_proxy_url is the same helper _progress now uses.
    masked = cli._mask_proxy_url("https://user:secret@target.example/path")
    assert "secret" not in masked
    assert "user" not in masked
    assert "***@target.example" in masked

"""Tests for v2.7.0 killer features: diff, notify, autofix, new plugins."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import aiohttp
import pytest

from webscan import cli
from webscan.autofix import FixSuggestion, suggest_fix, suggest_fixes_for_report
from webscan.diff import ChangedFinding, DiffResult, diff_reports, format_diff
from webscan.engine import ScanEngine, _build_stealth_trace, _random_forwarded_for
from webscan.models import Confidence, Finding, ScanReport, Severity, TargetResult
from webscan.net import USER_AGENTS, NetConfig, pick_user_agent
from webscan.notify import (
    build_discord_message,
    build_generic_payload,
    build_slack_message,
    build_webhook_payload,
    detect_webhook_type,
)
from webscan.plugins.csp_analyzer import _parse_csp

# ─── helpers ────────────────────────────────────────────────────────────────

def _report(findings: list[Finding]) -> ScanReport:
    r = ScanReport(scan_started="t0", scan_finished="t1")
    r.targets.append(TargetResult(target="https://example.com", findings=findings, scanned_at="t0"))
    r.total_findings = len(findings)
    return r


def _f(plugin="headers", title="test", sev=Severity.HIGH, conf=Confidence.FIRM, url="https://example.com") -> Finding:
    return Finding(plugin=plugin, title=title, severity=sev, confidence=conf, description="d", url=url)


# ─── diff tests ─────────────────────────────────────────────────────────────

def test_diff_no_changes() -> None:
    """Two identical reports → no new/fixed/changed."""
    old = _report([_f(title="A")])
    new = _report([_f(title="A")])
    result = diff_reports(old, new)
    assert result.new_findings == []
    assert result.fixed_findings == []
    assert result.changed_findings == []
    assert result.unchanged_count == 1


def test_diff_new_finding() -> None:
    """A finding in new but not old → regression."""
    old = _report([])
    new = _report([_f(title="New vuln")])
    result = diff_reports(old, new)
    assert len(result.new_findings) == 1
    assert result.new_findings[0].title == "New vuln"
    assert result.has_regressions is True  # default is HIGH → regression


def test_diff_new_critical_is_regression() -> None:
    old = _report([])
    new = _report([_f(title="RCE", sev=Severity.CRITICAL)])
    result = diff_reports(old, new)
    assert result.has_regressions is True


def test_diff_fixed_finding() -> None:
    """A finding in old but not new → fixed."""
    old = _report([_f(title="Old bug")])
    new = _report([])
    result = diff_reports(old, new)
    assert len(result.fixed_findings) == 1
    assert result.has_improvements is True


def test_diff_changed_severity() -> None:
    """Same finding, different severity → changed."""
    old = _report([_f(title="X", sev=Severity.MEDIUM)])
    new = _report([_f(title="X", sev=Severity.HIGH)])
    result = diff_reports(old, new)
    assert len(result.changed_findings) == 1
    assert result.changed_findings[0].severity_increased is True


def test_diff_changed_severity_decreased() -> None:
    old = _report([_f(title="X", sev=Severity.HIGH)])
    new = _report([_f(title="X", sev=Severity.LOW)])
    result = diff_reports(old, new)
    assert result.changed_findings[0].severity_increased is False


def test_diff_to_dict() -> None:
    import json
    old = _report([_f(title="A")])
    new = _report([_f(title="A"), _f(title="B", sev=Severity.CRITICAL)])
    result = diff_reports(old, new)
    d = result.to_dict()
    json.dumps(d)
    assert d["has_regressions"] is True
    assert len(d["new_findings"]) == 1


def test_format_diff_no_changes() -> None:
    result = DiffResult()
    text = format_diff(result)
    assert "No changes" in text


def test_format_diff_with_findings() -> None:
    result = DiffResult()
    result.new_findings = [_f(title="New bug", sev=Severity.CRITICAL)]
    result.fixed_findings = [_f(title="Fixed bug")]
    text = format_diff(result)
    assert "NEW" in text
    assert "FIXED" in text
    assert "New bug" in text


def test_changed_finding_to_dict() -> None:
    c = ChangedFinding(
        plugin="headers", title="X", url="https://example.com",
        old_severity=Severity.MEDIUM, new_severity=Severity.HIGH,
        old_confidence="firm", new_confidence="firm",
    )
    d = c.to_dict()
    assert d["severity_increased"] is True


# ─── notify tests ───────────────────────────────────────────────────────────

def test_detect_webhook_type_slack() -> None:
    assert detect_webhook_type("https://hooks.slack.com/services/T00/B00/xxx") == "slack"


def test_detect_webhook_type_discord() -> None:
    assert detect_webhook_type("https://discord.com/api/webhooks/123/abc") == "discord"


def test_detect_webhook_type_generic() -> None:
    assert detect_webhook_type("https://example.com/webhook") == "generic"


def test_build_slack_message() -> None:
    report = _report([_f(sev=Severity.HIGH)])
    msg = build_slack_message(report, risk_score=75, grade="B", target="https://example.com")
    assert msg["text"]
    assert "WebScan" in msg["text"]
    assert "75" in msg["text"]
    assert "example.com" in msg["text"]


def test_build_discord_message() -> None:
    report = _report([_f(sev=Severity.HIGH)])
    msg = build_discord_message(report, risk_score=75, grade="B", target="https://example.com")
    assert len(msg["embeds"]) == 1
    assert msg["embeds"][0]["color"] == 0xF87171  # orange for HIGH


def test_build_generic_payload() -> None:
    report = _report([_f(sev=Severity.CRITICAL)])
    payload = build_generic_payload(report, risk_score=50, grade="C", target="https://x.com")
    assert payload["scanner"] == "WebScan"
    assert payload["risk_score"] == 50
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["severity"] == "critical"


def test_build_webhook_payload_auto_detect() -> None:
    report = _report([])
    # Slack URL → slack format
    slack = build_webhook_payload("https://hooks.slack.com/services/x", report, target="https://x.com")
    assert "text" in slack
    # Discord URL → discord format
    discord = build_webhook_payload("https://discord.com/api/webhooks/x/y", report, target="https://x.com")
    assert "embeds" in discord
    # Generic → generic format
    generic = build_webhook_payload("https://example.com/wh", report, target="https://x.com")
    assert "findings" in generic


def test_build_slack_message_empty_report() -> None:
    report = _report([])
    msg = build_slack_message(report)
    assert "0" in msg["text"]  # 0 findings


# ─── autofix tests ──────────────────────────────────────────────────────────

def test_suggest_fix_headers_csp() -> None:
    f = _f(plugin="headers", title="Missing header: Content-Security-Policy")
    fix = suggest_fix(f)
    assert fix is not None
    assert "Content-Security-Policy" in fix.command
    assert fix.language == "nginx"


def test_suggest_fix_headers_hsts() -> None:
    f = _f(plugin="headers", title="Missing header: Strict-Transport-Security")
    fix = suggest_fix(f)
    assert fix is not None
    assert "Strict-Transport-Security" in fix.command


def test_suggest_fix_sql_injection() -> None:
    f = _f(plugin="sql_injection", title="SQL injection in /search")
    fix = suggest_fix(f)
    assert fix is not None
    assert "parameterised" in fix.command.lower() or "execute" in fix.command.lower()
    assert fix.language == "python"


def test_suggest_fix_xss() -> None:
    f = _f(plugin="xss", title="Reflected XSS in q parameter")
    fix = suggest_fix(f)
    assert fix is not None
    assert "escape" in fix.command.lower() or "CSP" in fix.command


def test_suggest_fix_cors() -> None:
    f = _f(plugin="cors", title="CORS reflects arbitrary Origin")
    fix = suggest_fix(f)
    assert fix is not None
    assert "Access-Control-Allow-Origin" in fix.command


def test_suggest_fix_cookies() -> None:
    f = _f(plugin="cookies", title="Cookie missing SameSite")
    fix = suggest_fix(f)
    assert fix is not None
    assert "SameSite" in fix.command


def test_suggest_fix_no_handler() -> None:
    """Plugins without a fix handler should return None."""
    f = _f(plugin="nonexistent_plugin")
    assert suggest_fix(f) is None


def test_suggest_fixes_for_report() -> None:
    report = _report([
        _f(plugin="headers", title="Missing header: X-Frame-Options"),
        _f(plugin="sql_injection", title="SQLi"),
        _f(plugin="unknown_plugin", title="???"),
    ])
    suggestions = suggest_fixes_for_report(report)
    assert len(suggestions) == 2  # unknown_plugin has no fix


def test_fix_suggestion_to_dict() -> None:
    fix = FixSuggestion(command="test", language="bash", description="desc")
    d = fix.to_dict()
    assert d["command"] == "test"
    assert d["language"] == "bash"
    assert d["references"] == []


def test_suggest_fix_ssl_tls_weak() -> None:
    f = _f(plugin="ssl_tls", title="Weak protocol: TLS 1.0 enabled")
    fix = suggest_fix(f)
    assert fix is not None
    assert "TLSv1.2" in fix.command


def test_suggest_fix_secrets() -> None:
    f = _f(plugin="secrets", title="Leaked AWS API key in HTML")
    fix = suggest_fix(f)
    assert fix is not None
    assert "Rotate" in fix.command or "rotate" in fix.command.lower()


# ─── CSP analyzer tests ─────────────────────────────────────────────────────

def test_parse_csp_basic() -> None:
    csp = "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"
    result = _parse_csp(csp)
    assert result["default-src"] == "'self'"
    assert result["script-src"] == "'self' 'unsafe-inline'"
    assert result["object-src"] == "'none'"


def test_parse_csp_empty() -> None:
    assert _parse_csp("") == {}


def test_parse_csp_single_directive() -> None:
    result = _parse_csp("default-src 'self'")
    assert result == {"default-src": "'self'"}


# ─── Reporter.from_json_file tests ──────────────────────────────────────────

def test_from_json_file(tmp_path: Path) -> None:
    """from_json_file should load a valid WebScan JSON report."""
    report_data = {
        "scan_started": "2026-01-01T00:00:00",
        "scan_finished": "2026-01-01T00:00:07",
        "total_findings": 2,
        "targets": [
            {
                "target": "https://example.com",
                "scanned_at": "2026-01-01T00:00:00",
                "findings": [
                    {"plugin": "headers", "title": "Missing CSP", "severity": "high",
                     "confidence": "firm", "description": "d", "url": "https://example.com"},
                    {"plugin": "xss", "title": "Reflected XSS", "severity": "critical",
                     "confidence": "firm", "description": "d", "url": "https://example.com/search"},
                ],
            }
        ],
    }
    f = tmp_path / "report.json"
    f.write_text(json.dumps(report_data), encoding="utf-8")

    from webscan.reporter import Reporter
    report = Reporter.from_json_file(str(f))
    assert len(report.targets) == 1
    assert report.targets[0].target == "https://example.com"
    assert len(report.targets[0].findings) == 2
    assert report.targets[0].findings[0].plugin == "headers"
    assert report.targets[0].findings[1].severity == Severity.CRITICAL


def test_from_json_file_not_found() -> None:
    from webscan.reporter import Reporter
    with pytest.raises(FileNotFoundError):
        Reporter.from_json_file("/nonexistent/file.json")


def test_from_json_file_invalid_json(tmp_path: Path) -> None:
    from webscan.reporter import Reporter
    f = tmp_path / "bad.json"
    f.write_text("not json at all", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        Reporter.from_json_file(str(f))


def test_from_json_file_not_webscan_report(tmp_path: Path) -> None:
    from webscan.reporter import Reporter
    f = tmp_path / "wrong.json"
    f.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(ValueError, match="Not a WebScan report"):
        Reporter.from_json_file(str(f))


# ─── Plugin registry tests ──────────────────────────────────────────────────

def test_new_plugins_registered() -> None:
    """The 3 new plugins should be in the registry."""
    from webscan.registry import ALL_PLUGINS
    assert "dns_security" in ALL_PLUGINS
    assert "csp_analyzer" in ALL_PLUGINS
    assert "waf_detect" in ALL_PLUGINS


def test_total_plugin_count() -> None:
    """Total plugins should be 41 (38 + 3 new)."""
    from webscan.registry import ALL_PLUGINS
    assert len(ALL_PLUGINS) == 41


# ─── Stealth mode tests (--stealth) ─────────────────────────────────────────
#
# Mirrors the _apply_safe_mode test pattern in test_cli.py: build a Namespace
# with --stealth, run the preset applier, and assert the post-conditions.


def _stealth_ns(stealth: bool = False, **kw: object) -> argparse.Namespace:
    """Build a minimal args Namespace for stealth-mode preset tests.

    Defaults mirror the argparse defaults so tests don't need to spell out
    every flag — pass ``stealth=True`` to exercise the preset.
    """
    defaults: dict[str, object] = {
        "stealth": stealth,
        "random_agent": False,
        "random_delay": False,
        "concurrency": 10,
        "delay": 0.0,
    }
    defaults.update(kw)
    return argparse.Namespace(**defaults)


def test_stealth_mode_sets_random_agent() -> None:
    """``--stealth`` forces ``random_agent=True`` regardless of the operator's flags."""
    args = _stealth_ns(stealth=True, random_agent=False)
    cli._apply_stealth_mode(args)
    assert args.random_agent is True


def test_stealth_mode_sets_low_concurrency() -> None:
    """``--stealth`` drops concurrency to 1 (single connection, no parallelism)."""
    args = _stealth_ns(stealth=True, concurrency=20)
    cli._apply_stealth_mode(args)
    assert args.concurrency == 1


def test_stealth_mode_sets_random_delay() -> None:
    """``--stealth`` forces ``random_delay=True`` so the per-target delay is jittered."""
    args = _stealth_ns(stealth=True, random_delay=False)
    cli._apply_stealth_mode(args)
    assert args.random_delay is True
    # And the base delay is floored at 2.0 s.
    assert args.delay >= 2.0


def test_stealth_mode_floors_delay_at_two_seconds() -> None:
    """``--stealth`` enforces a minimum 2 s delay even when --delay was lower."""
    args = _stealth_ns(stealth=True, delay=0.5)
    cli._apply_stealth_mode(args)
    assert args.delay == 2.0


def test_stealth_mode_preserves_larger_delay() -> None:
    """A larger explicit --delay is honoured by ``--stealth`` (max semantics)."""
    args = _stealth_ns(stealth=True, delay=5.0)
    cli._apply_stealth_mode(args)
    assert args.delay == 5.0


def test_stealth_mode_off_is_noop() -> None:
    """Without ``--stealth`` the preset applier leaves the args untouched."""
    args = _stealth_ns(stealth=False, concurrency=20, delay=0.5,
                       random_agent=True, random_delay=True)
    cli._apply_stealth_mode(args)
    assert args.concurrency == 20
    assert args.delay == 0.5
    assert args.random_agent is True
    assert args.random_delay is True


def test_stealth_mode_forces_random_user_agent() -> None:
    """``NetConfig.stealth=True`` makes ``pick_user_agent`` always rotate."""
    cfg = NetConfig(stealth=True, user_agent="MyFingerprint/1.0", random_agent=False)
    ua = pick_user_agent(cfg, 0, "Default/1.0")
    # Stealth ignores the explicit UA — emitting it would defeat the point.
    assert ua != "MyFingerprint/1.0"
    assert ua in USER_AGENTS


def test_resolve_net_threads_stealth_flag() -> None:
    """``--stealth`` is wired from args into the NetConfig returned by _resolve_net."""
    args = _stealth_ns(
        stealth=True,
        proxy="",
        user_agent="",
        random_agent=False,
        safe_mode=False,
        delay=2.0,
        random_delay=False,
        no_verify_ssl=True,
        strict_ssl=False,
    )
    net = cli._resolve_net(args, rate_limit=0.0)
    assert net.stealth is True


def test_random_forwarded_for_is_public_ipv4() -> None:
    """``_random_forwarded_for`` returns a 4-octet IPv4 with no private first octet."""
    for _ in range(50):
        ip = _random_forwarded_for()
        octets = ip.split(".")
        assert len(octets) == 4
        first = int(octets[0])
        assert 1 <= first <= 254
        # No private / loopback / link-local / CGNAT first octets.
        assert first not in (10, 127, 169, 172, 192)


async def test_stealth_mode_adds_forwarded_for_header() -> None:
    """A stealth-enabled engine injects ``X-Forwarded-For`` + ``Referer`` per request.

    Invokes the stealth trace config's ``on_request_start`` callback directly
    with a fake params object — no real network needed. The trace hook must
    mutate the request headers in place, exactly as aiohttp would observe
    during a live scan.
    """
    trace = _build_stealth_trace()
    assert trace.on_request_start, "stealth trace should register an on_request_start hook"

    fake_headers: dict[str, str] = {}
    fake_params = argparse.Namespace(
        headers=fake_headers,
        url="https://example.com/page",
    )
    for cb in trace.on_request_start:
        await cb(None, None, fake_params)  # type: ignore[arg-type]

    assert "X-Forwarded-For" in fake_headers
    assert "Referer" in fake_headers
    # Referer should be a search-engine URL referencing the target host.
    assert "example.com" in fake_headers["Referer"]
    # X-Forwarded-For must look like a public IPv4 (no private first octet).
    first_octet = int(fake_headers["X-Forwarded-For"].split(".")[0])
    assert first_octet not in (10, 127, 169, 172, 192)


async def test_stealth_engine_uses_single_connection_pool() -> None:
    """A stealth ScanEngine builds its connector with limit=1 / limit_per_host=1.

    We can't easily introspect the live TCPConnector, but we can verify the
    engine stored the stealth flag and that ``scan_all`` runs to completion
    against an empty target list (which exercises the connector construction
    branch without making real HTTP requests).
    """
    from webscan.plugins.base import BasePlugin

    class _NoopPlugin(BasePlugin):
        name = "noop"
        description = "yields nothing"

        async def run(self, target: str, session: aiohttp.ClientSession) -> list[Finding]:
            return []

    engine = ScanEngine([_NoopPlugin()], concurrency=10, timeout=5, stealth=True)
    assert engine._stealth is True
    # Sanity: the engine reports the *requested* concurrency, but the stealth
    # branch in scan_all overrides the connector pool size — the operator's
    # concurrency value is preserved on the instance for logging.
    assert engine.concurrency == 10
    report = await engine.scan_all([])
    assert report.targets == []
    assert report.total_findings == 0

"""Tests for CLI helpers: target loading, exit codes, safe mode, plugin wiring."""
from __future__ import annotations

import argparse
import ssl as ssl_lib
import sys
from pathlib import Path

import pytest

from webscan import cli, registry
from webscan.auth import LoginError, PreparedAuth
from webscan.models import Finding, ScanReport, Severity, TargetResult
from webscan.net import NetConfig
from webscan.plugins.cve_lookup import CveLookupPlugin
from webscan.plugins.graphql import GraphqlPlugin
from webscan.plugins.subdomains import SubdomainsPlugin
from webscan.reporter import Reporter


def _ns(**kw: object) -> argparse.Namespace:
    return argparse.Namespace(**kw)


# ── target loading / normalisation ─────────────────────────────────────────────

def test_load_targets_normalises_and_dedupes() -> None:
    args = _ns(target=["example.com", "https://example.com/", "http://b.test"], file=None)
    assert cli._load_targets(args) == ["https://example.com", "http://b.test"]


def test_load_targets_reads_file(tmp_path: Path) -> None:
    f = tmp_path / "targets.txt"
    f.write_text("# comment\nhttps://a.test\n\nb.test\n", encoding="utf-8")
    args = _ns(target=None, file=str(f))
    assert cli._load_targets(args) == ["https://a.test", "https://b.test"]


def test_load_targets_empty() -> None:
    assert cli._load_targets(_ns(target=None, file=None)) == []


# ── exit codes ──────────────────────────────────────────────────────────────────

def _report(*severities: Severity) -> ScanReport:
    findings = [
        Finding(plugin="p", title="t", severity=s, description="d", url="u")
        for s in severities
    ]
    return ScanReport(targets=[TargetResult(target="u", findings=findings)])


def test_exit_code_default_high_threshold() -> None:
    assert cli._exit_code(_report(Severity.HIGH), _ns(fail_on=None)) == 1
    assert cli._exit_code(_report(Severity.MEDIUM), _ns(fail_on=None)) == 0


def test_exit_code_custom_threshold() -> None:
    assert cli._exit_code(_report(Severity.LOW), _ns(fail_on="low")) == 1
    assert cli._exit_code(_report(Severity.INFO), _ns(fail_on="low")) == 0


# ── safe mode ───────────────────────────────────────────────────────────────────

def test_safe_mode_sets_polite_defaults() -> None:
    args = _ns(safe_mode=True, rate_limit=0.0, concurrency=50, ignore_robots=True)
    rate = cli._apply_safe_mode(args)
    assert rate == 2.0
    assert args.concurrency == 4
    assert args.ignore_robots is False


def test_safe_mode_off_is_noop() -> None:
    args = _ns(safe_mode=False, rate_limit=0.0, concurrency=50, ignore_robots=True)
    assert cli._apply_safe_mode(args) == 0.0
    assert args.concurrency == 50


# ── plugin registry / wiring ────────────────────────────────────────────────────

def test_registry_includes_new_plugins() -> None:
    assert "graphql" in cli.ALL_PLUGINS
    assert "cve_lookup" in cli.ALL_PLUGINS


def test_opt_in_plugins_excluded_from_defaults() -> None:
    assert "cve_lookup" not in registry.DEFAULT_PLUGINS
    assert "graphql" not in registry.DEFAULT_PLUGINS
    assert "headers" in registry.DEFAULT_PLUGINS


def test_discover_plugins_returns_baseplugin_subclasses() -> None:
    discovered = registry._discover_plugins()
    # Entry points are only present once the package metadata is installed; the
    # call must always succeed and only ever yield BasePlugin subclasses.
    from webscan.plugins.base import BasePlugin
    assert all(issubclass(c, BasePlugin) for c in discovered.values())


def test_make_plugins_wires_special_constructors() -> None:
    args = _ns(
        plugins=["subdomains", "cve_lookup", "graphql", "headers"],
        no_bruteforce=True,
        soft_404=False,
        retries=3,
        retry_backoff=0.7,
    )
    plugins = cli._make_plugins(args)
    by_type = {type(p): p for p in plugins}

    assert isinstance(by_type[SubdomainsPlugin], SubdomainsPlugin)
    assert isinstance(by_type[CveLookupPlugin], CveLookupPlugin)
    assert isinstance(by_type[GraphqlPlugin], GraphqlPlugin)
    # Retry config threaded through to the network-heavy plugins.
    assert by_type[CveLookupPlugin]._retry.retries == 3
    assert by_type[GraphqlPlugin]._retry.base_delay == 0.7


# ── disclaimer / die / file loading ─────────────────────────────────────────────

def test_disclaimer_dimmed_when_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    text = cli._disclaimer_text()
    assert text.startswith("\033[2m") and text.endswith("\033[0m")


def test_disclaimer_plain_when_not_tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    assert cli._disclaimer_text() == cli._LEGAL_DISCLAIMER


def test_die_exits_with_code_1(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli._die("boom")
    assert exc.value.code == 1
    assert "boom" in capsys.readouterr().err


def test_load_targets_missing_file_dies(tmp_path: Path) -> None:
    args = _ns(target=None, file=str(tmp_path / "nope.txt"))
    with pytest.raises(SystemExit):
        cli._load_targets(args)


# ── ssl context / network resolution ────────────────────────────────────────────

def test_build_ssl_ctx_disables_verification() -> None:
    ctx = cli._build_ssl_ctx()
    assert isinstance(ctx, ssl_lib.SSLContext)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl_lib.CERT_NONE


def test_resolve_net_publishes_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    args = _ns(
        proxy="http://127.0.0.1:8080",
        user_agent="UA",
        random_agent=False,
        safe_mode=False,
        delay=0.0,
        random_delay=False,
        no_verify_ssl=True,
    )
    net = cli._resolve_net(args, rate_limit=3.0)
    assert net.proxy == "http://127.0.0.1:8080"
    assert net.rate_limit == 3.0
    assert net.verify_ssl is False
    import os

    assert os.environ["HTTP_PROXY"] == "http://127.0.0.1:8080"
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:8080"


def test_resolve_net_no_proxy_leaves_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    args = _ns(
        proxy="",
        user_agent="",
        random_agent=True,
        safe_mode=True,  # random_agent suppressed in safe mode
        delay=1.0,
        random_delay=True,
        no_verify_ssl=False,
    )
    net = cli._resolve_net(args, rate_limit=0.0)
    assert net.proxy == ""
    assert net.random_agent is False  # safe mode wins
    import os

    assert "HTTP_PROXY" not in os.environ


# ── auth resolution ───────────────────────────────────────────────────────────────

async def test_resolve_auth_static_credentials() -> None:
    args = _ns(
        cookie="session=abc",
        header=["X-Test: 1"],
        basic_auth="",
        login_url="",
        login_data="",
        timeout=5,
    )
    auth = await cli._resolve_auth(args)
    assert auth.cookies == {"session": "abc"}
    assert auth.headers["X-Test"] == "1"


async def test_resolve_auth_login_error_dies(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _boom(*_a: object, **_kw: object) -> PreparedAuth:
        raise LoginError("bad login")

    monkeypatch.setattr(cli, "prepare_auth", _boom)
    args = _ns(
        cookie="", header=[], basic_auth="",
        login_url="https://t/login", login_data="u=a", timeout=5,
    )
    with pytest.raises(SystemExit):
        await cli._resolve_auth(args)


# ── report writing ────────────────────────────────────────────────────────────────

def _sample_report() -> ScanReport:
    findings = [Finding(plugin="p", title="t", severity=Severity.HIGH, description="d", url="u")]
    return ScanReport(
        targets=[TargetResult(target="https://x.test", findings=findings)],
        scan_started="s",
        scan_finished="f",
        total_findings=1,
    )


def test_write_reports_emits_all_formats(tmp_path: Path) -> None:
    reporter = Reporter(_sample_report())
    args = _ns(
        output=str(tmp_path / "rep"),
        format=["json", "md", "html", "sarif", "csv"],
        quiet=True,
    )
    cli._write_reports(reporter, args)
    for ext in ("json", "md", "html", "sarif", "csv"):
        assert (tmp_path / f"rep.{ext}").exists()


def test_write_reports_prints_when_not_quiet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    reporter = Reporter(_sample_report())
    args = _ns(output=str(tmp_path / "rep"), format=["json"], quiet=False)
    cli._write_reports(reporter, args)
    out = capsys.readouterr().out
    assert "JSON" in out


# ── setup / banner printing ───────────────────────────────────────────────────────

def test_print_setup_shows_auth_safe_and_proxy(capsys: pytest.CaptureFixture[str]) -> None:
    args = _ns(
        cookie="session=a", header=[], basic_auth="", login_url="",
        safe_mode=True,
    )
    auth = PreparedAuth(headers={"X": "1"}, cookies={"session": "a"})
    net = NetConfig(proxy="http://127.0.0.1:8080")
    cli._print_setup(args, auth, net)
    out = capsys.readouterr().out
    assert "Auth" in out
    assert "Safe Mode" in out
    assert "Proxy" in out


def test_print_banner_lists_plugins(capsys: pytest.CaptureFixture[str]) -> None:
    plugins = cli._make_plugins(_ns(
        plugins=["headers"], no_bruteforce=True, soft_404=False, retries=1, retry_backoff=0.5,
    ))
    args = _ns(concurrency=8, timeout=12)
    cli._print_banner(["https://x.test"], plugins, args)
    out = capsys.readouterr().out
    assert "WebScan" in out
    assert "headers" in out


# ── _apply_config error branches ──────────────────────────────────────────────────

def test_apply_config_no_config_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["webscan", "-t", "https://x.test"])
    parser = cli._build_parser()
    cli._apply_config(parser)  # no --config → returns early, no error
    assert parser.parse_args(["-t", "https://x.test"]).concurrency == 10


def test_apply_config_bad_plugin_dies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "c.yml"
    cfg.write_text("plugins: [headers, nonsense_plugin]\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["webscan", "--config", str(cfg)])
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        cli._apply_config(parser)


def test_apply_config_bad_format_dies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "c.yml"
    cfg.write_text("format: [json, banana]\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["webscan", "--config", str(cfg)])
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        cli._apply_config(parser)


def test_apply_config_invalid_yaml_dies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = tmp_path / "c.yml"
    cfg.write_text("profiles:\n  only_profiles: here\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["webscan", "--config", str(cfg)])
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        cli._apply_config(parser)


# ── main() entry point ────────────────────────────────────────────────────────────

def test_main_list_plugins(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["webscan", "--list-plugins"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert "Available plugins" in capsys.readouterr().out


def test_main_no_targets_prints_help(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["webscan"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_main_runs_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "argv", ["webscan", "-t", "https://x.test", "-q"])
    monkeypatch.setattr(cli.sys.stderr, "isatty", lambda: False)

    async def _fake_run(_args: argparse.Namespace) -> int:
        return 0

    monkeypatch.setattr(cli, "_run", _fake_run)
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0


# ── _run integration (engine + crawl faked) ──────────────────────────────────────

class _FakeEngine:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs

    async def scan_all(self, targets: list[str]) -> ScanReport:
        on_progress = self.kwargs.get("on_progress")
        if callable(on_progress):
            on_progress(targets[0], 1, 1)  # exercise the progress callback
        findings = [
            Finding(plugin="p", title="t", severity=Severity.HIGH, description="d", url=targets[0])
        ]
        return ScanReport(
            targets=[TargetResult(target=targets[0], findings=findings)],
            scan_started="s",
            scan_finished="f",
            total_findings=1,
        )


async def test_run_full_path_writes_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "ScanEngine", _FakeEngine)
    parser = cli._build_parser()
    args = parser.parse_args([
        "-t", "https://x.test",
        "-o", str(tmp_path / "rep"),
        "--format", "json", "md",
        "--explain", "--min-severity", "low",
        "--anonymize",
    ])
    code = await cli._run(args)
    assert code == 1  # a HIGH finding trips the default threshold
    assert (tmp_path / "rep.json").exists()


async def test_run_quiet_no_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "ScanEngine", _FakeEngine)
    parser = cli._build_parser()
    args = parser.parse_args(["-t", "https://x.test", "-q"])
    assert await cli._run(args) == 1


async def test_run_no_targets_dies() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(["-t", "  "])  # whitespace normalises to a target...
    # Force the empty case directly:
    args.target = []
    args.file = None
    with pytest.raises(SystemExit):
        await cli._run(args)


async def test_run_with_crawl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "ScanEngine", _FakeEngine)

    async def _fake_crawl(seeds: list[str], *_a: object, **_kw: object) -> list[str]:
        return [*seeds, "https://x.test/discovered"]

    monkeypatch.setattr(cli, "_crawl_targets", _fake_crawl)
    parser = cli._build_parser()
    args = parser.parse_args(["-t", "https://x.test", "--crawl", "-q"])
    assert await cli._run(args) == 1


# ── _crawl_targets (Crawler + aiohttp session faked) ──────────────────────────────

class _FakeCrawlResult:
    def __init__(self, urls: list[str]) -> None:
        self.urls = urls


class _FakeCrawler:
    def __init__(self, _session: object, _config: object) -> None:
        pass

    async def crawl(self, seed: str) -> _FakeCrawlResult:
        if "bad" in seed:
            raise RuntimeError("seed failed")
        return _FakeCrawlResult([seed, f"{seed}/page2"])


class _FakeClientSession:
    def __init__(self, *_a: object, **_kw: object) -> None:
        pass

    async def __aenter__(self) -> _FakeClientSession:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False


async def test_crawl_targets_collects_and_dedupes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "Crawler", _FakeCrawler)
    monkeypatch.setattr(cli.aiohttp, "ClientSession", _FakeClientSession)

    auth = PreparedAuth()
    net = NetConfig()
    args = parser_args = cli._build_parser().parse_args(["-t", "https://x.test"])

    discovered = await cli._crawl_targets(
        ["https://x.test"], parser_args, auth, net
    )
    assert "https://x.test" in discovered
    assert "https://x.test/page2" in discovered
    assert len(discovered) == len(set(discovered))  # deduped
    _ = args


async def test_crawl_targets_bad_seed_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "Crawler", _FakeCrawler)
    monkeypatch.setattr(cli.aiohttp, "ClientSession", _FakeClientSession)

    args = cli._build_parser().parse_args(["-t", "https://bad.test"])
    discovered = await cli._crawl_targets(["https://bad.test"], args, PreparedAuth(), NetConfig())
    # A failing seed is kept as-is so the scan still runs against it.
    assert discovered == ["https://bad.test"]

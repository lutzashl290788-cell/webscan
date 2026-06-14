"""Tests for CLI helpers: target loading, exit codes, safe mode, plugin wiring."""
from __future__ import annotations

import argparse
from pathlib import Path

from webscan import cli, registry
from webscan.models import Finding, ScanReport, Severity, TargetResult
from webscan.plugins.cve_lookup import CveLookupPlugin
from webscan.plugins.graphql import GraphqlPlugin
from webscan.plugins.subdomains import SubdomainsPlugin


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

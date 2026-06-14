"""Tests for the public library API (webscan.scan / webscan.scan_sync) and registry."""
from __future__ import annotations

import pytest

import webscan
from webscan import registry
from webscan.models import ScanReport
from webscan.plugins.base import BasePlugin


def test_public_exports_present() -> None:
    for name in ("scan", "scan_sync", "ScanReport", "Finding", "Severity", "Reporter"):
        assert hasattr(webscan, name), name
    assert "scan" in webscan.__all__


def test_registry_build_plugins_selects_and_wires() -> None:
    plugins = registry.build_plugins(
        ["headers", "directories", "config_files", "subdomains"],
        soft_404=True,
        bruteforce=False,
    )
    by_name = {p.name: p for p in plugins}
    assert set(by_name) == {"headers", "directories", "config_files", "subdomains"}
    assert by_name["directories"].soft_404 is True  # type: ignore[attr-defined]
    assert by_name["config_files"].soft_404 is True  # type: ignore[attr-defined]
    # subdomains brute force toggled off
    assert by_name["subdomains"]._bruteforce is False  # type: ignore[attr-defined]


def test_registry_defaults_exclude_opt_in() -> None:
    assert "cve_lookup" in registry.OPT_IN_PLUGINS
    assert "cve_lookup" not in registry.DEFAULT_PLUGINS
    assert all(isinstance(c, type) and issubclass(c, BasePlugin)
               for c in registry.ALL_PLUGINS.values())


def test_build_plugins_unknown_name_raises() -> None:
    with pytest.raises(KeyError):
        registry.build_plugins(["does_not_exist"])


# ── scan() facade ───────────────────────────────────────────────────────────


class _NoopPlugin(BasePlugin):
    """A plugin that records the targets it was asked to scan and finds nothing."""

    name = "noop"
    description = "test plugin"
    seen: list[str] = []

    async def run(self, target: str, session: object) -> list:  # type: ignore[override]
        _NoopPlugin.seen.append(target)
        return []


async def test_scan_normalises_targets_and_runs_selected_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _NoopPlugin.seen = []
    monkeypatch.setitem(registry.ALL_PLUGINS, "noop", _NoopPlugin)

    report = await webscan.scan(
        ["example.com", "https://b.test/"],
        plugins=["noop"],
    )
    assert isinstance(report, ScanReport)
    # Bare host got https://, trailing slash stripped.
    assert sorted(_NoopPlugin.seen) == ["https://b.test", "https://example.com"]
    assert {tr.target for tr in report.targets} == {
        "https://example.com",
        "https://b.test",
    }


async def test_scan_empty_targets_raises() -> None:
    with pytest.raises(ValueError):
        await webscan.scan([])


async def test_scan_empty_plugins_raises() -> None:
    with pytest.raises(ValueError):
        await webscan.scan(["https://example.com"], plugins=[])


def test_scan_sync_runs_outside_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    _NoopPlugin.seen = []
    monkeypatch.setitem(registry.ALL_PLUGINS, "noop", _NoopPlugin)

    report = webscan.scan_sync(["https://example.com"], plugins=["noop"])
    assert isinstance(report, ScanReport)
    assert _NoopPlugin.seen == ["https://example.com"]


async def test_scan_sync_inside_loop_raises() -> None:
    # Already inside a running loop (pytest-asyncio) — must refuse.
    with pytest.raises(RuntimeError):
        webscan.scan_sync(["https://example.com"], plugins=["headers"])

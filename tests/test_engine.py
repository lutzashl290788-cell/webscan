"""Tests for the asynchronous scan engine."""
from __future__ import annotations

import aiohttp

from webscan.engine import ScanEngine
from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin


class _OkPlugin(BasePlugin):
    name = "ok"
    description = "always yields one finding"

    async def run(self, target: str, session: aiohttp.ClientSession) -> list[Finding]:
        return [
            Finding(
                plugin=self.name,
                title="hello",
                severity=Severity.LOW,
                description="d",
                url=target,
            )
        ]


class _BoomPlugin(BasePlugin):
    name = "boom"
    description = "always raises"

    async def run(self, target: str, session: aiohttp.ClientSession) -> list[Finding]:
        raise RuntimeError("kaboom")


class _EmptyPlugin(BasePlugin):
    name = "empty"
    description = "yields nothing"

    async def run(self, target: str, session: aiohttp.ClientSession) -> list[Finding]:
        return []


async def test_collects_findings_across_targets() -> None:
    engine = ScanEngine([_OkPlugin(), _EmptyPlugin()], concurrency=2, timeout=5)
    report = await engine.scan_all(["https://a.test", "https://b.test"])

    assert len(report.targets) == 2
    assert report.total_findings == 2  # one per target
    assert report.scan_started and report.scan_finished


async def test_plugin_error_captured_not_raised() -> None:
    engine = ScanEngine([_OkPlugin(), _BoomPlugin()], concurrency=1, timeout=5)
    report = await engine.scan_all(["https://a.test"])

    target = report.targets[0]
    assert len(target.findings) == 1  # the ok plugin still ran
    assert any("boom" in e and "kaboom" in e for e in target.errors)


async def test_progress_callback_invoked() -> None:
    seen: list[tuple[str, int, int]] = []

    engine = ScanEngine(
        [_EmptyPlugin()],
        concurrency=3,
        timeout=5,
        on_progress=lambda t, done, total: seen.append((t, done, total)),
    )
    await engine.scan_all(["https://a.test", "https://b.test", "https://c.test"])

    assert len(seen) == 3
    assert {done for _t, done, _total in seen} == {1, 2, 3}
    assert all(total == 3 for _t, _done, total in seen)


async def test_empty_target_list() -> None:
    engine = ScanEngine([_OkPlugin()], concurrency=2, timeout=5)
    report = await engine.scan_all([])
    assert report.targets == []
    assert report.total_findings == 0

"""Asynchronous scanning engine — orchestrates plugins over a list of targets."""
from __future__ import annotations

import asyncio
import ssl as ssl_lib
from collections.abc import Callable
from datetime import datetime, timezone

import aiohttp

from webscan.models import ScanReport, TargetResult
from webscan.plugins.base import BasePlugin

_DEFAULT_HEADERS = {
    "User-Agent": "WebScan/1.0 (security-audit; github.com/lutzashl290788-cell/webscan)",
    "Accept": "*/*",
}

ProgressCallback = Callable[[str, int, int], None]


def _build_ssl_context() -> ssl_lib.SSLContext:
    """Return an SSL context that skips certificate verification.

    Security scanners routinely audit hosts with self-signed or expired
    certificates, so verification is intentionally disabled here.
    """
    ctx = ssl_lib.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl_lib.CERT_NONE
    return ctx


class ScanEngine:
    """
    Runs all configured plugins against every target URL concurrently.

    :param plugins:     List of :class:`~webscan.plugins.base.BasePlugin` instances.
    :param concurrency: Maximum number of simultaneous *targets* in flight.
    :param timeout:     Per-request timeout in seconds.
    :param on_progress: Optional callback ``(target, done, total) -> None``
                        invoked after each target finishes.
    """

    def __init__(
        self,
        plugins: list[BasePlugin],
        concurrency: int = 10,
        timeout: int = 10,
        on_progress: ProgressCallback | None = None,
        auth_headers: dict[str, str] | None = None,
        auth_cookies: dict[str, str] | None = None,
    ) -> None:
        self.plugins = plugins
        self.concurrency = max(1, concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=min(5, timeout))
        self.on_progress = on_progress
        self._ssl_ctx = _build_ssl_context()
        self._auth_headers = auth_headers or {}
        self._auth_cookies = auth_cookies or {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan_all(self, targets: list[str]) -> ScanReport:
        """Scan all *targets* and return a :class:`~webscan.models.ScanReport`."""
        report = ScanReport(
            scan_started=_utcnow(),
        )
        total = len(targets)
        done_counter = 0

        connector = aiohttp.TCPConnector(
            limit=self.concurrency * 5,  # total connection pool
            limit_per_host=self.concurrency,
            ssl=self._ssl_ctx,
        )
        semaphore = asyncio.Semaphore(self.concurrency)

        merged_headers = {**_DEFAULT_HEADERS, **self._auth_headers}
        cookies = self._auth_cookies or None

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=merged_headers,
            cookies=cookies,
            connector_owner=True,
        ) as session:

            async def _bounded(target: str) -> TargetResult:
                nonlocal done_counter
                async with semaphore:
                    result = await self._scan_target(target, session)
                done_counter += 1
                if self.on_progress:
                    self.on_progress(target, done_counter, total)
                return result

            tasks = [asyncio.create_task(_bounded(t)) for t in targets]
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)

        for idx, item in enumerate(raw_results):
            if isinstance(item, BaseException):
                report.targets.append(
                    TargetResult(
                        target=targets[idx] if idx < len(targets) else "unknown",
                        errors=[f"Unhandled engine error: {type(item).__name__}: {item}"],
                        scanned_at=_utcnow(),
                    )
                )
            else:
                report.targets.append(item)

        report.scan_finished = _utcnow()
        report.total_findings = sum(len(r.findings) for r in report.targets)
        return report

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _scan_target(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> TargetResult:
        result = TargetResult(target=target, scanned_at=_utcnow())

        for plugin in self.plugins:
            try:
                findings = await plugin.run(target, session)
                result.findings.extend(findings)
            except Exception as exc:  # noqa: BLE001 — intentional wide catch
                result.errors.append(
                    f"[plugin:{plugin.name}] {type(exc).__name__}: {exc}"
                )

        return result


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")

"""Asynchronous scanning engine — orchestrates plugins over a list of targets."""
from __future__ import annotations

import asyncio
import random
import ssl as ssl_lib
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import aiohttp

from webscan.models import ScanReport, TargetResult
from webscan.plugins.base import BasePlugin

_DEFAULT_HEADERS = {
    "User-Agent": "WebScan/1.0 (security-audit; github.com/lutzashl290788-cell/webscan)",
    "Accept": "*/*",
}

# Headers that must NOT follow a redirect to a different origin. aiohttp ≥3.8
# keeps the ``Authorization`` header across redirects by default, which leaks
# operator credentials to any host the target redirects to (CWE-200/CWE-522).
# We drop them via a TraceConfig on_request_redirect hook — see
# :func:`_build_redirect_safe_trace`.
_REDIRECT_SENSITIVE_HEADERS = (
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
)

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


def _same_host(url_a: str, url_b: str) -> bool:
    """True iff *url_a* and *url_b* target the same host (case-insensitive)."""
    return (urlparse(url_a).hostname or "").lower() == (
        urlparse(url_b).hostname or ""
    ).lower()


def _build_redirect_safe_trace() -> aiohttp.TraceConfig:
    """Build a TraceConfig that strips sensitive headers from cross-origin redirects.

    Without this, an ``Authorization`` header configured via ``--basic-auth`` /
    ``--header`` is replayed on every redirect hop — including to a host the
    target chooses via ``Location:``. We compare the redirect destination
    (read from the response's ``Location`` header) to the original request URL;
    if the host differs, we drop auth-bearing headers before aiohttp follows
    the redirect.
    """

    async def _on_request_redirect(
        session: aiohttp.ClientSession,
        trace_config_ctx: Any,  # noqa: ANN401 - aiohttp-defined trace context is dynamic
        params: aiohttp.TraceRequestRedirectParams,
    ) -> None:
        # ``params.url`` is the URL we just requested (the redirecting hop);
        # ``params.response`` carries the redirect response whose ``Location``
        # header tells us where aiohttp will send the next request.
        original = str(params.url)
        location = params.response.headers.get("Location", "")
        if not location or _same_host(original, location):
            return
        # ``params.headers`` is the headers mapping aiohttp is about to send on
        # the next hop. It is a real CIMultiDict we can mutate in place.
        headers = params.headers
        if not headers:
            return
        for key in list(headers.keys()):
            if key.lower() in _REDIRECT_SENSITIVE_HEADERS:
                del headers[key]

    trace = aiohttp.TraceConfig()
    trace.on_request_redirect.append(_on_request_redirect)
    return trace


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
        proxy: str = "",
        user_agent: str = "",
        delay: float = 0.0,
        random_delay: bool = False,
    ) -> None:
        self.plugins = plugins
        self.concurrency = max(1, concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=min(3, timeout))
        self.on_progress = on_progress
        self._ssl_ctx = _build_ssl_context()
        self._auth_headers = auth_headers or {}
        self._auth_cookies = auth_cookies or {}
        self._proxy = proxy
        self._user_agent = user_agent
        self._delay = max(0.0, delay)
        self._random_delay = random_delay

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
            limit=self.concurrency * 8,  # total connection pool
            limit_per_host=self.concurrency,
            ssl=self._ssl_ctx,
        )
        semaphore = asyncio.Semaphore(self.concurrency)

        merged_headers = {**_DEFAULT_HEADERS, **self._auth_headers}
        if self._user_agent:
            merged_headers["User-Agent"] = self._user_agent
        cookies = self._auth_cookies or None

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers=merged_headers,
            cookies=cookies,
            connector_owner=True,
            trust_env=bool(self._proxy),
            # Strip Authorization / Cookie / X-API-Key / X-Auth-Token /
            # Proxy-Authorization when aiohttp follows a redirect to a different
            # host. Without this, ``--basic-auth admin:secret`` against a target
            # that responds with ``302 Location: http://attacker/`` would replay
            # the credentials on the attacker host (CWE-200 / CWE-522).
            trace_configs=[_build_redirect_safe_trace()],
        ) as session:

            async def _bounded(target: str) -> TargetResult:
                nonlocal done_counter
                async with semaphore:
                    if self._delay:
                        wait = self._delay
                        if self._random_delay:
                            wait = wait * (0.5 + random.random())
                        await asyncio.sleep(wait)
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

        # Plugins are independent and almost entirely network-bound, so run them
        # concurrently rather than one after another. Actual request pressure
        # stays bounded by the shared connector's per-host connection limit, so
        # this speeds up scans (especially single-target ones) without making
        # them less polite. Each plugin's failure is isolated via gather's
        # return_exceptions so one crash never aborts the others.
        outcomes = await asyncio.gather(
            *(plugin.run(target, session) for plugin in self.plugins),
            return_exceptions=True,
        )
        for plugin, outcome in zip(self.plugins, outcomes):
            if isinstance(outcome, BaseException):
                result.errors.append(
                    f"[plugin:{plugin.name}] {type(outcome).__name__}: {outcome}"
                )
            else:
                result.findings.extend(outcome)

        return result


def _utcnow() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")

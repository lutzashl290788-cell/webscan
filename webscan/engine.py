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

# Minimum per-target delay enforced by ``--stealth``. Picked to sit well below
# the typical WAF rate-limit threshold while keeping the scan practical.
_STEALTH_MIN_DELAY: float = 2.0

ProgressCallback = Callable[[str, int, int], None]


def _build_ssl_context(verify: bool = False) -> ssl_lib.SSLContext:
    """Return an SSL context for the scan engine.

    :param verify: If ``False`` (the default), certificate verification is
        disabled — security scanners routinely audit hosts with self-signed or
        expired certificates, so verification would silently break most scans
        against staging/dev targets. If ``True`` (set via ``--strict-ssl``),
        a default verifiable context is returned so a TLS failure surfaces as
        a scan error instead of being silently swallowed.
    """
    if verify:
        # Default context loads system CAs, checks hostname, requires valid chain.
        return ssl_lib.create_default_context()
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


def _random_forwarded_for() -> str:
    """Return a random public-looking IPv4 for the ``X-Forwarded-For`` header.

    Avoids RFC 1918 / loopback / link-local ranges so the spoofed client IP
    looks like a real upstream visitor, not a probe from inside the operator's
    own network.
    """
    while True:
        octet0 = random.randint(1, 254)
        # Skip private/loopback/reserved first octets (10, 127, 169, 172, 192).
        if octet0 in (10, 127, 169, 172, 192):
            continue
        return ".".join(
            str(octet) for octet in (octet0, *(random.randint(0, 255) for _ in range(3)))
        )


def _random_search_referer(target_url: str) -> str:
    """Return a random Google/Bing/DuckDuckGo search Referer for *target_url*.

    Pairs naturally with ``--stealth``: real visitors often arrive at a deep
    link from a search engine, so a search-style Referer makes the request
    blend with organic traffic instead of looking like a direct scanner hit.
    """
    from urllib.parse import quote

    host = urlparse(target_url).hostname or "example.com"
    templates = [
        f"https://www.google.com/search?q=site%3A{quote(host)}",
        f"https://www.google.com/search?q={quote(host)}+login",
        f"https://www.bing.com/search?q=site%3A{quote(host)}",
        f"https://duckduckgo.com/?q={quote(host)}",
    ]
    return random.choice(templates)


def _build_stealth_trace() -> aiohttp.TraceConfig:
    """Build a TraceConfig that injects spoofed stealth headers per request.

    For every outgoing request this sets a random ``X-Forwarded-For`` IP and a
    random Google/Bing/DuckDuckGo ``Referer`` derived from the target host. The
    headers are written into aiohttp's mutable request headers in
    ``on_request_start`` so each request gets fresh values — the whole point of
    ``--stealth`` is to avoid emitting a stable fingerprint across probes.
    """

    async def _on_request_start(
        session: aiohttp.ClientSession,
        trace_plan_ctx: Any,  # noqa: ANN401 - aiohttp-defined trace context is dynamic
        params: aiohttp.TraceRequestStartParams,
    ) -> None:
        # aiohttp always populates ``params.headers`` with at least the session
        # defaults, but the mapping may legitimately be empty if the operator
        # zeroed every default. We always inject the stealth headers — the
        # whole point of the trace hook is to *add* fingerprint-masking headers
        # to whatever the request already carries.
        headers = params.headers
        if headers is None:  # pragma: no cover - aiohttp always provides a CIMultiDict
            return
        headers["X-Forwarded-For"] = _random_forwarded_for()
        headers["Referer"] = _random_search_referer(str(params.url))

    trace = aiohttp.TraceConfig()
    trace.on_request_start.append(_on_request_start)
    return trace


class ScanEngine:
    """
    Runs all configured plugins against every target URL concurrently.

    :param plugins:     List of :class:`~webscan.plugins.base.BasePlugin` instances.
    :param concurrency: Maximum number of simultaneous *targets* in flight.
    :param timeout:     Per-request timeout in seconds.
    :param on_progress: Optional callback ``(target, done, total) -> None``
                        invoked after each target finishes.
    :param stealth:     When True, the engine shrinks the connection pool to a
                        single connection and injects spoofed
                        ``X-Forwarded-For`` / ``Referer`` headers per request.
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
        verify_ssl: bool = False,
        stealth: bool = False,
    ) -> None:
        self.plugins = plugins
        self.concurrency = max(1, concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=min(3, timeout))
        self.on_progress = on_progress
        self._ssl_ctx = _build_ssl_context(verify=verify_ssl)
        self._auth_headers = auth_headers or {}
        self._auth_cookies = auth_cookies or {}
        self._proxy = proxy
        self._user_agent = user_agent
        self._delay = max(0.0, delay)
        self._random_delay = random_delay
        self._stealth = stealth

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

        if self._stealth:
            # Single in-flight connection, single per-host slot — the goal of
            # stealth is minimal footprint, not throughput. Dropping the pool
            # also makes the spoofed X-Forwarded-For sequence look like one
            # client browsing, rather than a burst of parallel probes.
            connector = aiohttp.TCPConnector(
                limit=1,
                limit_per_host=1,
                ssl=self._ssl_ctx,
            )
        else:
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

        trace_configs = [_build_redirect_safe_trace()]
        if self._stealth:
            trace_configs.append(_build_stealth_trace())

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
            trace_configs=trace_configs,
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

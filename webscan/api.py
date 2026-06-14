"""Public library API: run a WebScan scan from Python.

This is the supported entry point for embedding WebScan in another program
(custom recon pipelines, notebooks, CI glue) without shelling out to the CLI or
reaching into private internals. It returns the same
:class:`~webscan.models.ScanReport` the CLI produces, so callers can render it
with :class:`~webscan.reporter.Reporter` or inspect findings directly.

Example::

    import asyncio
    import webscan

    report = asyncio.run(webscan.scan(["https://example.com"]))
    for tr in report.targets:
        for f in tr.findings:
            print(f.severity.value, f.plugin, f.title)

    # Blocking convenience for scripts:
    report = webscan.scan_sync(["https://example.com"], plugins=["headers"])
"""
from __future__ import annotations

from collections.abc import Sequence

from webscan.engine import ProgressCallback, ScanEngine
from webscan.models import ScanReport
from webscan.registry import DEFAULT_PLUGINS, build_plugins
from webscan.retry import RetryConfig
from webscan.utils.http import normalise_url

__all__ = ["scan", "scan_sync"]


async def scan(
    targets: Sequence[str],
    *,
    plugins: Sequence[str] | None = None,
    concurrency: int = 10,
    timeout: int = 10,
    soft_404: bool = False,
    bruteforce: bool = True,
    retry: RetryConfig | None = None,
    proxy: str = "",
    user_agent: str = "",
    delay: float = 0.0,
    random_delay: bool = False,
    auth_headers: dict[str, str] | None = None,
    auth_cookies: dict[str, str] | None = None,
    on_progress: ProgressCallback | None = None,
) -> ScanReport:
    """Scan *targets* and return a :class:`~webscan.models.ScanReport`.

    :param targets: Target URLs. Bare hosts are normalised to ``https://`` and
        trailing slashes are stripped, matching CLI behaviour.
    :param plugins: Plugin names to run. ``None`` runs the default set
        (everything except network-heavy opt-in plugins). Pass an explicit list
        — e.g. ``["headers", "cookies"]`` — to narrow the scan, or include
        opt-in names like ``"cve_lookup"`` / ``"graphql"`` to enable them.
    :param concurrency: Maximum targets scanned simultaneously.
    :param timeout: Per-request timeout in seconds.
    :param soft_404: Enable soft-404 calibration for path-probing plugins.
    :param bruteforce: Enable DNS brute force for the ``subdomains`` plugin.
    :param retry: Retry policy for network-heavy lookups (sensible default if None).
    :param proxy: Optional HTTP/SOCKS proxy URL.
    :param user_agent: Explicit User-Agent override.
    :param delay: Seconds to pause before each target.
    :param random_delay: Jitter *delay* by ×0.5–×1.5.
    :param auth_headers: Extra headers attached to every request (e.g. bearer token).
    :param auth_cookies: Cookies attached to every request.
    :param on_progress: Optional ``(target, done, total) -> None`` callback.
    :returns: A populated :class:`~webscan.models.ScanReport`.
    :raises ValueError: If *targets* is empty or no plugins are selected.
    :raises KeyError: If an unknown plugin name is requested.
    """
    normalised = [normalise_url(t) for t in targets if t and t.strip()]
    if not normalised:
        raise ValueError("scan() requires at least one target URL.")

    names = list(plugins) if plugins is not None else list(DEFAULT_PLUGINS)
    if not names:
        raise ValueError("scan() requires at least one plugin.")

    plugin_instances = build_plugins(
        names,
        soft_404=soft_404,
        bruteforce=bruteforce,
        retry=retry,
    )

    engine = ScanEngine(
        plugins=plugin_instances,
        concurrency=concurrency,
        timeout=timeout,
        on_progress=on_progress,
        auth_headers=auth_headers,
        auth_cookies=auth_cookies,
        proxy=proxy,
        user_agent=user_agent,
        delay=delay,
        random_delay=random_delay,
    )
    return await engine.scan_all(normalised)


def scan_sync(targets: Sequence[str], **kwargs: object) -> ScanReport:
    """Blocking wrapper around :func:`scan` for non-async callers.

    Accepts the same keyword arguments as :func:`scan`. Must not be called from
    within a running event loop — use ``await scan(...)`` there instead.

    :raises RuntimeError: If invoked while an event loop is already running.
    """
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass  # no running loop — safe to drive our own
    else:
        raise RuntimeError(
            "scan_sync() cannot run inside an active event loop; "
            "use 'await webscan.scan(...)' instead."
        )
    return asyncio.run(scan(targets, **kwargs))  # type: ignore[arg-type]

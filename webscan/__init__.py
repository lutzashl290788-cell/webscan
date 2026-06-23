"""WebScan — automated web configuration security auditor.

WebScan is usable both as a CLI (``webscan ...``) and as a library::

    import asyncio
    import webscan

    report = asyncio.run(webscan.scan(["https://example.com"]))
    # or, for non-async code:
    report = webscan.scan_sync(["https://example.com"], plugins=["headers"])

    for tr in report.targets:
        for f in tr.findings:
            print(f.severity.value, f.plugin, f.title)

Render a report in any supported format with :class:`~webscan.reporter.Reporter`.
"""
from __future__ import annotations

from webscan.api import scan, scan_sync
from webscan.models import Confidence, Finding, ScanReport, Severity, TargetResult
from webscan.registry import ALL_PLUGINS, DEFAULT_PLUGINS, OPT_IN_PLUGINS
from webscan.reporter import Reporter

__version__ = "2.7.1"
__author__ = "WebScan contributors"

__all__ = [
    "scan",
    "scan_sync",
    "ScanReport",
    "TargetResult",
    "Finding",
    "Severity",
    "Confidence",
    "Reporter",
    "ALL_PLUGINS",
    "DEFAULT_PLUGINS",
    "OPT_IN_PLUGINS",
    "__version__",
]

"""Tests for the http_methods plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Severity
from webscan.plugins.http_methods import HttpMethodsPlugin

_TARGET = "https://example.com"


async def test_flags_put_and_delete() -> None:
    plugin = HttpMethodsPlugin()
    resp = FakeResponse(headers=[("Allow", "GET, POST, PUT, DELETE, OPTIONS")])
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    methods = {f.evidence["method"] for f in findings}
    assert methods == {"PUT", "DELETE"}
    assert all(f.severity is Severity.HIGH for f in findings)


async def test_safe_methods_only_yields_nothing() -> None:
    plugin = HttpMethodsPlugin()
    resp = FakeResponse(headers=[("Allow", "GET, HEAD, OPTIONS")])
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    assert findings == []


async def test_missing_allow_header_yields_nothing() -> None:
    plugin = HttpMethodsPlugin()
    resp = FakeResponse(headers=[])
    findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]

    assert findings == []

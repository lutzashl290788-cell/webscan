"""Tests for the http_methods plugin (active verification)."""
from __future__ import annotations

from collections.abc import Callable

from webscan.models import Severity
from webscan.plugins.http_methods import HttpMethodsPlugin

_TARGET = "https://example.com"


class _Resp:
    def __init__(self, status: int = 404, body: str = "") -> None:
        self.status = status
        self._body = body

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _RoutedSession:
    """Routes (method, url) -> _Resp via a handler, defaulting to 404."""

    def __init__(
        self, handler: Callable[[str, str, object], _Resp]
    ) -> None:
        self._handler = handler
        self.seen: list[tuple[str, str]] = []

    def get(self, url: str, **kw: object) -> _Resp:
        return self.request("GET", url, **kw)

    def request(self, method: str, url: str, **kw: object) -> _Resp:
        self.seen.append((method, url))
        headers = kw.get("headers") or {}
        return self._handler(method, url, headers)


async def test_put_accepted_is_flagged() -> None:
    def handler(method: str, url: str, _headers: dict) -> _Resp:
        if "webscan-method-probe" in url and method == "GET":
            return _Resp(404)  # not a catch-all
        if method == "PUT":
            return _Resp(201)  # genuinely created
        return _Resp(405)

    plugin = HttpMethodsPlugin()
    findings = await plugin.run(_TARGET, _RoutedSession(handler))  # type: ignore[arg-type]

    methods = {f.evidence["method"] for f in findings}
    assert methods == {"PUT"}
    assert findings[0].severity is Severity.HIGH


async def test_advertised_but_refused_method_not_flagged() -> None:
    """Allow header would say PUT/DELETE, but the server 405s — no finding."""
    def handler(method: str, url: str, _headers: dict) -> _Resp:
        if method == "GET":
            return _Resp(404)
        return _Resp(405)  # every dangerous verb refused

    plugin = HttpMethodsPlugin()
    findings = await plugin.run(_TARGET, _RoutedSession(handler))  # type: ignore[arg-type]

    assert findings == []


async def test_catch_all_host_skips_write_verbs() -> None:
    """A 2xx-for-everything host must not yield PUT/DELETE/PATCH false positives."""
    def handler(method: str, url: str, _headers: dict) -> _Resp:
        # Everything (incl. the bogus probe GET) returns 200 → catch-all.
        return _Resp(200)

    plugin = HttpMethodsPlugin()
    findings = await plugin.run(_TARGET, _RoutedSession(handler))  # type: ignore[arg-type]

    # TRACE has no echo marker here, so it is not flagged either.
    methods = {f.evidence["method"] for f in findings}
    assert "PUT" not in methods
    assert "DELETE" not in methods
    assert "PATCH" not in methods


async def test_trace_requires_echo() -> None:
    def handler(method: str, url: str, headers: dict) -> _Resp:
        if method == "GET":
            return _Resp(404)
        if method == "TRACE":
            # Echo the request headers back, as a TRACE-enabled server does.
            echoed = " ".join(f"{k}: {v}" for k, v in headers.items())
            return _Resp(200, body=f"TRACE / HTTP/1.1\n{echoed}")
        return _Resp(405)

    plugin = HttpMethodsPlugin()
    findings = await plugin.run(_TARGET, _RoutedSession(handler))  # type: ignore[arg-type]

    methods = {f.evidence["method"] for f in findings}
    assert methods == {"TRACE"}
    assert findings[0].severity is Severity.MEDIUM


async def test_trace_without_echo_not_flagged() -> None:
    def handler(method: str, url: str, _headers: dict) -> _Resp:
        if method == "GET":
            return _Resp(404)
        if method == "TRACE":
            return _Resp(200, body="<html>ok</html>")  # 200 but no echo
        return _Resp(405)

    plugin = HttpMethodsPlugin()
    findings = await plugin.run(_TARGET, _RoutedSession(handler))  # type: ignore[arg-type]

    assert findings == []

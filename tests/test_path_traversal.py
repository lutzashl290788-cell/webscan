"""Tests for the path traversal plugin."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.path_traversal import PathTraversalPlugin

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"


class _Resp:
    def __init__(self, body: str) -> None:
        self._body = body

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _Session:
    def __init__(self, body: str) -> None:
        self._body = body
        self.calls = 0

    def get(self, _url: str, **_kw: object) -> _Resp:
        self.calls += 1
        return _Resp(self._body)


async def test_detects_passwd_disclosure() -> None:
    plugin = PathTraversalPlugin()
    session = _Session(_PASSWD)

    findings = await plugin.run("https://example.com/?file=a.txt", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].evidence["disclosed_file"] == "/etc/passwd"


async def test_clean_response_no_finding() -> None:
    plugin = PathTraversalPlugin()
    session = _Session("<html>nothing to see</html>")

    findings = await plugin.run("https://example.com/?file=a.txt", session)  # type: ignore[arg-type]

    assert findings == []


async def test_no_params_skips() -> None:
    plugin = PathTraversalPlugin()
    session = _Session(_PASSWD)

    findings = await plugin.run("https://example.com/", session)  # type: ignore[arg-type]

    assert findings == []
    assert session.calls == 0


# ----------------------------------------------------------------------
# Coverage gaps
# ----------------------------------------------------------------------

import aiohttp  # noqa: E402


class _ClientError(Exception):
    pass


class _RaisingResp:
    async def __aenter__(self) -> _RaisingResp:
        raise _ClientError("transport error")

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return ""


async def test_network_error_during_probe_skipped() -> None:
    """Lines 58-59: a ClientError mid-probe is swallowed, no finding."""
    orig = aiohttp.ClientError
    aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
    try:
        plugin = PathTraversalPlugin()

        class _BoomSession:
            def get(self, _url: str, **_kw: object) -> _RaisingResp:
                return _RaisingResp()

        findings = await plugin.run(
            "https://example.com/?file=a.txt", _BoomSession()  # type: ignore[arg-type]
        )
        assert findings == []
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]


async def test_windows_ini_disclosure() -> None:
    """Line 97: the win.ini victim signature triggers the /windows/win.ini path."""
    winini = (
        "[fonts]\n"
        "Lucida Console=LUCON.TTF\n"
        "[extensions]\n"
        "[mci extensions]\n"
    )
    plugin = PathTraversalPlugin()
    session = _Session(winini)

    findings = await plugin.run("https://example.com/?file=a.txt", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].evidence["disclosed_file"] == "windows/win.ini"

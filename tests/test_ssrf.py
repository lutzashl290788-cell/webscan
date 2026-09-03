"""Tests for the SSRF plugin."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.ssrf import SsrfPlugin

_AWS_BODY = "ami-id\nami-launch-index\ninstance-id\niam/security-credentials/"


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


async def test_detects_aws_metadata_ssrf() -> None:
    plugin = SsrfPlugin()
    session = _Session(_AWS_BODY)

    findings = await plugin.run("https://example.com/?url=http://a", session)  # type: ignore[arg-type]

    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence["signal"] == "AWS metadata"


async def test_non_url_param_skipped() -> None:
    plugin = SsrfPlugin()
    session = _Session(_AWS_BODY)

    findings = await plugin.run("https://example.com/?id=5", session)  # type: ignore[arg-type]

    assert findings == []
    assert session.calls == 0


async def test_clean_response_no_finding() -> None:
    plugin = SsrfPlugin()
    session = _Session("<html>normal page</html>")

    findings = await plugin.run("https://example.com/?url=http://a", session)  # type: ignore[arg-type]

    assert findings == []

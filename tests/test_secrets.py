"""Tests for the secret/API-key leakage plugin."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.secrets import SecretsPlugin, _redact


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
    """Serves a main page; linked .js URLs get their own canned body."""

    def __init__(self, pages: dict[str, str]) -> None:
        self._pages = pages

    def get(self, url: str, **_kw: object) -> _Resp:
        return _Resp(self._pages.get(url, ""))


def test_redact_masks_secret() -> None:
    out = _redact("AKIAIOSFODNN7EXAMPLE")
    assert out.startswith("AKIA")
    assert "REDACTED" in out
    assert "IOSFODNN7EXAMPLE" not in out


async def test_detects_aws_and_anthropic_keys() -> None:
    body = (
        "<html><script>"
        "const aws='AKIAIOSFODNN7EXAMPLE';"
        "const ai='sk-ant-api03-AbCdEf0123456789AbCdEf0123456789';"
        "</script></html>"
    )
    plugin = SecretsPlugin()
    findings = await plugin.run("https://example.com", _Session({"https://example.com": body}))  # type: ignore[arg-type]

    labels = {f.evidence["type"] for f in findings}
    assert "AWS Access Key ID" in labels
    assert "Anthropic API key" in labels
    assert all(f.severity is Severity.CRITICAL for f in findings)
    # The full secret must never appear in the finding.
    assert all("IOSFODNN7EXAMPLE" not in str(f.evidence) for f in findings)


async def test_scans_linked_same_origin_js() -> None:
    pages = {
        "https://example.com": '<html><script src="https://example.com/app.js"></script></html>',
        "https://example.com/app.js": "var k='sk_live_abcdefabcdef1234567890';",
    }
    plugin = SecretsPlugin()
    findings = await plugin.run("https://example.com", _Session(pages))  # type: ignore[arg-type]

    assert any(f.evidence["type"] == "Stripe live secret key" for f in findings)
    assert any(f.url.endswith("app.js") for f in findings)


async def test_clean_page_no_findings() -> None:
    plugin = SecretsPlugin()
    findings = await plugin.run(
        "https://example.com",
        _Session({"https://example.com": "<html><p>nothing secret here</p></html>"}),  # type: ignore[arg-type]
    )
    assert findings == []


# ----------------------------------------------------------------------
# Coverage gaps
# ----------------------------------------------------------------------

import aiohttp  # noqa: E402


class _ClientError(Exception):
    pass


class _RaisingResp:
    async def __aenter__(self) -> _RaisingResp:
        raise _ClientError("connection reset")

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return ""


async def test_baseline_network_error_returns_empty() -> None:
    """Line 65: a ClientError fetching the main page yields no findings."""
    orig = aiohttp.ClientError
    aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
    try:
        plugin = SecretsPlugin()

        class _BoomSession:
            def get(self, _url: str, **_kw: object) -> _RaisingResp:
                return _RaisingResp()

        findings = await plugin.run("https://example.com", _BoomSession())  # type: ignore[arg-type]
        assert findings == []
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]


async def test_js_fetch_network_error_skipped() -> None:
    """Lines 126-127: a ClientError fetching a linked JS is swallowed."""
    orig = aiohttp.ClientError
    aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
    try:
        plugin = SecretsPlugin()

        class _MixedSession:
            def get(self, url: str, **_kw: object) -> object:
                if url == "https://example.com":
                    return _Resp(
                        '<html><script src="https://example.com/broken.js"></script></html>'
                    )
                # The JS fetch raises.
                return _RaisingResp()

        findings = await plugin.run("https://example.com", _MixedSession())  # type: ignore[arg-type]
        # No secrets found (JS fetch failed), but no exception either.
        assert findings == []
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]


async def test_duplicate_secret_deduplicated() -> None:
    """Line 100: the same secret appearing twice is reported once."""
    body = (
        "<html><script>"
        "var a='AKIAIOSFODNN7EXAMPLE';"
        "var b='AKIAIOSFODNN7EXAMPLE';"
        "</script></html>"
    )
    plugin = SecretsPlugin()
    findings = await plugin.run("https://example.com", _Session({"https://example.com": body}))  # type: ignore[arg-type]

    aws = [f for f in findings if f.evidence["type"] == "AWS Access Key ID"]
    assert len(aws) == 1  # deduplicated by (label, redacted)

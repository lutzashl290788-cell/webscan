"""Tests for webscan.plugins._active_helpers."""
from __future__ import annotations

from webscan.plugins._active_helpers import (
    body_similarity,
    fetch_body,
    fetch_with_headers,
    fetch_with_retry,
    is_soft404,
    looks_like_xml_or_json,
)
from webscan.plugins.soft404 import SoftBaseline
from webscan.retry import RetryConfig

# ─── Pure-function tests ──────────────────────────────────────────────────────


def test_is_soft404_none_baseline_returns_false() -> None:
    assert is_soft404("any body", 200, None) is False


def test_is_soft404_matching_body_returns_true() -> None:
    baseline = SoftBaseline(status=200, body="this is a generic not found page with some content")
    # The body must be similar enough (>= 0.90 threshold) to match.
    assert is_soft404(
        "this is a generic not found page with some content here", 200, baseline
    ) is True


def test_is_soft404_status_mismatch_returns_false() -> None:
    baseline = SoftBaseline(status=200, body="not found")
    assert is_soft404("not found page", 404, baseline) is False


def test_body_similarity_identical() -> None:
    assert body_similarity("hello world", "hello world") == 1.0


def test_body_similarity_different() -> None:
    assert body_similarity("abc", "xyz") < 0.5


def test_looks_like_xml_or_json_json_ct() -> None:
    assert looks_like_xml_or_json("application/json", "") is True


def test_looks_like_xml_or_json_xml_ct() -> None:
    assert looks_like_xml_or_json("text/xml", "") is True


def test_looks_like_xml_or_json_soap_ct() -> None:
    assert looks_like_xml_or_json("application/soap+xml", "") is True


def test_looks_like_xml_or_json_html_ct() -> None:
    assert looks_like_xml_or_json("text/html", "<html>ok</html>") is False


def test_looks_like_xml_or_json_json_body_start() -> None:
    """Line 182: body starts with '{' → JSON-like."""
    assert looks_like_xml_or_json("text/html", '{"key": "value"}') is True


def test_looks_like_xml_or_json_xml_body_start() -> None:
    """Line 189: body starts with XML tag '<?xml'."""
    assert looks_like_xml_or_json("text/html", '<?xml version="1.0"?><root/>') is True


def test_looks_like_xml_or_json_custom_xml_tag() -> None:
    """Line 191: body starts with <tag> that is not <html> → XML-like."""
    assert looks_like_xml_or_json("text/html", "<result><status>ok</status></result>") is True


def test_looks_like_xml_or_json_html_tag_not_flagged() -> None:
    """Body starting with <html> is not flagged as XML/JSON."""
    assert looks_like_xml_or_json("text/html", "<html><body>ok</body></html>") is False


def test_looks_like_xml_or_json_doctype_html_not_flagged() -> None:
    """Body starting with <!DOCTYPE html> is not flagged as XML/JSON."""
    assert looks_like_xml_or_json("text/html", "<!DOCTYPE html><html></html>") is False


def test_looks_like_xml_or_json_html_comment_not_flagged() -> None:
    """Line 188-189: <! (but not <!doctype) → treated as comment, not XML."""
    assert looks_like_xml_or_json("text/html", "<!-- comment --><html></html>") is False


# ─── fetch_with_headers coverage gaps ──────────────────────────────────────────


async def test_fetch_with_headers_bad_method_returns_none() -> None:
    """Line 94/111: an unknown method name returns None."""

    class _NoopSession:
        pass  # has no .patch or .bogusmethod

    no_retry = RetryConfig(retries=0, base_delay=0.0)
    result = await fetch_with_headers(
        _NoopSession(), "https://example.com", method="BOGUS", retry=no_retry,
    )
    assert result is None


async def test_fetch_with_retry_returns_none_on_all_failures() -> None:
    """When every retry attempt fails (all 503), returns None."""
    import aiohttp

    class _ClientError(Exception):
        pass

    class _RaisingResp:
        async def __aenter__(self) -> _RaisingResp:
            raise _ClientError("down")

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        async def text(self, **_kw: object) -> str:
            return ""

    class _BoomSession:
        def get(self, _url: str, **_kw: object) -> _RaisingResp:
            return _RaisingResp()

    orig = aiohttp.ClientError
    aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
    try:
        no_retry = RetryConfig(retries=1, base_delay=0.01)
        result = await fetch_with_retry(
            _BoomSession(), "https://example.com", retry=no_retry,
        )
        assert result is None
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]


async def test_fetch_with_retry_success() -> None:
    """A 200 response on the first attempt returns the body."""

    class _Resp:
        def __init__(self) -> None:
            pass

        async def __aenter__(self) -> _Resp:
            return self

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        async def text(self, **_kw: object) -> str:
            return "ok"

        @property
        def status(self) -> int:
            return 200

    class _OkSession:
        def get(self, _url: str, **_kw: object) -> _Resp:
            return _Resp()

    no_retry = RetryConfig(retries=0, base_delay=0.0)
    result = await fetch_with_retry(
        _OkSession(), "https://example.com", retry=no_retry,
    )
    assert result is not None
    body, status, _ct = result
    assert body == "ok"
    assert status == 200


# ─── fetch_body: chunked reads ────────────────────────────────────────────────


class _ChunkedContent:
    """Mimics ``aiohttp.StreamReader.read(n)``.

    The real reader returns whatever is *already buffered* once any data has
    arrived — never more than one chunk per call, even when ``n`` is larger and
    more of the body is still in flight. Reproducing that here is what makes
    these regression tests meaningful.
    """

    def __init__(self, data: bytes, chunk_size: int) -> None:
        self._data = data
        self._chunk_size = chunk_size
        self._pos = 0

    async def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._data):
            return b""  # EOF
        want = self._chunk_size if n < 0 else min(n, self._chunk_size)
        out = self._data[self._pos:self._pos + want]
        self._pos += len(out)
        return out


class _StreamingResp:
    def __init__(self, data: bytes, chunk_size: int = 16 * 1024) -> None:
        self.content = _ChunkedContent(data, chunk_size)


async def test_fetch_body_reads_past_the_first_chunk() -> None:
    """A body spanning many segments must come back whole, not truncated."""
    body = "A" * 500_000
    got = await fetch_body(_StreamingResp(body.encode()))
    assert len(got) == 500_000
    assert got == body


async def test_fetch_body_short_body_unaffected() -> None:
    got = await fetch_body(_StreamingResp(b"<html>hi</html>"))
    assert got == "<html>hi</html>"


async def test_fetch_body_honours_the_limit() -> None:
    """The memory cap (CWE-400) must still bound a hostile multi-MB response."""
    got = await fetch_body(_StreamingResp(b"B" * 1_000_000), limit=200_000)
    assert len(got) == 200_000


async def test_fetch_body_limit_larger_than_body_returns_whole_body() -> None:
    got = await fetch_body(_StreamingResp(b"C" * 1_000), limit=999_999)
    assert len(got) == 1_000


async def test_fetch_body_empty_body() -> None:
    assert await fetch_body(_StreamingResp(b"")) == ""


async def test_fetch_body_falls_back_to_text_without_content_attr() -> None:
    """The retry helper's Response dataclass and test fakes have no .content."""

    class _NoContent:
        async def text(self, **_kw: object) -> str:
            return "fallback body"

    assert await fetch_body(_NoContent()) == "fallback body"  # type: ignore[arg-type]


async def test_fetch_body_falls_back_to_text_without_kwargs() -> None:
    class _StrictText:
        async def text(self) -> str:
            return "no kwargs"

    assert await fetch_body(_StrictText()) == "no kwargs"  # type: ignore[arg-type]

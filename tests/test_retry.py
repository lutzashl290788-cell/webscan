"""Tests for the retry-with-backoff helper."""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.retry import RetryConfig, compute_backoff, request_with_retry


class _Resp:
    def __init__(self, status: int, body: str = "") -> None:
        self.status = status
        self._body = body

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _Boom:
    """A request context whose entry raises, simulating a transport error."""

    def __init__(self, exc: BaseException) -> None:
        self._exc = exc

    async def __aenter__(self) -> _Boom:
        raise self._exc

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class _SeqSession:
    """Returns one queued response (or raising context) per GET call."""

    def __init__(self, items: list[object]) -> None:
        self._items = items
        self.calls = 0

    def get(self, _url: str, **_kw: object) -> object:
        item = self._items[self.calls]
        self.calls += 1
        return item


async def _noop_sleep(_d: float) -> None:
    return None


# ── compute_backoff ───────────────────────────────────────────────────────────

def test_backoff_is_exponential() -> None:
    cfg = RetryConfig(base_delay=0.5, factor=2.0, max_delay=100)
    assert compute_backoff(1, cfg) == 0.5
    assert compute_backoff(2, cfg) == 1.0
    assert compute_backoff(3, cfg) == 2.0


def test_backoff_respects_cap() -> None:
    cfg = RetryConfig(base_delay=1.0, factor=10.0, max_delay=5.0)
    assert compute_backoff(5, cfg) == 5.0


def test_backoff_applies_jitter_and_zero_floor() -> None:
    cfg = RetryConfig(base_delay=2.0, factor=1.0)
    assert compute_backoff(1, cfg, jitter=0.5) == 3.0
    assert compute_backoff(0, cfg) == 0.0


# ── request_with_retry ────────────────────────────────────────────────────────

async def test_recovers_after_transient_error() -> None:
    sess = _SeqSession([_Boom(aiohttp.ClientError()), _Resp(200, "ok")])
    delays: list[float] = []

    async def sleep(d: float) -> None:
        delays.append(d)

    resp = await request_with_retry(
        sess, "GET", "u",  # type: ignore[arg-type]
        config=RetryConfig(retries=2, base_delay=0.1), sleep=sleep,
    )
    assert resp is not None
    assert resp.status == 200 and resp.text == "ok"
    assert len(delays) == 1  # exactly one backoff before the successful retry


async def test_retries_on_transient_status() -> None:
    sess = _SeqSession([_Resp(503), _Resp(200, "good")])
    resp = await request_with_retry(
        sess, "GET", "u",  # type: ignore[arg-type]
        config=RetryConfig(retries=1, base_delay=0.0), sleep=_noop_sleep,
    )
    assert resp is not None and resp.status == 200


async def test_exhausts_to_none() -> None:
    sess = _SeqSession([_Boom(asyncio.TimeoutError()) for _ in range(3)])
    resp = await request_with_retry(
        sess, "GET", "u",  # type: ignore[arg-type]
        config=RetryConfig(retries=2, base_delay=0.0), sleep=_noop_sleep,
    )
    assert resp is None
    assert sess.calls == 3  # first attempt + 2 retries


async def test_non_transient_4xx_returned_immediately() -> None:
    sess = _SeqSession([_Resp(404, "nope")])
    resp = await request_with_retry(
        sess, "GET", "u",  # type: ignore[arg-type]
        config=RetryConfig(retries=3, base_delay=0.0), sleep=_noop_sleep,
    )
    assert resp is not None and resp.status == 404
    assert sess.calls == 1  # no retries on a definitive 404

"""Retry-with-backoff helper for resilient, polite HTTP requests.

Network-heavy plugins (external API lookups) use this to ride out transient
failures — connection resets, timeouts and server-side ``5xx`` / ``429`` — with
exponential backoff instead of giving up on the first hiccup. The backoff
calculation is a pure function so it can be unit-tested without sleeping, and
the sleep call is injectable for the same reason.
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import aiohttp

# Transient HTTP statuses worth retrying: rate limiting and server-side errors.
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})

SleepFn = Callable[[float], Awaitable[None]]


@dataclass(frozen=True)
class RetryConfig:
    """Tunable retry policy.

    :param retries:    Extra attempts after the first (``0`` disables retrying).
    :param base_delay: Seconds to wait before the first retry.
    :param factor:     Exponential growth applied per subsequent retry.
    :param max_delay:  Upper bound on any single backoff wait.
    """

    retries: int = 2
    base_delay: float = 0.5
    factor: float = 2.0
    max_delay: float = 8.0

    def total_attempts(self) -> int:
        """Total request attempts including the first (always at least one)."""
        return max(1, self.retries + 1)


@dataclass
class Response:
    """Minimal materialised response (status + already-read body)."""

    status: int
    text: str


def compute_backoff(attempt: int, config: RetryConfig, jitter: float = 0.0) -> float:
    """Delay before retry *attempt* (1-based): exponential, capped, optional jitter.

    *jitter* is a factor in ``[0, 1)``; the delay is scaled by ``(1 + jitter)``.
    It is passed in rather than generated here so callers stay deterministic and
    the function remains trivially testable.

    >>> compute_backoff(1, RetryConfig(base_delay=0.5, factor=2.0))
    0.5
    >>> compute_backoff(3, RetryConfig(base_delay=0.5, factor=2.0))
    2.0
    """
    if attempt < 1:
        return 0.0
    raw = config.base_delay * (config.factor ** (attempt - 1))
    raw = min(raw, config.max_delay)
    return raw * (1.0 + max(0.0, jitter))


async def request_with_retry(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    *,
    config: RetryConfig | None = None,
    sleep: SleepFn = asyncio.sleep,
    jitter: float = 0.0,
    **kwargs: object,
) -> Response | None:
    """Issue ``session.<method>(url)`` with exponential-backoff retries.

    Retries on transport errors (:class:`aiohttp.ClientError`, timeouts) and on
    transient response statuses (``429`` / ``5xx``). Returns a :class:`Response`
    once a non-transient status is seen (including ``4xx`` other than ``429``),
    or ``None`` if every attempt fails — never raises, so a flaky external
    service degrades gracefully into "no findings" rather than aborting a scan.
    """
    cfg = config or RetryConfig()
    attempts = cfg.total_attempts()
    verb = getattr(session, method.lower(), None)
    if verb is None:
        return None

    for attempt in range(1, attempts + 1):
        try:
            async with verb(url, **kwargs) as resp:
                status = int(resp.status)
                if status in _RETRY_STATUSES and attempt < attempts:
                    await sleep(compute_backoff(attempt, cfg, jitter))
                    continue
                text = await resp.text(errors="ignore")
                return Response(status=status, text=text)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt < attempts:
                await sleep(compute_backoff(attempt, cfg, jitter))
                continue
            return None
    return None

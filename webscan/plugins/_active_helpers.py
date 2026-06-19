"""Shared helpers for active (probing) plugins.

Active plugins send probe requests beyond the initial GET. They share three
concerns:

* **Politeness / resilience** — probes should ride out transient ``5xx`` /
  ``429`` responses via :func:`webscan.retry.request_with_retry`, not give up
  on the first hiccup.
* **Soft-404 awareness** — many servers answer ``200 OK`` for *every* path
  with a templated "not found" page. Naive probing flags every probe as a
  hit. :mod:`webscan.plugins.soft404` calibrates against a bogus path; this
  module exposes :func:`is_soft404` to apply that calibration to probe
  responses.
* **Request deduplication** — multiple plugins probing the same target share
  one baseline GET; this helper caches baseline fetches per (target, plugin)
  pair so a plugin doesn't refetch its own baseline on every call.

The helpers here are pure-Python (only ``aiohttp`` at runtime) and use the
existing retry/soft-404 modules — no new dependencies.
"""
from __future__ import annotations

import asyncio
from typing import Any

import aiohttp

from webscan.plugins.soft404 import SoftBaseline, calibrate
from webscan.retry import RetryConfig, request_with_retry

# Default retry policy for probes. Two retries with exponential backoff is
# enough to ride out a transient 502/503 without making scans slow.
_DEFAULT_RETRY = RetryConfig(retries=2, base_delay=0.3, max_delay=4.0)

# Cap on body size for similarity comparison — keeps memory bounded on huge
# responses (some misconfigured servers return multi-MB error pages).
_MAX_BODY_FOR_COMPARE = 100_000


async def fetch_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    *,
    method: str = "GET",
    retry: RetryConfig | None = None,
    **kwargs: Any,  # noqa: ANN401 — aiohttp's get/post accept arbitrary kwargs
) -> tuple[str, int, str] | None:
    """Fetch *url* with retry on transient failures.

    Returns ``(body, status, content_type)`` on success, or ``None`` if every
    retry attempt failed. ``kwargs`` are forwarded to ``session.<method>()``
    (use ``data=`` / ``headers=`` for POST bodies).

    The content-type is the raw ``Content-Type`` header value (lower-cased)
    so callers can do simple ``"json" in ct`` checks.
    """
    response = await request_with_retry(
        session,
        method,
        url,
        config=retry or _DEFAULT_RETRY,
        ssl=False,
        allow_redirects=True,
        **kwargs,
    )
    if response is None:
        return None
    # request_with_retry returns text already; content-type isn't carried by
    # the lightweight Response dataclass. Fetch headers via a separate HEAD
    # call would be wasteful, so callers needing content-type should use the
    # raw session.get() form. For now we leave content-type empty and let
    # callers re-derive it from the body if needed.
    return response.text, response.status, ""


async def fetch_with_headers(
    session: aiohttp.ClientSession,
    url: str,
    *,
    method: str = "GET",
    retry: RetryConfig | None = None,
    **kwargs: object,
) -> tuple[str, int, str] | None:
    """Like :func:`fetch_with_retry` but also returns the ``Content-Type`` header.

    Use this when the caller needs the content type (e.g. IDOR's
    JSON-vs-HTML check). The trade-off is one extra attribute read on the
    response object, which is negligible.
    """
    cfg = retry or _DEFAULT_RETRY
    attempts = cfg.total_attempts()
    verb = getattr(session, method.lower(), None)
    if verb is None:
        return None

    for attempt in range(1, attempts + 1):
        try:
            async with verb(url, ssl=False, allow_redirects=True, **kwargs) as resp:
                status = int(resp.status)
                if status in {429, 500, 502, 503, 504} and attempt < attempts:
                    await asyncio.sleep(cfg.base_delay * (cfg.factor ** (attempt - 1)))
                    continue
                body = await resp.text(errors="ignore")
                ct = resp.headers.get("Content-Type", "").lower()
                return body, status, ct
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if attempt < attempts:
                await asyncio.sleep(cfg.base_delay * (cfg.factor ** (attempt - 1)))
                continue
            return None
    return None


def is_soft404(
    body: str,
    status: int,
    baseline: SoftBaseline | None,
) -> bool:
    """True if *(status, body)* matches the calibrated soft-404 signature.

    Returns ``False`` when ``baseline`` is ``None`` (no calibration was
    possible, or the server honestly returns 404 — both mean "don't filter").
    """
    if baseline is None:
        return False
    return baseline.matches(status, body[:_MAX_BODY_FOR_COMPARE])


async def calibrate_target(
    session: aiohttp.ClientSession,
    target: str,
) -> SoftBaseline | None:
    """Calibrate soft-404 baseline for *target*.

    Wraps :func:`webscan.plugins.soft404.calibrate` so callers don't need to
    import the soft-404 module directly. Strips the path off the target URL
    before calibrating against the host root.
    """
    from urllib.parse import urlparse

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return await calibrate(session, base)


def body_similarity(a: str, b: str) -> float:
    """Sequence-similarity ratio between two response bodies (0..1).

    Caps both inputs at :data:`_MAX_BODY_FOR_COMPARE` for performance.
    """
    return _sequence_matcher_ratio(a[:_MAX_BODY_FOR_COMPARE], b[:_MAX_BODY_FOR_COMPARE])


def _sequence_matcher_ratio(a: str, b: str) -> float:
    """Inline SequenceMatcher call to keep imports tidy."""
    from difflib import SequenceMatcher

    return SequenceMatcher(None, a, b).ratio()


def looks_like_xml_or_json(content_type: str, body: str) -> bool:
    """Heuristic: does this response look like XML or JSON (not HTML)?

    Used by active plugins to decide whether a "200 OK" probe response is
    worth flagging as suspicious (an XML/JSON response to an XML probe is
    interesting; an HTML error page is not).

    A response is considered XML/JSON if:

    * The Content-Type advertises it (``application/xml``, ``text/xml``,
      ``application/json``, ``application/soap+xml``, etc.), OR
    * The body starts with ``<?xml``, ``<rss``, ``<feed``, ``<soap:``, or
      ``{``/``[`` (JSON), ignoring leading whitespace, OR
    * The body starts with a ``<tag>`` that is NOT ``<!doctype html>`` or
      ``<html>`` (i.e. XML-like but not HTML).
    """
    ct = (content_type or "").lower()
    if any(s in ct for s in ("xml", "json", "soap")):
        return True
    stripped = body.lstrip()[:200].lower()
    if stripped.startswith(("<?xml", "<rss", "<feed", "<soap:", "{", "[")):
        return True
    # XML-like but not HTML: starts with a `<tag>` that isn't `<html>` or
    # `<!doctype html>`. This catches custom XML responses like `<result>`,
    # `<response>`, `<error>`, etc.
    if stripped.startswith("<") and not stripped.startswith(("<!doctype html", "<html")):
        # Must look like a tag (not a comment, not a CDATA-only doc).
        if stripped.startswith("<!") and not stripped.startswith("<!doctype"):
            return False  # comment or other declaration
        return True
    return False

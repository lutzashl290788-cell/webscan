"""Soft-404 calibration shared by path-probing plugins.

Some servers answer *every* request with ``200 OK`` (custom "Not Found"
pages, SPA catch-all routes, WAF/honeypot responses) instead of a real
``404``. Naive path probing then reports a false positive on every path it
tries. This module calibrates against the target up front: it requests a path
that is overwhelmingly unlikely to exist and, if the server still returns an
"interesting" status with a body, records that signature so genuine probes
matching it can be suppressed.

The comparison is fully offline — stdlib :class:`difflib.SequenceMatcher`,
the same approach already used by the SQL-injection plugin. No new dependency.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from difflib import SequenceMatcher

import aiohttp

# ``fetch_body`` is imported lazily inside ``calibrate`` to avoid a circular
# import: ``_active_helpers`` imports ``soft404.SoftBaseline`` at module load.

# A path no real site is expected to serve. Fixed (not random) so calibration
# is deterministic and unit-testable.
_PROBE_PATH = "/webscan-soft404-probe-zzq9x7w3k1"

# Bytes of the body sampled for comparison — enough to characterise a template
# without pulling large pages.
_BODY_SAMPLE = 2048

# Bodies whose similarity to the calibrated soft-404 is at or above this are
# treated as the same "not found" template and suppressed.
_DEFAULT_THRESHOLD = 0.90


@dataclass(frozen=True)
class SoftBaseline:
    """A captured soft-404 signature: the status and a body sample."""

    status: int
    body: str

    def matches(self, status: int, body: str, threshold: float = _DEFAULT_THRESHOLD) -> bool:
        """Return ``True`` if *(status, body)* looks like this soft-404 template.

        The status must match exactly; the body must be at least *threshold*
        similar. An empty calibrated body falls back to a status-only match,
        which is the correct behaviour when the soft-404 page is contentless.
        """
        if status != self.status:
            return False
        if not self.body:
            return True
        return SequenceMatcher(None, self.body, body).ratio() >= threshold


async def _read_body(resp: aiohttp.ClientResponse, limit: int = _BODY_SAMPLE) -> str:
    """Read up to *limit* bytes of *resp* as lower-cased text, robustly.

    Tries the streaming ``content.read`` path first (cheap, bounded) and falls
    back to ``fetch_body`` so it works against both real aiohttp responses and
    the lightweight fakes used in tests.
    """
    try:
        raw = await resp.content.read(limit)
        return raw.decode("utf-8", errors="ignore").lower()
    except (AttributeError, TypeError):
        # Lazy import to break the ``_active_helpers`` ↔ ``soft404`` cycle.
        from webscan.plugins._active_helpers import fetch_body

        try:
            text = await fetch_body(resp)
        except (aiohttp.ClientError, UnicodeDecodeError, AttributeError, TypeError):
            return ""
        return text[:limit].lower()


async def read_finding_body(resp: aiohttp.ClientResponse, limit: int = _BODY_SAMPLE) -> str:
    """Public wrapper: sample a response body for soft-404 comparison."""
    return await _read_body(resp, limit)


async def calibrate(
    session: aiohttp.ClientSession,
    base: str,
    interesting_statuses: frozenset[int] = frozenset({200, 403}),
) -> SoftBaseline | None:
    """Probe a non-existent path and capture its soft-404 signature, if any.

    :param session: Shared client session.
    :param base: Target base URL, without a trailing slash.
    :param interesting_statuses: Statuses that, if returned for a path known
        not to exist, indicate the server does not honestly signal 404.
    :returns: A :class:`SoftBaseline` when the server answers the bogus path
        with an interesting status (so a filter is warranted), else ``None``
        (the server is well-behaved and probing can proceed unfiltered).
    """
    url = f"{base}{_PROBE_PATH}"
    try:
        async with session.get(url, allow_redirects=False, ssl=False) as resp:
            status = resp.status
            if status not in interesting_statuses:
                return None
            body = await _read_body(resp)
            return SoftBaseline(status=status, body=body)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        # If calibration itself fails we cannot characterise soft-404s; fall
        # back to unfiltered probing rather than silently dropping findings.
        return None

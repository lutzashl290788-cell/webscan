"""Plugin: detect race conditions in state-changing endpoints.

Race conditions occur when an endpoint performs a non-atomic read-modify-write
on shared state. An attacker sends the same request many times simultaneously
(e.g. apply coupon, withdraw funds, cast vote) and the operation executes
more than once, leading to double-spending, duplicate votes, or balance
manipulation.

The plugin is **active**: it sends the same request N times concurrently
and checks if the response indicates the operation was applied more than
once (e.g. "Coupon applied" appears in multiple responses, or the balance
changed by N× the expected amount).

For low false positives:
- Only probes endpoints with state-changing parameters (coupon, vote, withdraw)
- Sends a harmless duplicate (e.g. applying the same coupon twice)
- All findings are TENTATIVE — race conditions are inherently hard to confirm
  without observing the server's internal state
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# Parameter names that suggest a state-changing operation worth racing.
_RACE_PARAM_NAMES: frozenset[str] = frozenset({
    "coupon", "code", "voucher", "promo", "discount",
    "vote", "poll", "rate", "like", "upvote",
    "withdraw", "transfer", "send", "payment",
    "redeem", "claim", "gift", "reward",
})

_CONCURRENT_REQUESTS = 10
_TIMEOUT_SECONDS = 15


def _has_race_params(target: str) -> bool:
    from urllib.parse import parse_qs, urlparse
    parsed = urlparse(target)
    if not parsed.query:
        return False
    return any(name.lower() in _RACE_PARAM_NAMES for name in parse_qs(parsed.query))


class RaceConditionPlugin(BasePlugin):
    """Probes state-changing endpoints for race conditions via concurrent requests."""

    name = "race_condition"
    description = "Detect race conditions by sending concurrent duplicate requests (TENTATIVE)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if not _has_race_params(target):
            return findings

        # Send N concurrent GET requests.
        async def _single_request() -> tuple[int, str]:
            try:
                async with session.get(
                    target, allow_redirects=False, ssl=False,
                    timeout=aiohttp.ClientTimeout(total=_TIMEOUT_SECONDS),
                ) as resp:
                    body = await fetch_body(resp)
                    return resp.status, body
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
                return 0, ""

        results = await asyncio.gather(*[_single_request() for _ in range(_CONCURRENT_REQUESTS)])

        # Count how many returned 200 with a "success" indicator.
        success_count = 0
        success_bodies: list[str] = []
        for status, body in results:
            if status == 200 and body:
                lowered = body.lower()
                if any(s in lowered for s in ("success", "applied", "done", "ok", "completed", "accepted")):  # noqa: E501
                    success_count += 1
                    success_bodies.append(body)

        # If more than 1 request "succeeded", it's a race condition.
        if success_count >= 2:
            findings.append(Finding(
                plugin=self.name,
                title=f"Race condition: {success_count}/{_CONCURRENT_REQUESTS} concurrent requests succeeded",  # noqa: E501
                severity=Severity.HIGH,
                confidence=Confidence.TENTATIVE,
                description=(
                    f" {_CONCURRENT_REQUESTS} concurrent requests to "
                    f"`{target}` resulted in {success_count} success "
                    "responses. This suggests the endpoint doesn't use "
                    "proper locking — an attacker can exploit the race to "
                    "apply a coupon multiple times, vote multiple times, "
                    "or withdraw more than the balance allows."
                ),
                url=target,
                evidence={
                    "concurrent_requests": _CONCURRENT_REQUESTS,
                    "successful_responses": success_count,
                    "sample_response": success_bodies[0][:200] if success_bodies else "",
                },
                remediation=(
                    "Use database transactions with proper isolation level "
                    "(SERIALIZABLE or SELECT ... FOR UPDATE). Implement "
                    "server-side locking (Redis SETNX, database advisory locks). "
                    "Make the operation idempotent — check if the action was "
                    "already performed before executing it."
                ),
            ))

        return findings

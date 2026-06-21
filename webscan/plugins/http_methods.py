"""Plugin: detect dangerous HTTP methods the target *actually* accepts.

Trusting the ``Allow`` / OPTIONS response is a classic false-positive source:
many servers and frameworks advertise ``PUT``/``DELETE``/``PATCH`` there yet
answer ``405``/``403`` when the method is really sent. This plugin verifies each
dangerous method by issuing it — against a throwaway probe path for
state-changing verbs, so a real resource is never touched — and only reports a
method the server genuinely honours.
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# Method -> (severity, why it is risky)
_DANGEROUS_METHODS: dict[str, tuple[Severity, str]] = {
    "PUT": (Severity.HIGH, "allows clients to upload or overwrite files on the server"),
    "DELETE": (Severity.HIGH, "allows clients to delete resources on the server"),
    "TRACE": (Severity.MEDIUM, "enables Cross-Site Tracing (XST) attacks"),
    "CONNECT": (Severity.MEDIUM, "can let the server be abused as an open proxy"),
    "PATCH": (Severity.LOW, "allows partial modification of server resources"),
}

# A path the target is overwhelmingly unlikely to serve, so PUT/DELETE/PATCH
# probes never hit (or alter) a real resource.
_PROBE_PATH = "/webscan-method-probe-9z7q1x"

# Header echoed back by a TRACE-enabled server (the basis of XST).
_TRACE_MARKER = "X-WebScan-Trace"

# Statuses that prove the verb was actually carried out.
_ACCEPTED = frozenset({200, 201, 202, 204})


class HttpMethodsPlugin(BasePlugin):
    """Actively probes dangerous HTTP methods and flags the ones truly enabled."""

    name = "http_methods"
    description = "Detect dangerous enabled HTTP methods (PUT, DELETE, TRACE, ...)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        probe_url = target.rstrip("/") + _PROBE_PATH

        # On a catch-all host (2xx for paths that do not exist), a 2xx response
        # to PUT/DELETE proves nothing — so state-changing verbs cannot be
        # verified there and are skipped rather than reported as false positives.
        catch_all = await self._is_catch_all(session, probe_url)

        for method, (severity, note) in _DANGEROUS_METHODS.items():
            if method == "TRACE":
                enabled = await self._trace_enabled(session, target)
                verified_via = target
            elif method == "CONNECT":
                enabled = await self._verb_accepted(session, "CONNECT", target)
                verified_via = target
            else:
                if catch_all:
                    continue
                enabled = await self._verb_accepted(session, method, probe_url)
                verified_via = probe_url

            if not enabled:
                continue

            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"Dangerous HTTP method enabled: {method}",
                    severity=severity,
                    description=(
                        f"The server accepted a live {method} request, which "
                        f"{note}. (Verified by issuing the method, not by trusting "
                        "the Allow header.)"
                    ),
                    url=target,
                    evidence={"method": method, "verified_via": verified_via},
                    remediation=(
                        f"Disable the {method} method at the web server or framework "
                        "level unless it is explicitly required."
                    ),
                )
            )

        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _is_catch_all(
        self, session: aiohttp.ClientSession, url: str
    ) -> bool:
        try:
            async with session.get(
                url, allow_redirects=False, ssl=False
            ) as resp:
                return 200 <= resp.status < 300
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    async def _verb_accepted(
        self, session: aiohttp.ClientSession, method: str, url: str
    ) -> bool:
        try:
            async with session.request(
                method, url, allow_redirects=False, ssl=False
            ) as resp:
                return resp.status in _ACCEPTED
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    async def _trace_enabled(
        self, session: aiohttp.ClientSession, target: str
    ) -> bool:
        # TRACE is dangerous only when the server echoes the request back; a bare
        # 200 without the echo is not exploitable, so we require the marker.
        try:
            async with session.request(
                "TRACE",
                target,
                headers={_TRACE_MARKER: "1"},
                allow_redirects=False,
                ssl=False,
            ) as resp:
                if resp.status != 200:
                    return False
                body = await fetch_body(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
        return _TRACE_MARKER.lower() in body.lower()

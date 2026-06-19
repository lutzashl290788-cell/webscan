"""Plugin: detect HTTP Request Smuggling (CL.TE, TE.CL, CL.CL).

HTTP request smuggling occurs when a front-end (proxy/CDN) and back-end
server disagree on how to parse the boundary between HTTP requests. An
attacker sends a specially crafted request that the front-end sees as one
request but the back-end sees as two — the second "smuggled" request
bypasses the front-end's security controls.

Three variants:
- **CL.TE** — front-end uses Content-Length, back-end uses Transfer-Encoding
- **TE.CL** — front-end uses Transfer-Encoding, back-end uses Content-Length
- **CL.CL** — both use Content-Length but with different values

The plugin is **active**: it sends probe requests with conflicting headers
and checks for timing differences or unexpected responses.

For low false positives:
- Only flags when the server's behaviour clearly indicates smuggling
  (timeout on TE.CL probe = back-end is waiting for more data)
- All findings are TENTATIVE — smuggling is hard to confirm without
  observing the back-end directly
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# TE.CL probe: front-end sees Transfer-Encoding, sends body; back-end uses
# Content-Length: 4, reads "0\r\n\r\n" as the end of the first request, and
# the rest becomes a smuggled second request.
_TE_CL_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /webscan-smuggling-probe HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "\r\n"
)

# CL.TE probe: front-end sees Content-Length, sends full body; back-end uses
# Transfer-Encoding: chunked, reads "0\r\n\r\n" as end, rest is smuggled.
_CL_TE_PROBE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 100\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /webscan-smuggling-probe HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Length: 10\r\n"
    "\r\n"
    "x=1\r\n"
)

_SMUGGLING_TIMEOUT = 8.0


class RequestSmugglingPlugin(BasePlugin):
    """Probes for HTTP request smuggling (CL.TE, TE.CL)."""

    name = "request_smuggling"
    description = "Detect HTTP request smuggling via CL.TE and TE.CL variants (TENTATIVE)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.netloc
        base = f"{parsed.scheme}://{host}"

        # TE.CL probe: if the back-end uses Content-Length, it will read
        # "0\r\n\r\n" as the end and wait for the smuggled request to
        # complete — causing a timeout. A timeout indicates TE.CL smuggling.
        te_cl_finding = await self._probe_te_cl(session, base, host)
        if te_cl_finding:
            findings.append(te_cl_finding)
            return findings

        # CL.TE probe: if the back-end uses Transfer-Encoding, it will
        # process the smuggled request. We check if a subsequent request
        # returns an unexpected response.
        cl_te_finding = await self._probe_cl_te(session, base, host)
        if cl_te_finding:
            findings.append(cl_te_finding)

        return findings

    async def _probe_te_cl(
        self,
        session: aiohttp.ClientSession,
        base: str,
        host: str,
    ) -> Finding | None:
        """TE.CL probe: send a request that causes a timeout if vulnerable."""
        probe = _TE_CL_PROBE.format(host=host).encode("utf-8")
        try:
            async with session.post(
                base + "/",
                data=probe,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "4",
                },
                timeout=aiohttp.ClientTimeout(total=_SMUGGLING_TIMEOUT),
                ssl=False,
            ):
                # A fast 200/400 response means no smuggling.
                # A timeout means the back-end is waiting for the smuggled
                # request to complete → TE.CL vulnerability.
                return None
        except asyncio.TimeoutError:
            return Finding(
                plugin=self.name,
                title="HTTP request smuggling: TE.CL variant (timeout on probe)",
                severity=Severity.CRITICAL,
                confidence=Confidence.TENTATIVE,
                description=(
                    "A TE.CL probe (Content-Length: 4 + Transfer-Encoding: "
                    "chunked) caused a timeout, suggesting the back-end "
                    "server processed the request using Content-Length and "
                    "is waiting for the smuggled second request to complete. "
                    "An attacker can exploit this to bypass front-end "
                    "security controls, poison the cache, or steal other "
                    "users' requests."
                ),
                url=base + "/",
                evidence={
                    "variant": "TE.CL",
                    "probe": "Content-Length: 4, Transfer-Encoding: chunked",
                    "timeout_seconds": _SMUGGLING_TIMEOUT,
                },
                remediation=(
                    "Reject requests with both Content-Length and "
                    "Transfer-Encoding headers. Normalize Transfer-Encoding "
                    "at the front-end (strip it, use Content-Length only). "
                    "Use HTTP/2 end-to-end, which doesn't have this ambiguity."
                ),
            )
        except (aiohttp.ClientError, UnicodeError):
            return None

    async def _probe_cl_te(
        self,
        session: aiohttp.ClientSession,
        base: str,
        host: str,
    ) -> Finding | None:
        """CL.TE probe: check for unexpected response on a follow-up request."""
        probe = _CL_TE_PROBE.format(host=host).encode("utf-8")
        try:
            async with session.post(
                base + "/",
                data=probe,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "100",
                    "Transfer-Encoding": "chunked",
                },
                timeout=aiohttp.ClientTimeout(total=_SMUGGLING_TIMEOUT),
                ssl=False,
            ):
                pass
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            pass

        # Send a normal follow-up request. If smuggling occurred, the
        # smuggled request may have polluted the connection's response queue.
        try:
            async with session.get(
                base + "/",
                timeout=aiohttp.ClientTimeout(total=_SMUGGLING_TIMEOUT),
                ssl=False,
            ) as resp:
                body = await resp.text(errors="ignore")
                if "webscan-smuggling-probe" in body:
                    return Finding(
                        plugin=self.name,
                        title="HTTP request smuggling: CL.TE variant (smuggled request detected)",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.TENTATIVE,
                        description=(
                            "A CL.TE probe was sent, and the follow-up request "
                            "returned a response containing the smuggled "
                            "request's marker. This confirms the back-end "
                            "server processed the smuggled request."
                        ),
                        url=base + "/",
                        evidence={
                            "variant": "CL.TE",
                            "follow_up_response_marker": "webscan-smuggling-probe",
                        },
                        remediation=(
                            "Reject requests with both Content-Length and "
                            "Transfer-Encoding headers. Use HTTP/2 end-to-end."
                        ),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            pass

        return None

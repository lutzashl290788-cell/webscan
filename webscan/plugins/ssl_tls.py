"""Plugin: audit TLS/SSL configuration — protocol version, certificate, HSTS."""
from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin

# Protocol versions considered obsolete/insecure if negotiated.
_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

# Warn when a certificate expires within this many days.
_EXPIRY_WARN_DAYS = 21


class SslTlsPlugin(BasePlugin):
    """Audits the target's TLS endpoint for weak protocols, cert and HSTS issues."""

    name = "ssl_tls"
    description = "Audit TLS version, certificate validity and HSTS"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        parsed = urlparse(target)
        if parsed.scheme != "https":
            return []  # nothing to audit on plain HTTP

        host = parsed.hostname
        if not host:
            return []
        port = parsed.port or 443

        try:
            info = await asyncio.to_thread(_probe_tls, host, port)
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            return []
        if info is None:
            return []

        findings: list[Finding] = []
        protocol, not_after, cert_expired = info

        if protocol in _WEAK_PROTOCOLS:
            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"Weak TLS protocol negotiated: {protocol}",
                    severity=Severity.HIGH,
                    description=(
                        f"The server negotiated {protocol}, which is deprecated and "
                        "vulnerable to known downgrade and cryptographic attacks."
                    ),
                    url=target,
                    evidence={"protocol": protocol},
                    remediation=(
                        "Disable SSLv2/v3 and TLS 1.0/1.1; serve TLS 1.2+ only."
                    ),
                )
            )

        if cert_expired:
            findings.append(
                Finding(
                    plugin=self.name,
                    title="Expired TLS certificate",
                    severity=Severity.HIGH,
                    description=(
                        f"The server's certificate expired on {not_after}."
                    ),
                    url=target,
                    evidence={"not_after": not_after},
                    remediation="Renew the certificate and automate renewal.",
                )
            )
        elif not_after is not None:
            days_left = _days_until(not_after)
            if days_left is not None and days_left <= _EXPIRY_WARN_DAYS:
                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"TLS certificate expires in {days_left} day(s)",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The certificate expires on {not_after} "
                            f"({days_left} day(s) away)."
                        ),
                        url=target,
                        evidence={"not_after": not_after, "days_left": days_left},
                        remediation="Renew the certificate before it expires.",
                    )
                )

        # HSTS check via the shared HTTP session.
        hsts = await self._check_hsts(session, target)
        if hsts is not None:
            findings.append(hsts)

        return findings

    async def _check_hsts(
        self, session: aiohttp.ClientSession, target: str
    ) -> Finding | None:
        try:
            async with session.get(target, ssl=False) as resp:
                has_hsts = "Strict-Transport-Security" in resp.headers
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        if has_hsts:
            return None
        return Finding(
            plugin=self.name,
            title="Missing HSTS header",
            severity=Severity.MEDIUM,
            description=(
                "The HTTPS response lacks a Strict-Transport-Security header, "
                "leaving users exposed to SSL-stripping downgrade attacks."
            ),
            url=target,
            evidence={"header": "Strict-Transport-Security"},
            remediation=(
                "Send 'Strict-Transport-Security: max-age=31536000; "
                "includeSubDomains' over HTTPS."
            ),
            # The headers plugin reports the very same absent header; the engine
            # keeps whichever report is more severe rather than listing both.
            dedup_key="missing-header:strict-transport-security",
        )


def _probe_tls(host: str, port: int) -> tuple[str, str | None, bool] | None:
    """Open a TLS connection and return (protocol, not_after, expired)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            protocol = ssock.version() or "unknown"
            cert = ssock.getpeercert()

    not_after_raw = cert.get("notAfter") if cert else None
    not_after = not_after_raw if isinstance(not_after_raw, str) else None
    expired = False
    if not_after:
        expiry = _parse_cert_time(not_after)
        if expiry is not None:
            expired = expiry < datetime.now(tz=timezone.utc)
    return protocol, not_after, expired


def _parse_cert_time(value: str) -> datetime | None:
    # OpenSSL format, e.g. "Jun  1 12:00:00 2027 GMT".
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def _days_until(not_after: str) -> int | None:
    expiry = _parse_cert_time(not_after)
    if expiry is None:
        return None
    delta = expiry - datetime.now(tz=timezone.utc)
    return delta.days

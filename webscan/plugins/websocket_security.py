"""Plugin: detect insecure WebSocket endpoints.

WebSocket (ws://) endpoints are increasingly used for real-time features
(chat, notifications, live data). When misconfigured, they expose several
security risks:

* **ws:// instead of wss://** — traffic is unencrypted; anyone on the
  network path can read/modify messages.
* **No origin validation** — the server accepts WebSocket connections from
  any origin, enabling cross-site WebSocket hijacking (CSWSH).
* **No authentication** — sensitive data is accessible without credentials.
* **Sensitive data in responses** — API keys, session tokens, or personal
  data sent over ws:// can be intercepted.

This plugin is **passive**: it scans the page's HTML and same-origin
JavaScript for WebSocket URLs (``ws://`` and ``wss://``) and reports
security issues based on the URL scheme and context.

Findings:

* **HIGH (FIRM)** — ``ws://`` endpoint found in page source (unencrypted).
  The traffic can be sniffed/MITM'd by anyone on the network path.
* **MEDIUM (TENTATIVE)** — ``wss://`` endpoint found but appears to carry
  sensitive data (near ``token``, ``auth``, ``session``, ``password``
  keywords in the surrounding code). Manual review needed to confirm.
* **LOW (INFORMATIONAL)** — ``wss://`` endpoint found with no obvious
  sensitive context. Informational — the endpoint exists and should be
  audited for origin/auth checks.
"""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin
from webscan.utils.html import parse_html

# Regex to find ws:// and wss:// URLs in HTML/JS source.
_WS_URL_RE: re.Pattern[str] = re.compile(
    r'(?:["\'])?(wss?:\/\/[^\s"\'<>\)]+)["\']?',
    re.IGNORECASE,
)

# Keywords that suggest the WebSocket carries sensitive data.
_SENSITIVE_CONTEXT_KEYWORDS: tuple[str, ...] = (
    "token",
    "auth",
    "session",
    "password",
    "secret",
    "api_key",
    "apikey",
    "credential",
    "private",
    "user",
    "account",
    "balance",
    "payment",
    "invoice",
    "ssn",
    "credit",
)

# How many characters of surrounding context to check for sensitive keywords.
_CONTEXT_RADIUS = 100

# Maximum JS files to fetch and scan.
_MAX_SCRIPTS = 10

# Minimum body length.
_MIN_BODY_LENGTH = 50


def _find_ws_urls(text: str) -> list[tuple[str, int, str]]:
    """Return ``(url, position, context)`` for each ws:// or wss:// URL found.

    ``context`` is the surrounding ±100 chars of text, used to check for
    sensitive keywords.
    """
    results: list[tuple[str, int, str]] = []
    for match in _WS_URL_RE.finditer(text):
        url = match.group(1)
        pos = match.start()
        ctx_start = max(0, pos - _CONTEXT_RADIUS)
        ctx_end = min(len(text), pos + len(url) + _CONTEXT_RADIUS)
        context = text[ctx_start:ctx_end].lower()
        results.append((url, pos, context))
    return results


def _has_sensitive_context(context: str) -> bool:
    """True if the surrounding context contains sensitive keywords."""
    return any(kw in context for kw in _SENSITIVE_CONTEXT_KEYWORDS)


class WebsocketSecurityPlugin(BasePlugin):
    """Scans HTML and JS for insecure WebSocket endpoints."""

    name = "websocket_security"
    description = "Detect insecure ws:// endpoints, missing wss://, and sensitive data over WebSocket"  # noqa: E501

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "html" not in content_type.lower() and not target.endswith((".html", ".htm")):
                    return findings
                body = await fetch_body(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        if len(body) < _MIN_BODY_LENGTH:
            return findings

        # Scan inline HTML.
        texts_to_scan: list[tuple[str, str]] = [(body, target)]

        # Fetch same-origin JS files.
        target_host = urlparse(target).netloc
        page = parse_html(body, base=target)
        scripts = [
            s for s in page.links
            if s.endswith(".js") and urlparse(s).netloc == target_host
        ][:_MAX_SCRIPTS]

        for src in scripts:
            try:
                async with session.get(src, ssl=False) as resp:
                    js = await fetch_body(resp)
                    if js:
                        texts_to_scan.append((js, src))
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
                continue

        seen_urls: set[str] = set()

        for text, location in texts_to_scan:
            ws_entries = _find_ws_urls(text)

            for url, _pos, context in ws_entries:
                # Dedupe by URL.
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                is_unencrypted = url.lower().startswith("ws://")
                has_sensitive = _has_sensitive_context(context)

                if is_unencrypted:
                    # ws:// — unencrypted WebSocket. Always HIGH.
                    findings.append(self._make_finding(
                        target=target,
                        ws_url=url,
                        location=location,
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        issue="unencrypted",
                        has_sensitive=has_sensitive,
                    ))
                elif has_sensitive:
                    # wss:// but sensitive context — MEDIUM (TENTATIVE).
                    findings.append(self._make_finding(
                        target=target,
                        ws_url=url,
                        location=location,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        issue="sensitive-context",
                        has_sensitive=True,
                    ))
                else:
                    # wss:// with no obvious sensitive context — LOW (INFO).
                    findings.append(self._make_finding(
                        target=target,
                        ws_url=url,
                        location=location,
                        severity=Severity.LOW,
                        confidence=Confidence.INFORMATIONAL,
                        issue="endpoint-exists",
                        has_sensitive=False,
                    ))

        return findings

    def _make_finding(
        self,
        *,
        target: str,
        ws_url: str,
        location: str,
        severity: Severity,
        confidence: Confidence,
        issue: str,
        has_sensitive: bool,
    ) -> Finding:
        if issue == "unencrypted":
            title = f"Insecure WebSocket: ws:// endpoint found ({ws_url[:60]})"
            desc = (
                f"An unencrypted WebSocket endpoint (`{ws_url}`) was found "
                f"in the page source at `{location}`. WebSocket traffic over "
                "ws:// is sent in plaintext — anyone on the network path "
                "(ISP, coffee-shop Wi-Fi, corporate proxy) can read and "
                "modify messages in real time."
            )
            if has_sensitive:
                desc += (
                    " The surrounding code context suggests this endpoint "
                    "carries sensitive data (auth tokens, user info, "
                    "payment data). Intercepting this traffic could lead "
                    "to account takeover or data theft."
                )
        elif issue == "sensitive-context":
            title = f"WebSocket with sensitive context ({ws_url[:60]})"
            desc = (
                f"A secure WebSocket endpoint (`{ws_url}`) was found at "
                f"`{location}`, but the surrounding code context contains "
                "sensitive keywords (token, auth, session, password). "
                "While the connection is encrypted (wss://), the endpoint "
                "should be audited for: (1) origin validation to prevent "
                "cross-site WebSocket hijacking, (2) authentication checks "
                "to ensure only authorised users can connect."
            )
        else:
            title = f"WebSocket endpoint discovered ({ws_url[:60]})"
            desc = (
                f"A WebSocket endpoint (`{ws_url}`) was found at "
                f"`{location}`. The connection uses wss:// (encrypted), "
                "but the endpoint should still be audited for origin "
                "validation and authentication. Manual review recommended."
            )

        return Finding(
            plugin=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            description=desc,
            url=target,
            evidence={
                "ws_url": ws_url,
                "location": location,
                "scheme": "ws" if issue == "unencrypted" else "wss",
                "has_sensitive_context": has_sensitive,
                "issue_type": issue,
            },
            remediation=(
                "Use wss:// (WebSocket Secure) instead of ws:// for all "
                "WebSocket connections. Implement origin validation on the "
                "server (check the Origin header against an allow-list). "
                "Require authentication (token/cookie) before accepting "
                "WebSocket connections. Never send sensitive data over "
                "ws:// — use wss:// with proper certificate validation."
            ),
        )

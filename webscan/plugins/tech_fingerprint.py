"""Plugin: fingerprint server, framework and CMS technologies."""
from __future__ import annotations

import asyncio
import re

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# (label, compiled body regex) — matched against the response HTML.
_BODY_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("WordPress", re.compile(r"/wp-(content|includes)/", re.IGNORECASE)),
    ("Drupal", re.compile(r'(Drupal\.settings|/sites/(all|default)/)', re.IGNORECASE)),
    ("Joomla", re.compile(r"/media/jui/|com_content", re.IGNORECASE)),
    ("Magento", re.compile(r"/static/version\d+/|Mage\.Cookies", re.IGNORECASE)),
    ("React", re.compile(r"data-reactroot|__REACT_DEVTOOLS", re.IGNORECASE)),
    ("Vue.js", re.compile(r"data-v-[0-9a-f]{8}|__VUE__", re.IGNORECASE)),
    ("Angular", re.compile(r"ng-version=|ng-app", re.IGNORECASE)),
    ("Next.js", re.compile(r"/_next/static/|__NEXT_DATA__", re.IGNORECASE)),
]

# (label, header name, optional value substring) — matched against headers.
_HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("Nginx", "Server", "nginx"),
    ("Apache", "Server", "apache"),
    ("Microsoft IIS", "Server", "iis"),
    ("LiteSpeed", "Server", "litespeed"),
    ("Cloudflare", "Server", "cloudflare"),
    ("PHP", "X-Powered-By", "php"),
    ("ASP.NET", "X-Powered-By", "asp.net"),
    ("Express", "X-Powered-By", "express"),
    ("WordPress", "X-Pingback", ""),
]

# (label, cookie-name substring) — matched against Set-Cookie.
_COOKIE_SIGNATURES: list[tuple[str, str]] = [
    ("PHP", "phpsessid"),
    ("ASP.NET", "asp.net_sessionid"),
    ("Java", "jsessionid"),
    ("Laravel", "laravel_session"),
    ("Django", "csrftoken"),
    ("Flask", "session"),
]


class TechFingerprintPlugin(BasePlugin):
    """Identifies server, framework and CMS technologies from one response."""

    name = "tech_fingerprint"
    description = "Fingerprint server, framework and CMS technologies"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        try:
            async with session.get(target, ssl=False) as resp:
                body = await fetch_body(resp)
                headers = dict(resp.headers.items())
                set_cookie = " ".join(resp.headers.getall("Set-Cookie", [])).lower()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return []

        detected: dict[str, str] = {}  # technology -> how it was detected

        for label, header_name, needle in _HEADER_SIGNATURES:
            value = headers.get(header_name, "")
            if value and (not needle or needle in value.lower()):
                detected.setdefault(label, f"{header_name}: {value}")

        for label, cookie_needle in _COOKIE_SIGNATURES:
            if cookie_needle in set_cookie:
                detected.setdefault(label, f"cookie matched '{cookie_needle}'")

        for label, pattern in _BODY_SIGNATURES:
            if pattern.search(body):
                detected.setdefault(label, "HTML body signature")

        # Surface the raw Server banner too, even if unrecognised.
        server = headers.get("Server", "")
        generator = _meta_generator(body)
        if generator:
            detected.setdefault(generator, "meta generator tag")

        if not detected:
            return []

        return [
            Finding(
                plugin=self.name,
                title=f"Technologies detected: {', '.join(sorted(detected))}",
                severity=Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                description=(
                    "The target exposes technology fingerprints in its response "
                    "headers, cookies or HTML. This information helps attackers "
                    "target known vulnerabilities for the identified stack."
                ),
                url=target,
                evidence={
                    "technologies": detected,
                    "server_banner": server,
                },
                dedup_key="site:technology-fingerprint",
                remediation=(
                    "Suppress or genericise version-revealing headers (Server, "
                    "X-Powered-By, X-Generator) and remove framework fingerprints "
                    "where practical."
                ),
            )
        ]


def _meta_generator(body: str) -> str:
    match = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
        body,
        re.IGNORECASE,
    )
    if match:
        return match.group(1).strip()
    return ""

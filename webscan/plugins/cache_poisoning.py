"""Plugin: detect cache-poisoning via Host-header / X-Forwarded-Host injection.

Many sites sit behind a CDN or reverse proxy (Cloudflare, Fastly, nginx,
Varnish, AWS CloudFront). The cache key is typically ``{method, path, query}``
— request *headers* are NOT part of the key. So if the origin server
reflects an attacker-controlled ``Host`` or ``X-Forwarded-Host`` header into
the response body (e.g. in a ``<link rel="canonical">`` tag, an OAuth
redirect URL, or a password-reset link), the cached version of the page
will serve the attacker's payload to every subsequent visitor.

The plugin is **active**: it sends probe requests with crafted headers
and verifies the response *reflects* the injected value. Pure status 200
is NOT enough — too many sites accept arbitrary Host headers without
reflecting them.

For low false positives:

* **CRITICAL (FIRM)** — the injected value appears in a *dangerous*
  location: ``<link>``, ``<script>``, ``<a href>``, ``<form action>``,
  ``<iframe src>``, ``<meta http-equiv="refresh" content="...;url=...">``,
  or any ``href``/``src``/``action`` attribute. These locations let the
  poisoned cache execute JavaScript or redirect users.
* **MEDIUM (FIRM)** — the injected value appears in the response body but
  NOT in a dangerous location (e.g. inside a comment, plain text). Still
  cacheable but less directly exploitable.
* **LOW (INFORMATIONAL)** — the server accepts the injected header
  (returns 200) but doesn't reflect it in the response body. Manual review
  needed: could be blind cache poisoning via a separate unkeyed input.

The plugin probes three headers — ``Host``, ``X-Forwarded-Host``, and
``X-Original-URL`` — because different cache layers honour different ones.
"""
from __future__ import annotations

import asyncio
import re

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# ─── Probe design ─────────────────────────────────────────────────────────────

# Unique sentinel host we try to inject. Random per scan so a fixed string in
# the response can't produce a false positive.
# Format: webscan-cache-probe-<random>.example
_SENTINEL_TEMPLATE = "webscan-cache-probe-{token}.example"

# Headers we probe. Each entry: (header_name, probe_value_template).
# We test them one at a time (not all together) so we can attribute a finding
# to a specific header. Templates use {sentinel} as a placeholder.
_PROBE_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Forwarded-Host", "{sentinel}"),
    ("Host", "{sentinel}"),
    ("X-Original-URL", "https://{sentinel}/"),
    ("X-Rewrite-URL", "https://{sentinel}/"),
    ("X-Forwarded-Server", "{sentinel}"),
)

# Regex patterns that match "dangerous" reflection locations — where the
# injected host can execute JavaScript or redirect users. Each pattern is
# applied to the lower-cased response body.
# The injected sentinel is interpolated at runtime so the patterns are
# pre-compiled with a {sentinel} placeholder.
_DANGEROUS_PATTERNS_RAW: tuple[str, ...] = (
    # <link href="...sentinel...">
    r'<link[^>]+href[^=]*=\s*["\'][^"\']*{sentinel}[^"\']*["\']',
    # <script src="...sentinel...">
    r'<script[^>]+src[^=]*=\s*["\'][^"\']*{sentinel}[^"\']*["\']',
    # <a href="...sentinel...">
    r'<a[^>]+href[^=]*=\s*["\'][^"\']*{sentinel}[^"\']*["\']',
    # <form action="...sentinel...">
    r'<form[^>]+action[^=]*=\s*["\'][^"\']*{sentinel}[^"\']*["\']',
    # <iframe src="...sentinel...">
    r'<iframe[^>]+src[^=]*=\s*["\'][^"\']*{sentinel}[^"\']*["\']',
    # <meta http-equiv="refresh" content="...;url=...sentinel...">
    r'<meta[^>]+http-equiv[^=]*=\s*["\']?refresh["\']?[^>]+content[^=]*=\s*["\'][^"\']*url=[^"\']*{sentinel}',
    # CSS @import or url() with sentinel
    r'url\([^)]*{sentinel}[^)]*\)',
    # JavaScript location assignment
    r'location(?:\.href)?\s*=\s*["\'][^"\']*{sentinel}',
)

# Minimum body length to consider the response a real page worth auditing.
_MIN_BODY_LENGTH = 200

# Cap on body length for regex matching (perf bound).
_MAX_BODY_LENGTH = 500_000


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _is_html_response(content_type: str, body: str) -> bool:
    """Heuristic: is this response an HTML page worth probing for reflection?"""
    ct = (content_type or "").lower()
    if "html" in ct:
        return True
    stripped = body.lstrip()[:200].lower()
    return stripped.startswith(("<!doctype html", "<html", "<head", "<body"))


def _compile_dangerous_patterns(sentinel: str) -> list[re.Pattern[str]]:
    """Compile the dangerous-reflection patterns with *sentinel* interpolated."""
    return [
        re.compile(p.format(sentinel=re.escape(sentinel)), re.IGNORECASE)
        for p in _DANGEROUS_PATTERNS_RAW
    ]


def _find_dangerous_reflection(body: str, sentinel: str) -> list[str]:
    """Return list of dangerous reflection contexts where *sentinel* appears."""
    patterns = _compile_dangerous_patterns(sentinel)
    body_lower = body.lower()[:_MAX_BODY_LENGTH]
    hits: list[str] = []
    for pattern in patterns:
        m = pattern.search(body_lower)
        if m:
            hits.append(m.group(0)[:120])
    return hits


def _has_plain_reflection(body: str, sentinel: str) -> bool:
    """True if *sentinel* appears anywhere in *body* (not just dangerous contexts)."""
    return sentinel.lower() in body.lower()[:_MAX_BODY_LENGTH]


# ─── Plugin ───────────────────────────────────────────────────────────────────


class CachePoisoningPlugin(BasePlugin):
    """Probes for cache-poisoning via Host / X-Forwarded-Host header injection."""

    name = "cache_poisoning"
    description = "Detect cache-poisoning via Host/X-Forwarded-Host/X-Original-URL reflection"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Fetch a baseline response to confirm the page is HTML and worth probing.
        try:
            async with session.get(target, allow_redirects=False, ssl=False) as resp:
                content_type = resp.headers.get("Content-Type", "")
                baseline_status = resp.status
                baseline_body = await resp.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        # Skip non-HTML — JSON/XML API responses aren't typically cached at
        # the page level and don't have <link>/<script> tags to poison.
        if not _is_html_response(content_type, baseline_body):
            return findings

        # Skip short / error responses.
        if len(baseline_body) < _MIN_BODY_LENGTH:
            return findings
        if baseline_status >= 400:
            return findings

        # Generate a per-scan sentinel so we don't false-positive on a string
        # that happens to be in the response already.
        import secrets
        token = secrets.token_hex(6)
        sentinel = _SENTINEL_TEMPLATE.format(token=token)

        # Probe each header one at a time.
        for header_name, value_template in _PROBE_HEADERS:
            probe_value = value_template.format(sentinel=sentinel)

            probe_body, probe_status = await self._fetch_with_header(
                session, target, header_name, probe_value
            )
            if probe_body is None:
                continue

            # Skip probes that errored out — we can't tell if reflection
            # would have happened.
            if probe_status >= 400:
                continue

            # Check for dangerous reflection (link, script, etc.).
            dangerous_hits = _find_dangerous_reflection(probe_body, sentinel)
            if dangerous_hits:
                findings.append(self._make_finding(
                    target=target,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.FIRM,
                    title=(
                        f"Cache poisoning via {header_name} header "
                        f"(reflected in {dangerous_hits[0][:40]}…)"
                    ),
                    description=(
                        f"The `{header_name}` request header is reflected into the "
                        f"response body in a dangerous location ({dangerous_hits[0][:80]}…). "
                        "If the response is cached (CDN, reverse proxy, browser cache), "
                        "every subsequent visitor will receive the attacker-controlled "
                        "payload. An attacker can poison the cache to serve malicious "
                        "JavaScript, redirect users to phishing sites, or exfiltrate "
                        "session tokens via a crafted <script src=...>."
                    ),
                    evidence={
                        "injected_header": header_name,
                        "injected_value": probe_value,
                        "sentinel": sentinel,
                        "http_status": probe_status,
                        "dangerous_matches": dangerous_hits[:3],
                    },
                    remediation=(
                        "Do not reflect user-controlled headers (Host, "
                        "X-Forwarded-Host, X-Original-URL) into the response body. "
                        "If you must use them, validate against an allow-list of "
                        "trusted hosts. Configure your cache to key on the Host "
                        "header (so a poisoned Host doesn't pollute the cache for "
                        "other hosts) and strip X-Forwarded-* headers from "
                        "untrusted origins at the edge."
                    ),
                ))
                # One CRITICAL per target is enough — no point probing more headers.
                return findings

            # Check for plain (non-dangerous) reflection.
            if _has_plain_reflection(probe_body, sentinel):
                findings.append(self._make_finding(
                    target=target,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    title=f"Cache poisoning via {header_name} header (reflected in body)",
                    description=(
                        f"The `{header_name}` request header is reflected into the "
                        "response body, but not in a directly dangerous location "
                        "(<link>, <script>, <a href>, etc.). If the response is "
                        "cached, every subsequent visitor will see the attacker-"
                        "controlled value. Exploitability depends on where the "
                        "value lands — manual review recommended."
                    ),
                    evidence={
                        "injected_header": header_name,
                        "injected_value": probe_value,
                        "sentinel": sentinel,
                        "http_status": probe_status,
                    },
                    remediation=(
                        "Do not reflect user-controlled headers into the response "
                        "body. Validate against an allow-list of trusted hosts."
                    ),
                ))
                # One MEDIUM per target is enough.
                return findings

        # No reflection found, but check if any probe returned a different
        # status than the baseline — that alone is suspicious (could indicate
        # the cache is being keyed on the header, which is itself a finding).
        # We don't flag this as a separate finding to keep noise low.

        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fetch_with_header(
        self,
        session: aiohttp.ClientSession,
        url: str,
        header_name: str,
        header_value: str,
    ) -> tuple[str | None, int]:
        """GET *url* with an extra request header. Returns ``(body, status)``."""
        try:
            async with session.get(
                url,
                headers={header_name: header_value},
                allow_redirects=False,
                ssl=False,
            ) as resp:
                body = await resp.text(errors="ignore")
                return body, resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return None, 0

    def _make_finding(
        self,
        *,
        target: str,
        severity: Severity,
        confidence: Confidence,
        title: str,
        description: str,
        evidence: dict[str, object],
        remediation: str,
    ) -> Finding:
        return Finding(
            plugin=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            description=description,
            url=target,
            evidence=evidence,
            remediation=remediation,
        )

"""Plugin: detect Web Cache Deception (WCD).

Web Cache Deception occurs when a cache (CDN, reverse proxy, browser) caches
a response for a URL that contains sensitive data, because the URL's extension
(`.css`, `.js`, `.png`) tricks the cache into treating it as a static asset.

Attack scenario:
1. Attacker crafts: ``https://victim.com/account/settings/style.css``
2. The origin server ignores the trailing ``/style.css`` and serves the
   user's account page (with sensitive data — email, API keys, balance).
3. The CDN caches the response because the URL ends in ``.css``.
4. Attacker requests the same URL — gets the cached page with the victim's
   sensitive data.

This plugin is **active**: it appends static-asset extensions to the target
URL and checks if the response contains sensitive data that the cache might
store.

For low false positives:
- **HIGH (FIRM)** — response with the asset extension contains sensitive
  markers (``email``, ``password``, ``api_key``, ``token``, ``session``,
  ``account``, ``balance``, ``SSN``) AND the content-type doesn't match
  the extension (e.g. ``.css`` returns ``text/html``).
- **MEDIUM (TENTATIVE)** — response is 200 with non-trivial body but no
  sensitive markers found. Could still be cacheable but doesn't leak data.
- Soft-404 calibration suppresses false positives.
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import calibrate_target, fetch_body, is_soft404
from webscan.plugins.base import BasePlugin

# Extensions that CDNs typically cache as static assets.
_CACHEABLE_EXTENSIONS: tuple[str, ...] = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".mp4",
    ".mp3",
    ".pdf",
    ".xml",
    ".txt",
)

# Markers that indicate the response contains sensitive data.
_SENSITIVE_MARKERS: tuple[str, ...] = (
    "email",
    "password",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "session",
    "account",
    "balance",
    "ssn",
    "social_security",
    "credit_card",
    "card_number",
    "cvv",
    "iban",
    "wallet",
    "private_key",
    "-----begin",
    "authorization",
    "bearer",
    "jwt",
    "secret",
    "user_id",
    "userid",
    "phone",
    "address",
    "date_of_birth",
    "dob",
)

# Content-Type prefixes that indicate a static asset (correct caching).
_STATIC_CONTENT_TYPES: frozenset[str] = frozenset({
    "text/css",
    "application/javascript",
    "text/javascript",
    "image/",
    "font/",
    "application/font",
    "video/",
    "audio/",
    "application/pdf",
    "application/xml",
    "text/xml",
    "text/plain",
})

# Minimum body length to consider a response real (not empty stub).
_MIN_BODY_LENGTH = 200


def _has_sensitive_marker(body: str) -> bool:
    """True if the body contains a sensitive-data marker."""
    lowered = body[:8000].lower()
    return any(m in lowered for m in _SENSITIVE_MARKERS)


def _is_static_content_type(content_type: str) -> bool:
    """True if the Content-Type matches a static asset type."""
    ct = (content_type or "").lower()
    return any(ct.startswith(s) for s in _STATIC_CONTENT_TYPES)


# ─── Plugin ───────────────────────────────────────────────────────────────────


class WebCacheDeceptionPlugin(BasePlugin):
    """Probes for Web Cache Deception by appending static-asset extensions."""

    name = "web_cache_deception"
    description = "Detect Web Cache Deception via .css/.js/.png extension appending (content-verified)"  # noqa: E501

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Fetch baseline response.
        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                baseline_body = await fetch_body(resp)
                
                baseline_ct = resp.headers.get("Content-Type", "")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        # Skip if baseline is not HTML (WCD only works on dynamic HTML pages).
        if "html" not in baseline_ct.lower() and not target.endswith((".html", ".htm")):
            return findings

        if len(baseline_body) < _MIN_BODY_LENGTH:
            return findings

        # Check if baseline already contains sensitive data (worth probing).
        

        # Calibrate soft-404.
        soft_baseline = await calibrate_target(session, target)

        # Probe each extension.
        for ext in _CACHEABLE_EXTENSIONS:
            probe_url = target.rstrip("/") + ext

            try:
                async with session.get(
                    probe_url, allow_redirects=True, ssl=False
                ) as resp:
                    probe_body = await fetch_body(resp)
                    probe_status = resp.status
                    probe_ct = resp.headers.get("Content-Type", "")
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
                continue

            # Skip non-200.
            if probe_status != 200:
                continue

            # Skip soft-404.
            if is_soft404(probe_body, probe_status, soft_baseline):
                continue

            # Skip if body is too short (empty stub).
            if len(probe_body) < _MIN_BODY_LENGTH:
                continue

            # Check: response contains sensitive data AND content-type
            # doesn't match a static asset → HIGH confidence WCD.
            has_sensitive = _has_sensitive_marker(probe_body)
            ct_is_static = _is_static_content_type(probe_ct)

            if has_sensitive and not ct_is_static:
                findings.append(self._make_finding(
                    target=target,
                    probe_url=probe_url,
                    extension=ext,
                    severity=Severity.HIGH,
                    confidence=Confidence.FIRM,
                    probe_status=probe_status,
                    probe_ct=probe_ct,
                    body_length=len(probe_body),
                    has_sensitive=True,
                ))
                # One HIGH finding is enough.
                return findings

            # Check: response is HTML (not static) but no sensitive markers.
            # Still suspicious — the cache might store it.
            if not ct_is_static and not is_soft404(probe_body, probe_status, soft_baseline):
                # Only flag if the response is structurally similar to baseline
                # (meaning the server served the same dynamic page with the extension).
                from webscan.plugins._active_helpers import body_similarity
                sim = body_similarity(probe_body, baseline_body)
                if sim > 0.85:
                    findings.append(self._make_finding(
                        target=target,
                        probe_url=probe_url,
                        extension=ext,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        probe_status=probe_status,
                        probe_ct=probe_ct,
                        body_length=len(probe_body),
                        has_sensitive=False,
                        similarity=round(sim, 3),
                    ))
                    # One MEDIUM is enough.
                    return findings

        return findings

    def _make_finding(
        self,
        *,
        target: str,
        probe_url: str,
        extension: str,
        severity: Severity,
        confidence: Confidence,
        probe_status: int,
        probe_ct: str,
        body_length: int,
        has_sensitive: bool,
        similarity: float | None = None,
    ) -> Finding:
        if severity is Severity.HIGH:
            title = f"Web Cache Deception: sensitive data served at {extension} extension"
            desc = (
                f"Appending `{extension}` to `{target}` causes the server to "
                f"return a dynamic HTML page (Content-Type: {probe_ct}) containing "
                "sensitive data markers. If a CDN or reverse proxy caches this "
                "response (because the URL ends in a static-asset extension), "
                "an attacker can access the cached page and read another user's "
                "private data (email, session token, API keys, balance)."
            )
        else:
            title = f"Web Cache Deception: dynamic page served at {extension} extension"
            desc = (
                f"Appending `{extension}` to `{target}` causes the server to "
                f"return a dynamic HTML page (Content-Type: {probe_ct}) with "
                f"similarity {similarity} to the original. No sensitive markers "
                "were found, but the response is still cacheable. Manual review "
                "recommended — verify the page doesn't contain sensitive data "
                "when accessed from an unauthenticated session."
            )

        return Finding(
            plugin=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            description=desc,
            url=target,
            evidence={
                "probe_url": probe_url,
                "extension": extension,
                "http_status": probe_status,
                "content_type": probe_ct,
                "body_length": body_length,
                "has_sensitive_markers": has_sensitive,
                "similarity": similarity,
            },
            remediation=(
                "Configure the origin server to reject requests with unexpected "
                "path extensions (return 404 for /account/settings.css). "
                "Configure the CDN to only cache responses whose Content-Type "
                "matches the URL extension (don't cache text/html at .css). "
                "Use Cache-Control: no-store on dynamic pages."
            ),
        )

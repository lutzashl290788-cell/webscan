"""Plugin: analyse HTTP security response headers."""
from __future__ import annotations

from dataclasses import dataclass

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin


_STATIC_CONTENT_TYPES = (
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "image/",
    "font/",
    "audio/",
    "video/",
)


@dataclass(frozen=True)
class _HeaderRule:
    severity: Severity
    description: str
    remediation: str
    #: Canonical key for the underlying issue, shared with any other plugin that
    #: detects the same problem, so the engine can collapse the duplicate
    #: reports. ``None`` falls back to a per-header key, which still dedupes
    #: against another plugin opting into the same ``missing-header:<name>``.
    dedup_key: str | None = None

    def key_for(self, header: str) -> str:
        return self.dedup_key or f"missing-header:{header.lower()}"


# Required security headers and what to say when they are absent
_REQUIRED_HEADERS: dict[str, _HeaderRule] = {
    "Content-Security-Policy": _HeaderRule(
        severity=Severity.HIGH,
        description=(
            "Content-Security-Policy is missing. Without it the browser applies "
            "no restrictions on inline scripts or external resources, making "
            "reflected/stored XSS exploitation trivial."
        ),
        remediation=(
            "Define a strict CSP, e.g. "
            "\"Content-Security-Policy: default-src 'self'; "
            "script-src 'self'; object-src 'none'\"."
        ),
    ),
    "Strict-Transport-Security": _HeaderRule(
        severity=Severity.HIGH,
        description=(
            "Strict-Transport-Security (HSTS) is absent. "
            "Browsers may accept plain-HTTP connections, enabling "
            "SSL-stripping and man-in-the-middle attacks."
        ),
        remediation=(
            "Add \"Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains; preload\"."
        ),
    ),
    "X-Frame-Options": _HeaderRule(
        severity=Severity.MEDIUM,
        description=(
            "X-Frame-Options is missing. The page can be embedded in an "
            "<iframe> on a third-party site, enabling clickjacking."
        ),
        remediation="Add \"X-Frame-Options: DENY\" or \"X-Frame-Options: SAMEORIGIN\".",
        # The clickjacking plugin reports the same missing framing protection
        # in more detail (it also inspects CSP frame-ancestors), so both share
        # this key and the engine keeps the better of the two.
        dedup_key="framing-protection-missing",
    ),
    "X-Content-Type-Options": _HeaderRule(
        severity=Severity.MEDIUM,
        description=(
            "X-Content-Type-Options is absent. Browsers may sniff the "
            "response MIME type, allowing certain content-injection attacks."
        ),
        remediation="Add \"X-Content-Type-Options: nosniff\".",
    ),
    "Referrer-Policy": _HeaderRule(
        severity=Severity.LOW,
        description=(
            "Referrer-Policy is not set. The full URL (including query "
            "strings with tokens) may be leaked in the Referer header."
        ),
        remediation="Add \"Referrer-Policy: strict-origin-when-cross-origin\".",
    ),
    "Permissions-Policy": _HeaderRule(
        severity=Severity.LOW,
        description=(
            "Permissions-Policy (formerly Feature-Policy) is missing. "
            "Powerful browser APIs (camera, microphone, geolocation, etc.) "
            "are unrestricted for this origin."
        ),
        remediation=(
            "Add \"Permissions-Policy: camera=(), microphone=(), "
            "geolocation=()\" at minimum."
        ),
    ),
}

# Headers whose mere presence indicates information disclosure
_DISCLOSURE_HEADERS: dict[str, str] = {
    "Server": "Reveals web-server software and version.",
    "X-Powered-By": "Reveals backend technology (PHP, ASP.NET, etc.).",
    "X-AspNet-Version": "Discloses exact ASP.NET runtime version.",
    "X-AspNetMvc-Version": "Discloses ASP.NET MVC version.",
    "X-Generator": "Reveals CMS or site-generator identity.",
    "X-Drupal-Cache": "Identifies site as running Drupal.",
    "X-Varnish": "Reveals Varnish cache usage.",
}


class HeadersPlugin(BasePlugin):
    """Checks HTTP response headers for missing protections and info leakage."""

    name = "headers"
    description = "Audit HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                headers = resp.headers
                status = resp.status

                # Header findings on every crawled asset are duplicates of the
                # document-level policy and create substantial report noise.
                # Keep API/JSON responses eligible, but skip clearly static
                # JS/CSS/media resources.
                content_type = headers.get("Content-Type", "").lower()
                if content_type.startswith(_STATIC_CONTENT_TYPES):
                    return findings

                # --- Missing security headers ---
                for name, rule in _REQUIRED_HEADERS.items():
                    if name not in headers:
                        findings.append(
                            Finding(
                                plugin=self.name,
                                title=f"Missing header: {name}",
                                severity=rule.severity,
                                description=rule.description,
                                url=target,
                                evidence={
                                    "http_status": status,
                                    "missing_header": name,
                                },
                                remediation=rule.remediation,
                                dedup_key=rule.key_for(name),
                            )
                        )

                # --- Information disclosure via response headers ---
                for hdr, note in _DISCLOSURE_HEADERS.items():
                    if hdr in headers:
                        findings.append(
                            Finding(
                                plugin=self.name,
                                title=f"Information disclosure: {hdr}",
                                severity=Severity.LOW,
                                confidence=Confidence.INFORMATIONAL,
                                description=(
                                    f"Header '{hdr}: {headers[hdr]}' "
                                    f"is present in the response. {note}"
                                ),
                                url=target,
                                evidence={
                                    "header": hdr,
                                    "value": headers[hdr],
                                },
                                remediation=(
                                    f"Remove or redact the '{hdr}' header in your "
                                    "web-server / reverse-proxy configuration."
                                ),
                            )
                        )

                # --- Weak CSP heuristic (present but trivially bypassable) ---
                csp = headers.get("Content-Security-Policy", "")
                if csp:
                    weak_directives = _check_weak_csp(csp)
                    for directive, reason in weak_directives:
                        findings.append(
                            Finding(
                                plugin=self.name,
                                title=f"Weak CSP directive: {directive}",
                                severity=Severity.MEDIUM,
                                description=reason,
                                url=target,
                                evidence={"csp_value": csp},
                                remediation=(
                                    "Review and tighten the Content-Security-Policy. "
                                    "Use nonces or hashes instead of 'unsafe-inline'/'unsafe-eval'."
                                ),
                            )
                        )

        except Exception:  # noqa: BLE001 — plugins must never propagate errors
            # Network errors are surfaced as engine-level errors, not findings
            pass

        return findings


def _check_weak_csp(csp: str) -> list[tuple[str, str]]:
    """Return a list of (directive, reason) for obviously unsafe CSP values."""
    issues: list[tuple[str, str]] = []
    low = csp.lower()

    if "'unsafe-inline'" in low:
        issues.append((
            "unsafe-inline",
            "CSP contains 'unsafe-inline', which negates XSS protection "
            "for inline scripts and styles.",
        ))
    if "'unsafe-eval'" in low:
        issues.append((
            "unsafe-eval",
            "CSP contains 'unsafe-eval', which allows eval() and related "
            "functions — a common XSS vector.",
        ))
    if "default-src *" in low or "script-src *" in low:
        issues.append((
            "wildcard source",
            "CSP uses a wildcard (*) source, allowing scripts from any origin.",
        ))

    return issues

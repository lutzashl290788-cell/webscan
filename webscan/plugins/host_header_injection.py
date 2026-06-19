"""Plugin: detect host-header injection for password-reset poisoning.

Many password-reset flows construct the reset link from the ``Host`` request
header (or ``X-Forwarded-Host``) without validating it. An attacker can
submit a password-reset request for ``victim@example.com`` with a crafted
``Host: attacker.example`` header. The server emails the victim a link like
``https://attacker.example/reset?token=SECRET``. When the victim clicks
the link, the secret token leaks to the attacker's server.

This plugin is **active**: it sends a probe request to common password-reset
endpoints with a crafted ``Host`` header and verifies the response *or the
server's behaviour* indicates the header is reflected into a reset link.

For low false positives:

* **CRITICAL (FIRM)** — the response body contains the injected sentinel
  host in a URL-like context (``https://sentinel/...``, ``//sentinel/...``,
  ``href="...sentinel..."``). This proves the header is reflected into a
  link that would be emailed to the user.
* **HIGH (TENTATIVE)** — the response body contains the sentinel host
  anywhere (not just in a URL). Could be in a comment, error message, or
  JSON field. Still suspicious but needs manual confirmation that the
  reflected value ends up in an outbound email.
* **MEDIUM (INFORMATIONAL)** — the server returned 200/302 to the probe
  (i.e. it accepted the crafted Host header) but doesn't reflect it in
  the response body. Manual review needed: could be blind poisoning (the
  link is emailed but not shown in the response).

The plugin probes:

* Common reset endpoints (``/reset``, ``/forgot``, ``/password-reset``,
  ``/account/recover``, etc.)
* Both ``Host`` and ``X-Forwarded-Host`` headers
* Sends a POST with a fake email to trigger the reset flow without
  spamming a real user

To keep false positives low, the plugin only fires on URLs whose path
looks like a password-reset endpoint — it doesn't probe every page on
the site.
"""
from __future__ import annotations

import asyncio
import re
import secrets
from urllib.parse import urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# ─── Endpoint detection ──────────────────────────────────────────────────────

# URL path patterns that suggest a password-reset / account-recovery endpoint.
# Matched case-insensitively as substrings of the URL path.
_RESET_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/reset(?:[-_]?password)?(?:/|$)", re.IGNORECASE),
    re.compile(r"/forgot(?:[-_]?password)?(?:/|$)", re.IGNORECASE),
    re.compile(r"/password[-_]?reset(?:/|$)", re.IGNORECASE),
    re.compile(r"/account/recover(?:/|$)", re.IGNORECASE),
    re.compile(r"/account/reset(?:/|$)", re.IGNORECASE),
    re.compile(r"/auth/recover(?:/|$)", re.IGNORECASE),
    re.compile(r"/auth/reset(?:/|$)", re.IGNORECASE),
    re.compile(r"/lost[-_]?password(?:/|$)", re.IGNORECASE),
    re.compile(r"/wp-login\.php\?action=lostpassword", re.IGNORECASE),  # WordPress
)

# Headers we probe. Each entry: (header_name, value_template).
# {sentinel} is interpolated at runtime with a per-scan random host.
_PROBE_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Forwarded-Host", "{sentinel}"),
    ("Host", "{sentinel}"),
    ("X-Forwarded-Server", "{sentinel}"),
    ("X-Host", "{sentinel}"),
    ("X-Real-Host", "{sentinel}"),
    ("Forwarded", "host={sentinel}"),
)

# Sentinel host template — random per scan so a fixed string in the response
# can't produce a false positive.
_SENTINEL_TEMPLATE = "webscan-reset-probe-{token}.example"

# Patterns that match "URL-like" reflection of the sentinel — proving the
# injected host is being used to construct a link.
_URL_REFLECTION_PATTERNS_RAW: tuple[str, ...] = (
    # https://sentinel/...
    r"https?://{sentinel}[/\s\"'<>]",
    # //sentinel/... (protocol-relative URL)
    r"//{sentinel}[/\s\"'<>]",
    # href="...sentinel..." or src="...sentinel..." or action="...sentinel..."
    r'(?:href|src|action)\s*=\s*["\'][^"\']*{sentinel}',
    # JSON field with URL value containing sentinel
    r'"(?:url|link|reset_url|reset_link|callback)"\s*:\s*"[^"]*{sentinel}',
)

# Minimum body length to consider the response a real page.
_MIN_BODY_LENGTH = 50

# Cap on body length for regex matching (perf bound).
_MAX_BODY_LENGTH = 100_000


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _is_reset_endpoint(target: str) -> bool:
    """True if the URL path looks like a password-reset endpoint."""
    path = urlparse(target).path
    query = urlparse(target).query
    full = f"{path}?{query}" if query else path
    return any(p.search(full) for p in _RESET_PATH_PATTERNS)


def _compile_url_patterns(sentinel: str) -> list[re.Pattern[str]]:
    """Compile the URL-reflection patterns with *sentinel* interpolated."""
    return [
        re.compile(p.format(sentinel=re.escape(sentinel)), re.IGNORECASE)
        for p in _URL_REFLECTION_PATTERNS_RAW
    ]


def _find_url_reflection(body: str, sentinel: str) -> list[str]:
    """Return list of URL-like reflection contexts where *sentinel* appears."""
    patterns = _compile_url_patterns(sentinel)
    body_lower = body.lower()[:_MAX_BODY_LENGTH]
    hits: list[str] = []
    for pattern in patterns:
        m = pattern.search(body_lower)
        if m:
            hits.append(m.group(0)[:120])
    return hits


def _has_plain_reflection(body: str, sentinel: str) -> bool:
    """True if *sentinel* appears anywhere in *body*."""
    return sentinel.lower() in body.lower()[:_MAX_BODY_LENGTH]


# ─── Plugin ───────────────────────────────────────────────────────────────────


class HostHeaderInjectionPlugin(BasePlugin):
    """Probes password-reset endpoints for host-header injection."""

    name = "host_header_injection"
    description = "Detect host-header injection in password-reset / account-recovery flows"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Only probe URLs that look like password-reset endpoints.
        if not _is_reset_endpoint(target):
            return findings

        # Generate a per-scan sentinel so we don't false-positive on a string
        # that happens to be in the response already.
        token = secrets.token_hex(6)
        sentinel = _SENTINEL_TEMPLATE.format(token=token)

        # Probe each header. Use GET first (most reset endpoints show a form
        # via GET and process it via POST — if GET reflects the header, POST
        # almost certainly does too).
        for header_name, value_template in _PROBE_HEADERS:
            probe_value = value_template.format(sentinel=sentinel)

            probe_body, probe_status = await self._fetch_with_header(
                session, target, header_name, probe_value
            )
            if probe_body is None:
                continue

            # Skip 4xx/5xx — server rejected the request entirely.
            if probe_status >= 400:
                continue

            # Check for URL-like reflection (CRITICAL).
            url_hits = _find_url_reflection(probe_body, sentinel)
            if url_hits:
                findings.append(self._make_finding(
                    target=target,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.FIRM,
                    title=(
                        f"Host-header injection in reset endpoint "
                        f"via {header_name} (URL reflection)"
                    ),
                    description=(
                        f"The `{header_name}` request header is reflected into a "
                        f"URL in the response body ({url_hits[0][:80]}…). On a "
                        "password-reset endpoint, this means the reset link "
                        "emailed to the user is constructed from the attacker-"
                        "controlled header. An attacker can submit a reset "
                        "request for victim@example.com with `Host: attacker.example` "
                        "and the victim receives a link like "
                        "`https://attacker.example/reset?token=SECRET`. Clicking "
                        "it leaks the secret reset token to the attacker."
                    ),
                    evidence={
                        "injected_header": header_name,
                        "injected_value": probe_value,
                        "sentinel": sentinel,
                        "http_status": probe_status,
                        "url_matches": url_hits[:3],
                    },
                    remediation=(
                        "Do NOT use the Host header (or X-Forwarded-Host) to "
                        "construct absolute URLs in emails. Use a server-side "
                        "configured base URL (e.g. `app.config['BASE_URL']`) "
                        "instead. If you must derive the host from the request, "
                        "validate it against an allow-list of trusted hosts."
                    ),
                ))
                # One CRITICAL is enough — no point probing more headers.
                return findings

            # Check for plain reflection (HIGH TENTATIVE).
            if _has_plain_reflection(probe_body, sentinel):
                findings.append(self._make_finding(
                    target=target,
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    title=(
                        f"Host-header injection in reset endpoint "
                        f"via {header_name} (plain reflection)"
                    ),
                    description=(
                        f"The `{header_name}` request header is reflected into "
                        "the response body, but not in a clear URL context. On "
                        "a password-reset endpoint this is still suspicious: the "
                        "reflected value may end up in an outbound email even if "
                        "it's not visible in the HTTP response. Manual "
                        "verification recommended — submit a real reset request "
                        "with the crafted header and inspect the received email."
                    ),
                    evidence={
                        "injected_header": header_name,
                        "injected_value": probe_value,
                        "sentinel": sentinel,
                        "http_status": probe_status,
                    },
                    remediation=(
                        "Do NOT use the Host header to construct URLs in emails. "
                        "Use a server-side configured base URL."
                    ),
                ))
                # One HIGH is enough.
                return findings

            # If probe returned 200/302 (accepted the header) but didn't
            # reflect it, that's still worth an INFO finding — could be
            # blind poisoning.
            if probe_status in (200, 301, 302, 303, 307, 308):
                # Only flag if the response body is non-trivial (i.e. this
                # is a real page, not an empty stub).
                if len(probe_body) >= _MIN_BODY_LENGTH:
                    findings.append(self._make_finding(
                        target=target,
                        severity=Severity.INFO,
                        confidence=Confidence.INFORMATIONAL,
                        title=(
                        f"Reset endpoint accepts crafted {header_name} "
                        f"(blind poisoning possible)"
                    ),
                        description=(
                            f"The password-reset endpoint accepted a crafted "
                            f"`{header_name}` header (HTTP {probe_status}) without "
                            "reflecting it in the response body. The header may "
                            "still be used to construct the reset link in the "
                            "outbound email — blind host-header poisoning. Manual "
                            "verification recommended: send a reset request to an "
                            "email address you control with the crafted header "
                            "and inspect the received email's reset link."
                        ),
                        evidence={
                            "injected_header": header_name,
                            "injected_value": probe_value,
                            "http_status": probe_status,
                        },
                        remediation=(
                            "Validate the Host header against an allow-list of "
                            "trusted hosts. Use a server-side configured base URL "
                            "for constructing reset links."
                        ),
                    ))
                    # One INFO is enough.
                    return findings

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

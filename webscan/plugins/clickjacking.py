"""Plugin: detect clickjacking exposure via missing frame-busting headers.

Clickjacking (UI redress attack) tricks a user into clicking on a transparent
framed page that contains a sensitive action (Delete account, Transfer funds,
Grant admin). The victim thinks they're clicking a benign button on the
attacker's site; in reality they're interacting with the framed victim page,
whose cookies ride along automatically.

Defence is a pair of HTTP response headers (either one is sufficient):

* ``X-Frame-Options: DENY`` (or ``SAMEORIGIN``) — legacy, supported by all
  browsers; honoured for the rendered top-level frame only.
* ``Content-Security-Policy: frame-ancestors 'none'`` (or ``'self'``) —
  modern, allows host-lists; overrides ``X-Frame-Options`` when both present.

This plugin is **passive**: it only inspects the response headers the server
already returns. It does NOT attempt to frame the page or simulate a click.

Findings:

* **MEDIUM (FIRM)** — neither header is present. The page can be framed by
  any origin. Severity is MEDIUM (not HIGH) because clickjacking requires
  social engineering on top of the framing capability.
* **LOW (FIRM)** — ``X-Frame-Options`` is present but ``CSP frame-ancestors``
  is not. The legacy header is honoured by all current browsers but is being
  deprecated in favour of CSP; flag so operators know to migrate.
* **INFO (INFORMATIONAL)** — ``X-Frame-Options: ALLOW-FROM <origin>`` is
  used. ``ALLOW-FROM`` is obsolete and unsupported by modern browsers; the
  page is effectively unprotected despite the header's presence.

To keep false positives low, the plugin skips:

* **Non-HTML responses** — JSON/XML API responses don't render in a frame
  in a way that would let an attacker click anything.
* **Responses with status >= 400** — error pages rarely contain a sensitive
  action; flagging them would be noise.
* **Responses shorter than 200 bytes** — probably empty stubs.
"""
from __future__ import annotations

import asyncio
import re

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# ─── Header parsing rules ────────────────────────────────────────────────────

# X-Frame-Options directive we consider "protective". ALLOW-FROM is excluded
# (it's obsolete and unsupported by modern browsers).
_XFO_PROTECTIVE_DIRECTIVES: frozenset[str] = frozenset({"deny", "sameorigin"})

# Match a CSP frame-ancestors directive in a Content-Security-Policy header.
# Captures the value (everything after `frame-ancestors` up to the next `;`
# or end of string). Case-insensitive on the directive name.
_CSP_FRAME_ANCESTORS_RE = re.compile(
    r"frame-ancestors\s+([^;]+)",
    re.IGNORECASE,
)

# A CSP frame-ancestors value is "protective" if it does NOT contain `*`
# and is not empty. `'none'`, `'self'`, or a host-list all qualify.
# We treat `*` as "no protection" because it explicitly allows any origin
# to frame the page (rare but real misconfiguration).

# Minimum body length to consider the response a real page (not an empty stub).
_MIN_BODY_LENGTH = 200


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _is_protective_xfo(xfo_value: str) -> bool:
    """True if the X-Frame-Options header value actually protects the page.

    ``DENY`` and ``SAMEORIGIN`` (case-insensitive) protect; ``ALLOW-FROM``
    is obsolete and unsupported, so it's NOT considered protective.
    """
    if not xfo_value:
        return False
    directive = xfo_value.strip().split()[0].lower()
    return directive in _XFO_PROTECTIVE_DIRECTIVES


def _is_protective_csp_frame_ancestors(csp_value: str) -> bool:
    """True if CSP frame-ancestors directive is present and not `*`.

    Returns ``False`` when:

    * The CSP header has no ``frame-ancestors`` directive at all.
    * The directive's value is ``*`` (explicitly allows any origin).

    Returns ``True`` for ``'none'``, ``'self'``, or a host-list — all of
    which restrict framing to fewer than all origins.
    """
    if not csp_value:
        return False
    m = _CSP_FRAME_ANCESTORS_RE.search(csp_value)
    if m is None:
        return False
    value = m.group(1).strip()
    if not value:
        return False
    # `*` as a standalone source (or in a list with other sources) means
    # any origin can frame — not protective.
    sources = [s.strip().lower() for s in value.split()]
    if "*" in sources:
        return False
    return True


def _is_allow_from(xfo_value: str) -> bool:
    """True if X-Frame-Options uses the obsolete ALLOW-FROM directive."""
    if not xfo_value:
        return False
    directive = xfo_value.strip().split()[0].lower()
    return directive == "allow-from"


def _is_html_response(content_type: str, url: str, body: str) -> bool:
    """Heuristic: is this response an HTML page worth auditing for clickjacking?

    True if Content-Type advertises HTML, or the URL ends in .html/.htm, or
    the body looks like HTML (starts with ``<!doctype`` or ``<html``).
    """
    ct = (content_type or "").lower()
    if "html" in ct:
        return True
    if url.lower().endswith((".html", ".htm")):
        return True
    stripped = body.lstrip()[:200].lower()
    return stripped.startswith(("<!doctype html", "<html", "<head", "<body"))


# ─── Plugin ───────────────────────────────────────────────────────────────────


class ClickjackingPlugin(BasePlugin):
    """Audits response headers for clickjacking protection (frame-busting)."""

    name = "clickjacking"
    description = "Detect missing X-Frame-Options and CSP frame-ancestors headers"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                content_type = resp.headers.get("Content-Type", "")
                xfo = resp.headers.get("X-Frame-Options", "")
                csp = resp.headers.get("Content-Security-Policy", "")
                status = resp.status
                body = await resp.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        # Skip non-HTML — JSON/XML/JS responses can't be clickjacked.
        if not _is_html_response(content_type, target, body):
            return findings

        # Skip error pages — they rarely contain a sensitive action.
        if status >= 400:
            return findings

        # Skip empty / stub responses.
        if len(body) < _MIN_BODY_LENGTH:
            return findings

        # Evaluate protection.
        has_xfo = _is_protective_xfo(xfo)
        has_csp = _is_protective_csp_frame_ancestors(csp)
        allow_from = _is_allow_from(xfo)

        # If ALLOW-FROM is used, flag as INFO regardless of CSP — operators
        # should know the directive is obsolete.
        if allow_from:
            findings.append(self._make_finding(
                target=target,
                severity=Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                title=(
                    "Obsolete X-Frame-Options: "
                    "ALLOW-FROM directive (unsupported by modern browsers)"
                ),
                description=(
                    "The response sets `X-Frame-Options: ALLOW-FROM <origin>`. "
                    "The ALLOW-FROM directive is obsolete and unsupported by "
                    "modern browsers (Chrome, Firefox, Safari, Edge all ignore "
                    "it). The page is effectively unprotected against "
                    "clickjacking despite the header's presence. "
                    f"Detected value: `{xfo.strip()}`."
                ),
                evidence={
                    "xfo_value": xfo.strip(),
                    "csp_present": bool(csp),
                    "csp_protective": has_csp,
                    "http_status": status,
                },
                remediation=(
                    "Replace `X-Frame-Options: ALLOW-FROM` with "
                    "`Content-Security-Policy: frame-ancestors <origin>` "
                    "(which supports a host-list and IS supported by modern "
                    "browsers). Keep `X-Frame-Options: SAMEORIGIN` as a "
                    "fallback for legacy browsers."
                ),
            ))
            # If CSP is also missing, escalate to a MEDIUM alongside the INFO.
            if not has_csp:
                findings.append(self._make_finding(
                    target=target,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    title="Page can be framed by any origin (no CSP frame-ancestors)",
                    description=(
                        "The response sets neither a protective "
                        "`X-Frame-Options` header (DENY/SAMEORIGIN) nor a "
                        "`Content-Security-Policy: frame-ancestors` directive. "
                        "Any malicious site can embed this page in an invisible "
                        "<iframe> and trick users into clicking framed buttons "
                        "(clickjacking / UI redress attack)."
                    ),
                    evidence={
                        "xfo_value": xfo.strip() or "(absent)",
                        "csp_present": False,
                        "http_status": status,
                    },
                    remediation=(
                        "Add `Content-Security-Policy: frame-ancestors 'self'` "
                        "(or `'none'` if the page should never be framed) and "
                        "`X-Frame-Options: SAMEORIGIN` as a legacy fallback."
                    ),
                ))
            return findings

        # No ALLOW-FROM — evaluate normally.
        if has_xfo and has_csp:
            # Both protections present — no finding.
            return findings

        if has_xfo and not has_csp:
            # Legacy header only — flag as LOW so operators migrate to CSP.
            findings.append(self._make_finding(
                target=target,
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                title="Clickjacking: X-Frame-Options present but CSP frame-ancestors missing",
                description=(
                    "The response sets `X-Frame-Options` (legacy frame-busting) "
                    "but no `Content-Security-Policy: frame-ancestors` directive. "
                    "X-Frame-Options is being deprecated in favour of CSP and "
                    "doesn't support host-lists — operators should add a CSP "
                    "frame-ancestors directive to enable fine-grained framing "
                    "policy. The page is currently protected in all current "
                    "browsers via X-Frame-Options, so severity is LOW."
                ),
                evidence={
                    "xfo_value": xfo.strip(),
                    "csp_present": False,
                    "http_status": status,
                },
                remediation=(
                    "Add `Content-Security-Policy: frame-ancestors 'self'` "
                    "(matching the existing X-Frame-Options policy) so the "
                    "framing policy survives the eventual deprecation of "
                    "X-Frame-Options."
                ),
            ))
            return findings

        if not has_xfo and has_csp:
            # CSP protects — no finding needed. CSP frame-ancestors overrides
            # X-Frame-Options when both are present, so the absence of XFO
            # is not a problem for modern browsers. We could flag INFO for
            # legacy-browser coverage, but that's noise.
            return findings

        # Neither header present — MEDIUM finding.
        findings.append(self._make_finding(
            target=target,
            severity=Severity.MEDIUM,
            confidence=Confidence.FIRM,
            title=(
                "Clickjacking: page can be framed by any origin "
                "(no X-Frame-Options, no CSP frame-ancestors)"
            ),
            description=(
                "The response sets neither `X-Frame-Options` nor a "
                "`Content-Security-Policy: frame-ancestors` directive. Any "
                "malicious site can embed this page in an invisible <iframe> "
                "and trick users into clicking framed buttons (clickjacking / "
                "UI redress attack). If the page contains a state-changing "
                "form (Delete account, Transfer funds, Grant admin), the "
                "framed click will execute on the victim's session."
            ),
            evidence={
                "xfo_value": "(absent)",
                "csp_present": False,
                "http_status": status,
            },
            remediation=(
                "Add BOTH headers (defence-in-depth — X-Frame-Options for "
                "legacy browsers, CSP for modern ones):\n"
                "  X-Frame-Options: SAMEORIGIN\n"
                "  Content-Security-Policy: frame-ancestors 'self'\n"
                "Use `DENY` / `'none'` instead if the page should never be framed."
            ),
        ))
        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

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

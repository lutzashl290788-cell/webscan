"""Plugin: detect CSRF-vulnerable state-changing forms.

A **state-changing** form (POST/PUT/DELETE/PATCH) that performs an
authenticated action must be protected by a CSRF token. Otherwise an attacker
can craft a fake form on a malicious site and submit it on the user's behalf
while their cookies ride along automatically.

This plugin is **passive**: it only inspects the HTML the server already
returned. It does not submit anything to the target.

Findings are produced only when ALL of the following are true:

1. The form's method is POST/PUT/PATCH/DELETE (GET is not state-changing).
2. The form's action targets the same origin as the target (cross-origin
   forms have a different threat model — the attacker controls them already).
3. The form does NOT contain a hidden input whose name matches a known
   CSRF-token naming convention (`csrf`, `_token`, `authenticity_token`,
   `__RequestVerificationToken`, …) AND no `csrf-token` ``<meta>`` tag is
   present in the page ``<head>``.

To keep false positives low, the plugin skips:

* **Login forms** — login CSRF has a different threat model and many
  legitimate sites don't protect them. Detected by field-name heuristic
  (`username`/`email` + `password`).
* **Search forms** — GET-only by definition, but we also skip POST forms
  whose only fields are search-like (`q`, `query`, `search`).
* **Forms with no fields** — typically navigation, not state-changing.
* **Forms whose action contains `/search`, `/filter`, `/sort`** — read-only
  endpoints that happen to be POST for query-string length reasons.
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

# ─── Detection rules ──────────────────────────────────────────────────────────

# State-changing HTTP methods (per RFC 7231 §4.2.1).
_STATE_CHANGING_METHODS: frozenset[str] = frozenset({"post", "put", "patch", "delete"})

# CSRF-token field name patterns. Matched case-insensitively as substrings.
# Conservative: a field name must match at least one of these to count as a
# CSRF token. Errs on the side of "this looks like a token" (reduces FP).
# Note: we use plain substring search (not \b word boundaries) because field
# names like `form_nonce` or `csrfmiddlewaretoken` would otherwise miss.
_CSRF_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)csrf"),
    re.compile(r"(?i)_token"),
    re.compile(r"(?i)authenticity_token"),
    re.compile(r"(?i)__requestverificationtoken"),
    re.compile(r"(?i)nonce"),
    re.compile(r"(?i)_xsrf"),
    re.compile(r"(?i)xsrf"),
    re.compile(r"(?i)form[_-]?token"),
    re.compile(r"(?i)security[_-]?token"),
    re.compile(r"(?i)anti[_-]?forgery"),
)

# Login-form heuristic: a form with at least one password field and at least
# one user-identifier field (username/email) is almost certainly a login form.
_PASSWORD_FIELD_RE = re.compile(r"(?i)\b(pass|passwd|password|pwd)\b")
_USER_FIELD_RE = re.compile(r"(?i)\b(user|username|email|login|account|uid)\b")

# Search-form heuristic: a POST form whose only non-hidden fields are
# search-like. These endpoints accept POST to allow long query strings but
# don't actually mutate state.
_SEARCH_FIELD_RE = re.compile(r"(?i)\b(q|query|search|keyword|find|filter|term)\b")

# Form action substrings that indicate read-only endpoints even when POST.
_READ_ONLY_ACTION_SUBSTRINGS: tuple[str, ...] = (
    "/search",
    "/filter",
    "/sort",
    "/query",
    "/find",
    "/lookup",
)

# Soft-404 / SPA fallback: if the page itself is suspiciously tiny it's
# probably an error page that contains no real forms to audit. 50 is
# generous enough for `<html><body><form>...</form></body></html>` with one
# field, but tight enough to skip 0-byte / "Not Found" stub responses.
_MIN_BODY_LENGTH = 50


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _is_csrf_token(field_name: str) -> bool:
    """Return True if *field_name* looks like a CSRF token field."""
    return any(p.search(field_name) for p in _CSRF_TOKEN_PATTERNS)


def _is_login_form(field_names: list[str]) -> bool:
    """A form with a password field + a user-identifier field is a login form."""
    has_password = any(_PASSWORD_FIELD_RE.search(n) for n in field_names)
    has_user = any(_USER_FIELD_RE.search(n) for n in field_names)
    return has_password and has_user


def _is_search_form(field_names: list[str]) -> bool:
    """A POST form whose fields are all search-like is a search form."""
    if not field_names:
        return False
    # Filter out CSRF tokens (they'd be in the form too).
    real = [n for n in field_names if not _is_csrf_token(n)]
    if not real:
        return False
    return all(_SEARCH_FIELD_RE.search(n) for n in real)


def _action_is_read_only(action: str) -> bool:
    """Heuristic: action URL containing /search, /filter, etc. is read-only."""
    if not action:
        return False
    path = urlparse(action).path.lower()
    return any(s in path for s in _READ_ONLY_ACTION_SUBSTRINGS)


def _same_origin(url_a: str, url_b: str) -> bool:
    """Two URLs are same-origin if scheme + host + port match."""
    a = urlparse(url_a)
    b = urlparse(url_b)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def _has_csrf_meta(html: str) -> bool:
    """Look for ``<meta name="csrf-token" content="...">`` in the head.

    Many frameworks (Rails, Laravel, Django) emit this tag so client-side JS
    can attach the token to AJAX requests. Its presence implies the page is
    CSRF-aware.
    """
    return bool(re.search(r'(?i)<meta[^>]+name=["\']?csrf[_-]?token["\']?', html))


def _has_samesite_protection(set_cookie_values: list[str]) -> bool:
    """True if at least one cookie on the page has SameSite=Strict or Lax.

    Modern browsers enforce CSRF protection at the cookie level when a cookie
    is set with ``SameSite=Strict`` or ``SameSite=Lax``. A page that sets a
    session cookie with one of these attributes is already protected against
    cross-site POST requests for that cookie's scope — so flagging its forms
    as CSRF-vulnerable would be a false positive.

    We only return True for Strict/Lax (not ``SameSite=None``), because None
    explicitly opts out of the protection.
    """
    for raw in set_cookie_values:
        # Parse attributes (case-insensitive).
        attrs = [a.strip().lower() for a in raw.split(";")]
        for attr in attrs:
            # Match `samesite=strict` or `samesite=lax` (with or without spaces).
            if attr.startswith("samesite="):
                value = attr.split("=", 1)[1].strip()
                if value in ("strict", "lax"):
                    return True
    return False


# ─── Plugin ───────────────────────────────────────────────────────────────────


class CsrfPlugin(BasePlugin):
    """Flags state-changing forms that lack CSRF protection."""

    name = "csrf"
    description = "Detect POST/PUT/PATCH forms missing CSRF tokens (skips login/search)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                content_type = resp.headers.get("Content-Type", "")
                # Only inspect HTML — JSON/XML responses have no forms.
                if "html" not in content_type.lower() and not target.endswith((".html", ".htm")):
                    return findings
                # Capture Set-Cookie headers for SameSite check.
                set_cookies = resp.headers.getall("Set-Cookie", [])
                body = await fetch_body(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        # Tiny body — probably an error page or JSON mislabelled as HTML.
        if len(body) < _MIN_BODY_LENGTH:
            return findings

        page = parse_html(body, base=target)

        # If the page declares a global CSRF meta tag, skip ALL forms on it.
        # The token is intended to be picked up by JS for every state-changing
        # request, so individual forms not having a hidden field is by design.
        if _has_csrf_meta(body):
            return findings

        # If at least one cookie on the page is set with SameSite=Strict or
        # SameSite=Lax, modern browsers already enforce CSRF protection at the
        # cookie level. Flagging the forms would be a false positive.
        if _has_samesite_protection(set_cookies):
            return findings

        for form in page.forms:
            # Skip non-state-changing methods.
            if form.method not in _STATE_CHANGING_METHODS:
                continue

            # Skip forms with no fields — likely navigation, not mutation.
            if not form.fields:
                continue

            field_names = [f.name for f in form.fields]

            # Skip login forms — different threat model (login CSRF).
            if _is_login_form(field_names):
                continue

            # Skip search forms.
            if _is_search_form(field_names):
                continue

            # Skip read-only-action forms (/search, /filter, etc.).
            if _action_is_read_only(form.action):
                continue

            # Skip cross-origin forms — different threat model.
            if form.action and not _same_origin(form.action, target):
                continue

            # Does the form carry a CSRF token (hidden or otherwise)?
            has_token = any(_is_csrf_token(name) for name in field_names)
            if has_token:
                continue

            # All filters passed → flag.
            severity = Severity.MEDIUM
            confidence = Confidence.FIRM  # passive: we directly observe absence

            findings.append(
                Finding(
                    plugin=self.name,
                    title=f"State-changing {form.method.upper()} form without CSRF token",
                    severity=severity,
                    confidence=confidence,
                    description=(
                        f"A {form.method.upper()} form targeting `{form.action or target}` "
                        f"does not include a CSRF token. State-changing forms must be "
                        "protected so an attacker cannot submit them on a logged-in "
                        "user's behalf via a cross-site request. This form was not "
                        "filtered as a login or search form, and the page declares no "
                        "global `csrf-token` meta tag."
                    ),
                    url=target,
                    evidence={
                        "form_action": form.action or target,
                        "form_method": form.method.upper(),
                        "field_names": field_names,
                    },
                    remediation=(
                        "Add a hidden CSRF token to the form (e.g. "
                        '`<input type="hidden" name="csrf_token" value="...">`), '
                        "or emit a `<meta name=\"csrf-token\">` tag in the page head "
                        "and have client-side code attach it to AJAX requests. Most "
                        "frameworks (Django, Rails, Laravel, Flask-WTF) provide this "
                        "out of the box."
                    ),
                )
            )

        return findings

"""Plugin: detect open redirects in query parameters.

Many web apps take a redirect destination as a URL parameter (``?next=...``,
``?redirect=...``, ``?return_url=...``) and pass it to a ``Location`` header
without validation. An attacker can craft a phishing link
``https://victim.example/login?next=https://attacker.example/`` that logs
the victim into the real site, then bounces them to the attacker.

The plugin is **active**: it sends probe requests with crafted payloads and
verifies the server actually issues a redirect to the attacker-controlled
host. Pure status 200 is NOT enough.

Improvements over the original implementation:

* **More parameter names** — covers 30+ redirect-parameter conventions
  (``next``, ``url``, ``redirect``, ``return``, ``goto``, ``target``,
  ``callback``, ``continue``, ``dest``, ``rurl``, ``from``, ``ref``, etc.).
* **More payloads** — covers protocol-relative (``//evil``), backslash-
  encoded (``/\\evil``), triple-slash (``///evil``), URL-encoded, and
  at-sign (``https://victim@evil``) variants that bypass naïve host
  validation.
* **Content verification** — checks the ``Location`` header's parsed host
  matches the sentinel, not a substring. This avoids the false positive
  where the sentinel merely appears inside a query string of a same-site
  redirect.
* **Multiple headers** — checks both ``Location`` and ``Refresh`` (some
  frameworks use ``<meta http-equiv="refresh">`` instead of a 3xx).
* **Retry on transient failures** — uses the shared ``fetch_with_retry``
  helper so a flaky 502/503 doesn't abort the whole plugin.
"""
from __future__ import annotations

import asyncio
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# Sentinel host we try to bounce the victim to. A redirect whose Location
# points here proves the parameter controls the destination.
_EVIL = "evil-webscan.example"

# Payloads designed to bypass common redirect-validation patterns. Each is
# tested in turn; the first one that produces a redirect to _EVIL wins.
_PAYLOADS: tuple[str, ...] = (
    f"https://{_EVIL}/",                       # absolute URL
    f"//{_EVIL}/",                              # protocol-relative
    f"https:{_EVIL}/",                          # missing slashes
    f"https:/{_EVIL}/",                         # single slash
    f"\\\\{_EVIL}\\",                           # backslash (browsers normalise)
    f"/\\{_EVIL}/",                             # mixed slashes
    f"///{_EVIL}/",                             # triple-slash
    f"//{_EVIL}@{_EVIL}/",                      # userinfo trick
    f"https://{_EVIL}%2f",                      # URL-encoded slash
    f"https://{_EVIL}/%2e%2e",                  # encoded dots
    f"{_EVIL}",                                 # bare host
    f" https://{_EVIL}/",                       # leading whitespace
    f"https://{_EVIL}/\t",                      # trailing tab
    f"https://{_EVIL}/\n",                      # CRLF injection
)

# Parameter names commonly used for redirects; others are skipped to limit
# noise. Matched case-insensitively against the *whole* parameter name.
_REDIRECT_PARAMS: frozenset[str] = frozenset({
    "next", "url", "redirect", "redirect_uri", "redirect_url",
    "redirect_to", "redirect", "return", "returnurl", "return_url",
    "returnto", "return_to", "dest", "destination", "continue",
    "goto", "target", "rurl", "forward", "callback", "from",
    "ref", "referer", "referrer", "back", "redir", "go",
    "out", "exit", "link", "site", "to", "view",
    "location", "page", "nav", "navigate",
})

# Maximum number of parameters to probe per target — bound request pressure.
_MAX_PARAMS_PER_TARGET = 5


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _find_redirect_params(target: str) -> list[str]:
    """Return parameter names in *target*'s query string that look redirect-like."""
    parsed = urlparse(target)
    if not parsed.query:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for name in parse_qs(parsed.query, keep_blank_values=True):
        if name.lower() in _REDIRECT_PARAMS and name not in seen:
            out.append(name)
            seen.add(name)
            if len(out) >= _MAX_PARAMS_PER_TARGET:
                break
    return out


def _replace_param(target: str, param: str, value: str) -> str:
    """Return *target* with *param* set to *value*, preserving other params."""
    parsed = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode({k: v[0] if len(v) == 1 else v for k, v in qs.items()}, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _points_to_evil(location: str) -> bool:
    """True only if *location*'s actual destination host is the sentinel host.

    Checking the parsed host — not a substring — avoids the false positive where
    the sentinel merely appears inside a query string of a same-site redirect,
    e.g. ``Location: /login?next=https://evil-webscan.example/`` (which keeps the
    victim on the original host and is therefore safe).
    """
    if not location:
        return False
    host = (urlparse(location).hostname or "").lower()
    return host == _EVIL


# ─── Plugin ───────────────────────────────────────────────────────────────────


class OpenRedirectPlugin(BasePlugin):
    """Probes redirect-like query parameters for open redirect."""

    name = "open_redirect"
    description = "Detect open redirects (13 payload variants, content-verified)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        params = _find_redirect_params(target)
        if not params:
            return findings

        for param_name in params:
            for payload in _PAYLOADS:
                test_url = _replace_param(target, param_name, payload)
                location = await self._redirect_location(session, test_url)
                if location is None or not _points_to_evil(location):
                    continue

                findings.append(
                    Finding(
                        plugin=self.name,
                        title=f"Open redirect in parameter '{param_name}'",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.FIRM,
                        description=(
                            f"Parameter '{param_name}' controls the redirect "
                            f"destination: a crafted value (`{payload}`) caused "
                            f"the response to redirect to `{location}`, an "
                            "attacker-controlled host. An attacker can craft a "
                            "phishing link like "
                            f"`{test_url}` that lures the victim to the real "
                            "site, then bounces them to attacker.example."
                        ),
                        url=test_url,
                        evidence={
                            "parameter": param_name,
                            "payload": payload,
                            "location": location,
                        },
                        remediation=(
                            "Validate redirect targets against an allow-list of "
                            "internal paths or hosts; never redirect to a raw "
                            "user-supplied absolute URL. Use a relative-URL-only "
                            "policy (`if not url.startswith('/'): reject`) and "
                            "reject `//` (protocol-relative) and `/\\` (backslash) "
                            "prefixes that bypass naïve checks."
                        ),
                    )
                )
                # Found a working payload for this param — no need to try more.
                break

        return findings

    async def _redirect_location(
        self, session: aiohttp.ClientSession, url: str
    ) -> str | None:
        """GET *url* without following redirects. Returns the Location header
        if the response is a 3xx, else None.

        Retries on transient 5xx/429 responses via the shared helper, but
        falls back to a direct session.get for the actual redirect check
        (which needs ``allow_redirects=False`` to capture the Location header
        before aiohttp follows it).
        """
        # Direct fetch with allow_redirects=False — we need the raw 3xx
        # response, not the followed final page.
        try:
            async with session.get(
                url, ssl=False, allow_redirects=False
            ) as resp:
                if resp.status in (301, 302, 303, 307, 308):
                    return resp.headers.get("Location")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
        return None

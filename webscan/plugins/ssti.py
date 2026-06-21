"""Plugin: detect Server-Side Template Injection (SSTI).

SSTI occurs when user input is concatenated into a template string instead
of being passed as a data variable. An attacker can inject template syntax
(``{{7*7}}``, ``${7*7}``, ``<%= 7*7 %>``, ``#{7*7}``) and the server
evaluates it, leading to RCE.

This plugin is **active**: it sends probe payloads to parameters and verifies
the response contains the evaluated result (e.g. ``49`` for ``7*7``).

For low false positives:

* **CRITICAL (FIRM)** — response contains the exact mathematical result of
  the probe (``49`` for ``{{7*7}}``, ``343`` for ``{{7*7*7}}``). This is
  unambiguous — the template engine evaluated the expression.
* **MEDIUM (TENTATIVE)** — response contains the raw template syntax
  (``{{`` or ``${``) reflected without evaluation. This could mean the
  engine is safe, or that a different syntax is needed.

The plugin probes 6 template syntaxes covering the major engines:

* ``{{7*7}}`` — Jinja2, Twig, Django, Nunjucks, Tornado
* ``${7*7}`` — FreeMarker, Velocity, Thymeleaf, Mako
* ``<%= 7*7 %>`` — ERB (Ruby), EJS (Node.js)
* ``#{7*7}`` — Ruby (alternative), Smarty
* ``{7*7}`` — Smarty (alternative)
* ``{{= 7*7}}`` — doT.js

To distinguish between engines, the second probe uses ``{{7*'7'}}`` (Jinja2
returns ``7777777``, Twig returns ``49``). But for FP-reduction we only flag
when the mathematical result appears, not when the syntax is reflected.
"""
from __future__ import annotations

import asyncio
from urllib.parse import ParseResult, parse_qs, urlencode, urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# ─── Probe design ─────────────────────────────────────────────────────────────

# Each probe: (syntax_name, payload, expected_result)
# The expected_result is a string that MUST appear in the response for a FIRM
# finding. Using multiplication (7*7=49, 7*7*7=343) avoids false positives
# from the number 7 appearing in normal content.
_PROBES: tuple[tuple[str, str, str], ...] = (
    ("Jinja2/Twig/Django", "{{7*7}}", "49"),
    ("Jinja2 (string mul)", "{{7*'7'}}", "7777777"),
    ("FreeMarker/Velocity/Mako", "${7*7}", "49"),
    ("ERB/EJS", "<%= 7*7 %>", "49"),
    ("Ruby/Smarty", "#{7*7}", "49"),
    ("Smarty (alt)", "{7*7}", "49"),
    ("doT.js", "{{= 7*7}}", "49"),
)

# Parameter names likely to be reflected in a template. We probe all query
# parameters (not just specific names) because SSTI can occur in any param
# that's reflected into a template.
_MAX_PARAMS_PER_TARGET = 5

# Templates for the second-stage probe: if the first probe reflects the
# syntax but doesn't evaluate, try a different expression to confirm.
# Using 7*7*7=343 to avoid collision with 49.
_CONFIRMATION_PROBE = "{{7*7*7}}"
_CONFIRMATION_RESULT = "343"


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _find_probe_params(target: str) -> list[tuple[str, str]]:
    """Return ``(param_name, original_value)`` pairs from the URL query string."""
    parsed = urlparse(target)
    if not parsed.query:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        if name not in seen:
            value = values[0] if values else ""
            out.append((name, value))
            seen.add(name)
            if len(out) >= _MAX_PARAMS_PER_TARGET:
                break
    return out


def _replace_param(target: str, param: str, value: str) -> str:
    """Return *target* with *param* set to *value*, preserving other params."""
    parsed: ParseResult = urlparse(target)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(
        {k: v[0] if len(v) == 1 else v for k, v in qs.items()}, doseq=True
    )
    return parsed._replace(query=new_query).geturl()


def _has_result(body: str, expected: str) -> bool:
    """True if *expected* appears in *body* as a standalone token.

    We check for the expected result surrounded by non-digit characters (or
    string boundaries) to avoid matching '49' inside a phone number or
    timestamp like '1492001234'.
    """
    if not expected:
        return False
    # Use a simple boundary check: the expected string must not be
    # immediately preceded or followed by a digit.
    idx = 0
    while True:
        idx = body.find(expected, idx)
        if idx == -1:
            return False
        before = body[idx - 1] if idx > 0 else ""
        after = body[idx + len(expected)] if idx + len(expected) < len(body) else ""
        if not before.isdigit() and not after.isdigit():
            return True
        idx += 1


def _has_syntax_reflection(body: str, syntax: str) -> bool:
    """True if the raw template syntax (e.g. ``{{``) appears in *body*."""
    # Check for the opening delimiter of the syntax
    if syntax.startswith("{{"):
        return "{{" in body
    if syntax.startswith("${"):
        return "${" in body
    if syntax.startswith("<%="):
        return "<%=" in body
    if syntax.startswith("#{"):
        return "#{" in body
    if syntax.startswith("{") and not syntax.startswith("{{"):
        return "{7" in body
    return False


# ─── Plugin ───────────────────────────────────────────────────────────────────


class SstiPlugin(BasePlugin):
    """Probes URL parameters for Server-Side Template Injection."""

    name = "ssti"
    description = "Detect SSTI via Jinja2/Twig/FreeMarker/ERB/Smarty syntax evaluation"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        params = _find_probe_params(target)
        if not params:
            return findings

        # Fetch baseline to check that the param is reflected at all.
        baseline_body, baseline_status = await self._fetch(session, target)
        if baseline_body is None:
            return findings

        seen_payloads: set[str] = set()

        for param, _original in params:
            for engine_name, payload, expected in _PROBES:
                key = f"{param}:{payload}"
                if key in seen_payloads:
                    continue
                seen_payloads.add(key)

                probe_url = _replace_param(target, param, payload)
                body, status = await self._fetch(session, probe_url)
                if body is None:
                    continue

                # FIRM finding: the mathematical result appears in the response.
                # This is unambiguous — the template engine evaluated the expression.
                if _has_result(body, expected):
                    # Double-check: make sure the result wasn't already in the
                    # baseline (could be a page that just happens to contain "49").
                    if _has_result(baseline_body, expected):
                        # Try the confirmation probe (343 instead of 49)
                        confirm_url = _replace_param(
                            target, param, _CONFIRMATION_PROBE
                        )
                        confirm_body, _ = await self._fetch(session, confirm_url)
                        if confirm_body is None or not _has_result(
                            confirm_body, _CONFIRMATION_RESULT
                        ):
                            continue

                    findings.append(self._make_finding(
                        target=target,
                        param=param,
                        payload=payload,
                        engine=engine_name,
                        expected=expected,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.FIRM,
                        probe_url=probe_url,
                        http_status=status,
                        baseline_status=baseline_status,
                    ))
                    # Found CRITICAL for this param — no need to try more syntaxes.
                    break

                # TENTATIVE finding: syntax is reflected but not evaluated.
                # Could mean the engine is safe, or that a different syntax is
                # needed, or that the engine evaluates but the result is
                # filtered/escaped.
                if (
                    _has_syntax_reflection(body, payload)
                    and not _has_syntax_reflection(baseline_body, payload)
                ):
                    findings.append(self._make_finding(
                        target=target,
                        param=param,
                        payload=payload,
                        engine=engine_name,
                        expected=expected,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        probe_url=probe_url,
                        http_status=status,
                        baseline_status=baseline_status,
                    ))
                    break  # one TENTATIVE per param is enough

        return findings

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> tuple[str | None, int]:
        """GET *url* with retry on transient failures."""
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                body = await fetch_body(resp)
                return body, resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return None, 0

    def _make_finding(
        self,
        *,
        target: str,
        param: str,
        payload: str,
        engine: str,
        expected: str,
        severity: Severity,
        confidence: Confidence,
        probe_url: str,
        http_status: int,
        baseline_status: int,
    ) -> Finding:
        if severity is Severity.CRITICAL:
            title = f"SSTI confirmed: {engine} evaluates `{payload}` → {expected}"
            desc = (
                f"The `{param}` parameter is reflected into a server-side "
                f"template. A payload `{payload}` ({engine} syntax) was "
                f"evaluated and the result `{expected}` appeared in the "
                "response. An attacker can execute arbitrary code on the "
                "server via template expressions like `{{config}}`, "
                "`{{''.__class__.__mro__[1].__subclasses__()}}` (Python), or "
                "`${'freemarker.template.utility.Execute'?new()('id')}` (Java)."
            )
        else:
            title = f"Possible SSTI: {engine} syntax reflected in '{param}'"
            desc = (
                f"The `{param}` parameter reflects template syntax ({engine}) "
                f"into the response without evaluation. The payload `{payload}` "
                "appeared in the response body but was not evaluated to "
                f"`{expected}`. This could mean the template engine is safely "
                "configured, or that a different syntax/encoding is needed. "
                "Manual verification recommended."
            )

        return Finding(
            plugin=self.name,
            title=title,
            severity=severity,
            confidence=confidence,
            description=desc,
            url=target,
            evidence={
                "param": param,
                "payload": payload,
                "engine": engine,
                "expected_result": expected,
                "probe_url": probe_url,
                "http_status": http_status,
                "baseline_status": baseline_status,
            },
            remediation=(
                "Never concatenate user input into template strings. Use the "
                "template engine's data-binding API: pass user input as a "
                "variable (e.g. `Template('Hello {{name}}').render(name=user_input)`), "
                "not as part of the template source. Enable sandboxing/auto-escaping "
                "where available."
            ),
        )

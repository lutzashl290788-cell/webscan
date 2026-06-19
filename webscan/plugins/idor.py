"""Plugin: detect Insecure Direct Object Reference (IDOR).

IDOR occurs when an application uses user-supplied object identifiers (URL
path segment, query parameter) to access an object directly, without
checking that the *current user* is allowed to see that object. The classic
case: ``GET /api/users/123`` returns Alice's profile — but changing the id
to ``124`` returns Bob's profile, even though you're logged in as Alice.

The plugin is **active**: it sends probe requests with the ID shifted by ±1
and compares the responses. Crucially:

* A **401/403 response** on the probe means auth is enforced → safe, no finding.
* A **404 response** means the next/prev ID doesn't exist → no finding (we
  can't tell if it would have been accessible).
* A **200 response with the same shape** as the original (similar length,
  no auth error markers) is suspicious. We flag it as TENTATIVE — manual
  verification needed to confirm the data actually belongs to a different
  user.

For low false positives:

* **Skip non-API URLs** — public content (articles, products, blog posts)
  is *meant* to be accessible by anyone; flagging it as IDOR would be wrong.
  We restrict probes to URLs whose path contains ``/api/``, ``/v1/``,
  ``/v2/``, etc., or whose content-type is JSON.
* **Skip URLs with no ID-like parameter** — we only probe when we can find
  a numeric ID in the path or query.
* **Compare response *shape*, not raw bytes** — different objects have
  different data, so identical responses are suspicious; very different
  lengths suggest one is an error page. We use a similarity ratio.
* **Flag as TENTATIVE** — even with all filters, IDOR is semantic: a
  public API endpoint that legitimately exposes object 124 is not IDOR.
  Confidence is TENTATIVE so operators can filter it out if needed.
* **Skip if response contains "unauthorized"/"forbidden"/"login"** —
  common auth-error markers.
"""
from __future__ import annotations

import asyncio
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# ─── Detection rules ──────────────────────────────────────────────────────────

# URL path patterns that suggest an API endpoint (where IDOR is meaningful).
# A URL is considered "API-like" if its path matches one of these patterns.
_API_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/api/"),
    re.compile(r"/v\d+/"),  # /v1/, /v2/, ...
    re.compile(r"/graphql", re.IGNORECASE),
    re.compile(r"/svc/"),
    re.compile(r"/service/"),
    re.compile(r"/internal/"),
    re.compile(r"/admin/", re.IGNORECASE),
)

# Numeric ID patterns in URL path segments and query parameters.
# Matches standalone integers (not floats, not parts of larger tokens).
# Captures the integer as a group so we can shift it.
_PATH_ID_RE: re.Pattern[str] = re.compile(r"/(\d{1,12})(?=/|$)")
_QUERY_ID_RE: re.Pattern[str] = re.compile(r"([?&][^=&]+=)(\d{1,12})(?=&|$)")

# Response-content markers indicating auth failed — if any of these appear,
# the probe got a legitimate "not allowed" response, not a successful leak.
_AUTH_ERROR_MARKERS: tuple[str, ...] = (
    "unauthorized",
    "forbidden",
    "not authorized",
    "access denied",
    "permission denied",
    "login required",
    "must be logged in",
    "not authenticated",
    "invalid token",
    "token expired",
    '"status": 401',
    '"status": 403',
    '"code": 401',
    '"code": 403',
    '"error": "auth',
)

# Response-similarity threshold: if probe response is THIS similar to the
# baseline (as a ratio 0..1), it suggests the same kind of object was
# returned (i.e. no auth check on the shifted ID).
_SIMILARITY_THRESHOLD = 0.75

# Length-ratio thresholds — the probe response should be in the same ballpark
# as the baseline. If it's 10x smaller (error stub) or 10x larger (different
# object entirely), it's not a clear IDOR.
_MIN_LENGTH_RATIO = 0.5
_MAX_LENGTH_RATIO = 2.0

# Only probe IDs >= this value (so we don't try shifting ID=0 to ID=-1).
_MIN_ID_VALUE = 1

# Cap the number of IDs we probe per target — bound request pressure.
_MAX_IDS_PER_TARGET = 3

# Don't probe if baseline is too short — can't meaningfully compare.
_MIN_BASELINE_LENGTH = 100

# Cap on baseline/probe body length for similarity comparison (perf bound).
_MAX_COMPARE_LENGTH = 100_000


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _is_api_endpoint(target: str) -> bool:
    """True if the URL path looks like an API endpoint (where IDOR matters)."""
    path = urlparse(target).path
    return any(p.search(path) for p in _API_PATH_PATTERNS)


def _find_id_in_path(target: str) -> list[tuple[str, int]]:
    """Find numeric IDs in the URL path. Returns ``[(kind, value), ...]``.

    ``kind`` is ``"path"`` so callers know which substitution to apply.
    """
    path = urlparse(target).path
    out: list[tuple[str, int]] = []
    for m in _PATH_ID_RE.finditer(path):
        try:
            value = int(m.group(1))
            if value >= _MIN_ID_VALUE:
                out.append(("path", value))
        except ValueError:
            continue
    return out


def _find_id_in_query(target: str) -> list[tuple[str, int]]:
    """Find numeric IDs in the URL query string. Returns ``[(kind, value), ...]``.

    ``kind`` is the full parameter name (e.g. ``"user_id"``).
    """
    parsed = urlparse(target)
    if not parsed.query:
        return []
    out: list[tuple[str, int]] = []
    seen: set[str] = set()
    for pair in parsed.query.split("&"):
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        # Only consider params whose value is a pure integer (not a float,
        # not a string that happens to start with digits).
        if value.isdigit():
            try:
                int_value = int(value)
                if int_value >= _MIN_ID_VALUE and name not in seen:
                    out.append((name, int_value))
                    seen.add(name)
            except ValueError:
                continue
    return out


def _shift_path_id(target: str, original: int, new: int) -> str:
    """Replace the *first* occurrence of *original* in the URL path with *new*."""
    # Use a regex to replace the path-segment integer; this is safer than
    # `str.replace` because the integer could appear elsewhere (e.g. query).
    parsed = urlparse(target)
    new_path = _PATH_ID_RE.sub(
        lambda m: f"/{new}" if int(m.group(1)) == original else m.group(0),
        parsed.path,
        count=1,
    )
    return parsed._replace(path=new_path).geturl()


def _shift_query_id(target: str, param: str, original: int, new: int) -> str:
    """Replace the value of *param* in the query string with *new*."""
    parsed = urlparse(target)
    pairs = parsed.query.split("&")
    new_pairs: list[str] = []
    for pair in pairs:
        if "=" in pair:
            name, value = pair.split("=", 1)
            if name == param and value == str(original):
                new_pairs.append(f"{name}={new}")
                continue
        new_pairs.append(pair)
    new_query = "&".join(new_pairs)
    return parsed._replace(query=new_query).geturl()


def _has_auth_error(body: str) -> bool:
    """True if the response body looks like an auth-failure message."""
    lowered = body[:4000].lower()  # cap for perf
    return any(m in lowered for m in _AUTH_ERROR_MARKERS)


def _similarity(a: str, b: str) -> float:
    """Sequence similarity ratio between *a* and *b* (0..1).

    Caps both strings at :data:`_MAX_COMPARE_LENGTH` to keep the diff fast.
    """
    a_cap = a[:_MAX_COMPARE_LENGTH]
    b_cap = b[:_MAX_COMPARE_LENGTH]
    return SequenceMatcher(None, a_cap, b_cap).ratio()


def _length_ratio(baseline: str, probe: str) -> float:
    """Ratio of probe length to baseline length (0..∞, 1.0 = equal)."""
    if not baseline:
        return 0.0
    return len(probe) / len(baseline)


# ─── Plugin ───────────────────────────────────────────────────────────────────


class IdorPlugin(BasePlugin):
    """Probes API endpoints with shifted object IDs to detect IDOR."""

    name = "idor"
    description = "Detect IDOR by probing ±1 object IDs on API endpoints (TENTATIVE)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Skip non-API URLs — public content (articles, products) is meant to
        # be accessible; flagging it as IDOR would be a false positive.
        if not _is_api_endpoint(target):
            return findings

        # Find candidate IDs in path and query.
        ids: list[tuple[str, int]] = []
        ids.extend(_find_id_in_path(target))
        ids.extend(_find_id_in_query(target))
        if not ids:
            return findings

        # Cap the number of IDs to probe.
        ids = ids[:_MAX_IDS_PER_TARGET]

        # Fetch the baseline response (original URL).
        baseline_body, baseline_status, baseline_ct = await self._fetch(session, target)
        if baseline_body is None or baseline_status != 200:
            # If the baseline itself isn't 200, we can't tell what a "successful"
            # response looks like — skip.
            return findings
        if len(baseline_body) < _MIN_BASELINE_LENGTH:
            return findings
        # Skip if baseline already says "unauthorized" — caller isn't auth'd,
        # so any further probe will also fail auth, which isn't IDOR.
        if _has_auth_error(baseline_body):
            return findings

        seen_probes: set[str] = set()

        for kind, original_value in ids:
            # Probe with original+1 (skip 0 → -1 case).
            for shift in (+1, -1):
                new_value = original_value + shift
                if new_value < _MIN_ID_VALUE:
                    continue

                if kind == "path":
                    probe_url = _shift_path_id(target, original_value, new_value)
                else:
                    probe_url = _shift_query_id(target, kind, original_value, new_value)

                if probe_url in seen_probes or probe_url == target:
                    continue
                seen_probes.add(probe_url)

                probe_body, probe_status, probe_ct = await self._fetch(session, probe_url)
                if probe_body is None:
                    continue

                # 401/403 → auth enforced. Safe. Skip.
                if probe_status in (401, 403):
                    continue
                # 404 → shifted ID doesn't exist. Can't tell if it'd be accessible.
                if probe_status == 404:
                    continue
                # Non-200 (5xx, etc.) → server error, not a clear IDOR signal.
                if probe_status != 200:
                    continue

                # Auth-error markers in body → still safe (just returned 200
                # with an error payload).
                if _has_auth_error(probe_body):
                    continue

                # Length check — wildly different sizes suggest a different
                # kind of response (error page, empty result), not IDOR.
                lr = _length_ratio(baseline_body, probe_body)
                if lr < _MIN_LENGTH_RATIO or lr > _MAX_LENGTH_RATIO:
                    continue

                # Content-Type mismatch (e.g. baseline JSON, probe HTML) —
                # suspicious in a different way; skip to avoid noise.
                if baseline_ct and probe_ct and baseline_ct.lower() != probe_ct.lower():
                    continue

                # Similarity check — if the probe is structurally similar to
                # the baseline (same JSON shape, same HTML template), it's
                # likely returning a different object of the same type → IDOR.
                sim = _similarity(baseline_body, probe_body)
                if sim < _SIMILARITY_THRESHOLD:
                    continue

                # All filters passed → flag.
                findings.append(self._make_finding(
                    target=target,
                    severity=Severity.HIGH,
                    confidence=Confidence.TENTATIVE,  # always TENTATIVE — semantic check needed
                    title=f"Possible IDOR: {kind}={original_value} shifted to {new_value}",
                    description=(
                        f"The {kind} {'parameter' if kind != 'path' else 'segment'} "
                        f"``{original_value}`` was shifted to ``{new_value}`` and the "
                        f"server returned a 200 response structurally similar to the "
                        f"baseline (similarity ratio {sim:.2f}, length ratio {lr:.2f}). "
                        "This suggests the endpoint exposes object data without "
                        "verifying that the requesting user is authorised to view it. "
                        "Manual verification needed — confirm the shifted object "
                        "actually belongs to a different user."
                    ),
                    evidence={
                        "original_id": original_value,
                        "shifted_id": new_value,
                        "id_location": kind,
                        "probe_url": probe_url,
                        "baseline_status": baseline_status,
                        "probe_status": probe_status,
                        "baseline_length": len(baseline_body),
                        "probe_length": len(probe_body),
                        "similarity": round(sim, 3),
                        "length_ratio": round(lr, 3),
                        "baseline_content_type": baseline_ct,
                        "probe_content_type": probe_ct,
                    },
                    remediation=(
                        "Implement object-level authorisation: on every request that "
                        "accesses an object by ID, verify the authenticated user owns "
                        "or is permitted to access that object. Use a framework-level "
                        "authz check (e.g. Django's `get_object_or_404` with the "
                        "user's ownership filter) rather than relying on the URL."
                    ),
                ))
                # One finding per ID is enough — don't also probe ID-1 if ID+1 fired.
                break

        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fetch(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> tuple[str | None, int, str]:
        """GET *url*. Returns ``(body, status, content_type)`` or ``(None, 0, '')``."""
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                body = await resp.text(errors="ignore")
                ct = resp.headers.get("Content-Type", "")
                return body, resp.status, ct
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return None, 0, ""

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

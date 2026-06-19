"""Plugin: audit JSON Web Tokens (JWT) leaked in HTTP responses.

A JWT observed in a response (Set-Cookie, Authorization echoed back, body, or
query string) carries a lot of security metadata in cleartext. This plugin
decodes — *without* verifying the signature, which we cannot do server-side —
and reports well-known configuration weaknesses:

* ``alg: none`` — token explicitly disables signature verification.
* Weak / unsigned algorithms (HS256 with a trivially-guessable secret is
  detected via a small built-in common-secret dictionary).
* Missing ``exp`` claim (tokens never expire) or already-expired tokens.
* Tokens expiring soon (< 7 days) — operational warning.
* Sensitive claims (``password``, ``secret``, ``ssn``, credit-card-shaped
  numbers) embedded in the payload.
* ``kid`` header containing SQL / path-traversal / template-injection patterns
  used for key-confusion attacks.
* ``jku`` / ``x5u`` header pointing at an external URL — potential key-source
  hijack if the server fetches keys from it without validation.

The plugin is **passive**: it only inspects what the server already returns.
It never sends forged tokens back to the target, so there is no risk of
exploiting the issues it finds.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin

# ─── JWT shape ────────────────────────────────────────────────────────────────

# Three base64url segments separated by dots. The third (signature) may be
# empty when ``alg=none`` — encoded as an empty string between two dots.
# Trailing ``(?![A-Za-z0-9_\-])`` is used instead of ``\b`` because ``\b``
# requires a word character on one side, which fails for tokens whose
# signature is empty (the token then ends in a dot — a non-word char).
_JWT_RE: re.Pattern[str] = re.compile(
    r"\b(eyJ[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]*)(?![A-Za-z0-9_\-])"
)

# Cookie names that commonly carry JWTs (case-insensitive).
_JWT_COOKIE_NAMES: frozenset[str] = frozenset({
    "jwt", "token", "access_token", "refresh_token", "auth_token",
    "id_token", "session", "sid", "bearer",
})

# Built-in wordlist of trivially weak HMAC secrets. If a token verifies
# against any of these, the secret is publicly guessable in seconds.
# Source: classic jwt-secrets lists, kept intentionally short.
_COMMON_HMAC_SECRETS: tuple[bytes, ...] = (
    b"secret", b"Secret", b"SECRET",
    b"password", b"Password",
    b"123456", b"12345678", b"12345678901234567890",
    b"admin", b"root", b"test", b"key",
    b"jwt", b"jwt-secret", b"jwt_secret",
    b"your-256-bit-secret",           # PyJWT documentation default
    b"supersecret", b"supersecretkey",
    b"changeme", b"change-me",
    b"default", b"example",
    b"nodejs", b"express",
    b"flask-secret", b"django-insecure",
)

# HMAC algorithms that the trivial-secret check applies to.
_HMAC_ALGS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})

# Claims that should never appear in a JWT payload — their presence alone is
# a CRITICAL disclosure, regardless of signature strength.
_SENSITIVE_CLAIM_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)password|passwd|pwd"),
    re.compile(r"(?i)secret|api[_-]?key|access[_-]?key"),
    re.compile(r"(?i)\bssn\b|social[_-]?security"),
    re.compile(r"(?i)credit[_-]?card|card[_-]?number|cvv|cvc"),
    # Bare 13- or 16-digit runs look like credit-card numbers.
    re.compile(r"\b(?:\d[ -]?){13,16}\b"),
)

# kid-header patterns that indicate a likely injection vector.
_KID_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "SQL-injection-shaped kid",
        re.compile(r"(?i)(?:'|\bor\b\s+1\s*=\s*1|union\s+select|--)"),
        "The ``kid`` header contains SQL-injection-like characters. Some "
        "implementations use ``kid`` unsanitised in a database lookup, "
        "turning it into a SQL-injection vector.",
    ),
    (
        "path-traversal-shaped kid",
        re.compile(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", re.IGNORECASE),
        "The ``kid`` header contains path-traversal sequences. Some JWT "
        "libraries load the verification key from a file path derived from "
        "``kid``, enabling LFI to read arbitrary files (e.g. ``kid=../../"
        "dev/null`` to bypass verification).",
    ),
    (
        "template-injection-shaped kid",
        re.compile(r"(?i)\{\{|\{%|<%|<%=|\$\{"),
        "The ``kid`` header contains server-side template markers. If the "
        "JWT library renders ``kid`` through a template engine, this is an "
        "SSTI vector.",
    ),
)

# Claims that carry expiry / time metadata.
_EXP_CLAIMS: tuple[str, ...] = ("exp",)
_NBF_CLAIMS: tuple[str, ...] = ("nbf",)
_IAT_CLAIMS: tuple[str, ...] = ("iat",)

# Soon-to-expire threshold (seconds).
_EXPIRING_SOON_SECONDS: int = 7 * 24 * 3600  # 7 days

# Where the plugin looks for JWTs.
_MAX_BODY_LENGTH: int = 5 * 1024 * 1024  # 5 MiB — bound memory on huge pages


# ─── Helpers ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class _DecodedJWT:
    """A decoded JWT — header and payload as plain dicts, plus the raw token."""

    raw: str
    header: dict[str, Any]
    payload: dict[str, Any]
    signature: str


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url string, padding it as needed. Returns b"" on failure."""
    # JWT uses base64url without padding. Add padding to a multiple of 4.
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError):
        return b""


def _decode_jwt(token: str) -> _DecodedJWT | None:
    """Decode a JWT *without* verifying its signature.

    Returns ``None`` if the token is malformed (not 3 segments, or the
    header/payload are not valid base64url-JSON).
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature = parts

    header_bytes = _b64url_decode(header_b64)
    payload_bytes = _b64url_decode(payload_b64)
    if not header_bytes or not payload_bytes:
        return None

    try:
        header = json.loads(header_bytes)
        payload = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None

    return _DecodedJWT(raw=token, header=header, payload=payload, signature=signature)


def _extract_jwt_cookies(set_cookie_values: list[str]) -> list[tuple[str, str]]:
    """Return ``(cookie_name, jwt_string)`` pairs from raw Set-Cookie lines.

    Only cookies whose name is in :data:`_JWT_COOKIE_NAMES` *or* whose value
    matches the JWT shape are considered.
    """
    out: list[tuple[str, str]] = []
    for raw in set_cookie_values:
        # A Set-Cookie line is ``name=value; Attr; Attr``.
        first = raw.split(";", 1)[0].strip()
        if "=" not in first:
            continue
        name, value = first.split("=", 1)
        name = name.strip()
        value = value.strip()
        if not value:
            continue
        # Strip surrounding quotes if any.
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        looks_like_jwt = _JWT_RE.fullmatch(value) is not None
        if name.lower() in _JWT_COOKIE_NAMES or looks_like_jwt:
            match = _JWT_RE.search(value)
            if match:
                out.append((name, match.group(1)))
    return out


def _extract_jwt_from_header(value: str) -> str | None:
    """Pull a JWT out of an ``Authorization: Bearer <jwt>`` header."""
    if not value:
        return None
    parts = value.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        match = _JWT_RE.search(parts[1])
        if match:
            return match.group(1)
    # Some servers echo the raw JWT without the ``Bearer`` scheme.
    match = _JWT_RE.search(value)
    return match.group(1) if match else None


def _extract_jwt_from_query(url: str) -> list[str]:
    """Find JWTs passed as query parameters (``?token=eyJ…``)."""
    parsed = urlparse(url)
    if not parsed.query:
        return []
    out: list[str] = []
    for pair in parsed.query.split("&"):
        if "=" not in pair:
            continue
        _key, value = pair.split("=", 1)
        match = _JWT_RE.search(value)
        if match:
            out.append(match.group(1))
    return out


def _hmac_verify(decoder: _DecodedJWT, secret: bytes) -> bool:
    """Recompute an HMAC-SHA signature and compare in constant time.

    Returns ``False`` for non-HMAC tokens or signature mismatches. Imported
    lazily so a missing/broken hashlib never crashes plugin discovery.
    """
    import hashlib
    import hmac

    alg = decoder.header.get("alg", "")
    if alg not in _HMAC_ALGS:
        return False

    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn = hash_map[alg]
    signing_input = f"{decoder.raw.rsplit('.', 1)[0]}.".encode("ascii")
    expected = hmac.new(secret, signing_input, hash_fn).digest()
    actual = _b64url_decode(decoder.signature)
    if not actual:
        return False
    return hmac.compare_digest(expected, actual)


def _find_weak_hmac_secret(decoder: _DecodedJWT) -> bytes | None:
    """Return the first built-in common secret that verifies the token, or None."""
    for secret in _COMMON_HMAC_SECRETS:
        if _hmac_verify(decoder, secret):
            return secret
    return None


def _safe_int(value: object) -> int | None:
    """Coerce a claim value to int (JWT numeric claims may be float or str)."""
    if isinstance(value, bool):  # bool is a subtype of int — exclude it explicitly
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _find_sensitive_claims(payload: dict[str, Any]) -> list[tuple[str, str, Any]]:
    """Return ``(key, why, value_preview)`` for claims that look sensitive."""
    hits: list[tuple[str, str, Any]] = []
    for key, value in payload.items():
        key_str = str(key)
        for pattern in _SENSITIVE_CLAIM_PATTERNS:
            if pattern.search(key_str):
                hits.append((key_str, "claim name matches a sensitive pattern", value))
                break
        else:
            # If the key didn't match, also scan the value if it's a string.
            if isinstance(value, str):
                for pattern in _SENSITIVE_CLAIM_PATTERNS:
                    if pattern.search(value):
                        hits.append((key_str, "claim value matches a sensitive pattern", value))
                        break
    return hits


def _redact(value: object) -> str:
    """Render a claim value for evidence without leaking it in full."""
    text = str(value)
    if len(text) <= 4:
        return "…"
    return text[:2] + "…[REDACTED]"


# ─── Plugin ───────────────────────────────────────────────────────────────────


class JwtAuditPlugin(BasePlugin):
    """Decodes JWTs observed in the HTTP response and flags configuration flaws."""

    name = "jwt_audit"
    description = "Audit JSON Web Tokens for alg=none, weak secrets, expiry and sensitive claims"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_tokens: set[str] = set()

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                headers = resp.headers
                # Set-Cookie (may be multiple)
                set_cookies = headers.getall("Set-Cookie", [])
                # Authorization — servers sometimes echo it back
                auth_header = headers.get("Authorization", "")
                # Custom token-bearing headers
                x_auth = headers.get("X-Auth-Token", "")
                x_access = headers.get("X-Access-Token", "")
                body = await resp.text(errors="ignore")
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        # Truncate enormous bodies so we don't burn CPU regex-matching them.
        if len(body) > _MAX_BODY_LENGTH:
            body = body[:_MAX_BODY_LENGTH]

        sources: list[tuple[str, str]] = []  # (jwt, source_location)

        # 1. Cookies
        for name, cookie_token in _extract_jwt_cookies(set_cookies):
            sources.append((cookie_token, f"Set-Cookie: {name}"))

        # 2. Authorization header echoed back
        auth_token = _extract_jwt_from_header(auth_header)
        if auth_token:
            sources.append((auth_token, "Authorization header"))

        # 3. Custom token headers
        for hdr_value, hdr_name in ((x_auth, "X-Auth-Token"), (x_access, "X-Access-Token")):
            match = _JWT_RE.search(hdr_value)
            if match:
                sources.append((match.group(1), f"{hdr_name} header"))

        # 4. Query string of the target URL itself (rare but real)
        for qtoken in _extract_jwt_from_query(target):
            sources.append((qtoken, "URL query string"))

        # 5. Body (HTML/JSON) — covers ``window.jwt = "..."`` and JSON APIs.
        for match in _JWT_RE.finditer(body):
            sources.append((match.group(1), "response body"))

        # Dedupe by token value so the same JWT seen in two places is audited once.
        for token, source in sources:
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            decoded = _decode_jwt(token)
            if decoded is None:
                # A JWT-shaped string that doesn't decode is itself suspicious —
                # likely a decoy or a malformed token. Report as INFO.
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="Malformed JWT observed",
                        severity=Severity.INFO,
                        confidence=Confidence.INFORMATIONAL,
                        description=(
                            f"A JWT-shaped string was observed in the response "
                            f"({source}) but its header/payload could not be "
                            "decoded as base64url JSON. It may be a decoy or a "
                            "custom token format."
                        ),
                        url=target,
                        evidence={"source": source, "preview": token[:32] + "…"},
                        remediation=(
                            "No action required unless this is a real token; "
                            "verify the format."
                        ),
                    )
                )
                continue
            findings.extend(self._audit(target, source, decoded))

        return findings

    # ------------------------------------------------------------------
    # Per-token audit
    # ------------------------------------------------------------------

    def _audit(
        self,
        target: str,
        source: str,
        decoder: _DecodedJWT,
    ) -> list[Finding]:
        findings: list[Finding] = []
        alg = str(decoder.header.get("alg", "") or "")
        preview = decoder.raw[:24] + "…"
        common_evidence: dict[str, Any] = {
            "source": source,
            "alg": alg,
            "header": _safe_header_for_evidence(decoder.header),
            "payload_keys": list(decoder.payload.keys()),
            "preview": preview,
        }

        def add(
            title: str,
            severity: Severity,
            description: str,
            remediation: str,
            *,
            evidence: dict[str, Any] | None = None,
            confidence: Confidence = Confidence.FIRM,
        ) -> None:
            findings.append(
                Finding(
                    plugin=self.name,
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    description=description,
                    url=target,
                    evidence={**common_evidence, **(evidence or {})},
                    remediation=remediation,
                )
            )

        # --- alg=none / unsigned ---
        if alg.lower() == "none":
            add(
                "JWT uses alg=none (unsigned)",
                Severity.CRITICAL,
                "The token declares ``alg=none``, which disables signature "
                "verification. Any party can forge a token with arbitrary claims "
                "(e.g. ``admin: true``) and the server will accept it.",
                "Reject ``alg=none`` server-side. Pin the expected algorithm "
                "explicitly when verifying signatures; never trust the ``alg`` "
                "from the token header.",
            )

        # --- Weak HMAC secret ---
        if alg in _HMAC_ALGS:
            weak_secret = _find_weak_hmac_secret(decoder)
            if weak_secret is not None:
                add(
                    f"JWT signed with a trivially-guessable {alg} secret",
                    Severity.CRITICAL,
                    f"The token's {alg} signature verifies against a built-in "
                    "list of common secrets (``"
                    + weak_secret.decode("utf-8", errors="replace")
                    + "``). An attacker can reproduce this signature in seconds "
                    "and forge arbitrary tokens.",
                    "Rotate the signing key to a long, random, high-entropy "
                    "value (>= 256 bits for HS256). Never reuse example values "
                    "from documentation or tutorials.",
                    evidence={
                        "weak_secret_preview": (
                            weak_secret[:8].decode("utf-8", "replace") + "…"
                        )
                    },
                )

        # --- Algorithm confusion: RS256 token without kid ---
        # An RS256 token with no ``kid`` and no ``jku`` is more likely to be
        # verified via algorithm confusion (attacker re-signs as HS256 with the
        # public key). Flag as TENTATIVE — needs the server to actually accept
        # the forged token, which we don't test here.
        if alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS"):
            if "kid" not in decoder.header and "x5c" not in decoder.header:
                add(
                    "Asymmetric JWT has no key identifier (kid)",
                    Severity.MEDIUM,
                    confidence=Confidence.TENTATIVE,
                    description=(
                        f"The token uses an asymmetric algorithm ({alg}) but its "
                        "header has no ``kid`` claim, so the server must pick a "
                        "verification key by other means. This makes the "
                        "deployment more likely to be vulnerable to "
                        "algorithm-confusion attacks (RS256 → HS256 with the "
                        "public key as HMAC secret)."
                    ),
                    remediation=(
                        "Always set ``kid`` in the header and look up the key "
                        "by ``kid`` server-side. Pin the allowed algorithm per "
                        "key id; reject tokens whose header algorithm doesn't "
                        "match the key's configured algorithm."
                    ),
                )

        # --- kid injection patterns ---
        kid = decoder.header.get("kid")
        if isinstance(kid, str):
            for label, pattern, why in _KID_INJECTION_PATTERNS:
                if pattern.search(kid):
                    add(
                        f"JWT kid header: {label}",
                        Severity.HIGH,
                        why
                        + f" Observed ``kid`` value: ``{_redact(kid)}``.",
                        "Sanitise the ``kid`` header before using it. If it "
                        "indexes a database, use parameterised queries. If it "
                        "indexes a file, restrict to an allow-list of key ids.",
                        evidence={"kid_preview": _redact(kid)},
                    )

        # --- jku / x5u pointing to external URL ---
        for claim in ("jku", "x5u"):
            url_val = decoder.header.get(claim)
            if isinstance(url_val, str) and url_val.startswith(("http://", "https://")):
                add(
                    f"JWT {claim} header points at an external URL",
                    Severity.HIGH,
                    confidence=Confidence.TENTATIVE,
                    description=(
                        f"The ``{claim}`` header is set to ``{url_val}``. If "
                        "the server fetches the key set from this URL without "
                        "validating it against an allow-list, an attacker who "
                        "can control ``{claim}`` can serve their own keys and "
                        "forge tokens."
                    ),
                    remediation=(
                        "Validate ``{claim}`` against an allow-list of trusted "
                        "URLs before fetching. Prefer ``kid`` + a locally "
                        "configured key set over remote URL-based lookup."
                    ),
                    evidence={claim: url_val},
                )

        # --- Missing exp ---
        if not any(clm in decoder.payload for clm in _EXP_CLAIMS):
            add(
                "JWT has no expiry (exp) claim",
                Severity.HIGH,
                "The token carries no ``exp`` claim, so it never expires. A "
                "stolen token remains valid forever — there is no automatic "
                "revocation via time.",
                "Always set ``exp`` to a short lifetime (minutes to hours). "
                "Use refresh tokens for long-lived sessions.",
            )
        else:
            exp_value = _safe_int(decoder.payload.get("exp"))
            now = int(time.time())
            if exp_value is None:
                add(
                    "JWT exp claim is not a valid timestamp",
                    Severity.MEDIUM,
                    "The ``exp`` claim is present but not a numeric timestamp, "
                    "which libraries may handle inconsistently — some reject, "
                    "some ignore. The token's effective lifetime is undefined.",
                    "Encode ``exp`` as an integer Unix timestamp.",
                    evidence={"exp_raw": _redact(decoder.payload.get("exp"))},
                )
            elif exp_value <= now:
                add(
                    "JWT is already expired",
                    Severity.MEDIUM,
                    confidence=Confidence.INFORMATIONAL,
                    description=(
                        f"The token's ``exp`` claim is in the past "
                        f"({exp_value} < now={now}). It should be rejected by "
                        "the server, but its presence in a response suggests "
                        "it may still be cached or accepted."
                    ),
                    remediation=(
                        "Reject expired tokens server-side and issue a new "
                        "one via the refresh-token flow. Clear expired tokens "
                        "from client storage."
                    ),
                    evidence={"exp": exp_value, "now": now},
                )
            elif exp_value - now < _EXPIRING_SOON_SECONDS:
                add(
                    "JWT expires soon",
                    Severity.LOW,
                    confidence=Confidence.INFORMATIONAL,
                    description=(
                        f"The token expires in {exp_value - now} seconds "
                        f"(less than {_EXPIRING_SOON_SECONDS // 3600} hours). "
                        "This is informational — short-lived tokens are best "
                        "practice — but flagged so operators can verify their "
                        "refresh flow works."
                    ),
                    remediation=(
                        "Short token lifetimes are good. Ensure clients have a "
                        "working refresh-token flow so users aren't logged out "
                        "unexpectedly."
                    ),
                    evidence={"exp": exp_value, "now": now, "seconds_left": exp_value - now},
                )

        # --- Missing nbf / iat (informational) ---
        if not any(clm in decoder.payload for clm in _NBF_CLAIMS):
            add(
                "JWT has no not-before (nbf) claim",
                Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                description=(
                    "The token has no ``nbf`` claim. Without it, a token "
                    "issued in the future (clock skew on the server) is "
                    "immediately valid."
                ),
                remediation=(
                    "Set ``nbf`` to the issue time so the server can reject "
                    "tokens issued in the future due to clock skew."
                ),
            )
        if not any(clm in decoder.payload for clm in _IAT_CLAIMS):
            add(
                "JWT has no issued-at (iat) claim",
                Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                description=(
                    "The token has no ``iat`` claim, so it is impossible to "
                    "tell when it was issued. This makes incident response "
                    "(\"was this token stolen before or after the breach?\") "
                    "harder."
                ),
                remediation="Always set ``iat`` to the issue time.",
            )

        # --- Sensitive claims in payload ---
        for key, why, value in _find_sensitive_claims(decoder.payload):
            add(
                f"JWT payload carries a sensitive claim: {key}",
                Severity.HIGH,
                (
                    f"The claim ``{key}`` ({why}) is embedded in the JWT "
                    "payload. JWT payloads are base64 — not encrypted — so any "
                    "party that observes the token can read it. A token "
                    "captured from logs, browser history, or a leaked cookie "
                    "exposes this data."
                ),
                "Keep sensitive data server-side keyed by a session id. Put "
                "only an opaque subject identifier in the JWT payload.",
                evidence={"claim": key, "value_preview": _redact(value)},
            )

        return findings


def _safe_header_for_evidence(header: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the JWT header safe to put in evidence.

    Drops nothing (the header is already public — it's base64 in the token),
    but truncates long values so the report stays readable.
    """
    out: dict[str, Any] = {}
    for key, value in header.items():
        text = str(value)
        out[str(key)] = text if len(text) <= 64 else text[:32] + "…" + text[-8:]
    return out

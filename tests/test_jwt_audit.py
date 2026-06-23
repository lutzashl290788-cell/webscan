"""Tests for the jwt_audit plugin."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

import pytest

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.jwt_audit import (
    JwtAuditPlugin,
    _b64url_decode,
    _decode_jwt,
    _extract_jwt_cookies,
    _extract_jwt_from_header,
    _extract_jwt_from_query,
    _find_sensitive_claims,
    _find_weak_hmac_secret,
    _hmac_verify,
    _safe_int,
)

_TARGET = "https://example.com"


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(
    *,
    header: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    secret: bytes | None = None,
    signature_override: str | None = None,
) -> str:
    """Build a JWT. If ``secret`` is given and alg is HS*, sign it; else empty sig."""
    header = header or {"alg": "HS256", "typ": "JWT"}
    payload = payload or {"sub": "user1", "exp": int(time.time()) + 3600}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}."

    if signature_override is not None:
        return f"{signing_input}{signature_override}"

    alg = header.get("alg", "")
    if alg in {"HS256", "HS384", "HS512"} and secret is not None:
        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        sig = hmac.new(secret, signing_input.encode("ascii"), hash_map[alg]).digest()
        sig_b64 = _b64url_encode(sig)
    else:
        # alg=none or no secret provided: empty signature
        sig_b64 = ""

    return f"{signing_input}{sig_b64}"


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestB64UrlDecode:
    def test_decodes_valid_base64url_without_padding(self) -> None:
        assert _b64url_decode("YWJj") == b"abc"  # "abc" base64 -> YWJj

    def test_handles_padding_implicitly(self) -> None:
        # "test" -> dGVzdA (no padding needed); "tests" -> dGVzdHM=
        assert _b64url_decode("dGVzdA") == b"test"
        assert _b64url_decode("dGVzdHM") == b"tests"

    def test_returns_empty_on_invalid_input(self) -> None:
        assert _b64url_decode("!!!not base64!!!") == b""


class TestDecodeJwt:
    def test_decodes_valid_token(self) -> None:
        token = make_jwt(
            header={"alg": "HS256", "typ": "JWT"},
            payload={"sub": "alice", "exp": 1234567890},
            secret=b"supersecret",
        )
        decoded = _decode_jwt(token)
        assert decoded is not None
        assert decoded.header["alg"] == "HS256"
        assert decoded.payload["sub"] == "alice"
        assert decoded.payload["exp"] == 1234567890

    def test_returns_none_for_two_segments(self) -> None:
        assert _decode_jwt("eyJhbGc.eyJzdWI") is None

    def test_returns_none_for_four_segments(self) -> None:
        assert _decode_jwt("a.b.c.d") is None

    def test_returns_none_when_header_is_not_json(self) -> None:
        # "notjson{}" base64url
        bad_header = _b64url_encode(b"not-json")
        bad_payload = _b64url_encode(b'{"sub":"x"}')
        assert _decode_jwt(f"{bad_header}.{bad_payload}.") is None

    def test_returns_none_when_header_is_not_object(self) -> None:
        bad_header = _b64url_encode(b'"string-header"')
        bad_payload = _b64url_encode(b'{"sub":"x"}')
        assert _decode_jwt(f"{bad_header}.{bad_payload}.") is None

    def test_returns_none_when_payload_is_not_object(self) -> None:
        good_header = _b64url_encode(b'{"alg":"HS256"}')
        bad_payload = _b64url_encode(b'["array","not","object"]')
        assert _decode_jwt(f"{good_header}.{bad_payload}.") is None


class TestExtractJwtCookies:
    def test_extracts_from_named_jwt_cookie(self) -> None:
        token = make_jwt(secret=b"k")
        cookies = [f"token={token}; Path=/; HttpOnly"]
        out = _extract_jwt_cookies(cookies)
        assert out == [("token", token)]

    def test_extracts_from_universal_cookie_name(self) -> None:
        token = make_jwt(secret=b"k")
        cookies = [f"access_token={token}; Secure"]
        out = _extract_jwt_cookies(cookies)
        assert out == [("access_token", token)]

    def test_extracts_jwt_shaped_value_even_with_unknown_cookie_name(self) -> None:
        token = make_jwt(secret=b"k")
        cookies = [f"custom_cookie={token}"]
        out = _extract_jwt_cookies(cookies)
        assert out == [("custom_cookie", token)]

    def test_strips_surrounding_quotes(self) -> None:
        token = make_jwt(secret=b"k")
        cookies = [f'token="{token}"; HttpOnly']
        out = _extract_jwt_cookies(cookies)
        assert out == [("token", token)]

    def test_skips_non_jwt_non_named_cookie(self) -> None:
        cookies = ["pref=dark-theme; Path=/"]
        assert _extract_jwt_cookies(cookies) == []

    def test_skips_cookie_with_no_value(self) -> None:
        cookies = ["token=; Path=/"]
        assert _extract_jwt_cookies(cookies) == []

    def test_skips_malformed_set_cookie_line(self) -> None:
        # No "=" in the first part
        assert _extract_jwt_cookies(["no_equals_sign_here; Path=/"]) == []


class TestExtractJwtFromHeader:
    def test_extracts_bearer_token(self) -> None:
        token = make_jwt(secret=b"k")
        assert _extract_jwt_from_header(f"Bearer {token}") == token

    def test_extracts_lowercase_bearer(self) -> None:
        token = make_jwt(secret=b"k")
        assert _extract_jwt_from_header(f"bearer {token}") == token

    def test_extracts_raw_jwt_without_scheme(self) -> None:
        token = make_jwt(secret=b"k")
        assert _extract_jwt_from_header(token) == token

    def test_returns_none_for_empty_header(self) -> None:
        assert _extract_jwt_from_header("") is None

    def test_returns_none_for_non_jwt_bearer(self) -> None:
        assert _extract_jwt_from_header("Bearer abc.notjwt") is None


class TestExtractJwtFromQuery:
    def test_extracts_token_param(self) -> None:
        token = make_jwt(secret=b"k")
        url = f"https://example.com/callback?token={token}"
        assert _extract_jwt_from_query(url) == [token]

    def test_handles_multiple_params(self) -> None:
        token = make_jwt(secret=b"k")
        url = f"https://example.com/cb?state=xyz&token={token}&code=abc"
        assert _extract_jwt_from_query(url) == [token]

    def test_returns_empty_for_no_query(self) -> None:
        assert _extract_jwt_from_query("https://example.com/path") == []

    def test_returns_empty_for_no_jwt(self) -> None:
        assert _extract_jwt_from_query("https://example.com/?foo=bar") == []

    def test_skips_params_without_equals(self) -> None:
        # Should not raise on malformed query strings.
        assert _extract_jwt_from_query("https://example.com/?bare") == []


class TestHmacVerify:
    def test_verifies_correct_signature(self) -> None:
        token = make_jwt(secret=b"mysecret")
        decoded = _decode_jwt(token)
        assert decoded is not None
        assert _hmac_verify(decoded, b"mysecret") is True

    def test_rejects_wrong_secret(self) -> None:
        token = make_jwt(secret=b"mysecret")
        decoded = _decode_jwt(token)
        assert decoded is not None
        assert _hmac_verify(decoded, b"wrong") is False

    def test_rejects_non_hmac_alg(self) -> None:
        token = make_jwt(header={"alg": "RS256"}, secret=b"mysecret")
        decoded = _decode_jwt(token)
        assert decoded is not None
        assert _hmac_verify(decoded, b"mysecret") is False

    def test_rejects_empty_signature(self) -> None:
        token = make_jwt(header={"alg": "HS256"}, signature_override="")
        decoded = _decode_jwt(token)
        assert decoded is not None
        assert _hmac_verify(decoded, b"any") is False


class TestFindWeakHmacSecret:
    def test_finds_common_secret(self) -> None:
        token = make_jwt(secret=b"secret")
        decoded = _decode_jwt(token)
        assert decoded is not None
        found = _find_weak_hmac_secret(decoded)
        assert found == b"secret"

    def test_returns_none_for_strong_secret(self) -> None:
        strong = b"x" * 64  # 64-byte random-ish secret
        token = make_jwt(secret=strong)
        decoded = _decode_jwt(token)
        assert decoded is not None
        assert _find_weak_hmac_secret(decoded) is None

    def test_returns_none_for_non_hmac(self) -> None:
        token = make_jwt(header={"alg": "RS256"})
        decoded = _decode_jwt(token)
        assert decoded is not None
        assert _find_weak_hmac_secret(decoded) is None


class TestSafeInt:
    def test_int_passthrough(self) -> None:
        assert _safe_int(123) == 123

    def test_float_truncates(self) -> None:
        assert _safe_int(123.7) == 123

    def test_numeric_string(self) -> None:
        assert _safe_int("123") == 123

    def test_bool_returns_none(self) -> None:
        # bool is a subclass of int but isn't a valid timestamp.
        assert _safe_int(True) is None
        assert _safe_int(False) is None

    def test_non_numeric_string(self) -> None:
        assert _safe_int("abc") is None

    def test_none(self) -> None:
        assert _safe_int(None) is None


class TestFindSensitiveClaims:
    def test_detects_password_claim(self) -> None:
        hits = _find_sensitive_claims({"sub": "x", "password": "hunter2"})
        keys = [h[0] for h in hits]
        assert "password" in keys

    def test_detects_api_key_claim(self) -> None:
        hits = _find_sensitive_claims({"api_key": "sk-..."})
        assert hits and hits[0][0] == "api_key"

    def test_detects_credit_card_number_in_value(self) -> None:
        hits = _find_sensitive_claims({"note": "card 4111111111111111 on file"})
        assert hits

    def test_detects_ssn_pattern(self) -> None:
        hits = _find_sensitive_claims({"ssn": "123-45-6789"})
        assert hits

    def test_no_hits_for_clean_payload(self) -> None:
        assert _find_sensitive_claims({"sub": "alice", "role": "admin"}) == []

    def test_no_hits_for_non_string_value(self) -> None:
        # Numbers/bools shouldn't crash the value-side regex.
        assert _find_sensitive_claims({"count": 42, "active": True}) == []


# ─── Plugin end-to-end tests ─────────────────────────────────────────────────


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


class TestPluginRun:
    async def test_no_jwt_no_findings(self) -> None:
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body="<html>no tokens here</html>")
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_clean_short_lived_jwt_no_findings(self) -> None:
        """A well-formed HS256 token with a strong secret and short expiry → no findings."""
        token = make_jwt(
            payload={
                "sub": "user",
                "iat": int(time.time()),
                "nbf": int(time.time()),
                "exp": int(time.time()) + 3600,  # 1h
            },
            secret=b"aGz8vN3Kq7pR2sT9wXyZ" * 4,  # 80-byte strong secret
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=f'<script>window.jwt="{token}"</script>')
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        titles = [f.title for f in findings]
        # Should not raise any CRITICAL/HIGH findings on a clean token.
        assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings), titles

    async def test_alg_none_is_critical(self) -> None:
        token = make_jwt(header={"alg": "none"}, payload={"sub": "x"})
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="alg=none")
        assert len(crit) == 1
        assert crit[0].severity is Severity.CRITICAL
        assert crit[0].confidence is Confidence.FIRM

    async def test_weak_hmac_secret_is_critical(self) -> None:
        now = int(time.time())
        token = make_jwt(
            header={"alg": "HS256"},
            payload={"sub": "x", "exp": now + 3600, "iat": now, "nbf": now},
            secret=b"secret",
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        weak = _findings_with(findings, title_contains="trivially-guessable")
        assert len(weak) == 1
        assert weak[0].severity is Severity.CRITICAL
        assert weak[0].evidence["weak_secret_preview"].startswith("secret"[:8][:2])

    async def test_missing_exp_is_high(self) -> None:
        token = make_jwt(
            payload={"sub": "x", "iat": int(time.time()), "nbf": int(time.time())},
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        missing_exp = _findings_with(findings, title_contains="no expiry")
        assert len(missing_exp) == 1
        assert missing_exp[0].severity is Severity.HIGH

    async def test_expired_jwt_is_medium(self) -> None:
        token = make_jwt(
            payload={
                "sub": "x",
                "iat": int(time.time()) - 7200,
                "nbf": int(time.time()) - 7200,
                "exp": int(time.time()) - 3600,  # expired 1h ago
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        expired = _findings_with(findings, title_contains="already expired")
        assert len(expired) == 1
        assert expired[0].severity is Severity.MEDIUM
        assert expired[0].confidence is Confidence.INFORMATIONAL

    async def test_expiring_soon_is_low(self) -> None:
        token = make_jwt(
            payload={
                "sub": "x",
                "iat": int(time.time()),
                "nbf": int(time.time()),
                "exp": int(time.time()) + 3600,  # 1 hour, < 7 days
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        soon = _findings_with(findings, title_contains="expires soon")
        assert len(soon) == 1
        assert soon[0].severity is Severity.LOW

    async def test_invalid_exp_type_is_medium(self) -> None:
        token = make_jwt(
            payload={
                "sub": "x",
                "iat": int(time.time()),
                "nbf": int(time.time()),
                "exp": "not-a-number",
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        bad_exp = _findings_with(findings, title_contains="not a valid timestamp")
        assert len(bad_exp) == 1
        assert bad_exp[0].severity is Severity.MEDIUM

    async def test_missing_nbf_and_iat_are_info(self) -> None:
        token = make_jwt(
            payload={"sub": "x", "exp": int(time.time()) + 3600},
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        nbf = _findings_with(findings, title_contains="no not-before")
        iat = _findings_with(findings, title_contains="no issued-at")
        assert len(nbf) == 1 and nbf[0].severity is Severity.INFO
        assert len(iat) == 1 and iat[0].severity is Severity.INFO

    async def test_sensitive_claim_password_is_high(self) -> None:
        token = make_jwt(
            payload={
                "sub": "x",
                "password": "hunter2",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "nbf": int(time.time()),
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        sens = _findings_with(findings, title_contains="sensitive claim")
        assert len(sens) == 1
        assert sens[0].severity is Severity.HIGH
        assert "password" in sens[0].title

    async def test_kid_sql_injection_is_high(self) -> None:
        token = make_jwt(
            header={"alg": "HS256", "kid": "x' OR '1'='1"},
            payload={
                "sub": "x",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "nbf": int(time.time()),
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        kid = _findings_with(findings, title_contains="kid header")
        assert len(kid) == 1
        assert kid[0].severity is Severity.HIGH
        assert "SQL-injection" in kid[0].title

    async def test_kid_path_traversal_is_high(self) -> None:
        token = make_jwt(
            header={"alg": "HS256", "kid": "../../dev/null"},
            payload={
                "sub": "x",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "nbf": int(time.time()),
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        kid = _findings_with(findings, title_contains="kid header")
        assert len(kid) == 1
        assert "path-traversal" in kid[0].title

    async def test_kid_template_injection_is_high(self) -> None:
        token = make_jwt(
            header={"alg": "HS256", "kid": "{{7*7}}"},
            payload={
                "sub": "x",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "nbf": int(time.time()),
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        kid = _findings_with(findings, title_contains="kid header")
        assert len(kid) == 1
        assert "template-injection" in kid[0].title

    async def test_jku_external_url_is_high(self) -> None:
        token = make_jwt(
            header={"alg": "HS256", "jku": "https://attacker.example/keys.json"},
            payload={
                "sub": "x",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "nbf": int(time.time()),
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        jku = _findings_with(findings, title_contains="jku")
        assert len(jku) == 1
        assert jku[0].severity is Severity.HIGH
        assert jku[0].confidence is Confidence.TENTATIVE
        assert jku[0].evidence["jku"] == "https://attacker.example/keys.json"

    async def test_x5u_external_url_is_high(self) -> None:
        token = make_jwt(
            header={"alg": "HS256", "x5u": "https://attacker.example/cert.pem"},
            payload={
                "sub": "x",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "nbf": int(time.time()),
            },
            secret=b"x" * 64,
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        x5u = _findings_with(findings, title_contains="x5u")
        assert len(x5u) == 1 and x5u[0].severity is Severity.HIGH

    async def test_rs256_without_kid_is_medium_tentative(self) -> None:
        # Build an RS256 token with no kid (signature is fake — we don't verify it)
        token = make_jwt(
            header={"alg": "RS256", "typ": "JWT"},
            payload={
                "sub": "x",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
                "nbf": int(time.time()),
            },
            signature_override="fakeRS256signature",
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        asym = _findings_with(findings, title_contains="Asymmetric JWT")
        assert len(asym) == 1
        assert asym[0].severity is Severity.MEDIUM
        assert asym[0].confidence is Confidence.TENTATIVE

    async def test_jwt_in_set_cookie_is_detected(self) -> None:
        token = make_jwt(
            header={"alg": "none"},
            payload={"sub": "x", "exp": int(time.time()) + 3600},
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(
            headers=[("Set-Cookie", f"access_token={token}; Path=/; HttpOnly")],
            body="",
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="alg=none")
        assert len(crit) == 1
        assert crit[0].evidence["source"] == "Set-Cookie: access_token"

    async def test_jwt_in_authorization_header_is_detected(self) -> None:
        token = make_jwt(
            header={"alg": "none"},
            payload={"sub": "x", "exp": int(time.time()) + 3600},
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(
            headers=[("Authorization", f"Bearer {token}")],
            body="",
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="alg=none")
        assert len(crit) == 1
        assert crit[0].evidence["source"] == "Authorization header"

    async def test_jwt_in_custom_header_is_detected(self) -> None:
        token = make_jwt(
            header={"alg": "none"},
            payload={"sub": "x", "exp": int(time.time()) + 3600},
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(
            headers=[("X-Auth-Token", token)],
            body="",
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="alg=none")
        assert len(crit) == 1
        assert crit[0].evidence["source"] == "X-Auth-Token header"

    async def test_jwt_in_query_string_is_detected(self) -> None:
        token = make_jwt(
            header={"alg": "none"},
            payload={"sub": "x", "exp": int(time.time()) + 3600},
        )
        plugin = JwtAuditPlugin()
        # FakeSession ignores the URL, but the plugin reads it from `target`.
        resp = FakeResponse(body="")
        findings = await plugin.run(
            f"{_TARGET}/callback?token={token}",
            FakeSession(resp),  # type: ignore[arg-type]
        )
        crit = _findings_with(findings, title_contains="alg=none")
        assert len(crit) == 1
        assert crit[0].evidence["source"] == "URL query string"

    async def test_same_jwt_in_two_places_audited_once(self) -> None:
        token = make_jwt(
            header={"alg": "none"},
            payload={"sub": "x", "exp": int(time.time()) + 3600},
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(
            headers=[
                ("Set-Cookie", f"token={token}; Path=/"),
                ("Authorization", f"Bearer {token}"),
            ],
            body=f'<script>var t = "{token}"</script>',
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="alg=none")
        # Only ONE alg=none finding — the token was deduped.
        assert len(crit) == 1

    async def test_malformed_jwt_is_info(self) -> None:
        # JWT-shaped (3 segments starting with eyJ) but the payload isn't valid JSON.
        # Real header is valid base64url JSON; payload is "not-json".
        good_header = _b64url_encode(b'{"alg":"HS256"}')
        bad_payload = _b64url_encode(b"not-json-but-long-enough")
        token = f"{good_header}.{bad_payload}.sig"
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        malformed = _findings_with(findings, title_contains="Malformed")
        assert len(malformed) == 1
        assert malformed[0].severity is Severity.INFO

    async def test_network_error_returns_empty(self) -> None:
        """If session.get raises, the plugin must return [] (never propagate)."""

        class _BoomSession:
            def get(self, url: str, **_kw: object) -> _BoomResponse:
                return _BoomResponse()

        class _BoomResponse:
            async def __aenter__(self) -> _BoomResponse:
                raise _ClientError("boom")

            async def __aexit__(self, *_exc: object) -> bool:
                return False

        class _ClientError(Exception):
            pass

        # Patch the plugin's view of aiohttp.ClientError by injecting it into
        # the plugin module's namespace via the exception class the run() method
        # catches. We monkey-patch aiohttp.ClientError for this test.
        import aiohttp

        original = aiohttp.ClientError
        try:
            aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
            plugin = JwtAuditPlugin()
            findings = await plugin.run(_TARGET, _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = original  # type: ignore[misc,assignment]


# ─── Edge cases / regression ──────────────────────────────────────────────────


class TestEdgeCases:
    async def test_multiple_distinct_jwts_both_audited(self) -> None:
        token_a = make_jwt(header={"alg": "none"}, payload={"sub": "a"})
        token_b = make_jwt(header={"alg": "none"}, payload={"sub": "b"})
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=f"{token_a} and {token_b}")
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="alg=none")
        assert len(crit) == 2

    async def test_finding_evidence_includes_alg_and_source(self) -> None:
        token = make_jwt(
            header={"alg": "none"},
            payload={"sub": "x", "exp": int(time.time()) + 3600},
        )
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=token)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="alg=none")[0]
        assert crit.evidence["alg"] == "none"
        assert crit.evidence["source"] == "response body"
        assert "preview" in crit.evidence
        assert "header" in crit.evidence

    async def test_decoded_jwt_dataclass_is_frozen(self) -> None:
        """_DecodedJWT is a frozen dataclass — confirms immutability contract."""
        token = make_jwt(secret=b"secret")
        decoded = _decode_jwt(token)
        assert decoded is not None
        with pytest.raises((AttributeError, Exception)):
            decoded.raw = "tampered"  # type: ignore[misc]

    async def test_long_body_is_truncated_without_crash(self) -> None:
        """A 10 MiB body of mostly-garbage shouldn't crash or take forever."""
        token = make_jwt(
            header={"alg": "none"},
            payload={"sub": "x", "exp": int(time.time()) + 3600},
        )
        # 10 MiB of filler + one real token at the end
        body = "x" * (10 * 1024 * 1024) + token
        plugin = JwtAuditPlugin()
        resp = FakeResponse(body=body)
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        # Token sits within the first 5 MiB? No — it's at the end. Either way,
        # the plugin must not crash. If the token is past the truncation point,
        # we simply get no findings (acceptable; documented behaviour).
        assert isinstance(findings, list)

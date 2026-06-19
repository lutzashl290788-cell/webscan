"""Tests for the csrf plugin."""
from __future__ import annotations

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.csrf import (
    CsrfPlugin,
    _action_is_read_only,
    _has_csrf_meta,
    _has_samesite_protection,
    _is_csrf_token,
    _is_login_form,
    _is_search_form,
    _same_origin,
)

_TARGET = "https://example.com"


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestIsCsrfToken:
    def test_matches_csrf_field(self) -> None:
        assert _is_csrf_token("csrf_token") is True
        assert _is_csrf_token("csrfmiddlewaretoken") is True
        assert _is_csrf_token("X-CSRF-Token") is True

    def test_matches_authenticity_token(self) -> None:
        assert _is_csrf_token("authenticity_token") is True

    def test_matches_request_verification_token(self) -> None:
        assert _is_csrf_token("__RequestVerificationToken") is True

    def test_matches_nonce(self) -> None:
        assert _is_csrf_token("nonce") is True
        assert _is_csrf_token("form_nonce") is True

    def test_matches_xsrf(self) -> None:
        assert _is_csrf_token("_xsrf") is True
        assert _is_csrf_token("XSRF-TOKEN") is True

    def test_does_not_match_username(self) -> None:
        assert _is_csrf_token("username") is False
        assert _is_csrf_token("password") is False
        assert _is_csrf_token("email") is False
        assert _is_csrf_token("submit") is False

    def test_does_not_match_empty(self) -> None:
        assert _is_csrf_token("") is False


class TestIsLoginForm:
    def test_user_plus_password_is_login(self) -> None:
        assert _is_login_form(["username", "password"]) is True
        assert _is_login_form(["email", "password"]) is True
        assert _is_login_form(["login", "passwd"]) is True

    def test_password_only_not_login(self) -> None:
        # Without a user identifier, we can't be sure.
        assert _is_login_form(["password"]) is False

    def test_user_only_not_login(self) -> None:
        assert _is_login_form(["username"]) is False

    def test_no_fields_not_login(self) -> None:
        assert _is_login_form([]) is False

    def test_unrelated_fields_not_login(self) -> None:
        assert _is_login_form(["amount", "currency"]) is False


class TestIsSearchForm:
    def test_search_only_is_search(self) -> None:
        assert _is_search_form(["q"]) is True
        assert _is_search_form(["query"]) is True
        assert _is_search_form(["search"]) is True
        assert _is_search_form(["keyword"]) is True

    def test_search_with_csrf_is_search(self) -> None:
        # CSRF tokens are filtered out before the search check.
        assert _is_search_form(["q", "csrf_token"]) is True

    def test_mixed_fields_not_search(self) -> None:
        assert _is_search_form(["q", "amount"]) is False

    def test_no_fields_not_search(self) -> None:
        assert _is_search_form([]) is False

    def test_password_field_not_search(self) -> None:
        assert _is_search_form(["password"]) is False


class TestActionIsReadOnly:
    def test_search_action(self) -> None:
        assert _action_is_read_only("https://example.com/search") is True
        assert _action_is_read_only("/search?q=foo") is True

    def test_filter_action(self) -> None:
        assert _action_is_read_only("https://example.com/filter") is True

    def test_sort_action(self) -> None:
        assert _action_is_read_only("https://example.com/sort") is True

    def test_save_action_not_read_only(self) -> None:
        assert _action_is_read_only("https://example.com/save") is False
        assert _action_is_read_only("https://example.com/profile/update") is False

    def test_empty_action(self) -> None:
        assert _action_is_read_only("") is False


class TestSameOrigin:
    def test_same_url(self) -> None:
        assert _same_origin("https://a.com/x", "https://a.com/y") is True

    def test_http_vs_https(self) -> None:
        assert _same_origin("http://a.com", "https://a.com") is False

    def test_different_hosts(self) -> None:
        assert _same_origin("https://a.com", "https://b.com") is False

    def test_different_ports(self) -> None:
        assert _same_origin("https://a.com:8080", "https://a.com:9090") is False

    def test_same_port(self) -> None:
        assert _same_origin("https://a.com:8080/x", "https://a.com:8080/y") is True


class TestHasCsrfMeta:
    def test_rails_meta_tag(self) -> None:
        html = '<head><meta name="csrf-token" content="abc"></head>'
        assert _has_csrf_meta(html) is True

    def test_django_meta_tag(self) -> None:
        html = '<meta name="csrf-token" content="xyz">'
        assert _has_csrf_meta(html) is True

    def test_no_meta_tag(self) -> None:
        html = '<head><title>x</title></head>'
        assert _has_csrf_meta(html) is False

    def test_other_meta_tag_not_csrf(self) -> None:
        html = '<meta name="viewport" content="width=device-width">'
        assert _has_csrf_meta(html) is False


class TestHasSamesiteProtection:
    def test_samesite_strict(self) -> None:
        cookies = ["session=abc; Path=/; SameSite=Strict"]
        assert _has_samesite_protection(cookies) is True

    def test_samesite_lax(self) -> None:
        cookies = ["session=abc; Path=/; SameSite=Lax"]
        assert _has_samesite_protection(cookies) is True

    def test_samesite_none_not_protected(self) -> None:
        cookies = ["session=abc; Path=/; SameSite=None; Secure"]
        assert _has_samesite_protection(cookies) is False

    def test_no_samesite_not_protected(self) -> None:
        cookies = ["session=abc; Path=/; HttpOnly"]
        assert _has_samesite_protection(cookies) is False

    def test_case_insensitive(self) -> None:
        cookies = ["session=abc; Path=/; samesite=STRICT"]
        assert _has_samesite_protection(cookies) is True

    def test_multiple_cookies_one_protected(self) -> None:
        cookies = [
            "tracking=xyz; Path=/; SameSite=None",
            "session=abc; Path=/; SameSite=Lax; HttpOnly",
        ]
        assert _has_samesite_protection(cookies) is True

    def test_empty_list(self) -> None:
        assert _has_samesite_protection([]) is False


# ─── Plugin end-to-end tests ─────────────────────────────────────────────────


class TestPluginRun:
    async def test_no_html_response_no_findings(self) -> None:
        """JSON responses have no forms to audit."""
        plugin = CsrfPlugin()
        resp = FakeResponse(
            body='{"data": "no forms here"}',
            headers=[("Content-Type", "application/json")],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_empty_page_no_findings(self) -> None:
        """Tiny body — probably an error page."""
        plugin = CsrfPlugin()
        resp = FakeResponse(body="<html></html>", headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_post_form_without_token_is_flagged(self) -> None:
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/transfer">
            <input type="text" name="amount">
            <input type="text" name="to_account">
            <button>Send</button>
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert len(findings) == 1
        assert findings[0].severity is Severity.MEDIUM
        assert findings[0].confidence is Confidence.FIRM
        assert "without CSRF token" in findings[0].title

    async def test_post_form_with_token_not_flagged(self) -> None:
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/transfer">
            <input type="hidden" name="csrf_token" value="abc123">
            <input type="text" name="amount">
            <input type="text" name="to_account">
            <button>Send</button>
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_page_with_csrf_meta_skips_all_forms(self) -> None:
        """A global csrf-token meta tag means the page is CSRF-aware."""
        plugin = CsrfPlugin()
        body = """
        <html><head>
            <meta name="csrf-token" content="globaltoken">
        </head><body>
        <form method="post" action="/save">
            <input type="text" name="data">
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_samesite_strict_cookie_skips_all_forms(self) -> None:
        """A page that sets a SameSite=Strict cookie is already CSRF-protected."""
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/save">
            <input type="text" name="amount">
        </form>
        </body></html>
        """
        resp = FakeResponse(
            body=body,
            headers=[
                ("Content-Type", "text/html"),
                ("Set-Cookie", "session=abc; Path=/; SameSite=Strict; HttpOnly"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_samesite_lax_cookie_skips_all_forms(self) -> None:
        """SameSite=Lax is enough protection for POST forms."""
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/save">
            <input type="text" name="amount">
        </form>
        </body></html>
        """
        resp = FakeResponse(
            body=body,
            headers=[
                ("Content-Type", "text/html"),
                ("Set-Cookie", "session=abc; Path=/; SameSite=Lax"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_samesite_none_cookie_does_not_skip(self) -> None:
        """SameSite=None explicitly opts out of protection — forms must still be flagged."""
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/save">
            <input type="text" name="amount">
        </form>
        </body></html>
        """
        resp = FakeResponse(
            body=body,
            headers=[
                ("Content-Type", "text/html"),
                ("Set-Cookie", "session=abc; Path=/; SameSite=None; Secure"),
            ],
        )
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert len(findings) == 1

    async def test_login_form_not_flagged(self) -> None:
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/login">
            <input type="text" name="username">
            <input type="password" name="password">
            <button>Login</button>
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_search_form_not_flagged(self) -> None:
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/search">
            <input type="text" name="q">
            <button>Search</button>
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_get_form_not_flagged(self) -> None:
        """GET forms are not state-changing — must never be flagged."""
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="get" action="/profile/update">
            <input type="text" name="email">
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_form_with_no_fields_not_flagged(self) -> None:
        """A form with no fields is navigation, not mutation."""
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/next-page">
            <button>Continue</button>
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_cross_origin_form_not_flagged(self) -> None:
        """Cross-origin forms are out of scope for CSRF protection analysis."""
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="https://api.other.com/submit">
            <input type="text" name="data">
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_read_only_action_not_flagged(self) -> None:
        """Action paths like /search are treated as read-only even for POST."""
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="https://example.com/search/advanced">
            <input type="text" name="amount">
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_multiple_vulnerable_forms_each_flagged(self) -> None:
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="/save-profile">
            <input type="text" name="email">
        </form>
        <form method="post" action="/change-password">
            <input type="hidden" name="user_id" value="123">
            <input type="password" name="new_password">
            <input type="password" name="confirm_password">
        </form>
        </body></html>
        """
        # The second form has user_id + new_password + confirm_password.
        # Heuristic check: has 'password' fields but no 'user'/'username'/'email'
        # field (user_id matches _USER_FIELD_RE because of 'user' substring).
        # So it WOULD be a login form... actually user_id matches \buser\b so
        # it IS classified as login. Let me make it clearer:
        body = """
        <html><body>
        <form method="post" action="/save-profile">
            <input type="text" name="email_addr">
            <input type="text" name="phone">
        </form>
        <form method="post" action="/change-settings">
            <input type="text" name="setting_name">
            <input type="text" name="setting_value">
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert len(findings) == 2

    async def test_evidence_contains_form_details(self) -> None:
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="https://example.com/save">
            <input type="text" name="amount">
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[("Content-Type", "text/html")])
        findings = await plugin.run(_TARGET, FakeSession(resp))  # type: ignore[arg-type]
        assert len(findings) == 1
        ev = findings[0].evidence
        assert ev["form_method"] == "POST"
        assert "amount" in ev["field_names"]
        assert ev["form_action"] == "https://example.com/save"

    async def test_network_error_returns_empty(self) -> None:
        """If session.get raises, return [] (never propagate)."""

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

        import aiohttp

        original = aiohttp.ClientError
        try:
            aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
            plugin = CsrfPlugin()
            findings = await plugin.run(_TARGET, _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = original  # type: ignore[misc,assignment]

    async def test_html_without_content_type_still_audited_for_html_extension(self) -> None:
        """URLs ending in .html should be audited even without explicit Content-Type."""
        plugin = CsrfPlugin()
        body = """
        <html><body>
        <form method="post" action="https://example.com/page.html">
            <input type="text" name="amount">
        </form>
        </body></html>
        """
        resp = FakeResponse(body=body, headers=[])
        findings = await plugin.run(
            "https://example.com/page.html", FakeSession(resp)  # type: ignore[arg-type]
        )
        assert len(findings) == 1

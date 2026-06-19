"""Tests for the xxe plugin."""
from __future__ import annotations

from typing import Any

from tests._fakes import FakeResponse
from webscan.models import Confidence, Severity
from webscan.plugins.xxe import (
    XxePlugin,
    _find_xml_params,
    _looks_like_xml_endpoint,
)

_TARGET = "https://example.com"


# ─── Fake session that returns different responses for GET vs POST ───────────


class _GetPostSession:
    """Returns one response for GET, another for POST."""

    def __init__(self, get_resp: FakeResponse, post_resp: FakeResponse) -> None:
        self._get = get_resp
        self._post = post_resp
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("GET", url, kwargs))
        return self._get

    def post(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("POST", url, kwargs))
        return self._post


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestLooksLikeXmlEndpoint:
    def test_xml_content_type(self) -> None:
        assert _looks_like_xml_endpoint("application/xml", "anything") is True

    def test_application_soap_xml(self) -> None:
        assert _looks_like_xml_endpoint("application/soap+xml", "x") is True

    def test_text_xml(self) -> None:
        assert _looks_like_xml_endpoint("text/xml", "x") is True

    def test_body_starts_with_xml_declaration(self) -> None:
        assert _looks_like_xml_endpoint("text/html", "<?xml version='1.0'?><foo/>") is True

    def test_body_has_soap_envelope(self) -> None:
        body = '<soap:Envelope xmlns:soap="..."><soap:Body/></soap:Envelope>'
        assert _looks_like_xml_endpoint("text/html", body) is True

    def test_plain_html(self) -> None:
        assert _looks_like_xml_endpoint("text/html", "<html><body>hi</body></html>") is False

    def test_empty(self) -> None:
        assert _looks_like_xml_endpoint("", "") is False

    def test_json(self) -> None:
        assert _looks_like_xml_endpoint("application/json", '{"x":1}') is False


class TestFindXmlParams:
    def test_finds_xml_param(self) -> None:
        assert _find_xml_params("https://example.com/?xml=foo") == ["xml"]

    def test_finds_data_param(self) -> None:
        assert _find_xml_params("https://example.com/?data=foo") == ["data"]

    def test_finds_payload_param(self) -> None:
        assert _find_xml_params("https://example.com/?payload=foo") == ["payload"]

    def test_no_xml_params(self) -> None:
        assert _find_xml_params("https://example.com/?id=12&q=search") == []

    def test_no_query(self) -> None:
        assert _find_xml_params("https://example.com/path") == []

    def test_case_insensitive(self) -> None:
        assert _find_xml_params("https://example.com/?XML=foo") == ["XML"]

    def test_multiple_xml_params(self) -> None:
        out = _find_xml_params("https://example.com/?xml=a&data=b")
        assert "xml" in out
        assert "data" in out


# ─── Plugin end-to-end tests ─────────────────────────────────────────────────


class TestPluginRun:
    async def test_non_xml_endpoint_no_xml_params_skipped(self) -> None:
        """If GET returns HTML and URL has no XML params, the plugin does nothing."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body="<html>plain html</html>",
            headers=[("Content-Type", "text/html")],
        )
        post_resp = FakeResponse(body="should not be reached")
        session = _GetPostSession(get_resp, post_resp)
        findings = await plugin.run("https://example.com/?id=12", session)  # type: ignore[arg-type]
        assert findings == []

    async def test_get_network_error_returns_empty(self) -> None:
        plugin = XxePlugin()

        class _BoomSession:
            def get(self, url: str, **_kw: object) -> _BoomResp:
                return _BoomResp()

        class _BoomResp:
            async def __aenter__(self) -> _BoomResp:
                raise _ClientError("boom")

            async def __aexit__(self, *_exc: object) -> bool:
                return False

        class _ClientError(Exception):
            pass

        import aiohttp

        orig = aiohttp.ClientError
        try:
            aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
            findings = await plugin.run("https://example.com/?xml=x", _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_critical_xxe_leaking_etc_passwd(self) -> None:
        """External entity resolution + /etc/passwd markers → CRITICAL."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body='<?xml version="1.0"?><root>baseline</root>',
            headers=[("Content-Type", "application/xml")],
        )
        # POST 1 (internal entity) — returns the marker (entity resolved)
        # POST 2 (external entity) — returns /etc/passwd content
        # Since FakeSession returns one response for all POSTs, we can't
        # differentiate. But we control the response body — include BOTH
        # the internal marker pattern AND the /etc/passwd markers in the
        # same body, so both checks pass with the same response.
        # We need to know what token will be generated — that's random.
        # Instead, make the post response contain a fixed string that includes
        # the prefix+suffix structure the plugin searches for. The plugin
        # generates `XXE_TEST_MARKER<token>_END` and searches for that exact
        # string in the response. We can't predict the token, so we need a
        # different approach.
        #
        # Solution: make the POST response contain the /etc/passwd markers
        # directly. The plugin will:
        # 1. Send internal-entity probe → check for marker (random)
        # 2. Marker not in response → skip external entity probe
        # That doesn't work either.
        #
        # The cleanest test: have POST return a body containing BOTH the
        # marker AND /etc/passwd content. But we don't know the token.
        #
        # Alternative: monkey-patch secrets.token_hex to return a fixed value.
        import secrets

        from webscan.plugins.xxe import _MARKER_PREFIX, _MARKER_SUFFIX
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "fixed123"  # type: ignore[assignment]
        try:
            fixed_marker = f"{_MARKER_PREFIX}fixed123{_MARKER_SUFFIX}"
            post_resp = FakeResponse(
                body=f"{fixed_marker}\nroot:x:0:0:root:/root:/bin/bash\n",
                headers=[("Content-Type", "application/xml")],
            )
            session = _GetPostSession(get_resp, post_resp)
            findings = await plugin.run("https://example.com/api", session)  # type: ignore[arg-type]

            critical = _findings_with(findings, title_contains="/etc/passwd leaked")
            assert len(critical) == 1
            assert critical[0].severity is Severity.CRITICAL
            assert critical[0].confidence is Confidence.FIRM
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]

    async def test_high_finding_internal_entity_only(self) -> None:
        """Internal entity resolves but external doesn't → HIGH."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body='<?xml version="1.0"?><root>baseline</root>',
            headers=[("Content-Type", "application/xml")],
        )
        # POST returns the marker (internal entity resolved) but no /etc/passwd
        import secrets
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "abc12345"  # type: ignore[assignment]
        try:
            from webscan.plugins.xxe import _MARKER_PREFIX, _MARKER_SUFFIX
            fixed_marker = f"{_MARKER_PREFIX}abc12345{_MARKER_SUFFIX}"
            post_resp = FakeResponse(
                body=f"<result>{fixed_marker}</result>",
                headers=[("Content-Type", "application/xml")],
            )
            session = _GetPostSession(get_resp, post_resp)
            findings = await plugin.run("https://example.com/api", session)  # type: ignore[arg-type]

            high = _findings_with(findings, title_contains="internal entities")
            assert len(high) == 1
            assert high[0].severity is Severity.HIGH
            assert high[0].confidence is Confidence.FIRM
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]

    async def test_info_finding_xml_accepted_but_no_entity_resolution(self) -> None:
        """Server accepts XML POST, returns 200, but doesn't echo entity."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body='<html>xml api</html>',
            headers=[("Content-Type", "text/html")],
        )
        # POST returns a different body, status 200, no marker
        post_resp = FakeResponse(
            body='<result>some processed response</result>',
            status=200,
        )
        session = _GetPostSession(get_resp, post_resp)
        # Trigger via xml param so plugin enters the XML-probe branch
        findings = await plugin.run("https://example.com/?xml=foo", session)  # type: ignore[arg-type]

        info = _findings_with(findings, title_contains="XML endpoint accepts POST XML")
        assert len(info) == 1
        assert info[0].severity is Severity.INFO
        assert info[0].confidence is Confidence.INFORMATIONAL

    async def test_no_finding_when_post_identical_to_get(self) -> None:
        """If POST returns the same body as GET, the POST body was ignored — no XML parser."""
        plugin = XxePlugin()
        identical = FakeResponse(
            body="<result>same</result>",
            headers=[("Content-Type", "application/xml")],
        )
        session = _GetPostSession(identical, identical)
        findings = await plugin.run("https://example.com/api", session)  # type: ignore[arg-type]
        # No markers resolved, no different response — no findings.
        assert findings == []

    async def test_no_finding_when_post_404(self) -> None:
        """If POST returns 4xx, the endpoint doesn't process XML — no finding."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body='<?xml version="1.0"?><root>baseline</root>',
            headers=[("Content-Type", "application/xml")],
        )
        post_resp = FakeResponse(body="Not Found", status=404)
        session = _GetPostSession(get_resp, post_resp)
        findings = await plugin.run("https://example.com/api", session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_post_too_short(self) -> None:
        """Very short POST responses don't carry markers — no INFO finding."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body='<html>xml</html>',
            headers=[("Content-Type", "text/html")],
        )
        post_resp = FakeResponse(body="ok", status=200)
        session = _GetPostSession(get_resp, post_resp)
        findings = await plugin.run("https://example.com/?xml=x", session)  # type: ignore[arg-type]
        assert findings == []

    async def test_xml_param_triggers_probes_even_without_xml_content_type(self) -> None:
        """URL param `?xml=...` triggers probe even if GET returns HTML."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body='<html>plain html page</html>',
            headers=[("Content-Type", "text/html")],
        )
        post_resp = FakeResponse(body="<result>ok</result>", status=200)
        session = _GetPostSession(get_resp, post_resp)
        findings = await plugin.run("https://example.com/?xml=foo", session)  # type: ignore[arg-type]
        # INFO finding expected (POST returns different body, status 200)
        info = _findings_with(findings, title_contains="XML endpoint accepts POST XML")
        assert len(info) == 1

    async def test_post_network_error_returns_empty(self) -> None:
        """If POST raises, no findings."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body='<?xml version="1.0"?><root>baseline</root>',
            headers=[("Content-Type", "application/xml")],
        )

        class _BoomPostSession:
            def get(self, url: str, **_kw: object) -> FakeResponse:
                return get_resp

            def post(self, url: str, **_kw: object) -> _BoomResp:
                return _BoomResp()

        class _BoomResp:
            async def __aenter__(self) -> _BoomResp:
                raise _ClientError("boom")

            async def __aexit__(self, *_exc: object) -> bool:
                return False

        class _ClientError(Exception):
            pass

        import aiohttp

        orig = aiohttp.ClientError
        try:
            aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
            findings = await plugin.run("https://example.com/api", _BoomPostSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_evidence_contains_probe_details(self) -> None:
        """CRITICAL finding evidence records probe details."""
        plugin = XxePlugin()
        get_resp = FakeResponse(
            body='<?xml version="1.0"?><root>baseline</root>',
            headers=[("Content-Type", "application/xml")],
        )
        import secrets
        original_token_hex = secrets.token_hex
        secrets.token_hex = lambda n: "deadbeef"  # type: ignore[assignment]
        try:
            from webscan.plugins.xxe import _MARKER_PREFIX, _MARKER_SUFFIX
            fixed_marker = f"{_MARKER_PREFIX}deadbeef{_MARKER_SUFFIX}"
            post_resp = FakeResponse(
                body=f"{fixed_marker}\nroot:x:0:0:root:/root:/bin/bash\n",
                headers=[("Content-Type", "application/xml")],
            )
            session = _GetPostSession(get_resp, post_resp)
            findings = await plugin.run("https://example.com/api", session)  # type: ignore[arg-type]
            crit = _findings_with(findings, title_contains="/etc/passwd leaked")[0]
            ev = crit.evidence
            assert ev["probe_method"] == "POST"
            assert ev["probe_content_type"] == "application/xml"
            assert ev["internal_entity_resolved"] is True
            assert ev["external_entity_resolved"] is True
            assert "matched_markers" in ev
            assert "http_status" in ev
        finally:
            secrets.token_hex = original_token_hex  # type: ignore[assignment]


# ─── Edge cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    async def test_baseline_with_xml_declaration_in_body(self) -> None:
        """Even without Content-Type: application/xml, an XML body triggers probes."""
        plugin = XxePlugin()
        get_resp = FakeResponse(body="<?xml version='1.0'?><root>x</root>")
        post_resp = FakeResponse(body="ok", status=200)
        session = _GetPostSession(get_resp, post_resp)
        findings = await plugin.run("https://example.com/api", session)  # type: ignore[arg-type]
        # The POST returns 'ok' (3 chars, < _MIN_RESPONSE_LENGTH=16), so no INFO finding.
        assert findings == []

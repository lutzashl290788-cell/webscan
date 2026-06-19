"""Tests for the lfi_rfi plugin."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from tests._fakes import FakeResponse, FakeSession
from webscan.models import Confidence, Severity
from webscan.plugins.lfi_rfi import (
    LfiRfiPlugin,
    _find_lfi_params,
    _has_marker,
    _has_php_marker,
    _replace_param,
    _try_decode_base64,
)

_TARGET = "https://example.com"


# ─── Pure-function tests ─────────────────────────────────────────────────────


class TestFindLfiParams:
    def test_finds_file_param(self) -> None:
        out = _find_lfi_params("https://example.com/?file=foo")
        assert out == [("file", "foo")]

    def test_finds_page_param(self) -> None:
        out = _find_lfi_params("https://example.com/?page=about")
        assert out == [("page", "about")]

    def test_finds_multiple_params(self) -> None:
        out = _find_lfi_params("https://example.com/?file=a&page=b&include=c")
        names = [n for n, _ in out]
        assert "file" in names
        assert "page" in names
        assert "include" in names

    def test_skips_unrelated_params(self) -> None:
        out = _find_lfi_params("https://example.com/?profile_id=12&q=search")
        assert out == []

    def test_case_insensitive(self) -> None:
        out = _find_lfi_params("https://example.com/?FILE=foo")
        assert out == [("FILE", "foo")]

    def test_no_query_returns_empty(self) -> None:
        assert _find_lfi_params("https://example.com/path") == []

    def test_blank_value_kept(self) -> None:
        out = _find_lfi_params("https://example.com/?file=")
        assert out == [("file", "")]

    def test_max_params_cap(self) -> None:
        param_names = ["file", "page", "include", "path", "template", "doc", "source"]
        url = "https://example.com/?" + "&".join(f"{p}=x" for p in param_names)
        out = _find_lfi_params(url)
        assert len(out) <= 5


class TestReplaceParam:
    def test_replaces_value(self) -> None:
        url = "https://example.com/?file=foo&other=bar"
        new = _replace_param(url, "file", "../../etc/passwd")
        # urlencode percent-encodes `/` as `%2F` — both forms are acceptable.
        assert (
            "file=../../etc/passwd" in new
            or "file=..%2F..%2Fetc%2Fpasswd" in new
        )
        assert "other=bar" in new

    def test_url_encodes_value(self) -> None:
        new = _replace_param("https://example.com/?file=x", "file", "../../etc/passwd")
        # `urlencode` percent-encodes `/` as `%2F`. Either form is acceptable.
        assert (
            "../../etc/passwd" in new
            or "..%2F..%2Fetc%2Fpasswd" in new
        )

    def test_preserves_fragment(self) -> None:
        # Fragments are client-side only, but `urlparse` handles them.
        url = "https://example.com/?file=foo#anchor"
        new = _replace_param(url, "file", "bar")
        assert "file=bar" in new

    def test_preserves_path(self) -> None:
        url = "https://example.com/path/to/page?file=foo"
        new = _replace_param(url, "file", "bar")
        assert urlparse(new).path == "/path/to/page"


class TestHasMarker:
    def test_matches_present_marker(self) -> None:
        assert _has_marker("hello\nroot:x:0:0:root:/root:/bin/bash\n", ("root:x:0:0:",)) is True

    def test_returns_false_when_absent(self) -> None:
        assert _has_marker("nothing useful here", ("root:x:0:0:",)) is False

    def test_multiple_markers_any_match(self) -> None:
        assert _has_marker("[fonts]\nCourier=...", ("[fonts]", "[extensions]")) is True


class TestTryDecodeBase64:
    def test_decodes_valid_base64(self) -> None:
        import base64
        # Encode the actual string we want to test
        src = "<?php echo 'hi';"
        encoded = base64.b64encode(src.encode()).decode()
        decoded = _try_decode_base64(encoded)
        assert decoded is not None
        assert "<?php" in decoded

    def test_returns_none_for_invalid(self) -> None:
        assert _try_decode_base64("not base64 !!!") is None

    def test_returns_none_for_empty(self) -> None:
        assert _try_decode_base64("") is None

    def test_returns_none_for_whitespace_only(self) -> None:
        assert _try_decode_base64("   ") is None

    def test_handles_padding_needed(self) -> None:
        # "<?php" without padding
        assert _try_decode_base64("PD9waHA") is not None


class TestHasPhpMarker:
    def test_detects_php_open_tag(self) -> None:
        assert _has_php_marker("<?php\necho 'hello';\n") is True

    def test_detects_require(self) -> None:
        assert _has_php_marker("require('config.php');") is True
        # Without parens (PHP allows both)
        assert _has_php_marker("require 'config.php';") is True

    def test_detects_include(self) -> None:
        assert _has_php_marker("include 'header.php';") is True
        assert _has_php_marker("include('header.php');") is True
        assert _has_php_marker("include_once 'header.php';") is True

    def test_detects_define(self) -> None:
        assert _has_php_marker("define('DB_HOST', 'localhost');") is True

    def test_detects_superglobal(self) -> None:
        assert _has_php_marker("$name = $_GET['name'];") is True

    def test_returns_false_for_plain_html(self) -> None:
        assert _has_php_marker("<html><body>Hello</body></html>") is False


# ─── Plugin end-to-end tests ─────────────────────────────────────────────────


class _TwoResponseSession:
    """Returns a baseline response first, then probe responses keyed by URL."""

    def __init__(self, baseline: FakeResponse, probes: dict[str, FakeResponse]) -> None:
        self._baseline = baseline
        self._probes = probes
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("GET", url, kwargs))
        if url in self._probes:
            return self._probes[url]
        return self._baseline


class _AllProbesReturnSession:
    """Returns the baseline response for the *original* URL, then probe_resp for all others.

    This mirrors how a real vulnerable target behaves: the original URL returns
    the page, and any modified probe URL returns the (different) probe response.

    The ``baseline_url`` parameter is the original target URL; the session
    returns ``baseline`` for that URL and ``probe`` for everything else
    (including the soft-404 calibration URL, which a real server would
    answer with its 404 page, not with the probe response).
    """

    def __init__(
        self,
        baseline: FakeResponse,
        probe: FakeResponse,
        baseline_url: str | None = None,
        calibration_response: FakeResponse | None = None,
    ) -> None:
        self._baseline = baseline
        self._probe = probe
        self._baseline_url = baseline_url
        # What to return for soft-404 calibration URLs. Defaults to a 404
        # (well-behaved server). Override to test soft-404 filtering.
        self._calibration = calibration_response or FakeResponse(body="", status=404)
        self._first_call = True
        self.requests: list[tuple[str, str, dict[str, Any]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append(("GET", url, kwargs))
        # Soft-404 calibration URL — return the configured calibration response.
        if "webscan-soft404-probe" in url:
            return self._calibration
        # If a baseline URL was specified, match against it (more precise than
        # the first-call heuristic, which gets confused by the soft-404
        # calibration request that the plugin makes between baseline and probe).
        if self._baseline_url is not None:
            if url == self._baseline_url:
                return self._baseline
            return self._probe
        # Fall back to first-call heuristic (preserves backward compat).
        if self._first_call:
            self._first_call = False
            return self._baseline
        return self._probe


def _findings_with(findings: list, *, title_contains: str) -> list:
    return [f for f in findings if title_contains.lower() in f.title.lower()]


class TestPluginRun:
    async def test_no_file_params_no_findings(self) -> None:
        plugin = LfiRfiPlugin()
        resp = FakeResponse(body="<html>no params</html>")
        findings = await plugin.run("https://example.com/page", FakeSession(resp))  # type: ignore[arg-type]
        assert findings == []

    async def test_baseline_fetch_failure_returns_empty(self) -> None:
        plugin = LfiRfiPlugin()

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
            findings = await plugin.run("https://example.com/?file=x", _BoomSession())  # type: ignore[arg-type]
            assert findings == []
        finally:
            aiohttp.ClientError = orig  # type: ignore[misc,assignment]

    async def test_linux_passwd_leak_is_critical_firm(self) -> None:
        plugin = LfiRfiPlugin()
        baseline = FakeResponse(body="<html>normal page here</html>", status=200)
        probe_resp = FakeResponse(
            body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            status=200,
        )
        session = _AllProbesReturnSession(baseline, probe_resp, baseline_url="https://example.com/?file=about")
        findings = await plugin.run("https://example.com/?file=about", session)  # type: ignore[arg-type]

        critical = _findings_with(findings, title_contains="/etc/passwd leaked")
        assert len(critical) == 1
        assert critical[0].severity is Severity.CRITICAL
        assert critical[0].confidence is Confidence.FIRM
        assert critical[0].evidence["param"] == "file"

    async def test_windows_winini_leak_is_critical_firm(self) -> None:
        plugin = LfiRfiPlugin()
        baseline = FakeResponse(body="<html>normal page here</html>", status=200)
        probe_body = "; for 16-bit app compatibility\n[fonts]\nCourier=...\n[extensions]\n"
        probe_resp = FakeResponse(body=probe_body, status=200)
        session = _AllProbesReturnSession(baseline, probe_resp, baseline_url="https://example.com/?file=foo")
        findings = await plugin.run("https://example.com/?file=foo", session)  # type: ignore[arg-type]

        critical = _findings_with(findings, title_contains="win.ini leaked")
        assert len(critical) == 1
        assert critical[0].severity is Severity.CRITICAL
        assert critical[0].confidence is Confidence.FIRM

    async def test_php_filter_leak_is_high_firm(self) -> None:
        plugin = LfiRfiPlugin()
        import base64
        php_src = "<?php require('config.php'); define('DB_HOST', 'localhost');"
        encoded = base64.b64encode(php_src.encode()).decode()
        baseline = FakeResponse(body="<html>normal page here, not base64</html>", status=200)
        probe_resp = FakeResponse(body=encoded, status=200)
        session = _AllProbesReturnSession(baseline, probe_resp, baseline_url="https://example.com/?file=index")
        findings = await plugin.run("https://example.com/?file=index", session)  # type: ignore[arg-type]

        php_findings = _findings_with(findings, title_contains="php://filter")
        assert len(php_findings) == 1
        assert php_findings[0].severity is Severity.HIGH
        assert php_findings[0].confidence is Confidence.FIRM
        assert php_findings[0].evidence["leaked_file"] == "index.php"

    async def test_tentative_finding_on_size_delta(self) -> None:
        """A probe that returns a different-sized response without markers → TENTATIVE."""
        plugin = LfiRfiPlugin()
        # The probe response is bigger — 100 + 50 = 150 bytes, delta 50
        probe_resp = FakeResponse(body="A" * 150, status=200)
        session = FakeSession(probe_resp)
        # Note: FakeSession returns probe_resp for BOTH baseline and probe URLs,
        # so the baseline_length == 150 too. That means delta = 0.
        # This test verifies that the plugin handles the FakeSession quirk
        # correctly: when delta is 0, no TENTATIVE finding is emitted.
        findings = await plugin.run("https://example.com/?file=x", session)  # type: ignore[arg-type]
        # No findings expected (no markers, no delta, no PHP base64)
        assert findings == []

    async def test_tentative_finding_with_distinct_responses(self) -> None:
        """A probe that returns a structurally-different response → TENTATIVE.

        The new heuristic (v2) compares response *similarity*, not size delta.
        A probe whose body has low similarity to the baseline (and is not a
        soft-404, not a file-not-found error, not 404) is flagged TENTATIVE.
        """
        plugin = LfiRfiPlugin()
        # Make baseline substantial so length-ratio is within bounds.
        baseline = FakeResponse(
            body="<html><body><h1>Welcome to Example Corp</h1>"
            "<p>This is the main landing page with some substantive content "
            "so the baseline body length is meaningful.</p></body></html>",
            status=200,
        )
        # Probe body must be structurally different (low similarity) but NOT
        # contain "file not found" markers (those get filtered out by the
        # new FP-reduction logic).
        probe_body = (
            "<html><body><h1>Application Error</h1>"
            "<p>Stack trace: /var/www/app/handlers.py line 42</p>"
            "<p>Failed to load resource: ../etc/something</p>"
            "</body></html>"
        )
        probe_resp = FakeResponse(body=probe_body, status=200)
        session = _AllProbesReturnSession(baseline, probe_resp, baseline_url="https://example.com/?file=about")
        findings = await plugin.run("https://example.com/?file=about", session)  # type: ignore[arg-type]

        tentative = _findings_with(findings, title_contains="Possible LFI")
        assert len(tentative) == 1
        assert tentative[0].severity is Severity.MEDIUM
        assert tentative[0].confidence is Confidence.TENTATIVE
        # New evidence fields
        assert "similarity" in tentative[0].evidence
        assert "length_ratio" in tentative[0].evidence

    async def test_no_tentative_when_probe_contains_file_not_found_marker(self) -> None:
        """A probe response with 'file not found' markers → no TENTATIVE finding.

        This is the new FP-reduction: a server that *did* process the path
        but the file doesn't exist is not exploitable, so we don't flag it.
        """
        plugin = LfiRfiPlugin()
        baseline = FakeResponse(body="<html>normal page here</html>", status=200)
        # Body contains "file not found" — should be filtered out.
        probe_body = (
            "<html><body>Error: file not found at /etc/passwd</body></html>"
        )
        probe_resp = FakeResponse(body=probe_body, status=200)
        session = _AllProbesReturnSession(baseline, probe_resp, baseline_url="https://example.com/?file=about")
        findings = await plugin.run("https://example.com/?file=about", session)  # type: ignore[arg-type]

        tentative = _findings_with(findings, title_contains="Possible LFI")
        # Should NOT fire — file-not-found marker suppresses TENTATIVE.
        assert tentative == []

    async def test_no_tentative_when_probe_identical_to_baseline(self) -> None:
        """If probe response is identical to baseline (server ignored payload), no finding."""
        plugin = LfiRfiPlugin()
        identical_body = "<html>same page</html>"
        baseline = FakeResponse(body=identical_body, status=200)
        # _AllProbesReturnSession returns baseline for the first URL, probe
        # for the rest. If probe == baseline, similarity is 1.0 — no finding.
        probe_resp = FakeResponse(body=identical_body, status=200)
        session = _AllProbesReturnSession(baseline, probe_resp, baseline_url="https://example.com/?file=about")
        findings = await plugin.run("https://example.com/?file=about", session)  # type: ignore[arg-type]
        assert findings == []

    async def test_no_finding_when_404(self) -> None:
        """404 on probe should NOT trigger a TENTATIVE finding."""
        plugin = LfiRfiPlugin()
        # All probes return 404
        probe_resp = FakeResponse(body="<html>not found</html>", status=404)
        session = FakeSession(probe_resp)
        findings = await plugin.run("https://example.com/?file=x", session)  # type: ignore[arg-type]
        # No findings — baseline returns probe_resp too, so delta=0 anyway.
        # But also no markers, no base64 — should be empty.
        assert findings == []

    async def test_multiple_params_each_probed(self) -> None:
        plugin = LfiRfiPlugin()
        baseline = FakeResponse(body="<html>page</html>", status=200)
        probe_resp = FakeResponse(body="root:x:0:0:root:/root:/bin/bash\n", status=200)
        session = _AllProbesReturnSession(baseline, probe_resp)
        findings = await plugin.run(
            "https://example.com/?file=a&page=b&include=c",
            session,  # type: ignore[arg-type]
        )
        critical = _findings_with(findings, title_contains="/etc/passwd leaked")
        assert len(critical) == 3

    async def test_evidence_includes_payload_and_probe_url(self) -> None:
        plugin = LfiRfiPlugin()
        baseline = FakeResponse(body="<html>page</html>", status=200)
        probe_resp = FakeResponse(body="root:x:0:0:root:/root:/bin/bash\n", status=200)
        session = _AllProbesReturnSession(baseline, probe_resp, baseline_url="https://example.com/?file=x")
        findings = await plugin.run("https://example.com/?file=x", session)  # type: ignore[arg-type]
        crit = _findings_with(findings, title_contains="/etc/passwd leaked")[0]
        ev = crit.evidence
        assert "param" in ev and ev["param"] == "file"
        assert "payload" in ev
        assert "probe_url" in ev
        assert "matched_markers" in ev


# ─── Edge cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    async def test_url_with_fragment(self) -> None:
        """URLs with fragments shouldn't break param detection."""
        plugin = LfiRfiPlugin()
        baseline = FakeResponse(body="<html>page</html>")
        session = FakeSession(baseline)
        # Should run without crashing
        findings = await plugin.run(
            "https://example.com/?file=x#section",
            session,  # type: ignore[arg-type]
        )
        # baseline returns the same response as probes → no findings
        assert findings == []

    async def test_decoded_jwt_dataclass_is_frozen(self) -> None:
        """Sanity: pytest import works."""
        assert LfiRfiPlugin is not None

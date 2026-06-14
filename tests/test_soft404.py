"""Tests for soft-404 calibration and its effect on path-probing plugins."""
from __future__ import annotations

from webscan.plugins.config_files import ConfigFilesPlugin
from webscan.plugins.directories import DirectoriesPlugin
from webscan.plugins.soft404 import SoftBaseline, calibrate

_BASE = "https://example.com"

_SOFT_BODY = (
    b"<html><body><h1>Sorry, that page could not be found.</h1>"
    b"<p>Return to our homepage.</p></body></html>"
)


class _Content:
    def __init__(self, body: bytes) -> None:
        self._body = body

    async def read(self, n: int) -> bytes:
        return self._body[:n]


class _Resp:
    def __init__(self, status: int, body: bytes = b"") -> None:
        self.status = status
        self.content = _Content(body)
        self.headers: dict[str, str] = {}

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class _SoftSession:
    """Returns ``200`` + a soft-404 template for *every* path not explicitly
    overridden — i.e. a server that never honestly signals 404."""

    def __init__(
        self,
        *,
        soft_status: int = 200,
        soft_body: bytes = _SOFT_BODY,
        overrides: dict[str, tuple[int, bytes]] | None = None,
    ) -> None:
        self._soft = (soft_status, soft_body)
        self._overrides = overrides or {}

    def get(self, url: str, **_kw: object) -> _Resp:
        path = url[len(_BASE):]
        status, body = self._overrides.get(path, self._soft)
        return _Resp(status, body)


# ── SoftBaseline.matches ────────────────────────────────────────────────────


def test_baseline_matches_identical_body() -> None:
    base = SoftBaseline(status=200, body="not found page")
    assert base.matches(200, "not found page")


def test_baseline_status_must_match() -> None:
    base = SoftBaseline(status=200, body="not found")
    assert not base.matches(403, "not found")


def test_baseline_dissimilar_body_not_matched() -> None:
    base = SoftBaseline(status=200, body="sorry that page could not be found here")
    assert not base.matches(200, "secret database credentials: root:toor")


def test_baseline_empty_body_falls_back_to_status() -> None:
    base = SoftBaseline(status=403, body="")
    assert base.matches(403, "anything at all")
    assert not base.matches(200, "anything at all")


# ── calibrate ───────────────────────────────────────────────────────────────


async def test_calibrate_returns_none_for_honest_404() -> None:
    session = _SoftSession(soft_status=404)
    baseline = await calibrate(session, _BASE)  # type: ignore[arg-type]
    assert baseline is None


async def test_calibrate_captures_soft_404() -> None:
    session = _SoftSession()
    baseline = await calibrate(session, _BASE)  # type: ignore[arg-type]
    assert baseline is not None
    assert baseline.status == 200
    assert "could not be found" in baseline.body


# ── directories plugin ──────────────────────────────────────────────────────


async def test_directories_soft404_suppresses_false_positives() -> None:
    session = _SoftSession()
    findings = await DirectoriesPlugin(soft_404=True).run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []


async def test_directories_without_soft404_floods_false_positives() -> None:
    session = _SoftSession()
    findings = await DirectoriesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert len(findings) > 0  # the bug we are fixing, reproduced when opt-out


async def test_directories_soft404_keeps_genuine_listing() -> None:
    listing = b"<html><title>Index of /uploads</title></html>"
    session = _SoftSession(overrides={"/uploads/": (200, listing)})
    findings = await DirectoriesPlugin(soft_404=True).run(_BASE, session)  # type: ignore[arg-type]

    uploads = [f for f in findings if f.url.endswith("/uploads/")]
    assert len(uploads) == 1
    assert uploads[0].evidence["directory_listing"] is True


async def test_directories_soft404_keeps_distinct_real_directory() -> None:
    real = b"<html><body>phpMyAdmin 5.2 login</body></html>"
    session = _SoftSession(overrides={"/phpmyadmin/": (200, real)})
    findings = await DirectoriesPlugin(soft_404=True).run(_BASE, session)  # type: ignore[arg-type]

    pma = [f for f in findings if f.url.endswith("/phpmyadmin/")]
    assert len(pma) == 1


# ── config_files plugin ─────────────────────────────────────────────────────


async def test_config_files_soft404_suppresses_false_positives() -> None:
    session = _SoftSession()
    findings = await ConfigFilesPlugin(soft_404=True).run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []


async def test_config_files_soft404_keeps_real_exposed_file() -> None:
    leak = b"DB_PASSWORD=supersecret\nAPI_KEY=sk_live_abcdef0123456789"
    session = _SoftSession(overrides={"/.env": (200, leak)})
    findings = await ConfigFilesPlugin(soft_404=True).run(_BASE, session)  # type: ignore[arg-type]

    env = [f for f in findings if f.url.endswith("/.env")]
    assert len(env) == 1


async def test_config_files_without_soft404_floods_false_positives() -> None:
    session = _SoftSession()
    findings = await ConfigFilesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert len(findings) > 0

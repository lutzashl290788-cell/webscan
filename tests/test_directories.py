"""Tests for the sensitive-directories plugin."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.directories import DirectoriesPlugin

_BASE = "https://example.com"


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


class _Session:
    """Maps each path to a (status, body); unknown paths 404."""

    def __init__(self, pages: dict[str, tuple[int, bytes]]) -> None:
        self._pages = pages

    def get(self, url: str, **_kw: object) -> _Resp:
        path = url[len(_BASE):]
        status, body = self._pages.get(path, (404, b""))
        return _Resp(status, body)


async def test_accessible_critical_directory() -> None:
    session = _Session({"/admin/": (200, b"<h1>Admin login</h1>")})
    findings = await DirectoriesPlugin().run(_BASE, session)  # type: ignore[arg-type]

    admin = next(f for f in findings if f.url.endswith("/admin/"))
    assert admin.severity is Severity.CRITICAL
    assert admin.title.startswith("Accessible directory")


async def test_directory_listing_detected_as_high() -> None:
    body = b"<html><head><title>Index of /uploads</title></head></html>"
    session = _Session({"/uploads/": (200, body)})
    findings = await DirectoriesPlugin().run(_BASE, session)  # type: ignore[arg-type]

    listing = next(f for f in findings if f.url.endswith("/uploads/"))
    assert listing.severity is Severity.HIGH
    assert "Directory listing enabled" in listing.title
    assert listing.evidence["directory_listing"] is True


async def test_403_on_critical_dir_reported_low() -> None:
    session = _Session({"/.git/": (403, b"")})
    findings = await DirectoriesPlugin().run(_BASE, session)  # type: ignore[arg-type]

    git = next(f for f in findings if f.url.endswith("/.git/"))
    assert git.severity is Severity.LOW


async def test_403_on_noncritical_dir_skipped() -> None:
    session = _Session({"/uploads/": (403, b"")})
    findings = await DirectoriesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []


async def test_clean_target_no_findings() -> None:
    session = _Session({})
    findings = await DirectoriesPlugin().run(_BASE, session)  # type: ignore[arg-type]
    assert findings == []


async def test_probes_origin_when_target_has_query() -> None:
    session = _Session({"/admin/": (200, b"<h1>Admin login</h1>")})
    findings = await DirectoriesPlugin().run(
        "https://example.com/search?q=invoice", session  # type: ignore[arg-type]
    )
    assert any(f.url == "https://example.com/admin/" for f in findings)

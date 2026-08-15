"""Tests for the robots.txt / sitemap.xml analysis plugin."""
from __future__ import annotations

from webscan.models import Severity
from webscan.plugins.robots_sitemap import RobotsSitemapPlugin


class _Resp:
    def __init__(self, body: str, status: int = 200) -> None:
        self._body = body
        self.status = status

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _Session:
    """Serves canned bodies per path; missing paths return 404."""

    def __init__(self, pages: dict[str, tuple[str, int]]) -> None:
        self._pages = pages

    def get(self, url: str, **_kw: object) -> _Resp:
        path = url.split("://", 1)[-1].split("/", 1)[-1]
        body, status = self._pages.get(path, ("", 404))
        return _Resp(body, status)


async def test_flags_sensitive_disallowed_paths() -> None:
    robots = "User-agent: *\nDisallow: /admin\nDisallow: /public\nDisallow: /backup\n"
    session = _Session({
        "robots.txt": (robots, 200),
        "sitemap.xml": ("<urlset></urlset>", 200),
    })
    plugin = RobotsSitemapPlugin()

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    leak = next(f for f in findings if "sensitive path" in f.title)
    paths = leak.evidence["disallowed_sensitive"]
    assert "/admin" in paths
    assert "/backup" in paths
    assert "/public" not in paths  # not sensitive
    assert leak.severity is Severity.LOW


async def test_missing_sitemap_is_not_a_security_finding() -> None:
    session = _Session({"robots.txt": ("User-agent: *\nDisallow: /x\n", 200)})
    plugin = RobotsSitemapPlugin()

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert not any("No sitemap.xml" in f.title for f in findings)


async def test_clean_site_no_leak() -> None:
    session = _Session({
        "robots.txt": ("User-agent: *\nDisallow: /cart\n", 200),
        "sitemap.xml": ("<urlset></urlset>", 200),
    })
    plugin = RobotsSitemapPlugin()

    findings = await plugin.run("https://example.com", session)  # type: ignore[arg-type]

    assert findings == []

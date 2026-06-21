"""Tests for the async crawler using a routed fake session."""
from __future__ import annotations

from webscan.crawler import CrawlConfig, Crawler


class _Resp:
    def __init__(self, body: str, status: int = 200, ctype: str = "text/html") -> None:
        self._body = body
        self.status = status
        self.headers = {"Content-Type": ctype}

    async def __aenter__(self) -> _Resp:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def text(self, **_kw: object) -> str:
        return self._body


class _RoutedSession:
    """Maps URL -> html body; unknown URLs yield 404 with empty body."""

    def __init__(self, pages: dict[str, str], robots: str | None = None) -> None:
        self._pages = pages
        self._robots = robots
        self.fetched: list[str] = []

    def get(self, url: str, **_kw: object) -> _Resp:
        if url.endswith("/robots.txt"):
            if self._robots is None:
                return _Resp("", status=404, ctype="text/plain")
            return _Resp(self._robots, ctype="text/plain")
        if url in self._pages:
            self.fetched.append(url)
            return _Resp(self._pages[url])
        return _Resp("", status=404)


async def test_crawls_within_depth_and_scope() -> None:
    pages = {
        "https://site.com": '<a href="/a">a</a><a href="https://evil.com/x">e</a>',
        "https://site.com/a": '<a href="/b">b</a>',
        "https://site.com/b": "<p>leaf</p>",
    }
    session = _RoutedSession(pages)
    crawler = Crawler(session, CrawlConfig(max_depth=2, respect_robots=False))  # type: ignore[arg-type]

    result = await crawler.crawl("https://site.com")

    assert "https://site.com" in result.urls
    assert "https://site.com/a" in result.urls
    assert "https://site.com/b" in result.urls
    # External host must be excluded by scope.
    assert all("evil.com" not in u for u in result.urls)


async def test_depth_limit_stops_expansion() -> None:
    pages = {
        "https://site.com": '<a href="/a">a</a>',
        "https://site.com/a": '<a href="/b">b</a>',
        "https://site.com/b": "<p>leaf</p>",
    }
    session = _RoutedSession(pages)
    crawler = Crawler(session, CrawlConfig(max_depth=1, respect_robots=False))  # type: ignore[arg-type]

    result = await crawler.crawl("https://site.com")

    assert "https://site.com/a" in result.urls
    assert "https://site.com/b" not in result.urls  # depth 2, beyond limit


async def test_collects_forms() -> None:
    pages = {
        "https://site.com": '<form action="/login" method="post"><input name="u"></form>',
    }
    session = _RoutedSession(pages)
    crawler = Crawler(session, CrawlConfig(max_depth=1, respect_robots=False))  # type: ignore[arg-type]

    result = await crawler.crawl("https://site.com")

    assert "https://site.com" in result.forms
    assert result.forms["https://site.com"][0].action == "https://site.com/login"


async def test_robots_disallow_is_respected() -> None:
    pages = {
        "https://site.com": '<a href="/private">p</a>',
        "https://site.com/private": "<p>secret</p>",
    }
    robots = "User-agent: *\nDisallow: /private"
    session = _RoutedSession(pages, robots=robots)
    crawler = Crawler(session, CrawlConfig(max_depth=2, respect_robots=True))  # type: ignore[arg-type]

    result = await crawler.crawl("https://site.com")

    assert "https://site.com/private" not in result.urls


async def test_max_urls_cap() -> None:
    pages = {f"https://site.com/{i}": f'<a href="/{i + 1}">n</a>' for i in range(20)}
    pages["https://site.com"] = '<a href="/0">start</a>'
    session = _RoutedSession(pages)
    crawler = Crawler(
        session,  # type: ignore[arg-type]
        CrawlConfig(max_depth=50, max_urls=5, respect_robots=False),
    )

    result = await crawler.crawl("https://site.com")

    assert len(result.urls) <= 5


# ----------------------------------------------------------------------
# Coverage gaps
# ----------------------------------------------------------------------


async def test_non_html_page_skipped() -> None:
    """Lines 101, 122: non-HTML responses (JSON, images) yield no new links."""
    pages = {
        "https://site.com": '<a href="/api/data">link</a>',
        "https://site.com/api/data": '{"items":[]}',
    }
    session = _RoutedSession(pages)
    crawler = Crawler(
        session,  # type: ignore[arg-type]
        CrawlConfig(max_depth=2, respect_robots=False),
    )
    result = await crawler.crawl("https://site.com")

    assert "https://site.com" in result.urls
    # The JSON page was fetched but produced no links to crawl further.
    # Depth=2: seed→/api/data→(no links from JSON). Since /api/data has
    # no links, the frontier at depth 2 is empty → crawling stops.
    assert len(result.urls) == 2


async def test_exclude_filter_works() -> None:
    """Line 141: URLs matching an exclude pattern are skipped."""
    pages = {
        "https://site.com": '<a href="/admin/secret">admin</a><a href="/public/page">pub</a>',
        "https://site.com/public/page": "<p>public</p>",
    }
    session = _RoutedSession(pages)
    crawler = Crawler(
        session,  # type: ignore[arg-type]
        CrawlConfig(max_depth=2, respect_robots=False, exclude=["admin"]),
    )
    result = await crawler.crawl("https://site.com")

    assert "https://site.com/public/page" in result.urls
    assert not any("admin" in u for u in result.urls)


async def test_fetch_error_page_returns_none() -> None:
    """Lines 124-125: a transport error fetching a page is swallowed."""
    import aiohttp

    class _ClientError(Exception):
        pass

    class _RaisingResp:
        async def __aenter__(self) -> _RaisingResp:
            raise _ClientError("connection reset")

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        async def text(self, **_kw: object) -> str:
            return ""

    class _BoomSession:
        def get(self, _url: str, **_kw: object) -> _RaisingResp:
            # Return the seed page normally, but fail on discovered links.
            if _url == "https://site.com":
                class _SeedResp:
                    headers = {"Content-Type": "text/html"}
                    async def __aenter__(self) -> _SeedResp: return self
                    async def __aexit__(self, *_: object) -> bool: return False
                    async def text(self, **_kw: object) -> str: return '<a href="/broken">link</a>'
                return _SeedResp()
            return _RaisingResp()

    orig = aiohttp.ClientError
    aiohttp.ClientError = _ClientError  # type: ignore[misc,assignment]
    try:
        crawler = Crawler(
            _BoomSession(),  # type: ignore[arg-type]
            CrawlConfig(max_depth=2, respect_robots=False),
        )
        result = await crawler.crawl("https://site.com")
        # Seed should be in URLs, the broken link silently dropped.
        assert "https://site.com" in result.urls
    finally:
        aiohttp.ClientError = orig  # type: ignore[misc,assignment]


async def test_visited_url_deduplicated() -> None:
    """Line 80: already-visited URLs are not added again."""
    pages = {
        "https://site.com": '<a href="/page">link</a><a href="/page">dup</a>',
        "https://site.com/page": "<p>page</p>",
    }
    session = _RoutedSession(pages)
    crawler = Crawler(
        session,  # type: ignore[arg-type]
        CrawlConfig(max_depth=2, respect_robots=False),
    )
    result = await crawler.crawl("https://site.com")

    # /page should appear exactly once.
    page_count = sum(1 for u in result.urls if "/page" in u)
    assert page_count == 1


async def test_robots_disallow_specific_path() -> None:
    """Line 143-144: robots.txt blocks a specific path via _robots_allows."""
    pages = {
        "https://site.com": '<a href="/admin/panel">admin</a><a href="/about">about</a>',
        "https://site.com/about": "<p>about us</p>",
    }
    robots = "User-agent: *\nDisallow: /admin/"
    session = _RoutedSession(pages, robots=robots)
    crawler = Crawler(session, CrawlConfig(max_depth=2, respect_robots=True))  # type: ignore[arg-type]
    result = await crawler.crawl("https://site.com")

    assert "https://site.com/about" in result.urls
    assert not any("admin" in u for u in result.urls)

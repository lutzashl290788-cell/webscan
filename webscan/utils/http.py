"""HTTP utility helpers shared across plugins."""
from __future__ import annotations

from urllib.parse import urlparse


def normalise_url(url: str) -> str:
    """Ensure *url* has a scheme and no trailing slash.

    >>> normalise_url("example.com")
    'https://example.com'
    >>> normalise_url("http://example.com/")
    'http://example.com'
    """
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def is_valid_url(url: str) -> bool:
    """Return ``True`` if *url* is a syntactically valid HTTP(S) URL."""
    try:
        result = urlparse(url)
        return result.scheme in ("http", "https") and bool(result.netloc)
    except ValueError:
        return False


def base_url(url: str) -> str:
    """Return scheme + host from a full URL.

    >>> base_url("https://example.com/some/path?q=1")
    'https://example.com'
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

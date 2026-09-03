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


def same_origin(url_a: str, url_b: str) -> bool:
    """True iff *url_a* and *url_b* share scheme + host + port.

    Used by active plugins to refuse following ``<form action>`` attributes /
    redirects that point off-site, preventing SSRF (CWE-918) and credential
    leakage (CWE-200) when the target serves a page that points to an
    attacker-controlled host.

    >>> same_origin("https://example.com/a", "https://example.com/b")
    True
    >>> same_origin("https://example.com", "http://example.com")
    False
    >>> same_origin("https://example.com", "https://evil.com")
    False
    """
    pa, pb = urlparse(url_a), urlparse(url_b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def same_host(url_a: str, url_b: str) -> bool:
    """True iff *url_a* and *url_b* target the same host (case-insensitive).

    Unlike :func:`same_origin` this ignores scheme/port — useful for redirect
    hygiene where the same host over http↔https is acceptable but a different
    host is not.
    """
    return (urlparse(url_a).hostname or "").lower() == (
        urlparse(url_b).hostname or ""
    ).lower()

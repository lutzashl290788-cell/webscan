"""Tests for the shared HTTP utility helpers (webscan.utils.http)."""
from __future__ import annotations

from webscan.utils.http import base_url, is_valid_url, normalise_url


def test_normalise_url_adds_scheme_and_strips_slash() -> None:
    assert normalise_url("example.com") == "https://example.com"
    assert normalise_url("http://example.com/") == "http://example.com"
    assert normalise_url("https://a.test/path/") == "https://a.test/path"


def test_is_valid_url_accepts_http_and_https() -> None:
    assert is_valid_url("https://example.com") is True
    assert is_valid_url("http://example.com/path?q=1") is True


def test_is_valid_url_rejects_non_http_and_garbage() -> None:
    assert is_valid_url("ftp://example.com") is False  # wrong scheme
    assert is_valid_url("example.com") is False  # no scheme/netloc
    assert is_valid_url("not a url") is False
    assert is_valid_url("") is False
    # Malformed IPv6 literal makes urlparse raise ValueError → handled gracefully.
    assert is_valid_url("http://[") is False


def test_base_url_strips_path_and_query() -> None:
    assert base_url("https://example.com/some/path?q=1") == "https://example.com"
    assert base_url("http://host:8080/x") == "http://host:8080"

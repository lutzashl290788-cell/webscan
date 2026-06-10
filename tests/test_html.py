"""Tests for the stdlib-based HTML parser (links + forms)."""
from __future__ import annotations

from webscan.utils.html import parse_html

_SAMPLE = """
<html>
  <head><link rel="stylesheet" href="/style.css"></head>
  <body>
    <a href="/about">About</a>
    <a href="https://other.com/x">External</a>
    <a href="mailto:a@b.com">Mail</a>
    <a href="#section">Anchor</a>
    <a href="page2?id=1">Relative</a>
    <form action="/login" method="POST">
      <input name="user" type="text">
      <input name="pass" type="password">
      <input name="csrf" type="hidden" value="tok123">
      <input type="submit">
    </form>
  </body>
</html>
"""


def test_extracts_and_resolves_links() -> None:
    page = parse_html(_SAMPLE, base="https://example.com/dir/")

    assert "https://example.com/style.css" in page.links
    assert "https://example.com/about" in page.links
    assert "https://other.com/x" in page.links
    assert "https://example.com/dir/page2?id=1" in page.links


def test_drops_mailto_and_anchor_links() -> None:
    page = parse_html(_SAMPLE, base="https://example.com/")

    assert all("mailto:" not in link for link in page.links)
    assert all("#section" not in link for link in page.links)


def test_parses_form_with_fields() -> None:
    page = parse_html(_SAMPLE, base="https://example.com/")

    assert len(page.forms) == 1
    form = page.forms[0]
    assert form.method == "post"
    assert form.action == "https://example.com/login"

    names = {f.name for f in form.fields}
    assert names == {"user", "pass", "csrf"}

    csrf = next(f for f in form.fields if f.name == "csrf")
    assert csrf.field_type == "hidden"
    assert csrf.value == "tok123"


def test_malformed_html_does_not_crash() -> None:
    page = parse_html("<a href='/ok'>x</a><form><input name=", base="https://e.com")
    assert "https://e.com/ok" in page.links

"""HTML parsing helpers built on the standard-library ``html.parser``.

Keeps WebScan dependency-free (only ``aiohttp`` at runtime) while still
extracting the two structures the crawler and injection plugins need:
hyperlinks and HTML forms.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin


@dataclass
class FormField:
    """A single input/textarea/select control inside a form."""

    name: str
    field_type: str = "text"
    value: str = ""


@dataclass
class Form:
    """A parsed HTML ``<form>`` with its action, method and fields."""

    action: str
    method: str = "get"
    fields: list[FormField] = field(default_factory=list)
    enctype: str = "application/x-www-form-urlencoded"


# Tags whose attributes can reference another URL worth crawling.
_URL_ATTRS: dict[str, str] = {
    "a": "href",
    "link": "href",
    "area": "href",
    "script": "src",
    "img": "src",
    "iframe": "src",
    "form": "action",
}


class _LinkAndFormParser(HTMLParser):
    """Collects hyperlink URLs and form definitions in a single pass."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._current: Form | None = None

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attr = {k.lower(): (v or "") for k, v in attrs}

        if tag == "form":
            self._current = Form(
                action=attr.get("action", ""),
                method=(attr.get("method") or "get").lower(),
                enctype=attr.get("enctype")
                or "application/x-www-form-urlencoded",
            )
            self.forms.append(self._current)
            return

        if tag in ("input", "textarea", "select") and self._current is not None:
            name = attr.get("name", "")
            if name:
                self._current.fields.append(
                    FormField(
                        name=name,
                        field_type=attr.get("type", "text").lower(),
                        value=attr.get("value", ""),
                    )
                )

        url_attr = _URL_ATTRS.get(tag)
        if url_attr:
            value = attr.get(url_attr, "").strip()
            if value:
                self.links.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current = None


@dataclass
class ParsedPage:
    """Result of parsing one HTML document."""

    links: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)


def parse_html(html: str, base: str = "") -> ParsedPage:
    """Parse *html*, resolving links against *base* when given.

    Link URLs are returned absolute (when *base* is provided) and stripped of
    fragments. Non-HTTP schemes (``mailto:``, ``javascript:``, ``tel:`` …) and
    pure in-page anchors are discarded.
    """
    parser = _LinkAndFormParser()
    try:
        parser.feed(html)
    except Exception:  # noqa: BLE001 — malformed markup must never crash a scan
        pass

    links: list[str] = []
    seen: set[str] = set()
    for raw in parser.links:
        resolved = _resolve(raw, base)
        if resolved and resolved not in seen:
            seen.add(resolved)
            links.append(resolved)

    # Resolve each form action against the page URL too.
    for form in parser.forms:
        form.action = _resolve(form.action, base) or base

    return ParsedPage(links=links, forms=parser.forms)


def _resolve(raw: str, base: str) -> str:
    """Resolve *raw* against *base*, dropping fragments and non-HTTP schemes."""
    raw = raw.strip()
    if not raw:
        return ""

    lowered = raw.lower()
    for skip in ("mailto:", "javascript:", "tel:", "data:", "#"):
        if lowered.startswith(skip):
            return ""

    resolved = urljoin(base, raw) if base else raw
    resolved, _, _ = resolved.partition("#")

    if resolved and not resolved.startswith(("http://", "https://")):
        return ""

    return resolved.rstrip("/") if resolved.endswith("/") else resolved

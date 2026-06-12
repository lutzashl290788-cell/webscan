"""Generate an animated SVG terminal demo for the README.

Produces a self-contained SVG (no external assets, no JS) whose lines reveal
progressively via SMIL animation — renders inline on GitHub like a screencast.
"""
from __future__ import annotations

from pathlib import Path

# (text, colour, indent_px). colour=None → default foreground.
FG = "#c9d1d9"
GREEN = "#3fb950"
CYAN = "#39c5cf"
DIM = "#8b949e"
ORANGE = "#db6d28"
YELLOW = "#d29922"
BLUE = "#58a6ff"
GREY = "#6e7681"
WHITE = "#f0f6fc"
PROMPT = "#7ee787"

LINES: list[tuple[str, str, int]] = [
    ("$ webscan -t https://example.com --crawl --depth 2", PROMPT, 0),
    ("", FG, 0),
    ("╔══════════════════════════════════════════════════╗", CYAN, 0),
    ("║          WebScan — Security Auditor              ║", CYAN, 0),
    ("╚══════════════════════════════════════════════════╝", CYAN, 0),
    ("  Targets     : 1", DIM, 0),
    ("  Plugins     : 14 enabled", DIM, 0),
    ("  Crawling 1 seed (depth=2) …", DIM, 0),
    ("  Discovered 12 URL(s) to scan.", GREEN, 0),
    ("", FG, 0),
    ("  [████████████████████] 12/12  done", GREEN, 0),
    ("", FG, 0),
    ("  Total findings  9", WHITE, 0),
    ("", FG, 0),
    ("  • [https://example.com]", FG, 0),
    ("🟠 [HIGH    ] Missing header: Content-Security-Policy", ORANGE, 1),
    ("🟠 [HIGH    ] Missing header: Strict-Transport-Security", ORANGE, 1),
    ("🟡 [MEDIUM  ] Missing header: X-Frame-Options", YELLOW, 1),
    ("🟡 [MEDIUM  ] Missing HSTS header", YELLOW, 1),
    ("🔵 [LOW     ] Information disclosure: Server", BLUE, 1),
    ("⚪ [INFO    ] Technologies detected: Cloudflare", DIM, 1),
    ("", FG, 0),
    ("  ✍  SARIF report : reports/scan.sarif", CYAN, 0),
    ("  ✓ scan complete", GREEN, 0),
]

CHAR_W = 8.4
LINE_H = 22
PAD_X = 20
PAD_TOP = 52
ROW_DELAY = 0.28  # seconds between line reveals


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def build() -> str:
    width = 760
    height = PAD_TOP + LINE_H * len(LINES) + 18

    rows: list[str] = []
    for i, (text, colour, indent) in enumerate(LINES):
        y = PAD_TOP + i * LINE_H
        begin = f"{i * ROW_DELAY:.2f}s"
        x = PAD_X + indent * CHAR_W * 4
        content = esc(text) if text else "&#160;"
        rows.append(
            f'<text x="{x:.0f}" y="{y}" fill="{colour}" opacity="0">'
            f'{content}'
            f'<animate attributeName="opacity" from="0" to="1" '
            f'dur="0.18s" begin="{begin}" fill="freeze"/>'
            f"</text>"
        )

    # Blinking cursor after the last line.
    cur_y = PAD_TOP + len(LINES) * LINE_H
    cursor = (
        f'<rect x="{PAD_X}" y="{cur_y - 14}" width="9" height="17" '
        f'fill="{GREEN}" opacity="0">'
        f'<animate attributeName="opacity" values="0;0;1" '
        f'dur="{len(LINES) * ROW_DELAY:.2f}s" fill="freeze"/>'
        f'<animate attributeName="opacity" values="1;0;1" dur="1s" '
        f'begin="{len(LINES) * ROW_DELAY:.2f}s" repeatCount="indefinite"/>'
        f"</rect>"
    )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="SFMono-Regular,Consolas,Liberation Mono,Menlo,monospace" font-size="14">
  <rect width="{width}" height="{height}" rx="10" fill="#0d1117" stroke="#30363d" stroke-width="1"/>
  <rect width="{width}" height="36" rx="10" fill="#161b22"/>
  <rect y="26" width="{width}" height="10" fill="#161b22"/>
  <circle cx="22" cy="18" r="6" fill="#ff5f56"/>
  <circle cx="42" cy="18" r="6" fill="#ffbd2e"/>
  <circle cx="62" cy="18" r="6" fill="#27c93f"/>
  <text x="{width // 2}" y="23" fill="#8b949e" font-size="12" text-anchor="middle">webscan — security audit</text>
  {chr(10).join("  " + r for r in rows)}
  {cursor}
</svg>"""


if __name__ == "__main__":
    out = Path(__file__).parent / "demo.svg"
    out.write_text(build(), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")

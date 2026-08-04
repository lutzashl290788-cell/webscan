"""Generate an animated SVG terminal demo for the README.

Produces a self-contained SVG (no external assets, no JS) whose lines reveal
progressively via SMIL animation — renders inline on GitHub like a screencast.

The version badge and plugin count are read from the installed package so the
demo cannot drift out of sync with ``webscan.__version__``. Regenerate with
``python assets/gen_demo.py`` after a release bump.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow running straight from a source checkout, without installing first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webscan import __version__  # noqa: E402
from webscan.registry import ALL_PLUGINS  # noqa: E402

VERSION = __version__
PLUGIN_COUNT = len(ALL_PLUGINS)

# Host used consistently throughout the mocked session.
DEMO_HOST = "httpbin.org"

FG = "#c9d1d9"
GREEN = "#3fb950"
CYAN = "#39c5cf"
DIM = "#8b949e"
ORANGE = "#db6d28"
YELLOW = "#d29922"
BLUE = "#58a6ff"
RED = "#f85149"
WHITE = "#f0f6fc"
PROMPT = "#7ee787"
MAGENTA = "#bc8cff"

# Inner width of the ASCII banner box, in characters.
_BOX_W = 50

# Mocked finding rows. The "Total findings" counter below is derived from this
# list so the two can never disagree, and no issue is listed twice — the
# engine deduplicates overlapping findings across plugins.
FINDING_ROWS: list[tuple[str, str, int]] = [
    ("🟠 [HIGH    ] Missing header: Content-Security-Policy", ORANGE, 1),
    ("🟠 [HIGH    ] Missing header: Strict-Transport-Security", ORANGE, 1),
    ("🟠 [HIGH    ] CORS reflects an arbitrary Origin", ORANGE, 1),
    ("🟡 [MEDIUM  ] Clickjacking: no X-Frame-Options / CSP", YELLOW, 1),
    ("🔵 [LOW     ] Missing header: Referrer-Policy", BLUE, 1),
    ("🔵 [LOW     ] Information disclosure: Server", BLUE, 1),
    ("🔵 [LOW     ] No sitemap.xml found", BLUE, 1),
    ("🔵 [LOW     ] No robots.txt found", BLUE, 1),
    ("⚪ [INFO    ] security.txt not found", DIM, 1),
]

SUBDOMAIN_ROW: tuple[str, str, int] = (
    f"⚪ [INFO    ] 2 subdomains discovered for {DEMO_HOST}", DIM, 1,
)

TOTAL_FINDINGS = len(FINDING_ROWS) + 1  # + the subdomain finding below
# Distinct plugins behind the rows above: headers, cors, clickjacking,
# robots_sitemap, security_txt, subdomains.
PLUGINS_FIRED = 6

LINES: list[tuple[str, str, int]] = [
    (f"$ webscan -t https://{DEMO_HOST} --safe-mode", PROMPT, 0),
    ("", FG, 0),
    ("╔" + "═" * _BOX_W + "╗", CYAN, 0),
    ("║" + f"WebScan v{VERSION} — Security Auditor".center(_BOX_W) + "║", CYAN, 0),
    ("╚" + "═" * _BOX_W + "╝", CYAN, 0),
    ("  Targets     : 1", DIM, 0),
    (f"  Plugins     : {PLUGIN_COUNT} enabled", DIM, 0),
    ("  Confidence  : firm (content-verified only)", DIM, 0),
    ("  Concurrency : 10  ·  Retry: 2  ·  Soft-404: on", DIM, 0),
    ("", FG, 0),
    ("  [████████████████████] 1/1  done in 7.1s", GREEN, 0),
    ("", FG, 0),
    (f"  Total findings  {TOTAL_FINDINGS}", WHITE, 0),
    ("", FG, 0),
    (f"  • https://{DEMO_HOST}", FG, 0),
    *FINDING_ROWS,
    ("", FG, 0),
    SUBDOMAIN_ROW,
    ("", FG, 0),
    ("  ✍  SARIF report : reports/scan.sarif", CYAN, 0),
    ("  ✍  JSON report  : reports/scan.json", CYAN, 0),
    (f"  ✓ scan complete — 0 false positives · {PLUGINS_FIRED} plugins fired", GREEN, 0),
]

CHAR_W = 8.4
LINE_H = 20
PAD_X = 20
PAD_TOP = 50
ROW_DELAY = 0.22  # seconds between line reveals


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def build() -> str:
    width = 780
    height = PAD_TOP + LINE_H * len(LINES) + 18

    rows: list[str] = []
    for i, (text, colour, indent) in enumerate(LINES):
        y = PAD_TOP + i * LINE_H
        begin = f"{i * ROW_DELAY:.2f}s"
        x = PAD_X + indent * CHAR_W * 4
        content = esc(text) if text else "&#160;"
        rows.append(
            f'<text x="{x:.0f}" y="{y}" fill="{colour}" opacity="0" font-size="13">'
            f'{content}'
            f'<animate attributeName="opacity" from="0" to="1" '
            f'dur="0.15s" begin="{begin}" fill="freeze"/>'
            f"</text>"
        )

    # Blinking cursor after the last line.
    cur_y = PAD_TOP + len(LINES) * LINE_H
    cursor = (
        f'<rect x="{PAD_X}" y="{cur_y - 13}" width="8" height="16" '
        f'fill="{GREEN}" opacity="0">'
        f'<animate attributeName="opacity" values="0;0;1" '
        f'dur="{len(LINES) * ROW_DELAY:.2f}s" fill="freeze"/>'
        f'<animate attributeName="opacity" values="1;0;1" dur="1s" '
        f'begin="{len(LINES) * ROW_DELAY:.2f}s" repeatCount="indefinite"/>'
        f"</rect>"
    )

    # Progress bar animation during scan
    bar_y = PAD_TOP + 9 * LINE_H
    bar_w = 300
    bar_x = PAD_X + 2
    progress = (
        f'<rect x="{bar_x}" y="{bar_y - 10}" width="{bar_w}" height="3" rx="1" fill="#21262d"/>'
        f'<rect x="{bar_x}" y="{bar_y - 10}" width="0" height="3" rx="1" fill="{GREEN}">'
        f'<animate attributeName="width" from="0" to="{bar_w}" dur="1.5s" '
        f'begin="2.0s" fill="freeze" '
        f'calcMode="spline" keyTimes="0;1" keySplines="0.2 0.8 0.2 1"/>'
        f'</rect>'
    )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" \
viewBox="0 0 {width} {height}" \
font-family="SFMono-Regular,Consolas,Liberation Mono,Menlo,monospace">
  <defs>
    <radialGradient id="glow" cx="50%" cy="0%" r="60%">
      <stop offset="0" stop-color="#dc2626" stop-opacity="0.06"/>
      <stop offset="1" stop-color="#dc2626" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="{width}" height="{height}" rx="10" fill="#0d1117"/>
  <rect width="{width}" height="{height}" rx="10" fill="url(#glow)"/>
  <rect width="{width}" height="{height}" rx="10" fill="none" stroke="#30363d" stroke-width="1"/>
  <rect width="{width}" height="34" rx="10" fill="#161b22"/>
  <rect y="24" width="{width}" height="10" fill="#161b22"/>
  <circle cx="22" cy="17" r="6" fill="#ff5f56"/>
  <circle cx="42" cy="17" r="6" fill="#ffbd2e"/>
  <circle cx="62" cy="17" r="6" fill="#27c93f"/>
  <text x="{width // 2}" y="22" fill="#8b949e" font-size="11" text-anchor="middle">\
webscan v{VERSION} — security audit · {PLUGIN_COUNT} plugins</text>
  {progress}
  {chr(10).join("  " + r for r in rows)}
  {cursor}
</svg>"""


if __name__ == "__main__":
    out = Path(__file__).parent / "demo.svg"
    out.write_text(build(), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")

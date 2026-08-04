"""Generate an animated SVG header banner for the README.

Self-contained SVG (no JS, SMIL only) — renders inline on GitHub. Shows a
typewriter-reveal title, a glowing underline, and cycling taglines.

The version badge and plugin count are read from the installed package so the
banner cannot drift out of sync with ``webscan.__version__`` the way a
hardcoded string does. Regenerate with ``python assets/gen_header.py`` after a
release bump.
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

W, H = 820, 240
ACCENT = "#dc2626"
ACCENT2 = "#f87171"
ACCENT3 = "#fbbf24"
FG = "#f5f5f5"
DIM = "#737373"
BG = "#0a0a0a"
SURFACE = "#141111"

MONO = "SFMono-Regular,Consolas,monospace"
FONT_STACK = "SFMono-Regular,Consolas,Liberation Mono,Menlo,monospace"

# Severity palette for the pulsing dot row: critical → high → medium → low → info.
SEVERITY_COLOURS = ["#dc2626", "#db6d28", "#d29922", "#3b82f6", "#22c55e"]

TITLE = "WebScan"
TAGLINES = [
    f"{PLUGIN_COUNT} plugins · 7.1s · content-verified · zero false positives",
    "SSTI · XXE · IDOR · LFI · CSRF · cache poisoning · smuggling",
    "safe mode · stealth · retry · soft-404 · confidence dimension",
    "for site owners, bug hunters and security researchers",
]


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_taglines(title_x: int, total: float, slot: float) -> list[str]:
    """Render each tagline as a <text> that fades in and out on its own slot."""
    out: list[str] = []
    for i, line in enumerate(TAGLINES):
        begin = i * slot
        kt = [0, begin / total, (begin + 0.3) / total,
              (begin + slot - 0.3) / total, (begin + slot) / total, 1]
        kv = [0, 0, 1, 1, 0, 0]
        keytimes = ";".join(f"{max(0.0, min(1.0, t)):.3f}" for t in kt)
        values = ";".join(str(v) for v in kv)
        out.append(
            f'<text x="{title_x}" y="168" text-anchor="middle" fill="{ACCENT2}" '
            f'font-size="16" font-family="{MONO}" '
            f'opacity="0" letter-spacing="0.5">'
            f'{_esc(line)}'
            f'<animate attributeName="opacity" values="{values}" keyTimes="{keytimes}" '
            f'dur="{total:.1f}s" repeatCount="indefinite"/>'
            f"</text>"
        )
    return out


def _build_severity_dots() -> list[str]:
    """Render the severity dot row, each dot pulsing 0.4 s after the previous."""
    return [
        f'<circle cx="{i * 24}" cy="0" r="5" fill="{colour}">'
        f'<animate attributeName="opacity" values="0.3;1;0.3" '
        f'dur="2s" begin="{i * 0.4:g}s" repeatCount="indefinite"/>'
        f"</circle>"
        for i, colour in enumerate(SEVERITY_COLOURS)
    ]


def build() -> str:
    title_x = W // 2
    title_y = 116
    sweep_w = 430
    sweep_x = title_x - sweep_w // 2

    slot = 2.4
    total = slot * len(TAGLINES)
    taglines_svg = _build_taglines(title_x, total, slot)
    dots_svg = _build_severity_dots()

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" \
viewBox="0 0 {W} {H}" font-family="{FONT_STACK}">
  <defs>
    <linearGradient id="grad" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{ACCENT}"/>
      <stop offset="0.5" stop-color="{ACCENT2}"/>
      <stop offset="1" stop-color="{ACCENT}"/>
      <animate attributeName="x1" values="0;1;0" dur="6s" repeatCount="indefinite"/>
      <animate attributeName="x2" values="1;2;1" dur="6s" repeatCount="indefinite"/>
    </linearGradient>
    <radialGradient id="glow" cx="50%" cy="40%" r="50%">
      <stop offset="0" stop-color="{ACCENT}" stop-opacity="0.08"/>
      <stop offset="1" stop-color="{ACCENT}" stop-opacity="0"/>
    </radialGradient>
    <clipPath id="reveal">
      <rect x="{sweep_x}" y="60" width="0" height="80">
        <animate attributeName="width" from="0" to="{sweep_w}" dur="1.1s"
                 begin="0.3s" fill="freeze" calcMode="spline"
                 keyTimes="0;1" keySplines="0.2 0.8 0.2 1"/>
      </rect>
    </clipPath>
  </defs>

  <rect width="{W}" height="{H}" rx="14" fill="{BG}"/>
  <rect width="{W}" height="{H}" rx="14" fill="url(#glow)"/>
  <rect width="{W}" height="{H}" rx="14" fill="none" stroke="#1a1a1a"/>

  <!-- scanline shimmer -->
  <rect x="0" y="0" width="{W}" height="1.5" fill="{ACCENT}" opacity="0.4">
    <animate attributeName="y" values="0;{H};0" dur="5s" repeatCount="indefinite"/>
    <animate attributeName="opacity" values="0;0.4;0" dur="5s" repeatCount="indefinite"/>
  </rect>

  <text x="{title_x}" y="40" text-anchor="middle" fill="{DIM}" font-size="11" letter-spacing="4">
    A U T O M A T E D   W E B   S E C U R I T Y   A U D I T O R
  </text>

  <!-- typewriter title -->
  <g clip-path="url(#reveal)">
    <text x="{title_x}" y="{title_y}" text-anchor="middle" fill="url(#grad)"
          font-size="76" font-weight="bold" letter-spacing="2">{TITLE}</text>
  </g>
  <!-- blinking caret after the title reveal -->
  <rect x="{title_x + sweep_w // 2 - 6}" y="60" width="5" height="76" fill="{ACCENT2}" opacity="0">
    <animate attributeName="opacity" values="0;0;1" keyTimes="0;0.12;0.13"
             dur="1.4s" fill="freeze"/>
    <animate attributeName="opacity" values="1;0;1" dur="1s" begin="1.4s" repeatCount="indefinite"/>
  </rect>

  <!-- animated gradient underline -->
  <rect x="{sweep_x}" y="132" width="0" height="2" rx="1" fill="url(#grad)">
    <animate attributeName="width" from="0" to="{sweep_w}" dur="1.1s" begin="0.4s"
             fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0.2 0.8 0.2 1"/>
  </rect>

  {chr(10).join("  " + t for t in taglines_svg)}

  <!-- severity dots pulsing -->
  <g transform="translate({title_x - 72}, 200)">
    {chr(10).join("    " + d for d in dots_svg)}
  </g>
  <!-- version badge -->
  <text x="{title_x + 110}" y="204" fill="{DIM}" font-size="11"
        font-family="{MONO}">v{VERSION}</text>
</svg>"""


if __name__ == "__main__":
    out = Path(__file__).parent / "header.svg"
    out.write_text(build(), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes) — v{VERSION}, {PLUGIN_COUNT} plugins")

"""Generate an animated SVG header banner for the README.

Self-contained SVG (no JS, SMIL only) — renders inline on GitHub. Shows a
typewriter-reveal title, a glowing underline, and cycling taglines.

v2.5.2 — updated with 38 plugins, 840 tests, content-verified findings.
"""
from __future__ import annotations

from pathlib import Path

W, H = 820, 240
ACCENT = "#dc2626"
ACCENT2 = "#f87171"
ACCENT3 = "#fbbf24"
FG = "#f5f5f5"
DIM = "#737373"
BG = "#0a0a0a"
SURFACE = "#141111"

TITLE = "WebScan"
TAGLINES = [
    "38 plugins · 7.1s · content-verified · zero false positives",
    "SSTI · XXE · IDOR · LFI · CSRF · cache poisoning · smuggling",
    "safe mode · stealth · retry · soft-404 · confidence dimension",
    "for site owners, bug hunters and security researchers",
]


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build() -> str:
    title_x = W // 2
    title_y = 116
    sweep_w = 430
    sweep_x = title_x - sweep_w // 2

    slot = 2.4
    total = slot * len(TAGLINES)
    taglines_svg: list[str] = []
    for i, line in enumerate(TAGLINES):
        begin = i * slot
        kt = [0, begin / total, (begin + 0.3) / total,
              (begin + slot - 0.3) / total, (begin + slot) / total, 1]
        kv = [0, 0, 1, 1, 0, 0]
        keytimes = ";".join(f"{max(0.0, min(1.0, t)):.3f}" for t in kt)
        values = ";".join(str(v) for v in kv)
        taglines_svg.append(
            f'<text x="{title_x}" y="168" text-anchor="middle" fill="{ACCENT2}" '
            f'font-size="16" font-family="SFMono-Regular,Consolas,monospace" opacity="0" letter-spacing="0.5">'
            f'{_esc(line)}'
            f'<animate attributeName="opacity" values="{values}" keyTimes="{keytimes}" '
            f'dur="{total:.1f}s" repeatCount="indefinite"/>'
            f"</text>"
        )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="SFMono-Regular,Consolas,Liberation Mono,Menlo,monospace">
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
    <animate attributeName="opacity" values="0;0;1" keyTimes="0;0.12;0.13" dur="1.4s" fill="freeze"/>
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
    <circle cx="0"  cy="0" r="5" fill="#dc2626"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="0s"   repeatCount="indefinite"/></circle>
    <circle cx="24" cy="0" r="5" fill="#db6d28"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="0.4s" repeatCount="indefinite"/></circle>
    <circle cx="48" cy="0" r="5" fill="#d29922"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="0.8s" repeatCount="indefinite"/></circle>
    <circle cx="72" cy="0" r="5" fill="#3b82f6"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="1.2s" repeatCount="indefinite"/></circle>
    <circle cx="96" cy="0" r="5" fill="#22c55e"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="1.6s" repeatCount="indefinite"/></circle>
  </g>
  <!-- version badge -->
  <text x="{title_x + 110}" y="204" fill="{DIM}" font-size="11" font-family="SFMono-Regular,Consolas,monospace">v2.5.2</text>
</svg>"""


if __name__ == "__main__":
    out = Path(__file__).parent / "header.svg"
    out.write_text(build(), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")

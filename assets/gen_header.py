"""Generate an animated SVG header banner for the README.

Self-contained SVG (no JS, SMIL only) — renders inline on GitHub. Shows a
typewriter-reveal title, a glowing underline, and cycling taglines.
"""
from __future__ import annotations

from pathlib import Path

W, H = 820, 240
ACCENT = "#39c5cf"
ACCENT2 = "#7ee787"
FG = "#e6edf3"
DIM = "#8b949e"
BG = "#0d1117"

TITLE = "WebScan"
TAGLINES = [
    "async web security scanner",
    "14 plugins · 5 report formats",
    "safe mode · stealth · anonymised reports",
    "for site owners, bug hunters and researchers",
]


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build() -> str:
    # Typewriter: a clip rect grows in width to reveal the title.
    title_x = W // 2
    title_y = 116
    # Approx title width for the clip sweep.
    sweep_w = 430
    sweep_x = title_x - sweep_w // 2

    # Cycling taglines: each visible for `slot` seconds, fading in/out.
    slot = 2.4
    total = slot * len(TAGLINES)
    taglines_svg: list[str] = []
    for i, line in enumerate(TAGLINES):
        begin = i * slot
        # opacity keyframes across the full loop: hidden→show→hide.
        kt = [0, begin / total, (begin + 0.3) / total,
              (begin + slot - 0.3) / total, (begin + slot) / total, 1]
        kv = [0, 0, 1, 1, 0, 0]
        # normalise/clamp
        keytimes = ";".join(f"{max(0.0, min(1.0, t)):.3f}" for t in kt)
        values = ";".join(str(v) for v in kv)
        taglines_svg.append(
            f'<text x="{title_x}" y="168" text-anchor="middle" fill="{ACCENT2}" '
            f'font-size="18" font-family="SFMono-Regular,Consolas,monospace" opacity="0">'
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
    <clipPath id="reveal">
      <rect x="{sweep_x}" y="60" width="0" height="80">
        <animate attributeName="width" from="0" to="{sweep_w}" dur="1.1s"
                 begin="0.3s" fill="freeze" calcMode="spline"
                 keyTimes="0;1" keySplines="0.2 0.8 0.2 1"/>
      </rect>
    </clipPath>
  </defs>

  <rect width="{W}" height="{H}" rx="14" fill="{BG}"/>
  <rect width="{W}" height="{H}" rx="14" fill="none" stroke="#21262d"/>

  <!-- scanline shimmer -->
  <rect x="0" y="0" width="{W}" height="2" fill="{ACCENT}" opacity="0.5">
    <animate attributeName="y" values="0;{H};0" dur="5s" repeatCount="indefinite"/>
    <animate attributeName="opacity" values="0;0.5;0" dur="5s" repeatCount="indefinite"/>
  </rect>

  <text x="{title_x}" y="40" text-anchor="middle" fill="{DIM}" font-size="13" letter-spacing="3">
    A U T O M A T E D   W E B   S E C U R I T Y   A U D I T O R
  </text>

  <!-- typewriter title -->
  <g clip-path="url(#reveal)">
    <text x="{title_x}" y="{title_y}" text-anchor="middle" fill="url(#grad)"
          font-size="76" font-weight="bold" letter-spacing="2">{TITLE}</text>
  </g>
  <!-- blinking caret after the title reveal -->
  <rect x="{title_x + sweep_w // 2 - 6}" y="60" width="6" height="76" fill="{ACCENT2}" opacity="0">
    <animate attributeName="opacity" values="0;0;1" keyTimes="0;0.12;0.13" dur="1.4s" fill="freeze"/>
    <animate attributeName="opacity" values="1;0;1" dur="1s" begin="1.4s" repeatCount="indefinite"/>
  </rect>

  <!-- animated gradient underline -->
  <rect x="{sweep_x}" y="132" width="0" height="3" rx="2" fill="url(#grad)">
    <animate attributeName="width" from="0" to="{sweep_w}" dur="1.1s" begin="0.4s"
             fill="freeze" calcMode="spline" keyTimes="0;1" keySplines="0.2 0.8 0.2 1"/>
  </rect>

  {chr(10).join("  " + t for t in taglines_svg)}

  <!-- severity dots pulsing -->
  <g transform="translate({title_x - 64}, 200)">
    <circle cx="0"  cy="0" r="6" fill="#da3633"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="0s"   repeatCount="indefinite"/></circle>
    <circle cx="28" cy="0" r="6" fill="#db6d28"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="0.4s" repeatCount="indefinite"/></circle>
    <circle cx="56" cy="0" r="6" fill="#d29922"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="0.8s" repeatCount="indefinite"/></circle>
    <circle cx="84" cy="0" r="6" fill="#58a6ff"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="1.2s" repeatCount="indefinite"/></circle>
    <circle cx="112" cy="0" r="6" fill="#3fb950"><animate attributeName="opacity" values="0.3;1;0.3" dur="2s" begin="1.6s" repeatCount="indefinite"/></circle>
  </g>
</svg>"""


if __name__ == "__main__":
    out = Path(__file__).parent / "header.svg"
    out.write_text(build(), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size} bytes)")

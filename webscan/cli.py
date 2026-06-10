"""WebScan CLI — entry point."""
from __future__ import annotations

import argparse
import asyncio
import ssl as ssl_lib
import sys
from pathlib import Path

import aiohttp

from webscan.crawler import CrawlConfig, Crawler
from webscan.engine import ScanEngine
from webscan.plugins.base import BasePlugin
from webscan.plugins.config_files import ConfigFilesPlugin
from webscan.plugins.cookies import CookiesPlugin
from webscan.plugins.cors import CorsPlugin
from webscan.plugins.directories import DirectoriesPlugin
from webscan.plugins.headers import HeadersPlugin
from webscan.plugins.http_methods import HttpMethodsPlugin
from webscan.plugins.security_txt import SecurityTxtPlugin
from webscan.plugins.sql_injection import SqlInjectionPlugin
from webscan.plugins.xss import XssPlugin
from webscan.reporter import Reporter

# ──────────────────────────────────────────────────────────────────────────────
# Plugin registry — add new plugins here
# ──────────────────────────────────────────────────────────────────────────────
ALL_PLUGINS: dict[str, type[BasePlugin]] = {
    "config_files":  ConfigFilesPlugin,
    "headers":       HeadersPlugin,
    "directories":   DirectoriesPlugin,
    "sql_injection": SqlInjectionPlugin,
    "xss":           XssPlugin,
    "cors":          CorsPlugin,
    "cookies":       CookiesPlugin,
    "http_methods":  HttpMethodsPlugin,
    "security_txt":  SecurityTxtPlugin,
}


# ──────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ──────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webscan",
        description="WebScan — automated web configuration security auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples
--------
  webscan -t https://example.com
  webscan -t https://a.com https://b.com --plugins headers
  webscan -f targets.txt -o ./reports/scan --format json md -v
  webscan --list-plugins
""",
    )

    # --- Targets ---
    tg = parser.add_argument_group("Targets (at least one required)")
    tg.add_argument(
        "-t", "--target",
        nargs="+",
        metavar="URL",
        help="One or more target URLs.",
    )
    tg.add_argument(
        "-f", "--file",
        metavar="FILE",
        help="Plain-text file with one target URL per line (# comments allowed).",
    )

    # --- Crawler ---
    cg = parser.add_argument_group("Crawler")
    cg.add_argument(
        "--crawl",
        action="store_true",
        help="Spider each target to discover additional URLs before scanning.",
    )
    cg.add_argument(
        "--depth",
        type=int,
        default=2,
        metavar="N",
        help="Maximum crawl depth from each seed URL (default: 2).",
    )
    cg.add_argument(
        "--max-urls",
        type=int,
        default=200,
        metavar="N",
        help="Maximum number of URLs to discover per seed (default: 200).",
    )
    cg.add_argument(
        "--scope",
        metavar="DOMAIN",
        help="Restrict crawling to this host (default: each seed's own host).",
    )
    cg.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        metavar="PATTERN",
        help="Skip URLs containing any of these substrings while crawling.",
    )
    cg.add_argument(
        "--ignore-robots",
        action="store_true",
        help="Ignore robots.txt rules while crawling.",
    )

    # --- Plugins ---
    pg = parser.add_argument_group("Plugins")
    pg.add_argument(
        "--plugins",
        nargs="+",
        choices=list(ALL_PLUGINS.keys()),
        default=list(ALL_PLUGINS.keys()),
        metavar="NAME",
        help=(
            f"Plugins to enable (default: all). "
            f"Available: {', '.join(ALL_PLUGINS.keys())}."
        ),
    )
    pg.add_argument(
        "--list-plugins",
        action="store_true",
        help="Print available plugins and exit.",
    )

    # --- Output ---
    og = parser.add_argument_group("Output")
    og.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Base path for report files, without extension (e.g. ./reports/scan).",
    )
    og.add_argument(
        "--format",
        nargs="+",
        choices=["json", "md"],
        default=["json", "md"],
        metavar="FMT",
        help="Output format(s): json, md (default: both).",
    )
    og.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print every finding to stdout after scanning.",
    )
    og.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress all stdout output except errors.",
    )

    # --- Performance ---
    perfg = parser.add_argument_group("Performance")
    perfg.add_argument(
        "-c", "--concurrency",
        type=int,
        default=10,
        metavar="N",
        help="Max concurrent targets (default: 10).",
    )
    perfg.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="Per-request timeout in seconds (default: 10).",
    )

    return parser


# ──────────────────────────────────────────────────────────────────────────────
# Target loading & normalisation
# ──────────────────────────────────────────────────────────────────────────────

def _load_targets(args: argparse.Namespace) -> list[str]:
    raw: list[str] = []

    if args.target:
        raw.extend(args.target)

    if args.file:
        path = Path(args.file)
        if not path.exists():
            _die(f"Target file not found: {args.file}")
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                raw.append(stripped)

    if not raw:
        return []

    normalised: list[str] = []
    for url in raw:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        normalised.append(url.rstrip("/"))

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for url in normalised:
        if url not in seen:
            seen.add(url)
            unique.append(url)

    return unique


# ──────────────────────────────────────────────────────────────────────────────
# Main async scan routine
# ──────────────────────────────────────────────────────────────────────────────

async def _crawl_targets(
    seeds: list[str],
    args: argparse.Namespace,
) -> list[str]:
    """Expand *seeds* into a deduplicated list of in-scope URLs via the crawler."""
    ctx = ssl_lib.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl_lib.CERT_NONE

    config = CrawlConfig(
        max_depth=args.depth,
        max_urls=args.max_urls,
        scope=args.scope or "",
        respect_robots=not args.ignore_robots,
        exclude=args.exclude,
    )

    discovered: list[str] = []
    seen: set[str] = set()
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=min(5, args.timeout))

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=aiohttp.TCPConnector(ssl=ctx),
    ) as session:
        crawler = Crawler(session, config)
        for seed in seeds:
            try:
                result = await crawler.crawl(seed)
            except Exception:  # noqa: BLE001 — a bad seed must not abort the scan
                if seed not in seen:
                    seen.add(seed)
                    discovered.append(seed)
                continue
            for url in result.urls:
                if url not in seen:
                    seen.add(url)
                    discovered.append(url)

    return discovered or seeds


async def _run(args: argparse.Namespace) -> int:
    targets = _load_targets(args)

    if not targets:
        _die("No targets specified. Use -t URL or -f FILE.")

    if args.crawl:
        if not args.quiet:
            print(f"  Crawling {len(targets)} seed(s) (depth={args.depth}) …")
        targets = await _crawl_targets(targets, args)
        if not args.quiet:
            print(f"  Discovered {len(targets)} URL(s) to scan.")
            print()

    plugins: list[BasePlugin] = [ALL_PLUGINS[name]() for name in args.plugins]
    quiet: bool = args.quiet

    def _progress(target: str, done: int, total: int) -> None:
        if not quiet:
            bar = "█" * done + "░" * (total - done)
            print(f"\r  [{bar}] {done}/{total} — {target[:60]:<60}", end="", flush=True)

    if not quiet:
        print("╔══════════════════════════════════════════════════════════╗")
        print("║              WebScan — Security Auditor                 ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"  Targets     : {len(targets)}")
        print(f"  Plugins     : {', '.join(p.name for p in plugins)}")
        print(f"  Concurrency : {args.concurrency}")
        print(f"  Timeout     : {args.timeout}s")
        print()

    engine = ScanEngine(
        plugins=plugins,
        concurrency=args.concurrency,
        timeout=args.timeout,
        on_progress=_progress,
    )
    report = await engine.scan_all(targets)

    if not quiet:
        print()  # end progress line
        print()

    reporter = Reporter(report)

    # Print summary / detailed findings to stdout
    if not quiet:
        print(f"  Scan completed  {report.scan_started} → {report.scan_finished}")
        print(f"  Total findings  {report.total_findings}")
        print()
        print(reporter.to_console_summary())
        print()

    # Write report files
    if args.output:
        base = Path(args.output)
        base.parent.mkdir(parents=True, exist_ok=True)

        if "json" in args.format:
            p = base.with_suffix(".json")
            reporter.to_json(p)
            if not quiet:
                print(f"  ✍  JSON report : {p}")

        if "md" in args.format:
            p = base.with_suffix(".md")
            reporter.to_markdown(p)
            if not quiet:
                print(f"  ✍  MD  report  : {p}")

        if not quiet:
            print()

    # Non-zero exit if any critical/high findings
    critical_or_high = sum(
        1
        for tr in report.targets
        for f in tr.findings
        if f.severity.value in ("critical", "high")
    )
    return 1 if critical_or_high > 0 else 0


# ──────────────────────────────────────────────────────────────────────────────
# Entry points
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.list_plugins:
        print("Available plugins:")
        for name, cls in ALL_PLUGINS.items():
            print(f"  {name:<20} {cls.description}")
        sys.exit(0)

    if not args.target and not args.file:
        parser.print_help()
        sys.exit(1)

    exit_code = asyncio.run(_run(args))
    sys.exit(exit_code)


def _die(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()

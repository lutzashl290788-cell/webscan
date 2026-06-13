"""WebScan CLI — entry point."""
from __future__ import annotations

import argparse
import asyncio
import os
import ssl as ssl_lib
import sys
from pathlib import Path
from typing import NoReturn

import aiohttp

from webscan.anonymize import anonymize_report
from webscan.auth import AuthConfig, LoginError, PreparedAuth, prepare_auth
from webscan.crawler import CrawlConfig, Crawler
from webscan.engine import ScanEngine
from webscan.models import SEVERITY_ORDER, Severity
from webscan.net import NetConfig, pick_user_agent
from webscan.plugins.base import BasePlugin
from webscan.plugins.config_files import ConfigFilesPlugin
from webscan.plugins.cookies import CookiesPlugin
from webscan.plugins.cors import CorsPlugin
from webscan.plugins.directories import DirectoriesPlugin
from webscan.plugins.headers import HeadersPlugin
from webscan.plugins.http_methods import HttpMethodsPlugin
from webscan.plugins.open_redirect import OpenRedirectPlugin
from webscan.plugins.path_traversal import PathTraversalPlugin
from webscan.plugins.security_txt import SecurityTxtPlugin
from webscan.plugins.sql_injection import SqlInjectionPlugin
from webscan.plugins.ssl_tls import SslTlsPlugin
from webscan.plugins.ssrf import SsrfPlugin
from webscan.plugins.subdomains import SubdomainsPlugin
from webscan.plugins.tech_fingerprint import TechFingerprintPlugin
from webscan.plugins.xss import XssPlugin
from webscan.reporter import Reporter

# Shown on every interactive run. WebScan is an authorised-testing tool; this
# notice makes the operator's responsibility explicit and discourages misuse.
_LEGAL_DISCLAIMER = (
    "WebScan — authorised security testing only. By scanning a target you "
    "confirm you own it or hold explicit written permission. Unauthorised "
    "scanning may be illegal. You are solely responsible for your use."
)


def _disclaimer_text() -> str:
    """Dim the disclaimer only when stderr is an interactive terminal."""
    if sys.stderr.isatty():
        return f"\033[2m{_LEGAL_DISCLAIMER}\033[0m"
    return _LEGAL_DISCLAIMER

# ──────────────────────────────────────────────────────────────────────────────
# Plugin registry — add new plugins here
# ──────────────────────────────────────────────────────────────────────────────
ALL_PLUGINS: dict[str, type[BasePlugin]] = {
    "config_files":  ConfigFilesPlugin,
    "headers":       HeadersPlugin,
    "directories":   DirectoriesPlugin,
    "sql_injection": SqlInjectionPlugin,
    "xss":           XssPlugin,
    "path_traversal": PathTraversalPlugin,
    "open_redirect": OpenRedirectPlugin,
    "ssrf":          SsrfPlugin,
    "cors":          CorsPlugin,
    "cookies":       CookiesPlugin,
    "http_methods":  HttpMethodsPlugin,
    "ssl_tls":       SslTlsPlugin,
    "security_txt":  SecurityTxtPlugin,
    "tech_fingerprint": TechFingerprintPlugin,
    "subdomains":    SubdomainsPlugin,
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

    # --- Authentication ---
    ag = parser.add_argument_group("Authentication")
    ag.add_argument(
        "--cookie",
        metavar="STR",
        help='Raw cookie header to send with every request, e.g. "session=abc123".',
    )
    ag.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help='Extra header to send (repeatable), e.g. --header "Authorization: Bearer T".',
    )
    ag.add_argument(
        "--basic-auth",
        metavar="USER:PASS",
        help="HTTP Basic auth credentials.",
    )
    ag.add_argument(
        "--login-url",
        metavar="URL",
        help="Form login endpoint; POSTed with --login-data to capture a session.",
    )
    ag.add_argument(
        "--login-data",
        metavar="STR",
        help='URL-encoded login body, e.g. "username=admin&password=secret".',
    )

    # --- Network ---
    ng = parser.add_argument_group("Network & evasion")
    ng.add_argument(
        "--safe-mode",
        action="store_true",
        help="Gentle, polite scan: low rate limit, honest User-Agent, lower "
        "concurrency and robots.txt respected. Recommended for non-experts.",
    )
    ng.add_argument(
        "--proxy",
        metavar="URL",
        help="Route all requests through a proxy, e.g. http://127.0.0.1:8080 "
        "or socks5://127.0.0.1:9050.",
    )
    ng.add_argument(
        "--user-agent",
        metavar="STR",
        help="Override the User-Agent header for every request.",
    )
    ng.add_argument(
        "--random-agent",
        action="store_true",
        help="Rotate through a pool of common browser User-Agents.",
    )
    ng.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Seconds to wait before each target (rate limiting; default: 0).",
    )
    ng.add_argument(
        "--random-delay",
        action="store_true",
        help="Randomise --delay by ×0.5–×1.5 to look less automated.",
    )
    ng.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="N",
        help="Cap requests to at most N per second (sets a minimum delay).",
    )
    ng.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Skip TLS certificate verification (default for security scans).",
    )
    ng.add_argument(
        "--no-bruteforce",
        action="store_true",
        help="Disable DNS subdomain brute force (subdomains plugin uses CT only).",
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
        choices=["json", "md", "html", "sarif", "csv"],
        default=["json", "md"],
        metavar="FMT",
        help="Output format(s): json, md, html, sarif, csv (default: json md).",
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
    og.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour in the console summary.",
    )
    og.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "info"],
        metavar="LEVEL",
        help="Only show findings at or above this severity in the console summary.",
    )
    og.add_argument(
        "--anonymize",
        action="store_true",
        help="Strip local paths, hostname/username and private IPs from reports "
        "before writing them (GDPR-friendly, safe to share externally).",
    )
    og.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info"],
        metavar="LEVEL",
        help="Exit with code 1 if any finding is at or above LEVEL "
        "(default: critical or high).",
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

def _build_ssl_ctx() -> ssl_lib.SSLContext:
    ctx = ssl_lib.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl_lib.CERT_NONE
    return ctx


async def _crawl_targets(
    seeds: list[str],
    args: argparse.Namespace,
    auth: PreparedAuth,
    net: NetConfig,
) -> list[str]:
    """Expand *seeds* into a deduplicated list of in-scope URLs via the crawler."""
    ctx = _build_ssl_ctx()

    config = CrawlConfig(
        max_depth=args.depth,
        max_urls=args.max_urls,
        scope=args.scope or "",
        respect_robots=not args.ignore_robots,
        exclude=args.exclude,
    )

    crawl_headers = dict(auth.headers)
    ua = pick_user_agent(net, 0, "")
    if ua:
        crawl_headers["User-Agent"] = ua

    discovered: list[str] = []
    seen: set[str] = set()
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=min(5, args.timeout))

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=aiohttp.TCPConnector(ssl=ctx),
        headers=crawl_headers or None,
        cookies=auth.cookies or None,
        trust_env=bool(net.proxy),
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

    # Resolve authentication (static material + optional form login).
    auth_config = AuthConfig(
        cookie=args.cookie or "",
        headers=args.header,
        basic_auth=args.basic_auth or "",
        login_url=args.login_url or "",
        login_data=args.login_data or "",
    )
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=min(5, args.timeout))
    try:
        auth = await prepare_auth(auth_config, _build_ssl_ctx(), timeout)
    except LoginError as exc:
        _die(str(exc))

    if not args.quiet and auth_config.is_configured():
        bits = []
        if auth.cookies:
            bits.append(f"{len(auth.cookies)} cookie(s)")
        if auth.headers:
            bits.append(f"{len(auth.headers)} header(s)")
        print(f"  Auth        : {', '.join(bits) or 'configured'}")

    # Safe Mode: a gentle, polite preset for non-experts. Caps the request
    # rate, keeps an honest User-Agent, lowers concurrency and respects
    # robots.txt — unless the user has overridden any of these explicitly.
    rate_limit = args.rate_limit
    if args.safe_mode:
        if rate_limit <= 0:
            rate_limit = 2.0  # at most ~2 requests/second
        if args.concurrency > 4:
            args.concurrency = 4
        args.ignore_robots = False  # always be polite in safe mode
        if not args.quiet:
            print("  Safe Mode   : on (polite rate, honest UA, robots respected)")

    # Resolve network options. A proxy is wired in via aiohttp's trust_env,
    # so we publish it through the standard proxy environment variables.
    net = NetConfig(
        proxy=args.proxy or "",
        user_agent=args.user_agent or "",
        random_agent=args.random_agent and not args.safe_mode,
        delay=args.delay,
        random_delay=args.random_delay,
        rate_limit=rate_limit,
        verify_ssl=not args.no_verify_ssl,
    )
    if net.proxy:
        os.environ["HTTP_PROXY"] = net.proxy
        os.environ["HTTPS_PROXY"] = net.proxy
        if not args.quiet:
            print(f"  Proxy       : {net.proxy}")

    if args.crawl:
        if not args.quiet:
            print(f"  Crawling {len(targets)} seed(s) (depth={args.depth}) …")
        targets = await _crawl_targets(targets, args, auth, net)
        if not args.quiet:
            print(f"  Discovered {len(targets)} URL(s) to scan.")
            print()

    plugins: list[BasePlugin] = []
    for name in args.plugins:
        if name == "subdomains":
            plugins.append(SubdomainsPlugin(bruteforce=not args.no_bruteforce))
        else:
            plugins.append(ALL_PLUGINS[name]())
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
        auth_headers=auth.headers,
        auth_cookies=auth.cookies,
        proxy=net.proxy,
        user_agent=pick_user_agent(net, 0, ""),
        delay=net.base_delay(),
        random_delay=net.random_delay,
    )
    report = await engine.scan_all(targets)

    if not quiet:
        print()  # end progress line
        print()

    if args.anonymize:
        report = anonymize_report(report)
        if not quiet:
            print("  Anonymize   : on (paths, host/user and private IPs redacted)")

    reporter = Reporter(report)

    # Print summary / detailed findings to stdout
    if not quiet:
        use_color = not args.no_color and sys.stdout.isatty()
        min_sev = Severity(args.min_severity) if args.min_severity else None
        print(f"  Scan completed  {report.scan_started} → {report.scan_finished}")
        print(f"  Total findings  {report.total_findings}")
        print()
        print(reporter.to_console_summary(color=use_color, min_severity=min_sev))
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

        if "html" in args.format:
            p = base.with_suffix(".html")
            reporter.to_html(p)
            if not quiet:
                print(f"  ✍  HTML report : {p}")

        if "sarif" in args.format:
            p = base.with_suffix(".sarif")
            reporter.to_sarif(p)
            if not quiet:
                print(f"  ✍  SARIF report: {p}")

        if "csv" in args.format:
            p = base.with_suffix(".csv")
            reporter.to_csv(p)
            if not quiet:
                print(f"  ✍  CSV report  : {p}")

        if not quiet:
            print()

    # Non-zero exit when findings meet the failure threshold. Default: any
    # CRITICAL or HIGH finding. --fail-on LEVEL lowers/raises that bar.
    if args.fail_on:
        threshold = SEVERITY_ORDER[Severity(args.fail_on)]
    else:
        threshold = SEVERITY_ORDER[Severity.HIGH]
    triggered = any(
        SEVERITY_ORDER.get(f.severity, 99) <= threshold
        for tr in report.targets
        for f in tr.findings
    )
    return 1 if triggered else 0


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

    if not args.quiet:
        print(_disclaimer_text(), file=sys.stderr)

    exit_code = asyncio.run(_run(args))
    sys.exit(exit_code)


def _die(msg: str) -> NoReturn:
    print(f"[!] {msg}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()

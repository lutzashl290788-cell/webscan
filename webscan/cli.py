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
from webscan.config import ConfigError, load_profile
from webscan.crawler import CrawlConfig, Crawler
from webscan.engine import ScanEngine, _build_redirect_safe_trace
from webscan.models import SEVERITY_ORDER, Confidence, ScanReport, Severity
from webscan.net import NetConfig, pick_user_agent
from webscan.plugins.base import BasePlugin
from webscan.registry import (
    ALL_PLUGINS,
    DEFAULT_PLUGINS,
    OPT_IN_PLUGINS,
    build_plugins,
)
from webscan.reporter import Reporter, filter_report_by_confidence
from webscan.retry import RetryConfig

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

# The plugin registry (ALL_PLUGINS, DEFAULT_PLUGINS, OPT_IN_PLUGINS,
# build_plugins) lives in webscan.registry, shared with the library API.

# Supported report output formats.
_OUTPUT_FORMATS = ["json", "jsonl", "md", "html", "sarif", "csv"]


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
  webscan serve --host 127.0.0.1 --port 8000   # local HTTP backend ([serve] extra)
""",
    )

    _add_config_args(parser)
    _add_target_args(parser)
    _add_crawler_args(parser)
    _add_auth_args(parser)
    _add_network_args(parser)
    _add_plugin_args(parser)
    _add_output_args(parser)
    _add_performance_args(parser)
    return parser


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    cg = parser.add_argument_group("Config file")
    cg.add_argument(
        "--config",
        metavar="FILE",
        help="YAML config file with reusable scan settings. CLI flags override "
        "values from the file.",
    )
    cg.add_argument(
        "--profile",
        metavar="NAME",
        help="Named profile to select from a config file's 'profiles:' section.",
    )


def _add_target_args(parser: argparse.ArgumentParser) -> None:
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


def _add_crawler_args(parser: argparse.ArgumentParser) -> None:
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


def _add_auth_args(parser: argparse.ArgumentParser) -> None:
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


def _add_network_args(parser: argparse.ArgumentParser) -> None:
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
        "--retries",
        type=int,
        default=2,
        metavar="N",
        help="Retries on transient errors (timeouts, 429/5xx) for external "
        "lookups, with exponential backoff (default: 2).",
    )
    ng.add_argument(
        "--retry-backoff",
        type=float,
        default=0.5,
        metavar="SEC",
        help="Base backoff delay before the first retry; doubles each attempt "
        "(default: 0.5).",
    )
    ng.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Skip TLS certificate verification (default for security scans). "
        "Kept for backward compatibility — the scanner always skips verification "
        "by default. Use --strict-ssl to enforce verification instead.",
    )
    ng.add_argument(
        "--strict-ssl",
        action="store_true",
        help="Enforce TLS certificate verification. By default the scanner skips "
        "verification so it can audit hosts with self-signed or expired certs. "
        "Enable this when scanning production sites where a valid cert is expected "
        "and a verification failure is itself a finding.",
    )
    ng.add_argument(
        "--no-bruteforce",
        action="store_true",
        help="Disable DNS subdomain brute force (subdomains plugin uses CT only).",
    )
    ng.add_argument(
        "--soft-404",
        action="store_true",
        help="Calibrate against a non-existent path first and suppress "
        "directories/config_files findings that match the server's soft-404 "
        "page (cuts false positives on sites that answer 200 for everything).",
    )


def _add_plugin_args(parser: argparse.ArgumentParser) -> None:
    pg = parser.add_argument_group("Plugins")
    pg.add_argument(
        "--plugins",
        nargs="+",
        choices=list(ALL_PLUGINS.keys()),
        default=DEFAULT_PLUGINS,
        metavar="NAME",
        help=(
            f"Plugins to enable (default: all except opt-in). "
            f"Opt-in (network-heavy): {', '.join(sorted(OPT_IN_PLUGINS))}. "
            f"Available: {', '.join(ALL_PLUGINS.keys())}."
        ),
    )
    pg.add_argument(
        "--list-plugins",
        action="store_true",
        help="Print available plugins and exit.",
    )


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    og = parser.add_argument_group("Output")
    og.add_argument(
        "-o", "--output",
        metavar="PATH",
        help="Base path for report files, without extension (e.g. ./reports/scan).",
    )
    og.add_argument(
        "--format",
        nargs="+",
        choices=_OUTPUT_FORMATS,
        default=["json", "md"],
        metavar="FMT",
        help="Output format(s): json, jsonl, md, html, sarif, csv (default: json md).",
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
        "--min-confidence",
        choices=["firm", "tentative", "informational"],
        metavar="LEVEL",
        help="Drop findings below this confidence from ALL output (reports too). "
        "'firm' keeps only directly-observed results (strongest false-positive "
        "filter); 'tentative' also keeps heuristic ones; default keeps all.",
    )
    og.add_argument(
        "--explain",
        action="store_true",
        help="Print a plain-language explanation under each finding (beginner-friendly).",
    )
    og.add_argument(
        "--ai-triage",
        action="store_true",
        help="Use Claude to review findings and flag likely false positives "
        "(needs ANTHROPIC_API_KEY and the [ai] extra; silently skipped otherwise).",
    )
    og.add_argument(
        "--ai-summary",
        action="store_true",
        help="Print a Claude-written plain-language executive summary of the scan "
        "(needs ANTHROPIC_API_KEY and the [ai] extra; silently skipped otherwise).",
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


def _add_performance_args(parser: argparse.ArgumentParser) -> None:
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
        concurrency=max(1, args.concurrency),
    )

    crawl_headers = dict(auth.headers)
    ua = pick_user_agent(net, 0, "")
    if ua:
        crawl_headers["User-Agent"] = ua

    discovered: list[str] = []
    seen: set[str] = set()
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=min(3, args.timeout))

    async with aiohttp.ClientSession(
        timeout=timeout,
        connector=aiohttp.TCPConnector(ssl=ctx),
        headers=crawl_headers or None,
        cookies=auth.cookies or None,
        trust_env=bool(net.proxy),
        # Strip Authorization / Cookie / X-API-Key / X-Auth-Token /
        # Proxy-Authorization when aiohttp follows a redirect to a different
        # host. The crawler session carries auth headers/cookies; without
        # this, a page that 302-redirects to an attacker host would replay
        # the credentials there (CWE-200 / CWE-522 — same issue H-1 fixed
        # for the engine session in v2.5.1).
        trace_configs=[_build_redirect_safe_trace()],
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


def _apply_safe_mode(args: argparse.Namespace) -> float:
    """Apply the polite Safe-Mode preset and return the effective rate limit."""
    rate_limit: float = args.rate_limit
    if args.safe_mode:
        if rate_limit <= 0:
            rate_limit = 2.0  # at most ~2 requests/second
        args.concurrency = min(args.concurrency, 8)
        args.ignore_robots = False  # always be polite in safe mode
    return rate_limit


def _resolve_net(args: argparse.Namespace, rate_limit: float) -> NetConfig:
    """Build the network config and publish proxy env vars for aiohttp."""
    net = NetConfig(
        proxy=args.proxy or "",
        user_agent=args.user_agent or "",
        random_agent=args.random_agent and not args.safe_mode,
        delay=args.delay,
        random_delay=args.random_delay,
        rate_limit=rate_limit,
        verify_ssl=bool(args.strict_ssl),
    )
    if net.proxy:
        os.environ["HTTP_PROXY"] = net.proxy
        os.environ["HTTPS_PROXY"] = net.proxy
    return net


async def _resolve_auth(args: argparse.Namespace) -> PreparedAuth:
    """Resolve static credentials and perform an optional form login."""
    auth_config = AuthConfig(
        cookie=args.cookie or "",
        headers=args.header,
        basic_auth=args.basic_auth or "",
        login_url=args.login_url or "",
        login_data=args.login_data or "",
    )
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=min(3, args.timeout))
    try:
        return await prepare_auth(auth_config, _build_ssl_ctx(), timeout)
    except LoginError as exc:
        _die(str(exc))


def _make_plugins(args: argparse.Namespace) -> list[BasePlugin]:
    """Instantiate the selected plugins, honouring plugin-specific options."""
    retry = RetryConfig(
        retries=max(0, args.retries),
        base_delay=max(0.0, args.retry_backoff),
    )
    return build_plugins(
        args.plugins,
        soft_404=args.soft_404,
        bruteforce=not args.no_bruteforce,
        retry=retry,
    )


def _write_reports(reporter: Reporter, args: argparse.Namespace) -> None:
    """Write every requested report format to disk."""
    writers = {
        "json": (".json", reporter.to_json),
        "jsonl": (".jsonl", reporter.to_jsonl),
        "md": (".md", reporter.to_markdown),
        "html": (".html", reporter.to_html),
        "sarif": (".sarif", reporter.to_sarif),
        "csv": (".csv", reporter.to_csv),
    }
    base = Path(args.output)
    base.parent.mkdir(parents=True, exist_ok=True)
    for fmt in args.format:
        suffix, writer = writers[fmt]
        path = base.with_suffix(suffix)
        writer(path)
        if not args.quiet:
            print(f"  ✍  {fmt.upper():<5} report : {path}")
    if not args.quiet:
        print()


def _exit_code(report: ScanReport, args: argparse.Namespace) -> int:
    """Return 1 if any finding meets the (default or --fail-on) threshold."""
    level = Severity(args.fail_on) if args.fail_on else Severity.HIGH
    threshold = SEVERITY_ORDER[level]
    triggered = any(
        SEVERITY_ORDER.get(f.severity, 99) <= threshold
        for tr in report.targets
        for f in tr.findings
    )
    return 1 if triggered else 0


async def _run_ai(report: ScanReport, args: argparse.Namespace, quiet: bool) -> str:
    """Run the optional Claude AI layer; return an executive summary (or '').

    Fail-safe: if the SDK or key is missing, or the API errors, this prints a
    one-line note (when not quiet) and returns without affecting the scan.
    """
    from webscan.ai import AIAssistant

    assistant = AIAssistant()
    if not assistant.available:
        if not quiet:
            print(
                "  AI          : skipped (set ANTHROPIC_API_KEY and "
                "install 'webscan-security[ai]')"
            )
        return ""

    if args.ai_triage:
        if not quiet:
            print("  AI triage   : reviewing findings for false positives …")
        await assistant.triage_report(report)

    summary = ""
    if args.ai_summary:
        if not quiet:
            print("  AI summary  : generating …")
        summary = await assistant.summarize_report(report)
    return summary


async def _run(args: argparse.Namespace) -> int:
    targets = _load_targets(args)
    if not targets:
        _die("No targets specified. Use -t URL or -f FILE.")

    quiet: bool = args.quiet
    auth = await _resolve_auth(args)
    rate_limit = _apply_safe_mode(args)
    net = _resolve_net(args, rate_limit)

    if not quiet:
        _print_setup(args, auth, net)

    if args.crawl:
        if not quiet:
            print(f"  Crawling {len(targets)} seed(s) (depth={args.depth}) …")
        targets = await _crawl_targets(targets, args, auth, net)
        if not quiet:
            print(f"  Discovered {len(targets)} URL(s) to scan.\n")

    plugins = _make_plugins(args)

    def _progress(target: str, done: int, total: int) -> None:
        if not quiet:
            bar = "█" * done + "░" * (total - done)
            # Mask any user:password embedded in the target URL before
            # printing — same rationale as _mask_proxy_url (CWE-532).
            safe_target = _mask_proxy_url(target)
            print(f"\r  [{bar}] {done}/{total} — {safe_target[:60]:<60}", end="", flush=True)

    if not quiet:
        _print_banner(targets, plugins, args)

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
        verify_ssl=bool(getattr(args, "strict_ssl", False)),
    )
    report = await engine.scan_all(targets)
    if not quiet:
        print("\n")

    if args.min_confidence:
        report = filter_report_by_confidence(report, Confidence(args.min_confidence))
        if not quiet:
            print(f"  Confidence  : ≥ {args.min_confidence} (lower-confidence findings dropped)")

    ai_summary = ""
    if args.ai_triage or args.ai_summary:
        ai_summary = await _run_ai(report, args, quiet)

    if args.anonymize:
        report = anonymize_report(report)
        if not quiet:
            print("  Anonymize   : on (paths, host/user and private IPs redacted)")

    reporter = Reporter(report)

    if not quiet:
        use_color = not args.no_color and sys.stdout.isatty()
        min_sev = Severity(args.min_severity) if args.min_severity else None
        print(f"  Scan completed  {report.scan_started} → {report.scan_finished}")
        print(f"  Total findings  {report.total_findings}\n")
        print(reporter.to_console_summary(
            color=use_color, min_severity=min_sev, explain=args.explain
        ))
        print()
        if ai_summary:
            print("  AI summary")
            print("  ─────────")
            for line in ai_summary.splitlines():
                print(f"  {line}")
            print()

    if args.output:
        _write_reports(reporter, args)

    return _exit_code(report, args)


def _print_setup(
    args: argparse.Namespace, auth: PreparedAuth, net: NetConfig
) -> None:
    """Print the auth / safe-mode / proxy status lines before scanning."""
    if (args.cookie or args.header or args.basic_auth or args.login_url) and (
        auth.cookies or auth.headers
    ):
        bits = []
        if auth.cookies:
            bits.append(f"{len(auth.cookies)} cookie(s)")
        if auth.headers:
            bits.append(f"{len(auth.headers)} header(s)")
        print(f"  Auth        : {', '.join(bits) or 'configured'}")
    if args.safe_mode:
        print("  Safe Mode   : on (polite rate, honest UA, robots respected)")
    if net.proxy:
        print(f"  Proxy       : {_mask_proxy_url(net.proxy)}")


def _mask_proxy_url(url: str) -> str:
    """Redact user:password in a proxy URL before printing (CWE-532).

    ``http://user:secret@proxy.local:8080`` → ``http://***@proxy.local:8080``.
    Plain URLs without credentials are returned unchanged.
    """
    from urllib.parse import urlparse, urlunparse

    p = urlparse(url)
    if p.username or p.password:
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        p = p._replace(netloc=f"***@{host}")
    return urlunparse(p)


def _print_banner(
    targets: list[str], plugins: list[BasePlugin], args: argparse.Namespace
) -> None:
    """Print the scan header banner."""
    print("╔══════════════════════════════════════════════════════════╗")
    print("║              WebScan — Security Auditor                 ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"  Targets     : {len(targets)}")
    print(f"  Plugins     : {', '.join(p.name for p in plugins)}")
    print(f"  Concurrency : {args.concurrency}")
    print(f"  Timeout     : {args.timeout}s")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Entry points
# ──────────────────────────────────────────────────────────────────────────────

def _apply_config(parser: argparse.ArgumentParser) -> None:
    """Fold a --config profile into the parser defaults (CLI still overrides).

    Resolved before the final parse so precedence is: explicit CLI flag >
    config-file value > built-in default.
    """
    pre, _ = parser.parse_known_args()
    if not pre.config:
        return
    try:
        profile = load_profile(pre.config, pre.profile)
    except ConfigError as exc:
        _die(str(exc))

    bad_plugins = [p for p in profile.get("plugins", []) if p not in ALL_PLUGINS]
    if bad_plugins:
        _die(f"Unknown plugin(s) in config: {', '.join(bad_plugins)}")
    bad_formats = [f for f in profile.get("format", []) if f not in _OUTPUT_FORMATS]
    if bad_formats:
        _die(f"Unknown format(s) in config: {', '.join(bad_formats)}")

    parser.set_defaults(**profile)


def _serve(argv: list[str]) -> NoReturn:
    """Handle the ``webscan serve`` subcommand and exit.

    Kept separate from the flat scan parser so the scanning CLI is untouched:
    ``serve`` is only recognised as the very first argument. Needs the ``serve``
    extra (fastapi/uvicorn); a missing dependency yields a clear install hint.
    """
    sub = argparse.ArgumentParser(
        prog="webscan serve",
        description="Run the local HTTP backend (needs the [serve] extra).",
    )
    sub.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1).")
    sub.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000).")
    opts = sub.parse_args(argv)

    from webscan.server import run_server, server_available

    if not server_available():
        _die(
            "The 'serve' extra is not installed. "
            "Run: pip install 'webscan-security[serve]'"
        )
    print(f"WebScan server listening on http://{opts.host}:{opts.port}", file=sys.stderr)
    try:
        run_server(host=opts.host, port=opts.port)
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        pass
    sys.exit(0)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        _serve(sys.argv[2:])

    parser = _build_parser()
    _apply_config(parser)
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

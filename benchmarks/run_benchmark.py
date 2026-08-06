"""Score WebScan against the ground truth of the local vulnerable target.

Speed alone says little about a scanner. This runner measures the two numbers
that decide whether a report can be trusted:

* **precision** — of everything reported, how much was real (false positives),
* **recall** — of everything actually there, how much was found (false
  negatives, the failure mode a scanner never shows you).

Both are computable here only because the target ships a machine-readable list
of what is wrong with it (:data:`benchmarks.vulnerable_target.GROUND_TRUTH`).

Usage::

    python benchmarks/run_benchmark.py              # 3 timed runs, table to stdout
    python benchmarks/run_benchmark.py --runs 5 --json results.json
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.vulnerable_target import DEFAULT_PORT, GROUND_TRUTH, HOST  # noqa: E402

STARTUP_TIMEOUT = 15.0
SCAN_TIMEOUT = 600


def _wait_for_port(port: int, timeout: float = STARTUP_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((HOST, port)) == 0:
                return True
        time.sleep(0.1)
    return False


def _start_target(port: int) -> subprocess.Popen[bytes]:
    target = Path(__file__).parent / "vulnerable_target.py"
    proc = subprocess.Popen(
        [sys.executable, str(target), "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if not _wait_for_port(port):
        proc.terminate()
        raise RuntimeError(f"vulnerable target failed to start on port {port}")
    return proc


def _run_scan(port: int, extra_args: list[str]) -> tuple[float, dict]:
    """Run one scan, returning (wall_clock_seconds, parsed_report)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report"
        cmd = [
            "webscan", "-t", f"http://{HOST}:{port}",
            "--crawl", "--depth", "2",
            "-o", str(out), "--format", "json",
            "--no-color", "-q", *extra_args,
        ]
        started = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, timeout=SCAN_TIMEOUT)
        elapsed = time.perf_counter() - started

        report_path = out.with_suffix(".json")
        if not report_path.exists():
            raise RuntimeError(
                f"no report written (exit {proc.returncode})\n"
                f"{proc.stderr.decode(errors='ignore')[-2000:]}"
            )
        return elapsed, json.loads(report_path.read_text())


def _findings(report: dict) -> list[dict]:
    return [f for target in report.get("targets", []) for f in target.get("findings", [])]


def _unique_issues(findings: list[dict]) -> list[dict]:
    """Collapse findings to one entry per distinct (plugin, title).

    A crawl visits many URLs, so a site-wide problem like a missing CSP header
    is reported once per page. Those repeats are the same defect and counting
    them individually would flatter or punish the scanner arbitrarily —
    accuracy is about distinct issues, not row count.
    """
    seen: dict[tuple[str, str], dict] = {}
    for finding in findings:
        key = ((finding.get("plugin") or "").lower(), (finding.get("title") or "").lower())
        entry = seen.setdefault(key, {**finding, "occurrences": 0})
        entry["occurrences"] += 1
    return list(seen.values())


def score(findings: list[dict], active_plugins: set[str] | None = None) -> dict:
    """Match findings against the ground truth, returning a scorecard.

    Ground-truth entries whose plugin is not in *active_plugins* are excluded:
    WebScan ships five opt-in plugins, and holding a scan responsible for a
    check it was never asked to run would understate recall.
    """
    expected = [
        gt for gt in GROUND_TRUTH
        if active_plugins is None or gt["plugin"] in active_plugins
    ]
    skipped = [gt for gt in GROUND_TRUTH if gt not in expected]

    issues = _unique_issues(findings)
    detected: dict[str, list[dict]] = {gt["id"]: [] for gt in expected}
    false_positives: list[dict] = []

    for finding in issues:
        plugin = (finding.get("plugin") or "").lower()
        title = (finding.get("title") or "").lower()
        hit = next(
            (gt for gt in expected
             if gt["plugin"] == plugin and gt["match"] in title),
            None,
        )
        if hit is None:
            false_positives.append(finding)
        else:
            detected[hit["id"]].append(finding)

    found = [gt for gt in expected if detected[gt["id"]]]
    missed = [gt for gt in expected if not detected[gt["id"]]]

    tp, fp, fn = len(found), len(false_positives), len(missed)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "planted": len(GROUND_TRUTH),
        "expected": len(expected),
        "skipped_opt_in": [{"id": gt["id"], "plugin": gt["plugin"]} for gt in skipped],
        "findings": len(findings),
        "unique_issues": len(issues),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "detected_ids": [gt["id"] for gt in found],
        "missed": missed,
        "unmatched_findings": false_positives,
    }


def _active_plugins(scan_args: list[str]) -> set[str]:
    """Which plugins a scan with *scan_args* actually runs.

    Mirrors the CLI: `--plugins a b c` selects explicitly, otherwise the
    default set runs (which excludes the opt-in plugins).
    """
    from webscan.registry import DEFAULT_PLUGINS

    if "--plugins" in scan_args:
        selected: list[str] = []
        for arg in scan_args[scan_args.index("--plugins") + 1:]:
            if arg.startswith("-"):
                break
            selected.append(arg)
        if selected:
            return set(selected)
    return set(DEFAULT_PLUGINS)


def _severity_breakdown(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "unknown").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3, help="timed runs (default: 3)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--json", type=Path, help="write the full scorecard here")
    parser.add_argument(
        "--scan-args", nargs=argparse.REMAINDER, default=[],
        help="extra flags passed through to webscan",
    )
    args = parser.parse_args()

    if shutil.which("webscan") is None:
        print("error: `webscan` is not on PATH — run `pip install -e .` first", file=sys.stderr)
        return 1

    proc = _start_target(args.port)
    try:
        timings: list[float] = []
        report: dict = {}
        for i in range(args.runs):
            elapsed, report = _run_scan(args.port, args.scan_args)
            timings.append(elapsed)
            print(f"  run {i + 1}/{args.runs}: {elapsed:.2f}s", file=sys.stderr)
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    findings = _findings(report)
    card = score(findings, active_plugins=_active_plugins(args.scan_args))
    card["runs"] = args.runs
    card["seconds_best"] = min(timings)
    card["seconds_mean"] = sum(timings) / len(timings)
    card["severity"] = _severity_breakdown(_unique_issues(findings))

    print()
    print(f"  planted weaknesses : {card['planted']}")
    if card["skipped_opt_in"]:
        names = ", ".join(sorted({s["plugin"] for s in card["skipped_opt_in"]}))
        print(f"  scored against     : {card['expected']} "
              f"(excludes opt-in plugins not run: {names})")
    print(f"  findings reported  : {card['findings']} "
          f"({card['unique_issues']} distinct issues after collapsing per-URL repeats)")
    print(f"  true positives     : {card['true_positives']}")
    print(f"  false positives    : {card['false_positives']}")
    print(f"  missed (FN)        : {card['false_negatives']}")
    print(f"  precision          : {card['precision']:.1%}")
    print(f"  recall             : {card['recall']:.1%}")
    print(f"  F1                 : {card['f1']:.3f}")
    print(f"  time (best of {args.runs})  : {card['seconds_best']:.2f}s")
    print(f"  time (mean)        : {card['seconds_mean']:.2f}s")
    print(f"  severity           : {card['severity']}")

    if card["missed"]:
        print("\n  MISSED:")
        for gt in card["missed"]:
            print(f"    - [{gt['plugin']}] {gt['id']}: {gt['note']}")

    if card["unmatched_findings"]:
        print("\n  UNMATCHED (candidate false positives — verify by hand):")
        for f in card["unmatched_findings"]:
            print(f"    - [{f.get('plugin')}] {f.get('severity')}: {f.get('title')}")

    if args.json:
        args.json.write_text(json.dumps(card, indent=2))
        print(f"\n  scorecard written to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

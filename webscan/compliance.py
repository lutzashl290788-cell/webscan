"""Compliance mapping — map WebScan findings to OWASP Top 10 2021 categories.

Enterprise security teams need to show compliance with standards like OWASP
Top 10, PCI-DSS, or ISO 27001. This module maps each WebScan plugin to one or
more OWASP Top 10 2021 categories, so the report can include a compliance
dashboard showing which categories are covered and which have findings.

Usage::

    from webscan.compliance import map_findings, compliance_summary

    mapping = map_findings(report)
    summary = compliance_summary(mapping)
    for cat, count in summary:
        print(f"{cat}: {count} findings")
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webscan.models import ScanReport

# ─── OWASP Top 10 2021 ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class OWASPCategory:
    """A single OWASP Top 10 2021 category."""
    id: str          # "A01"
    name: str        # "Broken Access Control"
    description: str # short description


OWASP_TOP_10_2021: list[OWASPCategory] = [
    OWASPCategory("A01", "Broken Access Control",
                  "Restrictions on what authenticated users can do are not properly enforced."),
    OWASPCategory("A02", "Cryptographic Failures",
                  "Failures related to cryptography, often leading to exposure of sensitive data."),
    OWASPCategory("A03", "Injection",
                  "User-supplied data is not validated, filtered, or sanitized by the "
                  "application."),
    OWASPCategory("A04", "Insecure Design",
                  "Missing or ineffective control design — not implementation bugs."),
    OWASPCategory("A05", "Security Misconfiguration",
                  "Missing hardening, default accounts, verbose error messages, "
                  "unnecessary features."),
    OWASPCategory("A06", "Vulnerable and Outdated Components",
                  "Using components with known vulnerabilities or outdated versions."),
    OWASPCategory("A07", "Identification and Authentication Failures",
                  "Weak authentication, session management, or credential handling."),
    OWASPCategory("A08", "Software and Data Integrity Failures",
                  "Code and infrastructure that does not protect against integrity violations."),
    OWASPCategory("A09", "Security Logging and Monitoring Failures",
                  "Insufficient logging, monitoring, and alerting to detect active breaches."),
    OWASPCategory("A10", "Server-Side Request Forgery (SSRF)",
                  "Web app fetches a remote resource without validating the user-supplied URL."),
]

# Map plugin name → OWASP categories (a plugin can map to multiple).
_PLUGIN_TO_OWASP: dict[str, list[str]] = {
    # A01: Broken Access Control
    "idor": ["A01"],
    "mass_assignment": ["A01"],
    "csrf": ["A01"],
    "cookies": ["A01", "A07"],  # missing Secure/HttpOnly/SameSite → access control + auth
    "clickjacking": ["A01"],

    # A02: Cryptographic Failures
    "ssl_tls": ["A02"],
    "jwt_audit": ["A02", "A07"],  # weak JWT crypto + auth issues
    "secrets": ["A02"],

    # A03: Injection
    "sql_injection": ["A03"],
    "xss": ["A03"],
    "ssti": ["A03"],
    "lfi_rfi": ["A03"],
    "xxe": ["A03"],
    "path_traversal": ["A03"],
    "graphql_depth": ["A03"],
    "prototype_pollution": ["A03"],

    # A05: Security Misconfiguration
    "headers": ["A05"],
    "cors": ["A05"],
    "http_methods": ["A05"],
    "config_files": ["A05"],
    "directories": ["A05"],
    "backup_files": ["A05"],
    "security_txt": ["A05"],
    "robots_sitemap": ["A05"],
    "verbose_errors": ["A05"],
    "file_upload": ["A05"],
    "websocket_security": ["A05"],
    "web_cache_deception": ["A05"],
    "cache_poisoning": ["A05"],
    "host_header_injection": ["A05"],
    "request_smuggling": ["A05"],
    "race_condition": ["A05"],

    # A06: Vulnerable Components
    "cve_lookup": ["A06"],
    "tech_fingerprint": ["A06"],

    # A07: Auth Failures (already mapped above where relevant)
    "open_redirect": ["A01"],  # redirect → access control / phishing

    # A08: Software & Data Integrity Failures
    # (no direct WebScan plugin maps here yet)

    # A09: Logging & Monitoring Failures
    # (no direct WebScan plugin — scanners don't detect missing logs well)

    # A10: SSRF
    "ssrf": ["A10"],
    "subdomains": ["A10"],  # subdomain discovery supports SSRF reconnaissance

    # Passive discovery — no specific OWASP category
    "graphql": ["A03"],  # GraphQL introspection → injection surface
}


@dataclass
class ComplianceMapping:
    """Result of mapping a report's findings to compliance categories."""
    # category_id → list of (plugin, title, severity) tuples
    by_category: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)
    # Unmapped plugins (no OWASP mapping defined)
    unmapped: list[tuple[str, str, str]] = field(default_factory=list)
    # Total findings mapped
    total_mapped: int = 0

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation."""
        return {
            "by_category": {
                cat: [
                    {"plugin": p, "title": t, "severity": s}
                    for p, t, s in findings
                ]
                for cat, findings in self.by_category.items()
            },
            "unmapped": [
                {"plugin": p, "title": t, "severity": s}
                for p, t, s in self.unmapped
            ],
            "total_mapped": self.total_mapped,
            "categories_affected": len(self.by_category),
            "total_categories": len(OWASP_TOP_10_2021),
        }


def map_findings(report: ScanReport) -> ComplianceMapping:
    """Map all findings in *report* to OWASP Top 10 2021 categories.

    Returns a :class:`ComplianceMapping` with findings grouped by category.
    Plugins without a mapping are collected in ``unmapped``.
    """
    mapping = ComplianceMapping()
    for tr in report.targets:
        for f in tr.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            entry = (f.plugin, f.title, sev)
            categories = _PLUGIN_TO_OWASP.get(f.plugin)
            if not categories:
                mapping.unmapped.append(entry)
                continue
            for cat_id in categories:
                if cat_id not in mapping.by_category:
                    mapping.by_category[cat_id] = []
                mapping.by_category[cat_id].append(entry)
            mapping.total_mapped += 1
    return mapping


def compliance_summary(mapping: ComplianceMapping) -> list[tuple[str, str, int, str]]:
    """Return a sorted summary of affected OWASP categories.

    Each tuple is ``(category_id, category_name, finding_count, severity_summary)``
    sorted by finding count (descending).
    """
    cat_lookup = {c.id: c for c in OWASP_TOP_10_2021}
    result: list[tuple[str, str, int, str]] = []
    for cat_id, findings in mapping.by_category.items():
        cat = cat_lookup.get(cat_id)
        if not cat:
            continue
        # Build severity summary: "2 high, 1 medium"
        sev_counts: dict[str, int] = {}
        for _, _, sev in findings:
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        sev_order = ["critical", "high", "medium", "low", "info"]
        parts = [f"{sev_counts[s]} {s}" for s in sev_order if sev_counts.get(s)]
        sev_summary = ", ".join(parts) if parts else "0"
        result.append((cat_id, cat.name, len(findings), sev_summary))
    # Sort by finding count descending, then by category ID.
    result.sort(key=lambda x: (-x[2], x[0]))
    return result


def compliance_gap_analysis(mapping: ComplianceMapping) -> list[tuple[str, str]]:
    """Return OWASP categories that have NO findings (compliance gaps).

    These are categories the scanner checked but found no issues — useful for
    compliance reporting ("we tested A01-A10 and found issues only in A03, A05").
    """
    affected = set(mapping.by_category.keys())
    all_cats = {c.id for c in OWASP_TOP_10_2021}
    gaps = sorted(all_cats - affected)
    cat_lookup = {c.id: c for c in OWASP_TOP_10_2021}
    return [(cat_id, cat_lookup[cat_id].name) for cat_id in gaps]

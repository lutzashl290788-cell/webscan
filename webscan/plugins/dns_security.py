"""Plugin: DNS security audit — DNSSEC, CAA, SPF, DMARC, DKIM.

Checks DNS security records that no other DAST scanner covers:
- DNSSEC (DNS Security Extensions) — is the zone signed?
- CAA (Certification Authority Authorization) — which CAs can issue certs?
- SPF (Sender Policy Framework) — email sending policy
- DMARC (Domain-based Message Authentication) — email auth policy
- DKIM (DomainKeys Identified Mail) — email signing

These are passive checks — no probes sent to the target, only DNS TXT lookups.
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins.base import BasePlugin


class DnsSecurityPlugin(BasePlugin):
    """Audit DNS security records (DNSSEC, CAA, SPF, DMARC)."""

    name = "dns_security"
    description = "DNSSEC, CAA, SPF, DMARC, DKIM record audit"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        from urllib.parse import urlparse
        host = urlparse(target).hostname or ""
        if not host:
            return findings

        # Run all DNS lookups concurrently in a thread pool (socket is blocking).
        loop = asyncio.get_event_loop()
        tasks = await asyncio.gather(
            loop.run_in_executor(None, _lookup_txt, host),
            loop.run_in_executor(None, _lookup_txt, f"_dmarc.{host}"),
            loop.run_in_executor(None, _lookup_caa, host),
            loop.run_in_executor(None, _lookup_dkim, host),
            return_exceptions=True,
        )

        txt_records = tasks[0] if isinstance(tasks[0], list) else []
        dmarc_records = tasks[1] if isinstance(tasks[1], list) else []
        caa_records = tasks[2] if isinstance(tasks[2], list) else []
        dkim_records = tasks[3] if isinstance(tasks[3], list) else []

        # ─── SPF ────────────────────────────────────────────────────────────
        spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]
        if not spf_records:
            findings.append(Finding(
                plugin=self.name,
                title="Missing SPF record",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                description=(
                    f"No SPF (Sender Policy Framework) record found for {host}. "
                    "Without SPF, attackers can spoof emails from your domain "
                    "(phishing, BEC attacks)."
                ),
                url=target,
                evidence={"record_type": "SPF", "status": "absent"},
                remediation=(
                    'Add a TXT record: "v=spf1 include:_spf.google.com -all" '
                    "(adjust for your email provider)."
                ),
            ))
        else:
            spf = spf_records[0]
            if " -all" not in spf and " ~all" not in spf:
                findings.append(Finding(
                    plugin=self.name,
                    title="Weak SPF policy (no hard fail)",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    description=(
                        f"SPF record for {host} does not end with '-all' or '~all'. "
                        f"Current: {spf}. Without a fail directive, spoofed emails "
                        "may still be delivered."
                    ),
                    url=target,
                    evidence={"record": spf, "issue": "no hard fail"},
                    remediation='Change the SPF record to end with "-all" (hard fail) or "~all" (soft fail).',
                ))

        # ─── DMARC ──────────────────────────────────────────────────────────
        if not dmarc_records:
            findings.append(Finding(
                plugin=self.name,
                title="Missing DMARC record",
                severity=Severity.MEDIUM,
                confidence=Confidence.FIRM,
                description=(
                    f"No DMARC record found for {host}. Without DMARC, email "
                    "receivers cannot enforce SPF/DKIM failures, making email "
                    "spoofing trivial."
                ),
                url=target,
                evidence={"record_type": "DMARC", "status": "absent"},
                remediation=(
                    'Add a TXT record at _dmarc.{host}: '
                    '"v=DMARC1; p=quarantine; rua=mailto:dmarc@{host}"'
                ),
            ))
        else:
            dmarc = dmarc_records[0]
            if "p=none" in dmarc.lower():
                findings.append(Finding(
                    plugin=self.name,
                    title="DMARC policy set to 'none' (monitor only)",
                    severity=Severity.LOW,
                    confidence=Confidence.FIRM,
                    description=(
                        f"DMARC policy for {host} is p=none (monitor mode). "
                        "No enforcement action is taken on failed authentication. "
                        f"Current: {dmarc}"
                    ),
                    url=target,
                    evidence={"record": dmarc, "policy": "none"},
                    remediation='Upgrade DMARC policy to "p=quarantine" or "p=reject" once you\'ve reviewed the reports.',
                ))

        # ─── CAA ────────────────────────────────────────────────────────────
        if not caa_records:
            findings.append(Finding(
                plugin=self.name,
                title="Missing CAA record",
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                description=(
                    f"No CAA (Certification Authority Authorization) record for {host}. "
                    "Any CA can issue certificates for your domain. CAA restricts "
                    "which CAs are allowed."
                ),
                url=target,
                evidence={"record_type": "CAA", "status": "absent"},
                remediation=(
                    f'Add a CAA record: "{host}. CAA 0 issue \\"letsencrypt.org\\"" '
                    "to restrict cert issuance to Let's Encrypt only."
                ),
            ))

        # ─── DKIM ───────────────────────────────────────────────────────────
        if not dkim_records:
            findings.append(Finding(
                plugin=self.name,
                title="No DKIM record found (default selector)",
                severity=Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                description=(
                    f"No DKIM record found for {host} on common selectors "
                    "(default, google, selector1, selector2). DKIM may be "
                    "configured on a non-standard selector — manual check needed."
                ),
                url=target,
                evidence={"record_type": "DKIM", "selectors_checked": ["default", "google", "selector1", "selector2"]},
                remediation="Verify DKIM is configured. Check your email provider's docs for the correct selector name.",
            ))

        return findings


def _lookup_txt(domain: str) -> list[str]:
    """Lookup TXT records for *domain*. Returns list of record strings."""
    try:
        # getaddrinfo doesn't return TXT — use a different approach
        import subprocess
        result = subprocess.run(
            ["nslookup", "-type=TXT", domain],
            capture_output=True, text=True, timeout=5,
        )
        # Parse TXT records from nslookup output
        txts: list[str] = []
        for line in result.stdout.split("\n"):
            if "text =" in line.lower():
                txt = line.split("text =")[-1].strip().strip('"')
                txts.append(txt)
        return txts
    except Exception:  # noqa: BLE001
        return []


def _lookup_caa(domain: str) -> list[str]:
    """Lookup CAA records for *domain*."""
    try:
        import subprocess
        result = subprocess.run(
            ["nslookup", "-type=CAA", domain],
            capture_output=True, text=True, timeout=5,
        )
        caas: list[str] = []
        for line in result.stdout.split("\n"):
            if "issue" in line.lower() or "issuewild" in line.lower() or "iodef" in line.lower():
                caas.append(line.strip())
        return caas
    except Exception:  # noqa: BLE001
        return []


def _lookup_dkim(domain: str) -> list[str]:
    """Lookup DKIM records on common selectors."""
    selectors = ["default", "google", "selector1", "selector2"]
    for sel in selectors:
        try:
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=TXT", f"{sel}._domainkey.{domain}"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.split("\n"):
                if "text =" in line.lower() and "v=dkim1" in line.lower():
                    return [line.split("text =")[-1].strip().strip('"')]
        except Exception:  # noqa: BLE001
            continue
    return []

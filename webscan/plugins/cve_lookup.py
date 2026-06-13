"""Plugin: map detected software/versions to known CVEs.

WebScan fingerprints product + version pairs from response headers (Server,
X-Powered-By). This plugin queries the NVD API — which indexes the same
MITRE / CVE.org records and, unlike cve.org, is keyword-searchable — and reports
matching CVEs, linking each to its official record on https://www.cve.org.

Network use is bounded (few products, few CVEs each, short timeout) and fully
fail-safe: any error yields no findings rather than aborting the scan.
"""
from __future__ import annotations

import asyncio
import json
import re

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin
from webscan.retry import RetryConfig, request_with_retry

_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CVE_ORG = "https://www.cve.org/CVERecord?id={cve_id}"

# Headers that commonly carry a "product/version" banner.
_VERSION_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version")
# e.g. "nginx/1.25.1", "Apache/2.4.57", "PHP/8.2.0"
_PRODUCT_VERSION = re.compile(r"([A-Za-z][A-Za-z0-9.\-]*?)/(\d+\.\d+(?:\.\d+)?)")

_MAX_PRODUCTS = 3
_MAX_CVES_PER_PRODUCT = 5

# Map NVD CVSS base severities to WebScan severities.
_CVSS_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class CveLookupPlugin(BasePlugin):
    """Looks up known CVEs for product/version banners exposed by the target."""

    name = "cve_lookup"
    description = "Look up known CVEs for detected software versions (cve.org)"

    def __init__(self, retry: RetryConfig | None = None) -> None:
        # External API (NVD) — be resilient to rate limiting / transient 5xx.
        self._retry = retry or RetryConfig(retries=2, base_delay=1.0)

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        products = await self._detect_products(target, session)
        if not products:
            return []

        findings: list[Finding] = []
        for product, version in products[:_MAX_PRODUCTS]:
            for cve in await self._query_cves(session, product, version):
                findings.append(self._to_finding(target, product, version, cve))
        return findings

    async def _detect_products(
        self, target: str, session: aiohttp.ClientSession
    ) -> list[tuple[str, str]]:
        try:
            async with session.get(target, ssl=False) as resp:
                headers = resp.headers
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return []

        seen: set[tuple[str, str]] = set()
        products: list[tuple[str, str]] = []
        for header in _VERSION_HEADERS:
            value = headers.get(header, "")
            for match in _PRODUCT_VERSION.finditer(value):
                product, version = match.group(1).lower(), match.group(2)
                if (product, version) not in seen:
                    seen.add((product, version))
                    products.append((product, version))
        return products

    async def _query_cves(
        self, session: aiohttp.ClientSession, product: str, version: str
    ) -> list[dict[str, object]]:
        params = {
            "keywordSearch": f"{product} {version}",
            "resultsPerPage": str(_MAX_CVES_PER_PRODUCT),
        }
        resp = await request_with_retry(
            session, "GET", _NVD_API,
            config=self._retry,
            params=params, ssl=False,
            timeout=aiohttp.ClientTimeout(total=12),
        )
        if resp is None or resp.status != 200:
            return []
        try:
            data = json.loads(resp.text)
        except (ValueError, TypeError):
            return []
        vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else []
        return [v["cve"] for v in vulns if isinstance(v, dict) and "cve" in v]

    def _to_finding(
        self, target: str, product: str, version: str, cve: dict[str, object]
    ) -> Finding:
        cve_id = str(cve.get("id", "CVE-UNKNOWN"))
        year = _year_from_id(cve_id)
        description = _english_description(cve)
        severity = _cve_severity(cve)

        return Finding(
            plugin=self.name,
            title=f"{cve_id} affects {product} {version}",
            severity=severity,
            description=(
                f"{product} {version} is associated with {cve_id} "
                f"({year}). {description}"
            ),
            url=target,
            evidence={
                "cve_id": cve_id,
                "year": year,
                "product": f"{product} {version}",
                "reference": _CVE_ORG.format(cve_id=cve_id),
            },
            remediation=(
                f"Review {cve_id} at {_CVE_ORG.format(cve_id=cve_id)} and update "
                f"{product} to a patched version."
            ),
        )


def _year_from_id(cve_id: str) -> str:
    match = re.match(r"CVE-(\d{4})-", cve_id)
    return match.group(1) if match else "unknown"


def _english_description(cve: dict[str, object]) -> str:
    descs = cve.get("descriptions", [])
    if isinstance(descs, list):
        for d in descs:
            if isinstance(d, dict) and d.get("lang") == "en":
                text = str(d.get("value", "")).strip()
                return (text[:240] + "…") if len(text) > 240 else text
    return "See the CVE record for details."


def _cve_severity(cve: dict[str, object]) -> Severity:
    metrics = cve.get("metrics", {})
    if isinstance(metrics, dict):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if isinstance(entries, list) and entries:
                data = entries[0].get("cvssData", {}) if isinstance(entries[0], dict) else {}
                sev = str(data.get("baseSeverity", "")).upper()
                if sev in _CVSS_SEVERITY:
                    return _CVSS_SEVERITY[sev]
    return Severity.MEDIUM

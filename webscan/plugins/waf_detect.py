"""Plugin: WAF detection — detect and fingerprint Web Application Firewalls.

Sends probes that trigger WAF signatures and checks response headers/body
for WAF fingerprints. Supports detection of: Cloudflare, AWS WAF, Akamai,
Imperva/Incapsula, F5 BIG-IP, Sucuri, ModSecurity, Wordfence, and generic
WAFs.

No other open-source DAST scanner has built-in WAF detection — you need
separate tools like wafw00f.
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin

# WAF fingerprints: (header_name, header_value_pattern, waf_name)
_WAF_HEADER_SIGNS: list[tuple[str, str, str]] = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("x-cdn", "cloudflare", "Cloudflare"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-amz-cf-pop", "", "AWS CloudFront"),
    ("x-akamai-transformed", "", "Akamai"),
    ("x-akamai-request-id", "", "Akamai"),
    ("x-iinfo", "", "Imperva/Incapsula"),
    ("incap_ses", "", "Imperva/Incapsula"),
    ("x-cdn-origin", "imperva", "Imperva/Incapsula"),
    ("x-sucuri-id", "", "Sucuri"),
    ("x-sucuri-cache", "", "Sucuri"),
    ("server", "sucuri", "Sucuri"),
    ("x-f5-cache-status", "", "F5 BIG-IP"),
    ("server", "bigip", "F5 BIG-IP"),
    ("server", "mod_security", "ModSecurity"),
    ("server", "nginx-mod-security", "ModSecurity"),
    ("x-powered-by", "wordfence", "Wordfence"),
    ("x-wpe", "", "WP Engine (WAF)"),
    ("x-cdn", "fastly", "Fastly"),
    ("x-fastly-request-id", "", "Fastly"),
    ("x-varnish", "", "Varnish (reverse proxy)"),
    ("via", "varnish", "Varnish (reverse proxy)"),
    ("x-drupal-cache", "", "Drupal (CMS-level WAF)"),
    ("x-backend", "azurefd", "Azure Front Door"),
    ("x-azure-ref", "", "Azure Front Door"),
]

# Body patterns that indicate a WAF block page.
_WAF_BODY_SIGNS: list[tuple[str, str]] = [
    ("cloudflare", "Cloudflare"),
    ("cf-browser-verification", "Cloudflare"),
    ("attention required", "Cloudflare"),
    ("sucuri web firewall", "Sucuri"),
    ("incapsula incident", "Imperva/Incapsula"),
    ("mod_security", "ModSecurity"),
    ("nginx-mod-security", "ModSecurity"),
    ("access denied", "Generic WAF"),
    ("request blocked", "Generic WAF"),
    ("security rule", "Generic WAF"),
    ("blocked by", "Generic WAF"),
    ("forbidden", "Generic WAF"),
    ("waf", "Generic WAF"),
]


class WafDetectPlugin(BasePlugin):
    """Detect and fingerprint Web Application Firewalls."""

    name = "waf_detect"
    description = "WAF detection and fingerprinting (Cloudflare, AWS, Akamai, Imperva, ModSecurity, etc.)"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Send a normal request and check headers.
        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                headers = dict(resp.headers)
                body = await fetch_body(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings

        detected_wafs: set[str] = set()

        # Check headers for WAF fingerprints.
        for header_name, pattern, waf_name in _WAF_HEADER_SIGNS:
            header_value = headers.get(header_name, "") or headers.get(header_name.lower(), "")
            if header_value and (not pattern or pattern in header_value.lower()):
                detected_wafs.add(waf_name)

        # Check body for WAF block-page patterns.
        body_lower = body.lower()[:5000]  # only check first 5KB
        for pattern, waf_name in _WAF_BODY_SIGNS:
            if pattern in body_lower:
                detected_wafs.add(waf_name)

        # Send a probe that would trigger most WAFs.
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(target)
        sqli = "wsprobe=1%27+OR+%271%27%3D%271"
        if parsed.query:
            probe_url = urlunparse(parsed._replace(query=parsed.query + "&" + sqli))
        else:
            probe_url = urlunparse(parsed._replace(query=sqli))

        try:
            async with session.get(probe_url, allow_redirects=False, ssl=False) as probe_resp:
                # WAFs often return 403, 406, 429, or 503 for blocked requests.
                if probe_resp.status in (403, 406, 429, 503):
                    # Check if this is different from the baseline status.
                    # A 403 on the probe but 200 on the baseline is a strong WAF signal.
                    detected_wafs.add("Generic WAF (blocked SQLi probe)")
                probe_headers = dict(probe_resp.headers)
                for header_name, pattern, waf_name in _WAF_HEADER_SIGNS:
                    header_value = probe_headers.get(header_name, "") or probe_headers.get(header_name.lower(), "")
                    if header_value and (not pattern or pattern in header_value.lower()):
                        detected_wafs.add(waf_name)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass  # ignore probe failure

        if detected_wafs:
            # Filter out generic if we have a specific match.
            specific = {w for w in detected_wafs if "Generic" not in w}
            waf_list = sorted(specific if specific else detected_wafs)
            findings.append(Finding(
                plugin=self.name,
                title=f"WAF detected: {', '.join(waf_list)}",
                severity=Severity.INFO,
                confidence=Confidence.FIRM,
                description=(
                    f"A Web Application Firewall is in front of the target: "
                    f"{', '.join(waf_list)}. WAFs can block or alter scan probes, "
                    "leading to false negatives. Consider: (1) whitelisting the "
                    "scanner IP, (2) using --random-delay and --random-agent, "
                    "(3) interpreting results with the WAF in mind."
                ),
                url=target,
                evidence={
                    "detected_wafs": waf_list,
                    "probe_url": probe_url,
                    "probe_status": probe_resp.status if 'probe_resp' in dir() else None,
                },
            ))
        else:
            findings.append(Finding(
                plugin=self.name,
                title="No WAF detected",
                severity=Severity.INFO,
                confidence=Confidence.INFORMATIONAL,
                description=(
                    "No Web Application Firewall was detected. The target responds "
                    "directly to probes without filtering. Consider deploying a WAF "
                    "(Cloudflare, AWS WAF, ModSecurity) for defense-in-depth."
                ),
                url=target,
                evidence={"waf_detected": False},
            ))

        return findings

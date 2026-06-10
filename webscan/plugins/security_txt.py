"""Plugin: check for security.txt (RFC 9116)."""
from __future__ import annotations

import aiohttp

from webscan.models import Finding, Severity
from webscan.plugins.base import BasePlugin


class SecurityTxtPlugin(BasePlugin):
    """Checks for the presence of a security.txt file (RFC 9116).

    The security.txt file should be located at ``/.well-known/security.txt``
    and provides a standard way for organizations to disclose security
    contact information.

    - **Absent** → INFO finding recommending one be published
    - **Present** → parses and reports contact/expires fields
    """

    name = "security_txt"
    description = "Check for security.txt (RFC 9116) presence and content"

    _SECURITY_TXT_PATH = "/.well-known/security.txt"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []
        url = target.rstrip("/") + self._SECURITY_TXT_PATH

        try:
            async with session.get(url, allow_redirects=True, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    findings.extend(self._parse_security_txt(text, target, url))
                else:
                    findings.append(
                        Finding(
                            plugin=self.name,
                            title="security.txt not found",
                            severity=Severity.INFO,
                            description=(
                                f"security.txt was not found at {url} "
                                f"(HTTP {resp.status}). Consider publishing one "
                                f"per RFC 9116 to provide a security contact."
                            ),
                            url=target,
                            evidence={"http_status": resp.status, "checked_url": url},
                            remediation=(
                                "Create a security.txt file at "
                                "/.well-known/security.txt with at least a "
                                "Contact field. Example:\n"
                                "  Contact: mailto:security@example.com\n"
                                "  Expires: 2027-01-01T00:00:00.000Z\n"
                                "  Preferred-Languages: en"
                            ),
                        )
                    )
        except Exception:
            pass

        return findings

    def _parse_security_txt(self, text: str, target: str, url: str) -> list[Finding]:
        findings: list[Finding] = []
        contact_found = False
        expires_found = False
        encryption_found = False
        acknowledgments_found = False
        hiring_found = False
        preferred_languages_found = False

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key_lower = key.strip().lower()
            value = value.strip()

            if key_lower == "contact":
                contact_found = True
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="security.txt: Contact",
                        severity=Severity.INFO,
                        description=f"Security contact: {value}",
                        url=target,
                        evidence={"field": "Contact", "value": value},
                    )
                )
            elif key_lower == "expires":
                expires_found = True
                findings.append(
                    Finding(
                        plugin=self.name,
                        title="security.txt: Expires",
                        severity=Severity.INFO,
                        description=f"security.txt expires: {value}",
                        url=target,
                        evidence={"field": "Expires", "value": value},
                    )
                )
            elif key_lower == "encryption":
                encryption_found = True
            elif key_lower == "acknowledgments":
                acknowledgments_found = True
            elif key_lower == "hiring":
                hiring_found = True
            elif key_lower == "preferred-languages":
                preferred_languages_found = True

        if not contact_found:
            findings.append(
                Finding(
                    plugin=self.name,
                    title="security.txt: missing Contact field",
                    severity=Severity.MEDIUM,
                    description=(
                        "security.txt is present but does not contain a "
                        "Contact field. RFC 9116 requires at least one."
                    ),
                    url=target,
                    evidence={"url": url},
                    remediation="Add a Contact field: Contact: mailto:security@example.com",
                )
            )

        if not expires_found:
            findings.append(
                Finding(
                    plugin=self.name,
                    title="security.txt: missing Expires field",
                    severity=Severity.LOW,
                    description=(
                        "security.txt is present but does not contain an "
                        "Expires field. RFC 9116 recommends including one."
                    ),
                    url=target,
                    evidence={"url": url},
                    remediation="Add an Expires field: Expires: 2027-01-01T00:00:00.000Z",
                )
            )

        fields_present = []
        if contact_found:
            fields_present.append("Contact")
        if expires_found:
            fields_present.append("Expires")
        if encryption_found:
            fields_present.append("Encryption")
        if acknowledgments_found:
            fields_present.append("Acknowledgments")
        if hiring_found:
            fields_present.append("Hiring")
        if preferred_languages_found:
            fields_present.append("Preferred-Languages")

        findings.append(
            Finding(
                plugin=self.name,
                title="security.txt: present",
                severity=Severity.INFO,
                description=(
                    f"security.txt found at {url}. "
                    f"Fields present: {', '.join(fields_present) or 'none recognized'}."
                ),
                url=target,
                evidence={"url": url, "fields": fields_present},
            )
        )

        return findings

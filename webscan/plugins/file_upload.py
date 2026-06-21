"""Plugin: detect unrestricted file upload.

Sends a harmless test file (``webscan-test.txt``) to upload endpoints and
checks if the file is accessible at a predictable URL. If the server
accepts and serves the file, it's vulnerable to file upload attacks —
an attacker can upload a web shell (``.php``, ``.phtml``, ``.jsp``).

The plugin only sends a **harmless text file** — never an executable.
"""
from __future__ import annotations

import asyncio

import aiohttp

from webscan.models import Confidence, Finding, Severity
from webscan.plugins._active_helpers import fetch_body
from webscan.plugins.base import BasePlugin
from webscan.utils.html import parse_html
from webscan.utils.http import same_origin

_UPLOAD_PATH_PATTERNS = ("/upload", "/uploads", "/file/upload", "/media/upload", "/attach")
_TEST_CONTENT = "webscan-upload-test-safe"
_TEST_FILENAME = "webscan-test.txt"
_MAX_FORMS = 3


class FileUploadPlugin(BasePlugin):
    """Probes upload endpoints with a harmless test file."""

    name = "file_upload"
    description = "Detect unrestricted file upload by sending a harmless test file"

    async def run(
        self,
        target: str,
        session: aiohttp.ClientSession,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Check if the URL looks like an upload endpoint or has a form with file input.
        is_upload_url = any(p in target.lower() for p in _UPLOAD_PATH_PATTERNS)

        try:
            async with session.get(target, allow_redirects=True, ssl=False) as resp:
                content_type = resp.headers.get("Content-Type", "")
                body = await fetch_body(resp)
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        has_file_form = False
        if "html" in content_type.lower():
            page = parse_html(body, base=target)
            # Check for forms with file inputs.
            for form in page.forms[:_MAX_FORMS]:
                if any(f.field_type == "file" for f in form.fields):
                    # SSRF guard (CWE-918): never follow a form action that
                    # points to a different origin — the target could serve a
                    # page that posts our test file (and any auth headers /
                    # cookies, see H-1) to an attacker host.
                    if form.action and not same_origin(form.action, target):
                        continue
                    has_file_form = True
                    target = form.action or target
                    break

        if not is_upload_url and not has_file_form:
            return findings

        # Send the harmless test file.
        try:
            data = aiohttp.FormData()
            data.add_field("file", _TEST_CONTENT, filename=_TEST_FILENAME, content_type="text/plain")  # noqa: E501
            async with session.post(
                target,
                data=data,
                allow_redirects=False,
                ssl=False,
            ) as resp:
                upload_body = await fetch_body(resp)
                upload_status = resp.status
        except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
            return findings

        if upload_status >= 400:
            return findings

        # Check if the response contains a URL to the uploaded file.
        import re
        url_match = re.search(r'https?://[^\s"\'<>]+webscan-test[^\s"\'<>]*', upload_body)
        if url_match:
            file_url = url_match.group(0)
            # Verify the file is accessible.
            try:
                async with session.get(file_url, ssl=False) as verify_resp:
                    if verify_resp.status == 200:
                        verify_body = await fetch_body(verify_resp)
                        if _TEST_CONTENT in verify_body:
                            findings.append(Finding(
                                plugin=self.name,
                                title="Unrestricted file upload: uploaded file is accessible",
                                severity=Severity.HIGH,
                                confidence=Confidence.FIRM,
                                description=(
                                    f"A file uploaded to `{target}` is accessible "
                                    f"at `{file_url}`. An attacker can upload a "
                                    "web shell (.php, .phtml, .jsp) and execute "
                                    "arbitrary code on the server."
                                ),
                                url=target,
                                evidence={
                                    "upload_url": target,
                                    "file_url": file_url,
                                    "upload_status": upload_status,
                                    "test_filename": _TEST_FILENAME,
                                },
                                remediation=(
                                    "Validate file types server-side (check magic "
                                    "bytes, not just extension). Store uploads "
                                    "outside the web root or on a separate domain. "
                                    "Disable script execution in the upload directory."
                                ),
                            ))
            except (aiohttp.ClientError, asyncio.TimeoutError, UnicodeError):
                pass

        return findings

"""Auto-fix suggestions — generate concrete remediation commands per finding.

For each finding, produces an actionable fix: a shell command, a config
snippet, or a code change. This goes beyond the generic "remediation" text
in the Finding model — it's a copy-paste-ready command.

Usage::

    from webscan.autofix import suggest_fix

    fix = suggest_fix(finding)
    if fix:
        print(fix.command)  # e.g. "add_header Strict-Transport-Security ..."
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webscan.models import Finding


@dataclass
class FixSuggestion:
    """A concrete, copy-paste-ready fix for a finding."""
    command: str        # the shell command or config snippet
    language: str       # "bash", "nginx", "apache", "python", "toml"
    description: str    # what the fix does
    references: list[str] | None = None  # URLs to docs/CVEs

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "language": self.language,
            "description": self.description,
            "references": self.references or [],
        }


def suggest_fix(finding: Finding) -> FixSuggestion | None:
    """Generate a concrete fix suggestion for *finding*.

    Returns None if no auto-fix is available for this plugin/finding type.
    """
    handler = _FIX_HANDLERS.get(finding.plugin)
    if handler is None:
        return None
    return handler(finding)  # type: ignore[no-any-return]


# ─── Per-plugin fix generators ──────────────────────────────────────────────

def _fix_missing_header(finding: Finding, header: str, value: str, nginx_directive: str = "") -> FixSuggestion:
    """Generic fix for a missing security header."""
    return FixSuggestion(
        command=f"# nginx\nadd_header {header} \"{value}\" always;\n\n# Apache\nHeader always set {header} \"{value}\"",
        language="nginx",
        description=f"Add the {header} header to all responses. The 'always' keyword ensures it's sent even on error pages.",
        references=[f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{header}"],
    )


def _fix_headers(finding: Finding) -> FixSuggestion | None:
    title_lower = finding.title.lower()
    if "content-security-policy" in title_lower:
        return FixSuggestion(
            command='# nginx\nadd_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\'; object-src \'none\'; frame-ancestors \'none\'" always;',
            language="nginx",
            description="Add a strict CSP that blocks inline scripts, object embeds, and framing. Adjust per-page as needed.",
            references=["https://content-security-policy.com/", "https://csp-evaluator.withgoogle.com/"],
        )
    if "strict-transport-security" in title_lower:
        return FixSuggestion(
            command='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            language="nginx",
            description="Enable HSTS for 1 year, covering all subdomains. Add 'preload' only if you're ready to submit to the HSTS preload list.",
            references=["https://hstspreload.org/"],
        )
    if "x-frame-options" in title_lower:
        return FixSuggestion(
            command='add_header X-Frame-Options "DENY" always;',
            language="nginx",
            description="Prevent the page from being framed (clickjacking protection). Use 'SAMEORIGIN' if you need to frame your own pages.",
        )
    if "x-content-type-options" in title_lower:
        return FixSuggestion(
            command='add_header X-Content-Type-Options "nosniff" always;',
            language="nginx",
            description="Prevent browsers from MIME-sniffing responses away from the declared Content-Type.",
        )
    if "referrer-policy" in title_lower:
        return FixSuggestion(
            command='add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            language="nginx",
            description="Only send the origin (not the full URL) in the Referer header on cross-origin requests.",
        )
    if "permissions-policy" in title_lower:
        return FixSuggestion(
            command='add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;',
            language="nginx",
            description="Disable browser features (camera, microphone, etc.) that the page doesn't need.",
        )
    return None


def _fix_cors(finding: Finding) -> FixSuggestion | None:
    return FixSuggestion(
        command='# nginx — only allow specific origins\nadd_header Access-Control-Allow-Origin "https://trusted.example.com" always;\nadd_header Access-Control-Allow-Credentials "true" always;\n\n# Never use: Access-Control-Allow-Origin * with credentials\n# It is a CORS spec violation and exploitable.',
        language="nginx",
        description="Replace wildcard or reflected CORS with an explicit allow-list of trusted origins.",
        references=["https://portswigger.net/web-security/cors"],
    )


def _fix_cookies(finding: Finding) -> FixSuggestion | None:
    return FixSuggestion(
        command='# Set-Cookie with all security flags:\nSet-Cookie: session=abc123; Path=/; HttpOnly; Secure; SameSite=Strict\n\n# Python/Django:\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = "Strict"\nCSRF_COOKIE_SECURE = True',
        language="bash",
        description="Add Secure (HTTPS-only), HttpOnly (no JS access), and SameSite=Strict (CSRF protection) to all cookies.",
    )


def _fix_clickjacking(finding: Finding) -> FixSuggestion | None:
    return FixSuggestion(
        command='# nginx — use CSP frame-ancestors (modern) + X-Frame-Options (legacy):\nadd_header Content-Security-Policy "frame-ancestors \'none\'" always;\nadd_header X-Frame-Options "DENY" always;',
        language="nginx",
        description="Block the page from being embedded in an iframe. CSP frame-ancestors is the modern standard; X-Frame-Options is a legacy fallback.",
    )


def _fix_ssl_tls(finding: Finding) -> FixSuggestion | None:
    title_lower = finding.title.lower()
    if "weak protocol" in title_lower or "ssl" in title_lower or "tls 1.0" in title_lower or "tls 1.1" in title_lower:
        return FixSuggestion(
            command='# nginx — only allow TLS 1.2 and 1.3:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\nssl_prefer_server_ciphers off;',
            language="nginx",
            description="Disable SSLv2/3, TLS 1.0, and TLS 1.1. Use only TLS 1.2+ with strong cipher suites.",
            references=["https://ssl-config.mozilla.org/"],
        )
    if "hsts" in title_lower:
        return FixSuggestion(
            command='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            language="nginx",
            description="Enable HSTS to force HTTPS for all future visits.",
        )
    if "expired" in title_lower or "expiring" in title_lower:
        return FixSuggestion(
            command='# Renew with certbot (Let\'s Encrypt):\ncertbot renew\n# Or get a new cert:\ncertbot certonly --nginx -d example.com',
            language="bash",
            description="Renew the TLS certificate before it expires.",
            references=["https://certbot.eff.org/"],
        )
    return None


def _fix_sql_injection(finding: Finding) -> FixSuggestion | None:
    return FixSuggestion(
        command='# Python — use parameterised queries (NEVER string formatting):\n# BAD:  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n# GOOD: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n\n# SQLAlchemy ORM (parameterised by default):\nuser = session.query(User).filter(User.id == user_id).one()',
        language="python",
        description="Use parameterised queries / prepared statements. NEVER concatenate user input into SQL strings.",
        references=["https://owasp.org/www-community/attacks/SQL_Injection", "https://bobby-tables.com/"],
    )


def _fix_xss(finding: Finding) -> FixSuggestion | None:
    return FixSuggestion(
        command='# Output encoding — escape ALL user input in HTML context:\n# Python/Flask: {{ user_input }} (auto-escaped by Jinja2)\n# React: {userInput} (auto-escaped by JSX)\n\n# NEVER use dangerouslySetInnerHTML (React) or |safe (Jinja2) with user input.\n\n# Add a strict CSP as defense-in-depth:\nadd_header Content-Security-Policy "script-src \'self\'" always;',
        language="python",
        description="Escape all user-controlled data when rendering HTML. Use your framework's auto-escaping. Add CSP as defense-in-depth.",
        references=["https://owasp.org/www-community/attacks/xss/"],
    )


def _fix_open_redirect(finding: Finding) -> FixSuggestion | None:
    return FixSuggestion(
        command='# Python — validate redirect URLs against an allow-list:\nALLOWED_REDIRECTS = {"/dashboard", "/login", "/profile"}\n\ndef safe_redirect(url: str) -> str:\n    from urllib.parse import urlparse\n    parsed = urlparse(url)\n    if not parsed.netloc and parsed.path in ALLOWED_REDIRECTS:\n        return url\n    return "/"  # fallback to home\n\n# NEVER: redirect(request.args.get("next"))  ← open redirect!',
        language="python",
        description="Validate redirect URLs against an allow-list. Never redirect to user-supplied URLs without checking.",
    )


def _fix_config_files(finding: Finding) -> FixSuggestion | None:
    return FixSuggestion(
        command='# nginx — block access to sensitive files:\nlocation ~ /\\.(env|git|svn|htaccess) { deny all; return 404; }\nlocation ~ /\\.(bak|old|orig|swp|save|tmp)$ { deny all; return 404; }\nlocation ~ /(wp-config\\.php|config\\.php|settings\\.py) { deny all; return 404; }\n\n# Apache:\n<FilesMatch "^\\.">(Require all denied)</FilesMatch>',
        language="nginx",
        description="Block access to dotfiles, backup files, and config files via web server rules.",
    )


def _fix_secrets(finding: Finding) -> FixSuggestion | None:
    return FixSuggestion(
        command='# 1. Rotate the leaked key IMMEDIATELY (it must be considered compromised)\n# 2. Remove it from source code / HTML / JS\n# 3. Use environment variables or a secrets manager instead:\n\n# Python:\nimport os\nAPI_KEY = os.environ["API_KEY"]  # never hardcode\n\n# .env file (add to .gitignore!):\nAPI_KEY=sk-xxx\n\n# Docker:\ndocker run -e API_KEY=$API_KEY ...',
        language="bash",
        description="Rotate the leaked key immediately, remove it from the codebase, and use environment variables or a secrets manager.",
        references=["https://owasp.org/www-community/controls/Secure_Coding_ Practices"],
    )


def _fix_dirs(finding: Finding) -> FixSuggestion:
    return FixSuggestion(
        command='# nginx — disable directory listing:\nautoindex off;\n\n# Block access to known sensitive paths:\nlocation ~ ^/(admin|backup|\\.git|phpmyadmin) { deny all; return 404; }',
        language="nginx",
        description="Disable directory autoindex and block access to sensitive paths.",
    )


# ─── Plugin → fix handler mapping ───────────────────────────────────────────

_FIX_HANDLERS: dict[str, Any] = {
    "headers": _fix_headers,
    "cors": _fix_cors,
    "cookies": _fix_cookies,
    "clickjacking": _fix_clickjacking,
    "ssl_tls": _fix_ssl_tls,
    "sql_injection": _fix_sql_injection,
    "xss": _fix_xss,
    "open_redirect": _fix_open_redirect,
    "config_files": _fix_config_files,
    "secrets": _fix_secrets,
    "directories": _fix_dirs,
}


def suggest_fixes_for_report(
    report: Any,  # noqa: ANN401 - accepts ScanReport
    *,
    max_suggestions: int = 20,
) -> list[tuple[Finding, FixSuggestion]]:
    """Generate fix suggestions for all findings in *report*.

    Returns a list of ``(finding, suggestion)`` tuples. Findings without a
    known auto-fix are skipped.
    """
    results: list[tuple[Finding, FixSuggestion]] = []
    for tr in report.targets:
        for f in tr.findings:
            if len(results) >= max_suggestions:
                return results
            suggestion = suggest_fix(f)
            if suggestion:
                results.append((f, suggestion))
    return results

"""Plain-language explanations of findings, keyed by plugin.

Curated, offline, jargon-free blurbs for the ``--explain`` mode. The goal is
that a non-expert site owner understands *what* a finding means and *why* it
matters in everyday terms. Falls back to a finding's own remediation when no
specific blurb exists.
"""
from __future__ import annotations

# plugin name -> one-sentence, plain-English explanation.
PLAIN_EXPLANATIONS: dict[str, str] = {
    "headers": (
        "Your site is missing a security header — a small instruction that tells "
        "browsers how to protect your visitors. Adding it makes attacks harder."
    ),
    "config_files": (
        "A sensitive file (like a password or config file) is reachable from the "
        "internet. Anyone can download it, so treat its contents as exposed."
    ),
    "secrets": (
        "A secret key (e.g. a cloud or AI API key) is visible in your website's "
        "code. Anyone can copy it and run up charges or access your data — rotate "
        "it now."
    ),
    "directories": (
        "A private folder (like /admin or /backup) is reachable from the internet. "
        "Restrict who can open it."
    ),
    "sql_injection": (
        "Part of your site may let an attacker tamper with your database through "
        "the web address or a form — potentially reading or changing your data."
    ),
    "xss": (
        "An attacker may be able to inject code that runs in your visitors' "
        "browsers, letting them steal sessions or deface pages."
    ),
    "path_traversal": (
        "An attacker may be able to trick your site into serving files it "
        "shouldn't — like system files outside the website folder."
    ),
    "open_redirect": (
        "Your site can be used to bounce visitors to an attacker's page while "
        "looking like it came from you — handy for phishing."
    ),
    "ssrf": (
        "Your server can be tricked into making requests to internal systems, "
        "which attackers use to reach things that should be private."
    ),
    "cors": (
        "Your site's cross-origin sharing rules are too loose, which can let other "
        "websites read data they shouldn't."
    ),
    "cookies": (
        "A cookie is missing a safety flag, making it easier to steal or misuse on "
        "insecure connections."
    ),
    "http_methods": (
        "Your server allows risky request types (like PUT or DELETE) that can let "
        "attackers change or remove content."
    ),
    "ssl_tls": (
        "There's an issue with your site's HTTPS encryption — an outdated protocol, "
        "an expiring certificate, or a missing protection — that weakens privacy."
    ),
    "security_txt": (
        "There's no standard way listed for security researchers to report "
        "problems to you. Publishing one is good practice (informational)."
    ),
    "tech_fingerprint": (
        "Your site reveals which software and versions it runs, which helps "
        "attackers look up known weaknesses for that exact stack."
    ),
    "subdomains": (
        "These extra subdomains exist for your domain. Forgotten or staging ones "
        "are a common way in — review and lock down any you don't need public."
    ),
    "robots_sitemap": (
        "Your robots.txt publicly lists private-looking paths. robots.txt is "
        "visible to everyone, so it advertises exactly what you wanted hidden."
    ),
}


def explain(plugin: str, fallback: str = "") -> str:
    """Return a plain-language blurb for *plugin*, or *fallback* if none exists."""
    return PLAIN_EXPLANATIONS.get(plugin, fallback)

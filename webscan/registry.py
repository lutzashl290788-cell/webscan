"""Plugin registry: the single source of truth for available plugins.

Both the CLI (:mod:`webscan.cli`) and the library facade (:mod:`webscan.api`)
build their plugin lists from here, so there is exactly one definition of which
plugins exist, which are opt-in, and how each is instantiated.

Third-party packages can contribute plugins under the ``webscan.plugins``
entry-point group; those are merged on top of the built-ins at import time.
"""
from __future__ import annotations

from importlib.metadata import entry_points

from webscan.plugins.base import BasePlugin
from webscan.plugins.cache_poisoning import CachePoisoningPlugin
from webscan.plugins.clickjacking import ClickjackingPlugin
from webscan.plugins.config_files import ConfigFilesPlugin
from webscan.plugins.cookies import CookiesPlugin
from webscan.plugins.cors import CorsPlugin
from webscan.plugins.csrf import CsrfPlugin
from webscan.plugins.cve_lookup import CveLookupPlugin
from webscan.plugins.directories import DirectoriesPlugin
from webscan.plugins.graphql import GraphqlPlugin
from webscan.plugins.headers import HeadersPlugin
from webscan.plugins.host_header_injection import HostHeaderInjectionPlugin
from webscan.plugins.http_methods import HttpMethodsPlugin
from webscan.plugins.idor import IdorPlugin
from webscan.plugins.jwt_audit import JwtAuditPlugin
from webscan.plugins.lfi_rfi import LfiRfiPlugin
from webscan.plugins.open_redirect import OpenRedirectPlugin
from webscan.plugins.path_traversal import PathTraversalPlugin
from webscan.plugins.robots_sitemap import RobotsSitemapPlugin
from webscan.plugins.secrets import SecretsPlugin
from webscan.plugins.security_txt import SecurityTxtPlugin
from webscan.plugins.sql_injection import SqlInjectionPlugin
from webscan.plugins.ssl_tls import SslTlsPlugin
from webscan.plugins.ssrf import SsrfPlugin
from webscan.plugins.subdomains import SubdomainsPlugin
from webscan.plugins.tech_fingerprint import TechFingerprintPlugin
from webscan.plugins.xss import XssPlugin
from webscan.plugins.xxe import XxePlugin
from webscan.retry import RetryConfig

# Built-in plugins, shipped in this package. Third parties can register their own
# under the ``webscan.plugins`` entry-point group (see _discover_plugins); those
# are merged on top of these at import time.
_BUILTIN_PLUGINS: dict[str, type[BasePlugin]] = {
    "config_files":  ConfigFilesPlugin,
    "secrets":       SecretsPlugin,
    "headers":       HeadersPlugin,
    "directories":   DirectoriesPlugin,
    "sql_injection": SqlInjectionPlugin,
    "xss":           XssPlugin,
    "path_traversal": PathTraversalPlugin,
    "open_redirect": OpenRedirectPlugin,
    "ssrf":          SsrfPlugin,
    "cors":          CorsPlugin,
    "cookies":       CookiesPlugin,
    "http_methods":  HttpMethodsPlugin,
    "ssl_tls":       SslTlsPlugin,
    "security_txt":  SecurityTxtPlugin,
    "tech_fingerprint": TechFingerprintPlugin,
    "robots_sitemap": RobotsSitemapPlugin,
    "subdomains":    SubdomainsPlugin,
    "graphql":       GraphqlPlugin,
    "cve_lookup":    CveLookupPlugin,
    "jwt_audit":     JwtAuditPlugin,
    "csrf":          CsrfPlugin,
    "lfi_rfi":       LfiRfiPlugin,
    "xxe":           XxePlugin,
    "idor":          IdorPlugin,
    "clickjacking":  ClickjackingPlugin,
    "cache_poisoning": CachePoisoningPlugin,
    "host_header_injection": HostHeaderInjectionPlugin,
}


def _discover_plugins() -> dict[str, type[BasePlugin]]:
    """Discover plugins registered under the ``webscan.plugins`` entry-point group.

    Each entry point must resolve to a :class:`BasePlugin` subclass. Discovery is
    fully fail-safe: a broken or missing entry point is skipped rather than
    aborting startup. Built-ins are always available even if metadata is absent
    (e.g. running from a source checkout that has not been reinstalled).
    """
    discovered: dict[str, type[BasePlugin]] = {}
    try:
        eps = entry_points(group="webscan.plugins")
    except Exception:  # noqa: BLE001 — metadata access must never crash startup
        return discovered
    for ep in eps:
        try:
            cls = ep.load()
        except Exception:  # noqa: BLE001 — skip a single bad plugin, keep the rest
            continue
        if isinstance(cls, type) and issubclass(cls, BasePlugin):
            discovered[ep.name] = cls
    return discovered


# Effective registry: built-ins, with entry-point plugins merged on top.
ALL_PLUGINS: dict[str, type[BasePlugin]] = {**_BUILTIN_PLUGINS, **_discover_plugins()}

# Plugins excluded from the default run (opt-in only): network-heavy or
# rate-limited external lookups the user should request explicitly.
OPT_IN_PLUGINS: frozenset[str] = frozenset({"cve_lookup", "graphql"})

# Names run by default — everything except the opt-in set, in registry order.
DEFAULT_PLUGINS: list[str] = [n for n in ALL_PLUGINS if n not in OPT_IN_PLUGINS]


def build_plugins(
    names: list[str],
    *,
    soft_404: bool = False,
    bruteforce: bool = True,
    retry: RetryConfig | None = None,
) -> list[BasePlugin]:
    """Instantiate the named plugins, honouring each one's specific options.

    This is the shared factory used by both the CLI and the library API, so a
    plugin's construction rules live in exactly one place.

    :param names: Plugin names to instantiate (must exist in :data:`ALL_PLUGINS`).
    :param soft_404: Enable soft-404 calibration for path-probing plugins.
    :param bruteforce: Enable DNS brute force for the ``subdomains`` plugin.
    :param retry: Retry policy for network-heavy lookups (defaults applied if None).
    :returns: Instantiated plugins, in the order requested.
    :raises KeyError: If a name is not a known plugin.
    """
    retry = retry or RetryConfig()
    plugins: list[BasePlugin] = []
    for name in names:
        cls = ALL_PLUGINS[name]
        if name == "subdomains":
            plugins.append(SubdomainsPlugin(bruteforce=bruteforce))
        elif name in {"cve_lookup", "graphql"}:
            plugins.append(cls(retry=retry))  # type: ignore[call-arg]
        elif name in {"directories", "config_files"}:
            plugins.append(cls(soft_404=soft_404))  # type: ignore[call-arg]
        else:
            plugins.append(cls())
    return plugins

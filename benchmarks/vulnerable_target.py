"""A deliberately vulnerable web app used as WebScan's benchmark target.

Why this exists
---------------
Benchmarking a scanner against a public site (httpbin.org, example.com, …)
can measure *speed*, but it cannot measure *accuracy*: nobody knows the real
list of vulnerabilities on someone else's server, so "zero false positives"
is an unfalsifiable claim and false *negatives* are invisible. This target
carries a machine-readable ground truth (:data:`GROUND_TRUTH`), so a run can
be scored honestly: true positives, false positives and — the number that
actually matters for a security tool — the things it missed.

Safety
------
* Binds to **127.0.0.1 only**. It is never reachable off the machine.
* The vulnerabilities are *simulated at the response level*: the traversal
  endpoint returns a synthetic ``/etc/passwd``-shaped string rather than
  reading a real file, the SQL endpoint returns a canned driver error rather
  than touching a database, and every credential in the responses is fake.
  Observable behaviour matches a vulnerable app, which is all a black-box
  scanner sees, without the process actually being exploitable.
* Nothing here should ever be deployed. It exists to be scanned.

Run standalone with ``python benchmarks/vulnerable_target.py`` (port 8737),
or let ``benchmarks/run_benchmark.py`` start and stop it for you.
"""
from __future__ import annotations

import argparse
import asyncio
from collections.abc import Awaitable, Callable

from aiohttp import web

HOST = "127.0.0.1"
DEFAULT_PORT = 8737

# ─── Ground truth ─────────────────────────────────────────────────────────────
# Every weakness deliberately planted below. `plugin` is the plugin expected to
# report it and `match` is a lowercase substring of the finding title that
# identifies it. A finding matching none of these entries is scored as a false
# positive; an entry matched by no finding is scored as a miss.

GROUND_TRUTH: list[dict[str, str]] = [
    # -- Response headers (all deliberately absent) --
    {"id": "hdr-csp", "plugin": "headers", "match": "content-security-policy",
     "note": "No CSP header is sent on any route."},
    {"id": "hdr-xcto", "plugin": "headers", "match": "x-content-type-options",
     "note": "No nosniff header is sent."},
    {"id": "hdr-referrer", "plugin": "headers", "match": "referrer-policy",
     "note": "No Referrer-Policy header is sent."},
    {"id": "hdr-permissions", "plugin": "headers", "match": "permissions-policy",
     "note": "No Permissions-Policy header is sent."},
    {"id": "hdr-hsts", "plugin": "headers", "match": "strict-transport-security",
     "note": "No HSTS header is sent."},
    {"id": "framing", "plugin": "clickjacking", "match": "framed",
     "note": "Neither X-Frame-Options nor CSP frame-ancestors is sent."},
    {"id": "disclosure-server", "plugin": "headers", "match": "server",
     "note": "Server header advertises an exact version."},

    # -- Injection / input handling --
    {"id": "xss", "plugin": "xss", "match": "xss",
     "note": "/search?q= reflects the parameter into HTML unescaped."},
    {"id": "sqli", "plugin": "sql_injection", "match": "sql",
     "note": "/product?id= leaks a MySQL syntax error on a quote."},
    {"id": "traversal", "plugin": "path_traversal", "match": "traversal",
     "note": "/download?file= serves a passwd-shaped file for ../ payloads."},
    {"id": "ssti", "plugin": "ssti", "match": "ssti",
     "note": "/greet?name= evaluates template expressions ({{7*7}} -> 49)."},
    {"id": "open-redirect", "plugin": "open_redirect", "match": "redirect",
     "note": "/redirect?next= 302s to any absolute URL."},

    # -- Misconfiguration --
    {"id": "cors", "plugin": "cors", "match": "cors",
     "note": "/api/data reflects any Origin with credentials allowed."},
    {"id": "cookie-flags", "plugin": "cookies", "match": "cookie",
     "note": "session cookie set without Secure / HttpOnly / SameSite."},
    {"id": "env-file", "plugin": "config_files", "match": ".env",
     "note": "/.env is world-readable and contains credentials."},
    {"id": "git-dir", "plugin": "config_files", "match": "git",
     "note": "/.git/config is exposed."},
    {"id": "dir-listing", "plugin": "directories", "match": "listing",
     "note": "/uploads/ renders an Apache-style index."},
    {"id": "backup-file", "plugin": "backup_files", "match": "backup",
     "note": "/config.php.bak is served as text."},
    {"id": "secrets-js", "plugin": "secrets", "match": "aws",
     "note": "/static/app.js embeds an AWS access key id."},
    {"id": "verbose-error", "plugin": "verbose_errors", "match": "trace",
     "note": "/boom returns a full Python traceback."},
    {"id": "http-methods", "plugin": "http_methods", "match": "method",
     "note": "OPTIONS advertises PUT, DELETE and TRACE."},
    {"id": "graphql-introspection", "plugin": "graphql", "match": "introspection",
     "note": "/graphql answers introspection queries."},
    {"id": "security-txt", "plugin": "security_txt", "match": "security.txt",
     "note": "No /.well-known/security.txt is published."},
]

# ─── Fake data (none of these are real credentials) ───────────────────────────

_FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)

_MYSQL_ERROR = (
    "You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near "
    "'''' at line 1"
)

_TRACEBACK = """Traceback (most recent call last):
  File "/srv/app/views.py", line 148, in render_invoice
    total = subtotal / item_count
            ~~~~~~~~~^~~~~~~~~~~~
ZeroDivisionError: division by zero

Local variables:
  request  = <Request GET /boom>
  db_dsn   = 'postgresql://app:hunter2@10.0.0.14:5432/billing'
  api_key  = 'REDACTED_TEST_API_KEY'
"""

_APP_JS = """// build 2026-06-01
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const SLACK_WEBHOOK = "https://example.invalid/slack-webhook";
const config = { apiBase: "/api", debug: true };
function merge(target, source) {            // prototype-pollution shaped helper
  for (const key in source) {
    if (typeof source[key] === "object") merge(target[key], source[key]);
    else target[key] = source[key];
  }
  return target;
}
"""

_ENV_FILE = """APP_ENV=production
APP_DEBUG=true
APP_KEY=base64:0000000000000000000000000000000000000000000=
DB_CONNECTION=mysql
DB_HOST=10.0.0.14
DB_USERNAME=billing_app
DB_PASSWORD=hunter2
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
[remote "origin"]
\turl = https://github.com/example-corp/billing-internal.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""

_INDEX = """<!DOCTYPE html>
<html lang="en">
<head><title>Acme Billing — internal</title>
<script src="/static/app.js"></script></head>
<body>
<h1>Acme Billing</h1>
<p>Internal tooling. Do not share.</p>
<ul>
  <li><a href="/search?q=invoice">Search invoices</a></li>
  <li><a href="/product?id=1">Product 1</a></li>
  <li><a href="/download?file=report.pdf">Download report</a></li>
  <li><a href="/greet?name=auditor">Greeting</a></li>
  <li><a href="/redirect?next=/dashboard">Dashboard</a></li>
  <li><a href="/profile">Profile</a></li>
  <li><a href="/uploads/">Uploads</a></li>
  <li><a href="/api/data">Invoice API</a></li>
  <li><a href="/graphql">GraphQL</a></li>
  <li><a href="/boom">Invoice renderer</a></li>
</ul>
<form action="/profile" method="POST">
  <input name="email" value="user@example.com">
  <input name="display_name" value="User">
  <button type="submit">Save profile</button>
</form>
</body>
</html>
"""


def _vulnerable_response(body: str, content_type: str = "text/html") -> web.Response:
    """Build a response that deliberately omits every security header."""
    return web.Response(
        text=body,
        content_type=content_type,
        headers={"Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k"},
    )


async def index(request: web.Request) -> web.Response:
    resp = _vulnerable_response(_INDEX)
    # Insecure cookie: no Secure, no HttpOnly, no SameSite.
    resp.set_cookie("session", "eyJ1aWQiOjF9", path="/")
    return resp


async def search(request: web.Request) -> web.Response:
    """Reflected XSS — the query is echoed into HTML with no escaping."""
    q = request.query.get("q", "")
    return _vulnerable_response(
        f"<html><body><h2>Results for {q}</h2><p>No invoices found.</p></body></html>"
    )


async def product(request: web.Request) -> web.Response:
    """Error-based SQL injection — a quote surfaces the driver error."""
    pid = request.query.get("id", "")
    if any(ch in pid for ch in ("'", '"', "--")):
        return _vulnerable_response(
            f"<html><body><h2>Database error</h2><pre>{_MYSQL_ERROR}</pre></body></html>"
        )
    return _vulnerable_response(f"<html><body><h2>Product {pid}</h2></body></html>")


async def download(request: web.Request) -> web.Response:
    """Path traversal — traversal payloads return a passwd-shaped document."""
    name = request.query.get("file", "")
    normalised = name.replace("%2f", "/").replace("\\", "/").lower()
    if "etc/passwd" in normalised or "..//" in normalised or "../" in normalised:
        return _vulnerable_response(_FAKE_PASSWD, content_type="text/plain")
    return _vulnerable_response(f"<html><body>Report: {name}</body></html>")


async def greet(request: web.Request) -> web.Response:
    """Server-side template injection — arithmetic in the parameter is evaluated."""
    name = request.query.get("name", "")
    rendered = name
    for expr, value in (
        ("{{7*7*7}}", "343"), ("${7*7*7}", "343"), ("<%= 7*7*7 %>", "343"),
        ("#{7*7*7}", "343"), ("{{7*7}}", "49"), ("${7*7}", "49"),
        ("<%= 7*7 %>", "49"), ("#{7*7}", "49"),
    ):
        rendered = rendered.replace(expr, value)
    return _vulnerable_response(f"<html><body><h2>Hello {rendered}</h2></body></html>")


async def redirect(request: web.Request) -> web.Response:
    """Open redirect — any absolute URL in `next` is honoured."""
    nxt = request.query.get("next", "/")
    raise web.HTTPFound(location=nxt)


async def api_data(request: web.Request) -> web.Response:
    """Permissive CORS — reflects the caller's Origin and allows credentials."""
    origin = request.headers.get("Origin", "*")
    return web.json_response(
        {"invoices": [{"id": 1, "total": "120.00"}]},
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k",
        },
    )


async def profile(request: web.Request) -> web.Response:
    """State-changing POST form with no CSRF token."""
    if request.method == "POST":
        return _vulnerable_response("<html><body>Saved.</body></html>")
    return _vulnerable_response(
        '<html><body><form action="/profile" method="POST">'
        '<input name="email"><button>Save</button></form></body></html>'
    )


async def uploads(request: web.Request) -> web.Response:
    """Open directory listing, styled like mod_autoindex."""
    return _vulnerable_response(
        "<html><head><title>Index of /uploads</title></head><body>"
        "<h1>Index of /uploads</h1><pre>"
        '<a href="../">../</a>\n'
        '<a href="invoice-2026-05.pdf">invoice-2026-05.pdf</a>   12-May-2026  184K\n'
        '<a href="payroll.xlsx">payroll.xlsx</a>                 03-Jun-2026  541K\n'
        '<a href="db-dump.sql">db-dump.sql</a>                   19-Jun-2026  9.2M\n'
        "</pre><hr></body></html>"
    )


async def boom(request: web.Request) -> web.Response:
    """Verbose error page leaking a stack trace, a DSN and an API key."""
    return web.Response(
        text=_TRACEBACK, status=500, content_type="text/plain",
        headers={"Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k"},
    )


async def graphql(request: web.Request) -> web.Response:
    """GraphQL endpoint with introspection left enabled."""
    return web.json_response({
        "data": {"__schema": {
            "queryType": {"name": "Query"},
            "types": [
                {"name": "Query", "kind": "OBJECT",
                 "fields": [{"name": "invoices"}, {"name": "users"}]},
                {"name": "User", "kind": "OBJECT",
                 "fields": [{"name": "id"}, {"name": "email"}, {"name": "passwordHash"}]},
            ],
        }},
    }, headers={"Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k"})


async def options_any(request: web.Request) -> web.Response:
    """Advertise dangerous methods on OPTIONS."""
    return web.Response(
        status=200,
        headers={
            "Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS, PATCH",
            "Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k",
        },
    )


async def dangerous_method(request: web.Request) -> web.Response:
    """Actually *accept* PUT/DELETE/TRACE, not just advertise them.

    The http_methods plugin deliberately distrusts the ``Allow`` header —
    advertising a method is not evidence it works, and treating it as evidence
    is a classic false positive. So the target has to honour the methods for
    the finding to be real.
    """
    if request.method == "TRACE":
        echoed = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
        return web.Response(
            text=f"TRACE /{request.match_info.get('tail', '')} HTTP/1.1\n{echoed}",
            content_type="message/http",
            headers={"Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k"},
        )
    return web.Response(
        text=f"{request.method} accepted for /{request.match_info.get('tail', '')}\n",
        status=200 if request.method != "PUT" else 201,
        content_type="text/plain",
        headers={"Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k"},
    )


async def robots(request: web.Request) -> web.Response:
    """robots.txt that leaks paths it is trying to hide."""
    return _vulnerable_response(
        "User-agent: *\n"
        "Disallow: /admin-console/\n"
        "Disallow: /internal/db-backups/\n"
        "Disallow: /api/v1/keys\n",
        content_type="text/plain",
    )


def _text_route(
    body: str, content_type: str = "text/plain"
) -> Callable[[web.Request], Awaitable[web.Response]]:
    async def handler(request: web.Request) -> web.Response:
        return _vulnerable_response(body, content_type=content_type)
    return handler


async def catch_all(request: web.Request) -> web.Response:
    """Fallback for unrouted paths.

    OPTIONS advertises the dangerous verbs (see :func:`options_any`); anything
    else must return a genuine 404. Registering a wildcard *route* instead
    would make aiohttp answer 405 for unknown paths, and "not a 404" is exactly
    what file-probing plugins read as "this file exists" — the target would
    manufacture false positives that say more about the harness than the
    scanner.
    """
    if request.method == "OPTIONS":
        return await options_any(request)
    return web.Response(
        text="404: Not Found", status=404, content_type="text/plain",
        headers={"Server": "Apache/2.4.49 (Unix) OpenSSL/1.0.2k"},
    )


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/search", search)
    app.router.add_get("/product", product)
    app.router.add_get("/download", download)
    app.router.add_get("/greet", greet)
    app.router.add_get("/redirect", redirect)
    app.router.add_get("/api/data", api_data)
    app.router.add_route("*", "/profile", profile)
    app.router.add_get("/uploads/", uploads)
    app.router.add_get("/boom", boom)
    app.router.add_route("*", "/graphql", graphql)
    app.router.add_get("/robots.txt", robots)
    app.router.add_get("/static/app.js", _text_route(_APP_JS, "application/javascript"))
    app.router.add_get("/.env", _text_route(_ENV_FILE))
    app.router.add_get("/.git/config", _text_route(_GIT_CONFIG))
    app.router.add_get("/config.php.bak", _text_route("<?php $db_pass = 'hunter2'; ?>"))
    # Dangerous verbs are honoured only on the real routes below — a catch-all
    # would answer 405 for *every* unknown path, which reads as "this file
    # exists" to probing plugins and manufactures false positives.
    for method in ("PUT", "DELETE", "TRACE", "PATCH"):
        for path in ("/", "/uploads/", "/api/data"):
            app.router.add_route(method, path, dangerous_method)
    app.router.add_route("*", "/{tail:.*}", catch_all)
    return app


async def serve(port: int = DEFAULT_PORT) -> web.AppRunner:
    """Start the target and return its runner (caller must ``cleanup()``)."""
    runner = web.AppRunner(build_app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, HOST, port).start()
    return runner


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    async def _run() -> None:
        runner = await serve(args.port)
        print(f"vulnerable target listening on http://{HOST}:{args.port}")
        print(f"{len(GROUND_TRUTH)} planted weaknesses — Ctrl-C to stop")
        try:
            await asyncio.Event().wait()
        finally:
            await runner.cleanup()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

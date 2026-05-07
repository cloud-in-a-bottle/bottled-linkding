"""OpenHost trusted-header auth-proxy for linkding.

Sits between the OpenHost router and linkding (uWSGI on
127.0.0.1:9090).  Pattern A from the OpenHost SSO playbook:

  1. The OpenHost router has already verified the visitor's
     zone_auth JWT and stamped ``X-OpenHost-Is-Owner: true`` on
     owner requests before they reach us.
  2. This proxy strips any client-supplied ``X-OpenHost-*`` and
     ``X-Remote-User`` headers (defence in depth — the router
     also strips them on inbound requests, but a hostile actor
     who somehow bypassed the router shouldn't be able to inject
     a trusted username) and, if the request is owner-stamped
     AND the request is *not* hitting one of the public paths,
     adds ``X-Remote-User: <owner-username>`` to the forwarded
     request.
  3. uWSGI translates the ``X-Remote-User`` HTTP header into
     ``request.META['HTTP_X_REMOTE_USER']``.  linkding is
     configured with ``LD_ENABLE_AUTH_PROXY=True`` and
     ``LD_AUTH_PROXY_USERNAME_HEADER=HTTP_X_REMOTE_USER``, so
     Django's RemoteUserMiddleware reads that meta value, finds
     the persistent superuser created at boot via
     ``LD_SUPERUSER_NAME``, and treats the visitor as logged in
     for that user.

There is no auto-login dance (no /login POST, no session cookie
minting) and crucially **no plaintext password is ever stored on
disk** — the bootstrap creates a passwordless superuser
(``set_unusable_password()``) which can only be authenticated
via the trusted REMOTE_USER path that the auth-proxy controls.

Public paths:

  * ``/api/`` — REST API used by the official browser extension,
    bookmarklet, and third-party integrations.  Auth via Django
    REST framework token (``Authorization: Token <abc>``);
    requires the OpenHost router to let anonymous traffic through
    so the request reaches linkding without a 302 to /login.
  * ``/static/`` — static assets (CSS / JS / favicons).  No auth.
  * ``/health`` — linkding's unauthenticated health endpoint.
  * ``/feeds/`` — token-keyed feed URLs.  The token is in the URL.
  * ``/bookmarks/shared`` — public list of shared bookmarks.
  * ``/_healthz`` — handled locally, never reaches linkding.

For these paths we do NOT stamp ``X-Remote-User`` even if the
visitor is the owner: the goal of the public-path passthrough is
that an anonymous visitor reaches the same response, so taking
the owner-auth code path would be a behaviour skew between owner
and non-owner sessions.

Auth model summary:

  * Anonymous (no zone_auth)         → router 302's to /login on
                                        parent zone unless the
                                        path is in the OpenHost
                                        manifest's ``public_paths``.
  * Owner, public path               → forward unchanged; linkding
                                        serves the public response.
  * Owner, private path              → forward with X-Remote-User
                                        stamped → linkding logs the
                                        owner in.
  * /_healthz                        → handled locally as 200 OK
                                        (ahead of upstream; no
                                        dependency on linkding).

Trust boundary: this proxy treats inbound
``X-OpenHost-Is-Owner: true`` as authoritative for owner identity.
That trust is only safe because the OpenHost router (the only
network-reachable entry point to this container's port 8080) is
the entity that stamps that header AND strips any client-supplied
copy on inbound requests.  If the OpenHost runtime ever changed
to expose 8080 directly to the public internet, an attacker could
forge ``X-OpenHost-Is-Owner: true`` and get owner-level access to
linkding.  Don't ship a deploy that bypasses the OpenHost router
in front of this listener.

Defense in depth: ALWAYS strip client-supplied
``X-OpenHost-Is-Owner`` / ``X-OpenHost-User`` / ``X-Remote-User``
headers before forwarding upstream.  This protects against a
hostile-but-confused intermediary that forwards a body verbatim
without scrubbing the trusted-header set we control.

Implementation is adapted from openhost-mediawiki/auth_proxy.py
(Pattern A) with HTTP/1.1 streaming patterns from
openhost-memos/auth_proxy.py to handle large API responses
(bookmark exports, asset downloads).
"""

from __future__ import annotations

import http.client
import logging
import os
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import AbstractSet, Iterable

OWNER_HEADER_NAME = "X-OpenHost-Is-Owner"
USER_HEADER_NAME = "X-OpenHost-User"
REMOTE_USER_HEADER_NAME = "X-Remote-User"

# Username we stamp on owner requests.  Must match the username
# that bootstrap_admin.py / the LD_SUPERUSER_NAME env var
# materialised in the linkding DB.
OWNER_USERNAME = os.environ.get("AUTH_PROXY_OWNER_USERNAME", "owner")

# Public paths.  MUST mirror the openhost.toml ``public_paths``
# list (the OpenHost router lets these through without zone_auth;
# we let them through without stamping owner identity).  Anything
# matched here is treated as anonymous-friendly: the proxy will
# forward unchanged, never inject X-Remote-User.
#
# Entries ending in ``/`` are prefix matches (everything under
# that namespace is public).  Entries NOT ending in ``/`` are
# matched either exactly or with a ``/``-or-EOL boundary, so
# ``/health`` matches ``/health`` and ``/health/foo`` but NOT
# ``/healthcheck-private``.  This avoids accidentally exposing
# unrelated paths that happen to share a string prefix with a
# legitimate public path.
PUBLIC_PATH_PATTERNS = (
    "/api/",
    "/static/",
    "/health",
    "/feeds/",
    "/bookmarks/shared",
    "/manifest.json",
    "/opensearch.xml",
    "/favicon.ico",
)

HOP_BY_HOP_HEADERS = frozenset(
    h.lower()
    for h in (
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailer",
        "Transfer-Encoding",
        "Upgrade",
        "Host",
        "Content-Length",
    )
)

# Headers a hostile client must never be able to inject.  ALWAYS
# stripped from inbound requests.  The X-Remote-User family is
# the trusted header linkding consults via its
# CustomRemoteUserMiddleware — we have to strip the client-
# supplied version so we can safely stamp our own.
ALWAYS_STRIP_HEADERS = frozenset(
    h.lower()
    for h in (
        OWNER_HEADER_NAME,
        USER_HEADER_NAME,
        REMOTE_USER_HEADER_NAME,
        "Remote-User",  # alternate form
    )
)

CLIENT_READ_TIMEOUT_SECONDS = 60

# 100 MiB body cap for *requests*.  linkding accepts asset uploads
# and bookmark imports; the upstream defaults to no limit
# (LD_REQUEST_MAX_CONTENT_LENGTH unset), but we keep our own cap
# so a hostile uploader can't drive the proxy out of memory.
MAX_BODY_BYTES = 100 * 1024 * 1024

# Streaming chunk size for response bodies.  Plenty fast for both
# small JSON responses and long-poll style downloads (bookmark
# exports can be tens of MiB on a heavy library).
STREAM_CHUNK_BYTES = 64 * 1024
# Long timeout for streamed responses.  uWSGI's default
# LD_REQUEST_TIMEOUT is 60s, so we never need to wait this long
# for a response, but bookmark imports can be slow.
STREAM_TIMEOUT_SECONDS = 6 * 60 * 60

logging.basicConfig(
    level=os.environ.get("AUTH_PROXY_LOG_LEVEL", "INFO"),
    format="[auth-proxy] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("auth_proxy")


def _normalize_header_name(name: str) -> str:
    """Normalize a header name for the strip-set comparison.

    HTTP per RFC 7230 names are case-insensitive and use only
    hyphens — but some clients send the underscore form
    (``X_Remote_User`` instead of ``X-Remote-User``).  Many
    WSGI / FastCGI servers map both forms to the same
    ``HTTP_X_REMOTE_USER`` meta key (the WSGI spec uppercases
    the name and replaces hyphens with underscores), so the
    underscore form is just as dangerous as the hyphen form
    for trusted-header injection.

    We canonicalise both into a hyphen-lowercase form for the
    strip-set comparison, which catches both spellings.
    """
    return name.lower().replace("_", "-")


def _strip_headers(
    headers: Iterable[tuple[str, str]], drop: AbstractSet[str]
) -> list[tuple[str, str]]:
    drop_canonical = {_normalize_header_name(h) for h in drop}
    return [
        (k, v) for k, v in headers if _normalize_header_name(k) not in drop_canonical
    ]


def _redact_log_arg(arg: object) -> object:
    """Strip query strings and feed tokens from a log arg.

    BaseHTTPRequestHandler passes the full request line as one
    of the ``log_message`` args (e.g. ``"GET /feeds/abc123/all
    HTTP/1.1"``).  Tokens in URL paths (``/feeds/<token>/``) and
    in query strings (``?api_token=...``) should never be
    written to logs, since they're effectively passwords.

    For non-string args (response status codes etc.) we pass the
    arg through unchanged.
    """
    if not isinstance(arg, str):
        return arg
    # Drop query strings entirely.
    redacted = arg
    qmark = redacted.find("?")
    while qmark >= 0:
        # Find the end of this URL token (next whitespace or end
        # of string).  log args are typically the full request
        # line, so the URL is followed by " HTTP/1.1".
        end = qmark
        for i in range(qmark + 1, len(redacted)):
            ch = redacted[i]
            if ch == " " or ch == "\t":
                end = i
                break
            end = i + 1
        redacted = redacted[:qmark] + "?<redacted>" + redacted[end:]
        qmark = redacted.find("?", qmark + len("?<redacted>"))
    # Mask feed tokens in paths.  Pattern: /feeds/<token>/...
    # The token is the path segment between /feeds/ and the next
    # /.
    feeds_idx = redacted.find("/feeds/")
    while feeds_idx >= 0:
        token_start = feeds_idx + len("/feeds/")
        # End of token = next slash or whitespace.
        token_end = token_start
        for i in range(token_start, len(redacted)):
            ch = redacted[i]
            if ch == "/" or ch == " " or ch == "\t":
                token_end = i
                break
            token_end = i + 1
        if token_end > token_start:
            redacted = (
                redacted[:token_start] + "<redacted>" + redacted[token_end:]
            )
        feeds_idx = redacted.find("/feeds/", token_start + len("<redacted>"))
    return redacted


def _is_public_path(path: str) -> bool:
    """Return True if ``path`` matches one of the public-path patterns.

    Patterns ending in ``/`` are prefix matches; other patterns
    match either exactly or up to a ``/`` boundary.  This means
    ``/health`` will match ``/health`` and ``/health/foo`` but
    NOT ``/healthcheck-private``.

    Matching is on the URL path component only — the query string
    is preserved for ``feeds/<key>?ctype=...`` style URLs but is
    not consulted in the match.
    """
    path_only = path.split("?", 1)[0]
    for pattern in PUBLIC_PATH_PATTERNS:
        if pattern.endswith("/"):
            if path_only.startswith(pattern):
                return True
            continue
        # Exact-or-boundary match.
        if path_only == pattern or path_only.startswith(pattern + "/"):
            return True
    return False


class AuthProxyHandler(BaseHTTPRequestHandler):
    # HTTP/1.1 lets us forward Transfer-Encoding: chunked from
    # upstream untouched and supports Range responses (206).
    # Default is HTTP/1.0 which forces close-per-request and
    # rejects chunked encoding — which would break linkding's
    # streamed bookmark export endpoint.
    protocol_version = "HTTP/1.1"

    upstream_host: str = "127.0.0.1"
    upstream_port: int = 9090

    def log_message(self, format: str, *args) -> None:  # noqa: A002, N802
        path = getattr(self, "path", "")
        # Suppress noisy local health probes.
        if path.startswith("/_healthz") or path == "/health":
            return
        # Redact query strings and tokenised path components.
        # The default BaseHTTPRequestHandler log format includes
        # the full request line, which on linkding can contain:
        #   * /feeds/<token>/all          — RSS/Atom token in path
        #   * /feeds/<token>/shared        — same
        #   * any URL with ?api_token=... — third-party clients
        # Logging those leaks credentials to stdout / OpenHost
        # logs, which is exactly the credential-leak failure
        # mode this image is supposed to avoid.
        sanitized_args = tuple(_redact_log_arg(a) for a in args)
        log.info("%s - " + format, self.address_string(), *sanitized_args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def _safe_send_error(self, code: int, message: str) -> None:
        try:
            self.send_error(code, message)
        except OSError as exc:
            log.debug("client disconnected before error response: %s", exc)

    def _dispatch(self) -> None:
        try:
            self.connection.settimeout(CLIENT_READ_TIMEOUT_SECONDS)
        except OSError:
            pass

        path_only = self.path.split("?", 1)[0]

        # Local-only liveness endpoint.  We serve it directly so the
        # OpenHost router's healthcheck doesn't depend on linkding
        # being up; linkding's own /health stays available too (for
        # operators who want a deeper signal).
        if path_only == "/_healthz":
            try:
                body = b'{"status":"ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except OSError as exc:
                log.debug("/_healthz client disconnected: %s", exc)
            return

        is_owner = self.headers.get(OWNER_HEADER_NAME, "").lower() == "true"
        # Don't stamp on public paths even if the visitor is the
        # owner.  Public-path passthrough means anonymous visitors
        # see the same response; if we logged the owner in here
        # they'd see a different (logged-in) view of the same URL,
        # which leaks information and surprises the operator.
        stamp = is_owner and not _is_public_path(self.path)
        self._proxy(stamp_remote_user=stamp)

    def _proxy(self, *, stamp_remote_user: bool) -> None:
        cleaned_headers = _strip_headers(
            self.headers.items(),
            HOP_BY_HOP_HEADERS | ALWAYS_STRIP_HEADERS,
        )
        # Preserve the original Host header (X-Forwarded-Host) so
        # linkding's URL generation matches the public URL.  This
        # also matters for CSRF on POSTs: linkding's
        # LD_CSRF_TRUSTED_ORIGINS validation checks the Origin
        # header against the configured origin, which is derived
        # from the public hostname.
        forwarded_host = self.headers.get("X-Forwarded-Host", "").strip()
        host_header = (
            forwarded_host or f"{self.upstream_host}:{self.upstream_port}"
        )
        cleaned_headers.append(("Host", host_header))
        # Force https on the X-Forwarded-Proto so Django's
        # is_secure() reports True; linkding's CSRF and
        # cookie-secure logic depend on this when behind a
        # TLS-terminating front proxy.
        cleaned_headers = [
            (k, v) for k, v in cleaned_headers if k.lower() != "x-forwarded-proto"
        ]
        cleaned_headers.append(("X-Forwarded-Proto", "https"))
        if stamp_remote_user:
            cleaned_headers.append((REMOTE_USER_HEADER_NAME, OWNER_USERNAME))

        # Reject request-side Transfer-Encoding: we don't bother
        # decoding chunked client uploads (none of linkding's
        # supported clients send chunked).
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        if transfer_encoding and transfer_encoding != "identity":
            self._safe_send_error(501, "Transfer-Encoding not supported on requests")
            return

        body: bytes | None = None
        content_length_header = self.headers.get("Content-Length")
        if content_length_header:
            try:
                length = int(content_length_header)
            except ValueError:
                self._safe_send_error(400, "invalid Content-Length")
                return
            if length < 0:
                self._safe_send_error(400, "negative Content-Length")
                return
            if length > MAX_BODY_BYTES:
                self._safe_send_error(413, "request body too large")
                return
            if length > 0:
                try:
                    body = self.rfile.read(length)
                except (OSError, TimeoutError) as exc:
                    log.info("client read error: %s", exc)
                    self._safe_send_error(400, "request body read failed")
                    return
                if len(body) != length:
                    self._safe_send_error(400, "incomplete request body")
                    return
            else:
                body = b""
        elif self.command in ("POST", "PUT", "PATCH", "DELETE"):
            body = b""

        # Long timeout so streamed responses (bookmark exports,
        # asset downloads) aren't capped at the default 120s.
        conn = http.client.HTTPConnection(
            self.upstream_host,
            self.upstream_port,
            timeout=STREAM_TIMEOUT_SECONDS,
        )
        try:
            try:
                # skip_host=True so http.client doesn't auto-inject
                # ``Host: 127.0.0.1:9090`` — we add the public Host
                # explicitly via cleaned_headers above.
                conn.putrequest(
                    self.command,
                    self.path,
                    skip_host=True,
                    skip_accept_encoding=True,
                )
                for key, value in cleaned_headers:
                    conn.putheader(key, value)
                if body is not None:
                    conn.putheader("Content-Length", str(len(body)))
                conn.endheaders(message_body=body)
                upstream = conn.getresponse()
            except (OSError, http.client.HTTPException) as exc:
                log.warning("upstream error: %s", exc)
                self._safe_send_error(502, "Bad Gateway")
                return

            # Drop upstream's Content-Length and Transfer-Encoding:
            # http.client.HTTPResponse.read() de-chunks chunked
            # responses transparently, so passing Transfer-Encoding:
            # chunked through to the client while writing
            # already-de-chunked bytes would break framing.
            # Content-Length is also dropped because we don't know
            # the exact wire size in advance for streamed responses
            # (the upstream may have rewritten the body during
            # de-chunking).  Framing is unambiguous via
            # ``Connection: close`` below — the client reads until
            # EOF, which is the HTTP/1.1 fallback framing.
            #
            # Range responses (206 with Content-Range) still work:
            # the Content-Range header passes through, and the body
            # is read until upstream EOF.
            reason = upstream.reason or ""
            try:
                self.send_response(upstream.status, reason)
                for key, value in upstream.getheaders():
                    if key.lower() in HOP_BY_HOP_HEADERS:
                        continue
                    self.send_header(key, value)
                # Force one-and-done so we don't have to manage
                # HTTP/1.1 keep-alive state between requests on the
                # same TCP connection, and so the close-EOF framing
                # described above works.  Browsers / OpenHost's
                # outer router handle close-per-request fine.
                self.send_header("Connection", "close")
                self.close_connection = True
                self.end_headers()
            except OSError as exc:
                log.debug("client disconnected during response head: %s", exc)
                upstream.close()
                return

            if self.command != "HEAD":
                try:
                    while True:
                        chunk = upstream.read(STREAM_CHUNK_BYTES)
                        if not chunk:
                            break
                        try:
                            self.wfile.write(chunk)
                        except OSError as exc:
                            log.debug(
                                "client disconnected mid-stream after %d bytes: %s",
                                len(chunk),
                                exc,
                            )
                            return
                except (OSError, http.client.HTTPException) as exc:
                    log.warning("upstream read error mid-stream: %s", exc)
                    return
            try:
                upstream.close()
            except Exception as exc:  # noqa: BLE001
                log.debug("upstream.close() raised (ignored): %s", exc)
        finally:
            conn.close()


class IPv4ThreadingServer(ThreadingHTTPServer):
    address_family = socket.AF_INET
    allow_reuse_address = True
    daemon_threads = True


def _port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name}={raw!r} is not an integer: {exc}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name}={raw!r} is out of range (1-65535)")
    return port


def main() -> int:
    try:
        listen_port = _port_from_env("AUTH_PROXY_LISTEN_PORT", 8080)
        upstream_port = _port_from_env("AUTH_PROXY_UPSTREAM_PORT", 9090)
    except ValueError as exc:
        log.error("invalid port configuration: %s", exc)
        return 1

    upstream_host = os.environ.get("AUTH_PROXY_UPSTREAM_HOST", "127.0.0.1").strip()

    AuthProxyHandler.upstream_host = upstream_host
    AuthProxyHandler.upstream_port = upstream_port

    try:
        server = IPv4ThreadingServer(("0.0.0.0", listen_port), AuthProxyHandler)
    except OSError as exc:
        log.error(
            "failed to bind auth-proxy listener on 0.0.0.0:%d: %s",
            listen_port,
            exc,
        )
        return 1
    log.info(
        "listening on 0.0.0.0:%d -> %s:%d (owner=%s, public=%s)",
        listen_port,
        upstream_host,
        upstream_port,
        OWNER_USERNAME,
        ",".join(PUBLIC_PATH_PATTERNS),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

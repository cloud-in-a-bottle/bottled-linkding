# linkding packaged for OpenHost with trusted-header SSO via the
# upstream LD_ENABLE_AUTH_PROXY hook.
#
# Layout:
#
#   /opt/openhost-linkding/
#     start.sh             — supervises linkding + auth-proxy
#     auth_proxy.py        — owner-gated proxy, stamps X-Remote-User
#                             on owner requests; bypasses public
#                             paths
#     bootstrap_admin.py   — defensive idempotent owner-superuser
#                             bootstrap
#
# Auth flow (Pattern A — trusted-header, no on-disk credentials):
#
#   1. Browser hits https://linkding.<zone>/.  The OpenHost router
#      verifies the visitor's zone_auth JWT and stamps
#      X-OpenHost-Is-Owner: true.
#   2. auth_proxy.py strips client-supplied X-OpenHost-* and
#      X-Remote-User headers (defence in depth) and, on
#      non-public paths, stamps X-Remote-User: <owner-username>.
#   3. linkding's CustomRemoteUserMiddleware (configured via
#      LD_AUTH_PROXY_USERNAME_HEADER=HTTP_X_REMOTE_USER) consults
#      request.META['HTTP_X_REMOTE_USER'] and authenticates the
#      passwordless superuser created at boot via
#      LD_SUPERUSER_NAME.  No password is ever consulted, so no
#      password is ever persisted.
#
# Public paths (router AND auth-proxy let these through without
# zone_auth and without owner stamping respectively):
#
#   * /api/        — REST API (browser extension, bookmarklet,
#                     third-party integrations); auth via Django
#                     REST framework Token header.
#   * /static/     — static assets (CSS/JS).
#   * /health      — linkding's unauthenticated health endpoint.
#   * /feeds/      — token-keyed feeds; token is in the URL.
#   * /bookmarks/shared — public list of shared bookmarks.

# OpenHost's rootless podman build doesn't have any
# ``unqualified-search-registries`` configured, so a bare image
# reference like ``sissbruecker/linkding:latest`` fails to
# resolve.  Pin the docker.io registry explicitly.
FROM docker.io/sissbruecker/linkding:latest

# linkding's image is python:3.13.7-slim-trixie based, so the
# system python3 binary is already present and is what
# /opt/openhost-linkding/{auth_proxy,bootstrap_admin}.py run
# under (no virtualenv activation needed for stdlib-only
# scripts).  Additional packages we install:
#
#   * tini    — PID-1 reaping & signal forwarding
#   * gosu    — defensive privilege drop (currently unused; kept
#               around in case a future fix-cycle needs it)
USER root
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        tini \
        gosu \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# All app files committed with mode 0755 in the git index.
COPY start.sh           /opt/openhost-linkding/start.sh
COPY auth_proxy.py      /opt/openhost-linkding/auth_proxy.py
COPY bootstrap_admin.py /opt/openhost-linkding/bootstrap_admin.py

# OpenHost-routed port.  linkding's port (9090) stays loopback.
EXPOSE 8080

# tini reaps zombies and forwards SIGTERM to start.sh's child set.
ENTRYPOINT ["/usr/bin/tini", "--", "/opt/openhost-linkding/start.sh"]

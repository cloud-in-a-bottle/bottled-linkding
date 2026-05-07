#!/bin/bash
# Boot linkding for OpenHost.
#
# Topology:
#
#   browser → OpenHost outer Caddy (TLS termination)
#          → OpenHost router (subdomain linkding.<zone>; verifies
#                              zone_auth JWT and stamps
#                              X-OpenHost-Is-Owner: true)
#          → container :8080  (auth_proxy.py — stamps X-Remote-User
#                              on owner requests; bypasses public
#                              paths)
#          → 127.0.0.1:9090   (uWSGI + linkding/Django)
#
# Auth flow (Pattern A — trusted-header SSO via Django's
# RemoteUserMiddleware):
#
#   1. linkding starts with LD_ENABLE_AUTH_PROXY=True and
#      LD_AUTH_PROXY_USERNAME_HEADER=HTTP_X_REMOTE_USER, so its
#      CustomRemoteUserMiddleware reads the per-request value of
#      request.META['HTTP_X_REMOTE_USER'] (which uWSGI populates
#      from the X-Remote-User HTTP header).
#   2. linkding starts with LD_SUPERUSER_NAME=owner and no
#      LD_SUPERUSER_PASSWORD, so the upstream
#      create_initial_superuser command materialises a passwordless
#      superuser named 'owner' on first boot.  bootstrap_admin.py
#      below re-asserts that the user is unusable-password on
#      every boot (defensive idempotency — if a prior deploy set
#      a password, we clear it).
#   3. The auth-proxy stamps X-Remote-User: owner on every owner
#      request that ISN'T a public-path passthrough.
#   4. linkding finds the matching User row and authenticates the
#      session via Django's RemoteUserBackend.  No password is
#      ever consulted.
#
# Public-path passthrough is implemented in two places that MUST
# stay in sync:
#
#   * openhost.toml's routing.public_paths (the OpenHost router
#     lets these through without zone_auth).
#   * auth_proxy.py's PUBLIC_PATH_PREFIXES (we don't stamp owner
#     identity on these so anonymous and owner visitors see the
#     same response).
#
# Persistent state lives under $OPENHOST_APP_DATA_DIR and is
# bind-mounted into /etc/linkding/data.  The sqlite DB, favicon
# cache, asset uploads, and HTML preview snapshots all land here.

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/linkding}"
LD_DATA_DIR="$PERSIST/data"

mkdir -p "$LD_DATA_DIR"

# linkding's upstream image bind-mounts /etc/linkding/data as the
# data directory; the bootstrap.sh chowns it to www-data on every
# boot.  Symlink our persistent dir to that path so a single
# OpenHost-bound mount holds all state.
#
# The upstream image's /etc/linkding/data is created by the build
# (RUN mkdir data) so it already exists.  Replace it with a
# symlink to our persistent dir.  Use -T (treat dest as a regular
# file) so we don't accidentally create a nested symlink the
# second boot.
if [[ ! -L /etc/linkding/data ]]; then
    rm -rf /etc/linkding/data
    ln -sfnT "$LD_DATA_DIR" /etc/linkding/data
fi

# Make sure the linkding user (www-data, uid 33) can read+write
# the persistent state.  The bind-mount is created by the
# OpenHost runtime as root by default, so chown defensively on
# every boot.
chown -R www-data:www-data "$LD_DATA_DIR" 2>/dev/null || true

# -----------------------------------------------------------------
# Defense in depth: remove any legacy admin-credentials.txt that
# an earlier (Pattern B1) deploy may have written.  This image
# uses Pattern A and never persists credentials, but if anyone
# ever switched patterns we don't want a stale credential file
# lying around for file-browser to read.
# -----------------------------------------------------------------
rm -f "$PERSIST/admin-credentials.txt" 2>/dev/null || true

# -----------------------------------------------------------------
# Trusted-header SSO config.  These env vars are consumed by
# linkding's bookmarks/settings/base.py at process start.  We
# also set HTTP host trust for the public hostname so Django's
# CSRF and absolute-URL generation work behind the OpenHost
# router.
# -----------------------------------------------------------------
export LD_ENABLE_AUTH_PROXY=True
# CustomRemoteUserMiddleware reads request.META[<header>].  uWSGI
# turns the HTTP header X-Remote-User into HTTP_X_REMOTE_USER in
# request.META, so this is the value Django expects.
export LD_AUTH_PROXY_USERNAME_HEADER=HTTP_X_REMOTE_USER
# Sign-out should drop the visitor at the OpenHost root, where
# they get a clean OpenHost login page.  Linkding's standard
# Django logout view will redirect here after clearing the
# session.
export LD_AUTH_PROXY_LOGOUT_URL="${LD_AUTH_PROXY_LOGOUT_URL:-/}"

# Trust X-Forwarded-Host so Django builds absolute URLs that
# match the public hostname.
export LD_USE_X_FORWARDED_HOST=true

# CSRF: Django checks Origin against the public host on POSTs.
# Always include the OpenHost public URL.
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-linkding}"
PUBLIC_URL="https://${APP_NAME}.${ZONE_DOMAIN}"
export LD_CSRF_TRUSTED_ORIGINS="$PUBLIC_URL"

# Owner superuser.  No password — the user is authenticated via
# X-Remote-User only.
export LD_SUPERUSER_NAME="${LD_SUPERUSER_NAME:-owner}"
unset LD_SUPERUSER_PASSWORD || true

# linkding listens loopback-only.  The auth-proxy on :8080 is
# what the OpenHost router talks to.
export LD_SERVER_HOST=127.0.0.1
export LD_SERVER_PORT=9090

# -----------------------------------------------------------------
# Launch linkding via its upstream bootstrap.sh.  bootstrap.sh:
#   * creates the data folder, runs migrations, generates the
#     secret key, runs create_initial_superuser
#   * starts background tasks supervisor (best-effort)
#   * execs uwsgi as PID 1 of its process group
#
# We exec via bash so we keep $? for the supervision loop below.
# -----------------------------------------------------------------
echo "[start.sh] Starting linkding (uwsgi) on 127.0.0.1:9090"
cd /etc/linkding
./bootstrap.sh &
LINKDING_PID=$!

# -----------------------------------------------------------------
# Wait for linkding's HTTP listener to come up before running
# bootstrap_admin.py.  Up to ~120s — first boot does
# collectstatic + migrate + create-superuser before uwsgi binds.
# -----------------------------------------------------------------
LINKDING_READY=0
for _ in $(seq 1 120); do
    if python3 -c "
import socket, sys
s = socket.socket()
s.settimeout(0.5)
sys.exit(0 if s.connect_ex(('127.0.0.1', 9090)) == 0 else 1)
" 2>/dev/null; then
        echo "[start.sh] linkding is listening on 9090"
        LINKDING_READY=1
        break
    fi
    if ! kill -0 "$LINKDING_PID" 2>/dev/null; then
        echo "[start.sh] linkding exited prematurely"
        wait "$LINKDING_PID" || true
        exit 1
    fi
    sleep 1
done

# If linkding hasn't bound its port within the timeout, abort.
# The alternative — silently starting the auth-proxy on top of a
# stuck linkding — would leave /_healthz returning 200 while
# every real request 502'd, hiding the failure from the OpenHost
# liveness probe.  Hard-failing here causes the OpenHost runtime
# to restart the container and surface the problem in
# /api/app_logs.
if [[ "$LINKDING_READY" != "1" ]]; then
    echo "[start.sh] linkding did not start listening on 9090 within 120s; aborting" >&2
    kill -TERM "$LINKDING_PID" 2>/dev/null || true
    wait "$LINKDING_PID" 2>/dev/null || true
    exit 1
fi

# -----------------------------------------------------------------
# Defensive idempotent re-bootstrap.  Best-effort: any failure
# here is logged but doesn't block the container.  See
# bootstrap_admin.py for what this guarantees on top of the
# upstream create_initial_superuser command.
# -----------------------------------------------------------------
echo "[start.sh] Running bootstrap_admin.py (defensive idempotency)"
LINKDING_DIR=/etc/linkding \
    LD_SUPERUSER_NAME="$LD_SUPERUSER_NAME" \
    python3 /opt/openhost-linkding/bootstrap_admin.py || true

# -----------------------------------------------------------------
# Launch auth-proxy.
# -----------------------------------------------------------------
echo "[start.sh] Starting auth-proxy on 0.0.0.0:8080 -> 127.0.0.1:9090"
export AUTH_PROXY_LISTEN_PORT="${AUTH_PROXY_LISTEN_PORT:-8080}"
export AUTH_PROXY_UPSTREAM_HOST="127.0.0.1"
export AUTH_PROXY_UPSTREAM_PORT="9090"
export AUTH_PROXY_OWNER_USERNAME="$LD_SUPERUSER_NAME"
python3 /opt/openhost-linkding/auth_proxy.py &
PROXY_PID=$!

# -----------------------------------------------------------------
# Supervision: exit when either child dies.
# -----------------------------------------------------------------

trap 'kill -TERM "$LINKDING_PID" "$PROXY_PID" 2>/dev/null; wait' TERM INT

set +e
wait -n "$LINKDING_PID" "$PROXY_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$LINKDING_PID" "$PROXY_PID" 2>/dev/null || true
wait || true
exit "$EXIT_CODE"

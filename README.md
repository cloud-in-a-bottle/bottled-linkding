# openhost-linkding

[linkding](https://github.com/sissbruecker/linkding) (self-hosted
bookmark manager) packaged for [OpenHost](https://openhost.ai)
with one-click SSO.

## What this is

A thin wrapper around the upstream `sissbruecker/linkding:latest`
image that:

- Auto-logs the zone owner in with no password form (Pattern A —
  trusted-header SSO via Django's `RemoteUserMiddleware`, hooked
  through linkding's first-class `LD_ENABLE_AUTH_PROXY` setting).
- Lets the REST API, static assets, public shared bookmarks, and
  RSS/Atom feeds reach anonymous visitors so the browser
  extension, bookmarklet, and public share links keep working.
- Persists state under `$OPENHOST_APP_DATA_DIR` (sqlite DB,
  favicons, asset uploads, HTML preview snapshots).
- Stores **no plaintext credentials anywhere** on disk. The owner
  account uses Django's `set_unusable_password()`; the only
  auth path is the trusted `X-Remote-User` header that the
  auth-proxy controls.

## Files

- `Dockerfile` — extends `docker.io/sissbruecker/linkding:latest`
  with `tini`, `gosu`, and our supervisor / auth-proxy /
  bootstrap scripts.
- `openhost.toml` — the OpenHost manifest. Lists `public_paths`
  the OpenHost router lets through without `zone_auth`.
- `start.sh` — supervises linkding (uwsgi) + the auth-proxy.
- `auth_proxy.py` — the SSO sidecar. Strips client-supplied
  trusted headers, stamps `X-Remote-User: <owner>` on owner
  navigations, bypasses owner stamping on public paths.
- `bootstrap_admin.py` — defensive idempotent bootstrap that
  re-asserts the owner superuser exists with an unusable
  password on every boot. The upstream `bootstrap.sh` already
  runs `python manage.py create_initial_superuser`; this script
  is belt-and-braces in case `LD_SUPERUSER_PASSWORD` was ever
  set in a prior deploy.

## Auth model

```
                 zone_auth (verified by router)
                         │
                         ▼
                ┌─────────────────┐
   browser ───► │ OpenHost router │ ───► X-OpenHost-Is-Owner: true
                └─────────────────┘
                         │
                         ▼
              ┌────────────────────┐
              │   auth_proxy.py    │
              │  (port 8080)       │
              │                    │
              │  if owner & not    │
              │  public path:      │
              │  + X-Remote-User   │
              └─────────┬──────────┘
                        │
                        ▼
              ┌────────────────────┐
              │   linkding/uwsgi   │
              │  (loopback :9090)  │
              │                    │
              │  RemoteUserMW      │
              │  reads             │
              │  HTTP_X_REMOTE_USER│
              │  → logs owner in   │
              └────────────────────┘
```

Anonymous visitors hitting a non-public path are redirected to
the OpenHost `/login` page by the router before reaching us.

Anonymous visitors hitting a public path (e.g. a
`/bookmarks/shared` page, or `/api/bookmarks/?...&Token=...`) are
forwarded to linkding unchanged — so the browser extension,
bookmarklet, and shared-link recipients all work without an
OpenHost account.

The owner sees the linkding UI directly with no manual login
step.

## Persistent storage

```
$OPENHOST_APP_DATA_DIR/
└── data/             (symlinked into /etc/linkding/data)
    ├── db.sqlite3    # the bookmark database
    ├── secret_key    # Django SECRET_KEY (auto-generated)
    ├── favicons/     # cached favicons
    ├── previews/     # HTML preview snapshots
    └── assets/       # uploaded assets (icons, archived pages)
```

Nothing in this tree is a usable credential; reading these files
gives an attacker your bookmark database (which they could already
read by visiting the app as the owner) but no password they could
take elsewhere.

## REST API & browser extension

Set up the official linkding browser extension by:

1. Visit `https://linkding.<your-zone>/settings/integrations` as
   the owner.
2. Generate a REST API token.
3. Configure the extension with the URL
   `https://linkding.<your-zone>` and the token.

The extension hits `/api/...` paths which are in the OpenHost
router's `public_paths` list, so the request reaches linkding
without a 302 to `/login`. linkding authenticates the request
via the `Authorization: Token ...` header.

The bookmarklet works the same way.

## Public shared bookmarks

Mark a bookmark as "shared" in the linkding UI. The
`/bookmarks/shared` page is in `public_paths`, so the resulting
URL is reachable by anyone — no OpenHost account required.

## Caveats / what's still rough

- **No OIDC.** linkding has built-in OIDC support, but for
  OpenHost we've gone with trusted-header SSO because it
  requires no shared secret between the OpenHost router and
  linkding. If you want to point linkding at an external
  OIDC provider, you'll need to fork this and add the OIDC env
  vars (`OIDC_OP_*` etc.) — it'll layer cleanly with the
  trusted-header path.
- **One owner only.** Multiple OpenHost zone members all map to
  the single `owner` superuser. linkding's own multi-user
  support is unused. If you want per-user bookmarks, use the
  OpenHost router's per-user header convention and configure
  `LD_AUTH_PROXY_USERNAME_HEADER` accordingly.
- **First boot is slow.** The upstream `bootstrap.sh` runs
  migrations + collects static + creates the secret key on
  first boot, which can take ~30s. The OpenHost healthcheck
  hits `/_healthz` (served by the auth-proxy independently) so
  the cold-start window doesn't trip the "App started but not
  responding" detector.

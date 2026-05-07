"""Bootstrap the OpenHost owner as the linkding superuser on first boot.

linkding's upstream ``bootstrap.sh`` already invokes
``python manage.py create_initial_superuser`` which, when
``LD_SUPERUSER_NAME`` is set without ``LD_SUPERUSER_PASSWORD``,
creates a superuser with ``set_unusable_password()`` — exactly
the shape we want for Pattern A trusted-header SSO: the user can
ONLY be authenticated via the X-Remote-User header that our
auth-proxy stamps, never via a password form.

We could rely entirely on the upstream behaviour, but this script
adds three guarantees on top:

  1. Idempotency: re-running on every boot is safe and a no-op
     when the owner already exists.

  2. Defensive un-setting of the password: if a previous deploy
     accidentally set a usable password (e.g. an operator
     experimented with ``LD_SUPERUSER_PASSWORD``), we clear it
     back to unusable so no on-disk credential ever exists.

  3. Logging an explicit success line that's easy to grep in
     ``oh logs linkding`` when debugging an SSO failure.

Idempotent: safe to invoke on every boot.  Best-effort: a failure
here doesn't block the container — the worst case is that the
upstream ``create_initial_superuser`` did its job and our run is
a no-op anyway.

Usage (called from start.sh):

    LD_SUPERUSER_NAME=owner python3 bootstrap_admin.py

This script does NOT write any credentials to disk.  The whole
point of Pattern A is that there's no password to leak.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

logging.basicConfig(
    level=os.environ.get("BOOTSTRAP_LOG_LEVEL", "INFO"),
    format="[bootstrap] %(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("bootstrap_admin")

LINKDING_DIR = os.environ.get("LINKDING_DIR", "/etc/linkding")
OWNER_USERNAME = os.environ.get("LD_SUPERUSER_NAME", "owner")


# We invoke this via ``manage.py shell -c`` rather than a
# bare ``python -c`` snippet so we inherit linkding's
# DJANGO_SETTINGS_MODULE wiring (set in manage.py via
# os.environ.setdefault).  manage.py's settings module changes
# across upstream versions (e.g. bookmarks.settings vs
# bookmarks.settings.prod for uwsgi); manage.py already knows
# the right one.
PYTHON_SNIPPET = r"""
import os
from django.contrib.auth import get_user_model

username = os.environ["LD_SUPERUSER_NAME"]
User = get_user_model()
user, created = User.objects.get_or_create(
    username=username,
    defaults={"is_superuser": True, "is_staff": True},
)
changed = False
if not user.is_superuser:
    user.is_superuser = True
    changed = True
if not user.is_staff:
    user.is_staff = True
    changed = True
# Always force unusable password.  Pattern A: the user is
# authenticated via X-Remote-User only; a usable password would
# allow an attacker who got hold of the password (e.g. via a
# previous deploy that set LD_SUPERUSER_PASSWORD) to log in via
# the standard form on /login/.  Defensive idempotency.
if user.has_usable_password():
    user.set_unusable_password()
    changed = True
if created or changed:
    user.save()
print("created=%s changed=%s username=%s id=%s" % (
    created, changed, user.username, user.pk,
))
"""


def main() -> int:
    if not OWNER_USERNAME:
        log.warning("LD_SUPERUSER_NAME is empty; skipping bootstrap")
        return 0

    env = os.environ.copy()
    env["LD_SUPERUSER_NAME"] = OWNER_USERNAME

    # Use the linkding venv's python (where Django and the
    # linkding apps are installed) and invoke via
    # ``manage.py shell -c`` so we inherit linkding's
    # DJANGO_SETTINGS_MODULE wiring.
    venv_python = os.path.join(LINKDING_DIR, ".venv", "bin", "python")
    python_bin = venv_python if os.path.exists(venv_python) else "python"

    try:
        result = subprocess.run(
            [python_bin, "manage.py", "shell", "-c", PYTHON_SNIPPET],
            cwd=LINKDING_DIR,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.error("failed to invoke django shell: %s", exc)
        return 1

    if result.returncode != 0:
        log.error(
            "bootstrap snippet returned %d; stderr=%r stdout=%r",
            result.returncode,
            result.stderr.strip(),
            result.stdout.strip(),
        )
        return 1

    log.info("bootstrap complete: %s", result.stdout.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())

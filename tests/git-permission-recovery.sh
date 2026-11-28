#!/usr/bin/env bash
set -euo pipefail

# Run as root on a disposable Linux host with Git, Python, and sudo.
if [[ "$(uname -s)" != Linux || "${EUID}" != 0 || -e /opt/apps || -L /opt/apps ||
      -e /usr/local/bin/bover-helper ]] || getent passwd bover app_demo >/dev/null ||
      getent group bover >/dev/null; then
    echo "Run this test on a fresh, disposable Linux host as root." >&2
    exit 1
fi

export LC_ALL=C
groupadd bover
useradd -g bover -d /opt/apps bover
useradd -G bover -d /opt/apps/demo app_demo
install -d -o bover -g bover -m 0755 /opt/apps /opt/apps/upstream /opt/apps/demo
install -m 0755 scripts/bover-helper.sh /usr/local/bin/bover-helper
install -m 0644 scripts/bover-cli.py /opt/apps/bover_cli.py
printf '%s\n' 'bover ALL=(root) NOPASSWD: /usr/local/bin/bover-helper' > /etc/sudoers.d/bover-test
chmod 0440 /etc/sudoers.d/bover-test

upstream=/opt/apps/upstream
app=/opt/apps/demo
git_as_bover() {
    runuser -u bover -- git "$@"
}
git_as_bover -C "$upstream" init -q -b main
commit() {
    git_as_bover -C "$upstream" -c user.name=Harness -c user.email=harness@example.test \
        commit -q --allow-empty -m "$1"
}
commit Initial
git_as_bover -C "$app" init -q --shared=group -b main
git_as_bover -C "$app" remote add origin "$upstream"
git_as_bover -C "$app" pull -q origin main
commit Update
expected="$(git_as_bover -C "$upstream" rev-parse HEAD)"

# Reproduce an older checkout whose loose object directory lost group write.
object_bucket="$app/.git/objects/${expected:0:2}"
mkdir -p "$object_bucket" "$app/data" /opt/apps/outside
ln -s /opt/apps/outside "$app/.git/objects/outside"
chown -R app_demo:bover "$app" /opt/apps/outside
chmod 0755 "$object_bucket" /opt/apps/outside
chmod 0700 "$app/data"
chmod 0770 "$app"
chmod 0664 "$app/.git/FETCH_HEAD"
git_as_bover config --global --add safe.directory "$app"
if git_as_bover -C "$app" fetch origin > /opt/apps/fetch-error 2>&1; then
    echo "Expected fetch to fail before recovery." >&2
    exit 1
fi
cat /opt/apps/fetch-error
grep -F 'insufficient permission for adding an object to repository database .git/objects' /opt/apps/fetch-error

sync_checkout() {
    runuser -u bover -- env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/apps python3 - <<'PY' |
from pathlib import Path
from bover_cli import git_sync

git_sync(Path("/opt/apps/demo"), branch="main")
PY
        tee /opt/apps/recovery-log
    test "$(grep -c '\[AutoRecovery\] Restoring Git permissions' /opt/apps/recovery-log)" = 1
    test "$(git_as_bover -C "$app" rev-parse HEAD)" = "$(git_as_bover -C "$upstream" rev-parse HEAD)"
}

sync_checkout
test "$(git_as_bover -C "$app" rev-parse HEAD)" = "$expected"
test "$(stat -c %a "$object_bucket")" = 2775

# Older checkouts can also leave this in-place file writable only by the app user.
commit "Another update"
chmod 0644 "$app/.git/FETCH_HEAD"
sync_checkout
test "$(stat -c %a "$app/.git/FETCH_HEAD")" = 664
test "$(stat -c %a "$app/data")" = 700
test "$(stat -c %a /opt/apps/outside)" = 755
echo "Git permission recovery verified."

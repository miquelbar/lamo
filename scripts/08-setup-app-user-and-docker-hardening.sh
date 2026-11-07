#!/usr/bin/env bash
set -euo pipefail

# Script 08: Dedicated 'bover' Service User & Docker Daemon Hardening (CIS / K8s inspired)
# - Creates isolated 'bover' daemon user with home at /opt/apps
# - Assigns deploy keys and repository permissions to 'bover'
# - Hardens Docker daemon: no-new-privileges, live-restore, userland-proxy=false, ulimits
# - Grants '${ADMIN_USER}' passwordless delegation to run commands as 'bover'
# - Grants 'bover' strictly scoped privileges for per-app users and systemctl lifecycle

ADMIN_USER="${1:-${ADMIN_USER:-admin}}"
DOCKER_LOG_MAX_SIZE="${2:-${DOCKER_LOG_MAX_SIZE:-10m}}"
DOCKER_LOG_MAX_FILES="${3:-${DOCKER_LOG_MAX_FILES:-3}}"
BOVER_USER="bover"
BOVER_HOME="/opt/apps"

echo "==> [08] Creating dedicated service user '${BOVER_USER}' with home at '${BOVER_HOME}'..."

# 1. Create bover group and user
if ! getent group "${BOVER_USER}" >/dev/null 2>&1; then
    groupadd -r "${BOVER_USER}"
fi

if ! getent group docker >/dev/null 2>&1; then
    groupadd -r docker
fi

if ! id "${BOVER_USER}" >/dev/null 2>&1; then
    useradd -r -g "${BOVER_USER}" -G docker -d "${BOVER_HOME}" -s /bin/bash "${BOVER_USER}"
    echo "Created system user '${BOVER_USER}' in group 'docker'."
else
    usermod -aG docker "${BOVER_USER}"
    usermod -s /bin/bash "${BOVER_USER}"
fi

# Ensure password login is disabled for bover user
passwd -l "${BOVER_USER}" >/dev/null 2>&1 || true

# Clean up legacy 'app' user and group if present
if id "app" >/dev/null 2>&1; then
    echo "==> [08] Removing obsolete 'app' user..."
    userdel -f app 2>/dev/null || true
    groupdel app 2>/dev/null || true
fi

# 2. Directory structure and permissions
mkdir -p "${BOVER_HOME}"/{.ssh,shared,backups,.vault}
chmod 750 "${BOVER_HOME}"
chmod 700 "${BOVER_HOME}/.vault"

# 3. Grant admin sudo rights to act as bover without password
cat <<EOF > /etc/sudoers.d/91-${ADMIN_USER}-as-bover
# Allow ${ADMIN_USER} to run commands and open shells as ${BOVER_USER} without password
${ADMIN_USER} ALL=(${BOVER_USER}) NOPASSWD: ALL
EOF
chmod 0440 "/etc/sudoers.d/91-${ADMIN_USER}-as-bover"

# Clean up legacy app sudoers if present
rm -f "/etc/sudoers.d/91-${ADMIN_USER}-as-app" "/etc/sudoers.d/92-app-systemctl"

# Install scoped bover-helper binary (replaces broad root useradd/chown permissions)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/bover-helper.sh" ]]; then
    cp "${SCRIPT_DIR}/bover-helper.sh" /usr/local/bin/bover-helper
    chmod 755 /usr/local/bin/bover-helper
    chown root:root /usr/local/bin/bover-helper
fi

# Allow bover daemon user to manage bover-app@ systemd units and scoped per-app users
cat <<EOF > /etc/sudoers.d/92-${BOVER_USER}-privileges
# Principle of least privilege: bover user manages app units and dedicated app users via bover-helper
${BOVER_USER} ALL=(root) NOPASSWD: /bin/systemctl enable bover-app@*, /bin/systemctl disable bover-app@*, /bin/systemctl start bover-app@*, /bin/systemctl stop bover-app@*, /bin/systemctl restart bover-app@*, /bin/systemctl is-active bover-app@*, /bin/systemctl reload bover-app@*, /bin/systemctl is-enabled bover-app@*, /usr/local/bin/bover-helper
EOF
chmod 0440 "/etc/sudoers.d/92-${BOVER_USER}-privileges"

# 4. Migrate or setup GitHub Deploy Keys into /opt/apps/.ssh/
echo "==> [08] Setting up repository Deploy Keys for '${BOVER_USER}'..."
mkdir -p "${BOVER_HOME}/.ssh"
chmod 700 "${BOVER_HOME}/.ssh"

# If admin user or legacy app user already generated deploy keys, copy them over
if compgen -G "/home/${ADMIN_USER}/.ssh/id_deploy_*" > /dev/null; then
    cp "/home/${ADMIN_USER}/.ssh/id_deploy_"* "${BOVER_HOME}/.ssh/" 2>/dev/null || true
    cp "/home/${ADMIN_USER}/.ssh/config" "${BOVER_HOME}/.ssh/" 2>/dev/null || true
fi

# Ensure git SSH config exists in /opt/apps/.ssh/config
if [[ ! -f "${BOVER_HOME}/.ssh/config" ]]; then
    cat <<'EOF' > "${BOVER_HOME}/.ssh/config"
# Managed by Lamo CLI & provisioning scripts - GitHub Deploy Key aliases
EOF
fi

chmod 600 "${BOVER_HOME}/.ssh/config"
chmod 600 "${BOVER_HOME}/.ssh/id_deploy_"* 2>/dev/null || true
chmod 644 "${BOVER_HOME}/.ssh/id_deploy_"*.pub 2>/dev/null || true
# Set ownership only for bover root and shared infrastructure directories, never clobbering per-app ownership
chown "${BOVER_USER}:${BOVER_USER}" "${BOVER_HOME}"
chown -R "${BOVER_USER}:${BOVER_USER}" "${BOVER_HOME}/.ssh" "${BOVER_HOME}/shared" "${BOVER_HOME}/backups" "${BOVER_HOME}/.vault" 2>/dev/null || true

# 5. Container Daemon Hardening (CIS Docker Benchmark & Podman compatibility)
if systemctl is-active docker >/dev/null 2>&1 || [[ -d /etc/docker ]] || command -v dockerd >/dev/null 2>&1; then
    echo "==> [08] Applying Docker Daemon security hardening..."
    mkdir -p /etc/docker
    TMP_DAEMON_JSON="/tmp/daemon.json.$$"
    cat <<EOF > "${TMP_DAEMON_JSON}"
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "${DOCKER_LOG_MAX_SIZE}",
    "max-file": "${DOCKER_LOG_MAX_FILES}"
  },
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    }
  }
}
EOF

    if [[ -f /etc/docker/daemon.json ]] && cmp -s /etc/docker/daemon.json "${TMP_DAEMON_JSON}"; then
        rm -f "${TMP_DAEMON_JSON}"
        echo "==> [08] Docker Daemon hardening already applied (skipping service reload/restart)."
    else
        mv "${TMP_DAEMON_JSON}" /etc/docker/daemon.json
        RUNNING_CONTAINERS="$(docker ps -q 2>/dev/null || true)"
        if [[ -n "${RUNNING_CONTAINERS}" ]]; then
            echo "==> [08] Running containers detected. Reloading Docker daemon configuration dynamically (zero downtime)..."
            systemctl reload docker 2>/dev/null || true
        else
            echo "==> [08] Restarting Docker with updated hardened configuration..."
            systemctl restart docker 2>/dev/null || true
        fi
    fi
elif systemctl is-active podman.socket >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
    echo "==> [08] Ensuring Podman socket is active..."
    systemctl restart podman.socket 2>/dev/null || true
fi

# 5. Configure Git for bover user to trust managed app directories
sudo -u "${BOVER_USER}" git config --global --add safe.directory "*" || true

# 6. Add convenience aliases to admin's .bashrc
BASHRC="/home/${ADMIN_USER}/.bashrc"
if [[ -f "${BASHRC}" ]]; then
    sed -i '/# BEGIN APP USER CONVENIENCE/,/# END APP USER CONVENIENCE/d' "${BASHRC}"
    sed -i '/# BEGIN BOVER USER CONVENIENCE/,/# END BOVER USER CONVENIENCE/d' "${BASHRC}"
    cat <<'EOF' >> "${BASHRC}"
# BEGIN BOVER USER CONVENIENCE
# Quick jump and execution as daemon user 'bover'
alias as-bover='sudo -u bover -i'
alias bover-compose='sudo -u bover docker compose'
alias cdapps='cd /opt/apps'
# END BOVER USER CONVENIENCE
EOF
    chown "${ADMIN_USER}:${ADMIN_USER}" "${BASHRC}"
fi

echo "==> [08] User '${BOVER_USER}' and Docker hardening setup complete."

#!/usr/bin/env bash
set -euo pipefail

# Script 01: Create non-root admin user and configure SSH key + sudo
# Target OS: Debian 12/13
# Must be executed as root on the target server.

ADMIN_USER="${1:-${ADMIN_USER:-admin}}"

echo "==> [01] Ensuring sudo is installed..."
apt-get update -qq
apt-get install -y -qq sudo curl

echo "==> [01] Creating user '${ADMIN_USER}' if not present..."
if id "${ADMIN_USER}" >/dev/null 2>&1; then
    echo "User '${ADMIN_USER}' already exists."
    usermod -aG sudo,adm,systemd-journal "${ADMIN_USER}" 2>/dev/null || true
else
    useradd -m -s /bin/bash -G sudo,adm,systemd-journal "${ADMIN_USER}"
    echo "User '${ADMIN_USER}' created and added to 'sudo', 'adm', 'systemd-journal' groups."
fi

# Ensure user has a valid password for emergency VNC console login
if [[ -z "$(passwd -S "${ADMIN_USER}" | awk '{print $2}' | grep -v '[LK]')" ]]; then
    echo "==> [01] Setting emergency password for '${ADMIN_USER}' (used for VNC web console only)..."
    # Generate a random 16-char password if none set, or ask operator
    TEMP_PASS=$(openssl rand -base64 12)
    echo "${ADMIN_USER}:${TEMP_PASS}" | chpasswd
    echo "------------------------------------------------------------------"
    echo " EMERGENCY VNC PASSWORD FOR '${ADMIN_USER}': ${TEMP_PASS}"
    echo " Save this password! It allows logging in via provider VNC console"
    echo " if SSH network access is ever blocked."
    echo "------------------------------------------------------------------"
fi

echo "==> [01] Configuring passwordless sudo for '${ADMIN_USER}' in /etc/sudoers.d/..."
cat <<EOF > "/etc/sudoers.d/90-${ADMIN_USER}"
# Managed by provisioning scripts
${ADMIN_USER} ALL=(ALL:ALL) NOPASSWD:ALL
EOF
chmod 0440 "/etc/sudoers.d/90-${ADMIN_USER}"

echo "==> [01] Copying authorized_keys from root to '${ADMIN_USER}'..."
USER_SSH_DIR="/home/${ADMIN_USER}/.ssh"
mkdir -p "${USER_SSH_DIR}"
chmod 700 "${USER_SSH_DIR}"

if [[ -f "/root/.ssh/authorized_keys" ]]; then
    cp "/root/.ssh/authorized_keys" "${USER_SSH_DIR}/authorized_keys"
    chmod 600 "${USER_SSH_DIR}/authorized_keys"
    chown -R "${ADMIN_USER}:${ADMIN_USER}" "${USER_SSH_DIR}"
    echo "Authorized keys installed for '${ADMIN_USER}'."
else
    echo "WARNING: /root/.ssh/authorized_keys not found. You must add your public key manually!"
fi

echo "==> [01] User setup complete."

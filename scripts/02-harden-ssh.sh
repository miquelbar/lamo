#!/usr/bin/env bash
set -euo pipefail

# Script 02: Harden SSH daemon
# - Changes SSH port (default: 2245)
# - Disables root login
# - Disables password and keyboard-interactive authentication
# - Limits allowed users to the admin user
# - Handles Debian 12/13 systemd socket activation cleanly

SSH_PORT="${1:-${SSH_PORT:-2245}}"
ADMIN_USER="${2:-${ADMIN_USER:-admin}}"

echo "==> [02] Safety check: verifying authorized_keys for '${ADMIN_USER}' before locking SSH..."
USER_KEYS="/home/${ADMIN_USER}/.ssh/authorized_keys"
if [[ ! -s "${USER_KEYS}" ]]; then
    echo "ERROR: ${USER_KEYS} does not exist or is empty!"
    echo "ABORTING SSH hardening to prevent accidental lockout."
    exit 1
fi

if ! grep -qE "^(ssh-rsa|ssh-ed25519|ecdsa-)" "${USER_KEYS}"; then
    echo "ERROR: No valid public key found in ${USER_KEYS}!"
    echo "ABORTING SSH hardening to prevent accidental lockout."
    exit 1
fi
echo "==> [02] Safety check passed: valid SSH key found for '${ADMIN_USER}'."

echo "==> [02] Hardening SSH for user '${ADMIN_USER}' on port ${SSH_PORT}..."

# 1. Configure systemd socket activation for Debian 12/13
if systemctl is-active --quiet ssh.socket || systemctl is-enabled --quiet ssh.socket; then
    echo "==> [02] Configuring systemd ssh.socket override for port ${SSH_PORT}..."
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat <<EOF > /etc/systemd/system/ssh.socket.d/listen.conf
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
fi

# 2. Configure drop-in sshd configuration
mkdir -p /etc/ssh/sshd_config.d
cat <<EOF > /etc/ssh/sshd_config.d/99-hardening.conf
# Managed by provisioning scripts - Do not edit manually

# Port configuration
Port ${SSH_PORT}

# Disable root login completely
PermitRootLogin no

# Authentication restrictions
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

# Limit access to admin user only
AllowUsers ${ADMIN_USER}

# Brute-force & session hardening
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no

# Detailed authentication audit logging (logs public key fingerprints and IPs)
LogLevel VERBOSE
ExposeAuthInfo yes
EOF

# 3. Install smart SSH intrusion detection alert hook
echo "==> [02] Installing smart SSH intrusion detection alert hook..."
cat <<'EOF' > /usr/local/bin/bover-ssh-alert
#!/usr/bin/env bash
# Managed by provisioning scripts - Smart SSH Intrusion Alert Hook
set -u

USER_NAME="${USER:-unknown}"
CLIENT_IP=$(echo "${SSH_CONNECTION:-}" | awk '{print $1}')
CLIENT_PORT=$(echo "${SSH_CONNECTION:-}" | awk '{print $2}')
HOSTNAME=$(hostname 2>/dev/null || echo "server")

# If auth info is exposed by sshd, verify against authorized_keys
FP=""
USER_KEYS="/home/${USER_NAME}/.ssh/authorized_keys"
TRUSTED=false

if [ -n "${SSH_USER_AUTH:-}" ] && [ -f "${SSH_USER_AUTH}" ]; then
    KEY_BLOB=$(awk '/^publickey / {print $3}' "${SSH_USER_AUTH}" 2>/dev/null | head -n1 || true)
    if [ -n "${KEY_BLOB}" ] && [ -f "${USER_KEYS}" ] && grep -Fq "${KEY_BLOB}" "${USER_KEYS}" 2>/dev/null; then
        TRUSTED=true
        FP="verified-key"
    else
        FP=$(sed 's/^publickey //' "${SSH_USER_AUTH}" 2>/dev/null | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || true)
    fi
fi

# Fallback fingerprint comparison if key blob format differed
if [ "${TRUSTED}" = "false" ] && [ -n "${FP}" ] && [ -f "${USER_KEYS}" ]; then
    while IFS= read -r line || [ -n "${line}" ]; do
        line="$(echo "${line}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
        if [ -n "${line}" ]; then
            case "${line}" in
                \#*) ;; # skip comment
                *)
                    line_fp=$(echo "${line}" | ssh-keygen -lf - 2>/dev/null | awk '{print $2}' || true)
                    if [ -n "${line_fp}" ] && [ "${line_fp}" = "${FP}" ]; then
                        TRUSTED=true
                        break
                    fi
                    ;;
            esac
        fi
    done < "${USER_KEYS}"
fi

# Log the event locally for systemd journal audit trail
logger -p authpriv.notice -t "ssh-auth-check" "user=${USER_NAME} ip=${CLIENT_IP} fp=${FP} trusted=${TRUSTED}"

# Decision Logic:
# If the connection matches an authorized SSH key -> SILENT (it is YOU!)
if [ "${TRUSTED}" = "true" ]; then
    exit 0
fi

# If the connection does NOT match the authorized SSH key -> ALERT!
ALERT_MSG="🛡️ <b>ES BOVER · ALERTA DE SEGURIDAD</b>
<i>Intrusión SSH no autorizada detectada</i>

🖥️  <b>Nodo:</b> <code>${HOSTNAME}</code>
👤 <b>Usuario:</b> <code>${USER_NAME}</code>
🌐 <b>IP Origen:</b> <code>${CLIENT_IP}:${CLIENT_PORT}</code>
🔑 <b>Huella SSH:</b> <code>${FP:-desconocida}</code>
⏱️ <b>Fecha:</b> <code>$(date '+%Y-%m-%d %H:%M:%S %Z')</code>

<blockquote>⚠️ <b>Aviso:</b> Se ha iniciado una sesión con una clave SSH ajena al registro autorizado. Comprueba las sesiones activas de inmediato.</blockquote>

<i>Es Bover Guardian :: Security Engine</i>"

if [ -x /usr/local/bin/bover ]; then
    sudo -u bover /usr/local/bin/bover telegram --send "${ALERT_MSG}" >/dev/null 2>&1 || true
fi
EOF
chmod 0755 /usr/local/bin/bover-ssh-alert
chown root:root /usr/local/bin/bover-ssh-alert

# 4. Configure /etc/ssh/sshrc to trigger the alert script in the background
echo "==> [02] Configuring /etc/ssh/sshrc trigger..."
cat <<'EOF' > /etc/ssh/sshrc
#!/bin/sh
if [ -x /usr/local/bin/bover-ssh-alert ]; then
    /usr/local/bin/bover-ssh-alert "$@" </dev/null >/dev/null 2>&1 &
fi
EOF
chmod 0755 /etc/ssh/sshrc
chown root:root /etc/ssh/sshrc

# 5. Test sshd configuration syntax before restarting
echo "==> [02] Verifying sshd configuration syntax..."
sshd -t

# 4. Restart services cleanly
echo "==> [02] Reloading systemd and restarting SSH services..."
systemctl daemon-reload

if systemctl is-active --quiet ssh.socket; then
    systemctl restart ssh.socket
fi

systemctl restart ssh

echo "==> [02] SSH hardening complete. Listening on port ${SSH_PORT} for user '${ADMIN_USER}'."

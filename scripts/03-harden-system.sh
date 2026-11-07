#!/usr/bin/env bash
set -euo pipefail

# Script 03: OS and Kernel Hardening
# - Sysctl network security parameters
# - Automated security updates (unattended-upgrades)
# - Fail2ban brute-force protection tuned to the custom SSH port

SSH_PORT="${1:-2245}"
RETENTION_DAYS="${2:-7}"
JOURNALD_MAX_MB="${3:-150}"

echo "==> [03] Applying kernel sysctl hardening..."
cat <<EOF > /etc/sysctl.d/99-hardening.conf
# Network hardening against spoofing, floods and route injection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast echo requests (Smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable ICMP redirect acceptance (prevents route poisoning)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable ICMP redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Enable TCP SYN Cookies (mitigates SYN flood attacks)
net.ipv4.tcp_syncookies = 1

# Log martian packets (unreasonable addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF

sysctl --system >/dev/null

echo "==> [03] Installing and configuring unattended-upgrades (automatic security updates)..."
apt-get update -qq
apt-get install -y -qq unattended-upgrades apt-listchanges fail2ban

cat <<EOF > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

echo "==> [03] Configuring Fail2ban Telegram action and jail for SSH port ${SSH_PORT}..."
mkdir -p /etc/fail2ban/action.d
cat <<'EOF' > /etc/fail2ban/action.d/bover-telegram.conf
[Definition]
actionban = if [ -x /usr/local/bin/bover ]; then MSG=$(printf "🛡️ <b>ES BOVER · DEFENSA PERIMETRAL</b>\n<i>IP bloqueada por fuerza bruta (Fail2ban)</i>\n\n🖥️  <b>Nodo:</b> <code>$(hostname 2>/dev/null || echo server)</code>\n🎯 <b>IP Atacante:</b> <code><ip></code>\n🚪 <b>Servicio:</b> SSH (Puerto <code><port></code>)\n❌ <b>Intentos fallidos:</b> <failures> intentos consecutivos\n⏳ <b>Sanción:</b> Bloqueo total durante <code>2 horas</code>\n\n<blockquote>🛡️ <b>Mitigación:</b> Tráfico descartado por iptables. Tu servidor permanece protegido.</blockquote>\n\n<i>Es Bover Guardian :: Fail2ban Shield</i>"); sudo -u bover /usr/local/bin/bover telegram --send "$MSG" >/dev/null 2>&1 || true; fi
actionunban =
EOF

cat <<EOF > /etc/fail2ban/jail.d/sshd-custom.conf
[sshd]
enabled = true
port = ${SSH_PORT}
mode = aggressive
maxretry = 3
findtime = 600
bantime = 7200
action = %(action_)s
         bover-telegram[port="${SSH_PORT}"]
EOF

systemctl enable fail2ban --quiet
systemctl restart fail2ban

echo "==> [03] Configuring Systemd Journald ${RETENTION_DAYS}-day log retention and ${JOURNALD_MAX_MB}M storage boundaries..."
mkdir -p /etc/systemd/journald.conf.d
cat <<EOF > /etc/systemd/journald.conf.d/99-retention.conf
[Journal]
Storage=persistent
MaxRetentionSec=${RETENTION_DAYS}day
SystemMaxUse=${JOURNALD_MAX_MB}M
RuntimeMaxUse=50M
EOF
systemctl restart systemd-journald 2>/dev/null || true

echo "==> [03] Configuring user command audit logging (authpriv & /var/log/user-activity.log)..."
cat <<'EOF' > /etc/profile.d/99-audit-commands.sh
# User session command audit logging to syslog and /var/log/user-activity.log
export HISTTIMEFORMAT="%F %T "
export HISTCONTROL=""
export HISTIGNORE=""
shopt -s histappend 2>/dev/null || true

log_user_command() {
    local exit_code="$?"
    local cmd="$(history 1 2>/dev/null | sed 's/^[ ]*[0-9]*[ ]*//')"
    if [[ -n "${cmd}" ]] && [[ "${cmd}" != "${LAST_LOGGED_CMD:-}" ]]; then
        local user_id="$(id -un 2>/dev/null || echo unknown)"
        local user_uid="$(id -u 2>/dev/null || echo 0)"
        local term="$(tty 2>/dev/null || echo notty)"
        local entry="[$(date '+%Y-%m-%d %H:%M:%S')] [user=${user_id} uid=${user_uid} tty=${term} pwd=${PWD} exit=${exit_code}] ${cmd}"
        echo "${entry}" >> /var/log/user-activity.log 2>/dev/null || true
        logger -p authpriv.notice -t "user-activity" "[user=${user_id} uid=${user_uid} tty=${term} pwd=${PWD} exit=${exit_code}] ${cmd}" 2>/dev/null || true
        LAST_LOGGED_CMD="${cmd}"
    fi
}
PROMPT_COMMAND="log_user_command; ${PROMPT_COMMAND:-:}"
EOF
chmod 644 /etc/profile.d/99-audit-commands.sh
touch /var/log/user-activity.log
chattr -a /var/log/user-activity.log 2>/dev/null || true
chmod 0666 /var/log/user-activity.log
chattr +a /var/log/user-activity.log 2>/dev/null || true

echo "==> [03] Configuring Sudoers command execution audit log..."
cat <<'EOF' > /etc/sudoers.d/90-sudo-audit
# Audit all sudo commands to dedicated log file
Defaults log_year, log_host, logfile="/var/log/sudo.log"
EOF
chmod 0440 /etc/sudoers.d/90-sudo-audit
touch /var/log/sudo.log
chmod 0640 /var/log/sudo.log
chown root:adm /var/log/sudo.log 2>/dev/null || true

echo "==> [03] Configuring Logrotate for strict ${RETENTION_DAYS}-day retention on all audit logs..."
cat <<EOF > /etc/logrotate.d/user-audit
/var/log/sudo.log /var/log/user-activity.log {
    daily
    rotate ${RETENTION_DAYS}
    missingok
    notifempty
    compress
    delaycompress
    prerotate
        chattr -a /var/log/user-activity.log 2>/dev/null || true
    endscript
    postrotate
        chattr +a /var/log/user-activity.log 2>/dev/null || true
    endscript
}
EOF

echo "==> [03] Configuring out-of-band KVM / VNC console login detection and alert..."
cat <<'EOF' > /usr/local/bin/bover-console-alert
#!/usr/bin/env bash
# Managed by provisioning scripts - KVM / VNC Physical Console Intrusion Alert
set -u

PAM_TYPE="${PAM_TYPE:-}"
PAM_USER="${PAM_USER:-unknown}"
PAM_TTY="${PAM_TTY:-console}"
PAM_SERVICE="${PAM_SERVICE:-login}"
HOSTNAME="$(hostname 2>/dev/null || echo server)"

# Only trigger on opening a console session
if [ "${PAM_TYPE}" != "open_session" ]; then
    exit 0
fi

# Log the event locally
logger -p authpriv.warning -t "console-auth-check" "Out-of-band console login: user=${PAM_USER} tty=${PAM_TTY} service=${PAM_SERVICE}"

ALERT_MSG="🛡️ <b>ES BOVER · ACCESO FUERA DE BANDA</b>
<i>Sesión abierta en consola física / KVM</i>

🖥️  <b>Nodo:</b> <code>${HOSTNAME}</code>
👤 <b>Usuario:</b> <code>${PAM_USER}</code>
📺 <b>Terminal:</b> <code>${PAM_TTY}</code> (KVM Virtual Display)
⚙️ <b>Servicio:</b> <code>${PAM_SERVICE}</code> (PAM Local Console)
⏱️ <b>Fecha:</b> <code>$(date '+%Y-%m-%d %H:%M:%S %Z')</code>

<blockquote>🛑 <b>Atención:</b> Se ha iniciado sesión mediante la consola web del panel del proveedor (KVM/VNC). Si no has sido tú, cambia la contraseña del panel inmediatamente.</blockquote>

<i>Es Bover Guardian :: Hardware Hook</i>"

if [ -x /usr/local/bin/bover ]; then
    sudo -u bover /usr/local/bin/bover telegram --send "${ALERT_MSG}" >/dev/null 2>&1 || true
fi
EOF
chmod 0755 /usr/local/bin/bover-console-alert
chown root:root /usr/local/bin/bover-console-alert

# Add to /etc/pam.d/login if not already present
if ! grep -q "bover-console-alert" /etc/pam.d/login 2>/dev/null; then
    echo "session optional pam_exec.so /usr/local/bin/bover-console-alert" >> /etc/pam.d/login
fi

echo "==> [03] System hardening and user audit logging complete."

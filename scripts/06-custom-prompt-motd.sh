#!/usr/bin/env bash
set -euo pipefail

# Script 06: Custom Hostname, Dynamic MOTD (Dashboard on Login) & Enhanced Prompt
# Works on Debian 12/13
# Configures a clean hostname, modern colored bash prompt, handy aliases,
# and a fast system status dashboard shown whenever you log in via SSH.

NEW_HOSTNAME="${1:-${SERVER_HOSTNAME:-myserver}}"
ADMIN_USER="${2:-${ADMIN_USER:-admin}}"

echo "==> [06] Setting system hostname to '${NEW_HOSTNAME}'..."
hostnamectl set-hostname "${NEW_HOSTNAME}"

# Ensure /etc/hosts maps the new hostname
if ! grep -q "${NEW_HOSTNAME}" /etc/hosts; then
    sed -i "s/127\.0\.1\.1.*/127.0.1.1\t${NEW_HOSTNAME}/" /etc/hosts || echo -e "127.0.1.1\t${NEW_HOSTNAME}" >> /etc/hosts
fi

echo "==> [06] Creating dynamic MOTD dashboard in /etc/update-motd.d/..."
# Remove default motd files that clutter the login
mkdir -p /etc/update-motd.d
chmod -x /etc/update-motd.d/* 2>/dev/null || true
rm -f /etc/motd
touch /etc/motd

cat <<'EOF' > /etc/update-motd.d/10-sysinfo
#!/usr/bin/env bash
# Fast & lightweight dynamic MOTD for Debian

# Color definitions
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_CYAN="\033[36m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_RED="\033[31m"
C_GRAY="\033[90m"

# System data
HOSTNAME=$(hostname)
UPTIME=$(uptime -p 2>/dev/null | sed 's/up //')
LOAD=$(cat /proc/loadavg | awk '{print $1", "$2", "$3}')
CORES=$(nproc)

# Memory & Swap
MEM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
MEM_USED=$(free -m | awk '/Mem:/ {print $3}')
MEM_PCT=$(awk -v u="${MEM_USED}" -v t="${MEM_TOTAL}" 'BEGIN {printf "%.1f", (u/t)*100}')
SWAP_TOTAL=$(free -m | awk '/Swap:/ {print $2}')
SWAP_USED=$(free -m | awk '/Swap:/ {print $3}')
if [ "${SWAP_TOTAL}" -gt 0 ]; then
    SWAP_INFO=" [Swap: ${SWAP_USED}/${SWAP_TOTAL} MB]"
else
    SWAP_INFO=""
fi

# Disk
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
DISK_PCT=$(df -h / | awk 'NR==2 {print $5}')

# IP
PRIMARY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7}' | head -n1 || echo "unknown")

# Container engine status (Docker or Podman) - read pre-sampled summary first to avoid blocking SSH handshake
if [ -r /opt/apps/.docker-summary.env ]; then
    . /opt/apps/.docker-summary.env
    DOCKER_INFO="${C_GREEN}${RUNNING_CONTAINERS:-0} running${C_RESET} (${TOTAL_CONTAINERS:-0} total)"
elif [ -S /var/run/docker.sock ]; then
    RUNNING_CONTAINERS=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')
    TOTAL_CONTAINERS=$(docker ps -a -q 2>/dev/null | wc -l | tr -d ' ')
    DOCKER_INFO="${C_GREEN}${RUNNING_CONTAINERS} running${C_RESET} (${TOTAL_CONTAINERS} total)"
else
    DOCKER_INFO="${C_GRAY}inactive / not installed${C_RESET}"
fi

# Fail2ban status - use non-blocking cache in /run so pam_motd returns in <10ms
if [ -r /run/bover-f2b.cache ]; then
    BANNED_IPS=$(cat /run/bover-f2b.cache 2>/dev/null || echo "0")
    F2B_INFO="${C_GREEN}${BANNED_IPS:-0} banned IPs${C_RESET}"
    if [ -S /var/run/fail2ban/fail2ban.sock ]; then
        (fail2ban-client status sshd 2>/dev/null | awk '/Currently banned:/ {print $NF}' > /run/bover-f2b.cache.tmp && chmod 0644 /run/bover-f2b.cache.tmp && mv -f /run/bover-f2b.cache.tmp /run/bover-f2b.cache) </dev/null >/dev/null 2>&1 &
    fi
elif [ -S /var/run/fail2ban/fail2ban.sock ]; then
    BANNED_IPS="0"
    (fail2ban-client status sshd 2>/dev/null | awk '/Currently banned:/ {print $NF}' > /run/bover-f2b.cache.tmp && chmod 0644 /run/bover-f2b.cache.tmp && mv -f /run/bover-f2b.cache.tmp /run/bover-f2b.cache) </dev/null >/dev/null 2>&1 &
    F2B_INFO="${C_GREEN}${BANNED_IPS} banned IPs${C_RESET}"
else
    F2B_INFO="${C_GRAY}inactive${C_RESET}"
fi

HOST_LABEL=$(echo "${HOSTNAME}" | tr '[:lower:]' '[:upper:]')
echo -e ""
echo -e "${C_CYAN}${C_BOLD}  ==============================================================${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}   >>> NODE :: ${HOST_LABEL}                                   ${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}  ==============================================================${C_RESET}"
echo -e "   ${C_BOLD}Host:${C_RESET}      ${C_GREEN}${HOSTNAME}${C_RESET} (${PRIMARY_IP})"
echo -e "   ${C_BOLD}OS:${C_RESET}        $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"') ($(uname -m))"
echo -e "   ${C_BOLD}Uptime:${C_RESET}    ${UPTIME}"
echo -e "   ${C_BOLD}Load avg:${C_RESET}  ${LOAD} [${CORES} vCores]"
echo -e "   ${C_BOLD}Memory:${C_RESET}    ${MEM_USED} MB / ${MEM_TOTAL} MB (${MEM_PCT}%)${SWAP_INFO}"
echo -e "   ${C_BOLD}Disk /:${C_RESET}    ${DISK_USED} / ${DISK_TOTAL} (${DISK_PCT})"
echo -e "   ${C_BOLD}Docker:${C_RESET}    ${DOCKER_INFO}"
echo -e "   ${C_BOLD}Fail2ban:${C_RESET}  ${F2B_INFO}"
echo -e "${C_CYAN}${C_BOLD}  ==============================================================${C_RESET}"
echo -e ""
EOF

chmod +x /etc/update-motd.d/10-sysinfo

echo "==> [06] Ensuring htop, ncdu, and procps utilities are installed..."
apt-get update -qq
apt-get install -y -qq htop ncdu procps

echo "==> [06] Configuring modern bash prompt and useful aliases for '${ADMIN_USER}' and root..."

configure_bashrc() {
    local target_user="$1"
    local user_home="$2"
    local bashrc="${user_home}/.bashrc"

    if [[ ! -f "${bashrc}" ]]; then
        touch "${bashrc}"
    fi

    # Remove old custom block if present
    sed -i '/# BEGIN NETCUP CUSTOM PROMPT/,/# END NETCUP CUSTOM PROMPT/d' "${bashrc}" 2>/dev/null || true
    sed -i '/# BEGIN NODE CUSTOM PROMPT/,/# END NODE CUSTOM PROMPT/d' "${bashrc}" 2>/dev/null || true

    cat <<'EOF' >> "${bashrc}"
# BEGIN NODE CUSTOM PROMPT
# Colored modern prompt with exit code tracking and git branch
set_bash_prompt() {
    local EXIT_CODE=$?
    local ERR_STATUS=""
    if [ $EXIT_CODE -ne 0 ]; then
        ERR_STATUS="\[\033[01;31m\][✗ $EXIT_CODE]\[\033[00m\] "
    fi
    local UCOLOR="\[\033[01;32m\]"
    if [ "$USER" = "root" ]; then
        UCOLOR="\[\033[01;31m\]"
    fi
    local GIT_INFO=""
    local BRANCH
    BRANCH=$(git branch 2>/dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/')
    if [ -n "$BRANCH" ]; then
        GIT_INFO=" \[\033[01;33m\](${BRANCH})\[\033[00m\]"
    fi
    PS1="${ERR_STATUS}\[\033[90m\][\t] ${UCOLOR}\u\[\033[00m\]@\[\033[01;36m\]\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]${GIT_INFO}\$ "
}
PROMPT_COMMAND=set_bash_prompt

# Useful system & Docker aliases
alias ll='ls -lah --color=auto --group-directories-first'
alias la='ls -A --color=auto'
alias df='df -h'
alias free='free -m'
alias ports='ss -tulpn'
alias myip='ip -4 addr show scope global | grep inet | awk "{print \$2}" | cut -d/ -f1'

# Docker convenience aliases
alias dps='docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"'
alias dlogs='docker logs -f --tail=100'
alias dcompose='docker compose'
# END NODE CUSTOM PROMPT
EOF

    chown "${target_user}:${target_user}" "${bashrc}"
}

configure_bashrc "${ADMIN_USER}" "/home/${ADMIN_USER}"
configure_bashrc "root" "/root"

echo "==> [06] Prompt and MOTD dashboard setup complete."

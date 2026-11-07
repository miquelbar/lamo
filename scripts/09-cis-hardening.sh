#!/usr/bin/env bash
set -euo pipefail

# Script 09: CIS Benchmark Hardening (Debian 13 Level-1, OpenSSH & Docker)
# Implements Center for Internet Security (CIS) recommended controls.
# Designed for production Docker hosts without breaking container networking.

ADMIN_USER="${1:-${ADMIN_USER:-admin}}"
SSH_PORT="${2:-${SSH_PORT:-2245}}"

echo "=================================================================="
echo " ==> [09] Starting CIS Benchmark Hardening Suite"
echo "=================================================================="

# ------------------------------------------------------------------------------
# 1. CIS OS HARDENING (Debian 13 Level-1 Server)
# ------------------------------------------------------------------------------
echo "==> [09.1] CIS: Disabling obsolete/vulnerable kernel filesystems & protocols..."
cat <<'EOF' > /etc/modprobe.d/cis-blacklist.conf
# CIS Benchmark: Disable unneeded filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true

# CIS Benchmark: Disable uncommon/vulnerable network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

echo "==> [09.2] CIS: Hardening kernel memory, ptrace, bpf, and network via sysctl..."
cat <<EOF > /etc/sysctl.d/99-cis-hardening.conf
# CIS: Memory space randomization (ASLR) fully enabled
kernel.randomize_va_space = 2

# CIS: Restrict dmesg access to root only (prevents kernel pointer leakage)
kernel.dmesg_restrict = 1

# CIS: Disable unprivileged eBPF to prevent kernel exploit attacks
kernel.unprivileged_bpf_disabled = 1

# CIS: Restrict ptrace scope (prevents process snooping across users)
kernel.yama.ptrace_scope = 1

# CIS: Disable kexec loading
kernel.kexec_load_disabled = 1

# CIS: Prevent core dumps for setuid binaries
fs.suid_dumpable = 0

# --- Network Hardening ---
# NOTE: net.ipv4.ip_forward MUST be 1 on Docker hosts for container routing.
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# CIS: IP Spoofing protection (Reverse Path Filter)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# CIS: Ignore ICMP broadcast echo requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# CIS: Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# CIS: Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# CIS: Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# CIS: Enable TCP SYN Cookies (mitigates SYN floods)
net.ipv4.tcp_syncookies = 1

# CIS: Log martian packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
EOF

sysctl --system >/dev/null

echo "==> [09.3] CIS: Restricting core dumps and file limits in limits.conf..."
cat <<'EOF' > /etc/security/limits.d/10-cis-coredumps.conf
# CIS Benchmark: Disable core dumps for all users
* hard core 0
* soft core 0
EOF

echo "==> [09.4] CIS: Hardening system umask (027)..."
cat <<'EOF' > /etc/profile.d/99-cis-umask.sh
# CIS Benchmark: Restrict default file creation mask
umask 027
EOF
chmod 0644 /etc/profile.d/99-cis-umask.sh

echo "==> [09.5] CIS: Setting legal authorization warning banner..."
cat <<'EOF' > /etc/issue.net
*******************************************************************************
*                                                                             *
*  AUTHORIZED ACCESS ONLY                                                     *
*  This system is restricted to authorized personnel only. All activities    *
*  on this system are monitored and recorded. Unauthorized access or use      *
*  will be prosecuted to the fullest extent of the law.                       *
*                                                                             *
*******************************************************************************
EOF
chmod 0644 /etc/issue.net

# ------------------------------------------------------------------------------
# 2. CIS OPENSSH HARDENING
# ------------------------------------------------------------------------------
# CIS Strong Cryptography (Post-Quantum hybrid KEX, Modern AEAD ciphers & Elliptic Curves)
PQ_KEX=""
if ssh -Q kex 2>/dev/null | grep -q "mlkem768x25519-sha256"; then
    PQ_KEX="mlkem768x25519-sha256,"
fi
if ssh -Q kex 2>/dev/null | grep -q "sntrup761x25519-sha512@openssh.com"; then
    PQ_KEX="${PQ_KEX}sntrup761x25519-sha512@openssh.com,"
fi
KEX_LIST="${PQ_KEX}curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"

echo "==> [09.6] CIS: Applying strict OpenSSH crypto and session controls..."
cat <<EOF > /etc/ssh/sshd_config.d/99-cis-hardening.conf
# CIS OpenSSH Server Benchmark Configuration
Port ${SSH_PORT}

# Authentication controls
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes

# Access restriction
AllowUsers ${ADMIN_USER}

# Brute force & resource limits
MaxAuthTries 3
MaxSessions 4
MaxStartups 10:30:60
LoginGraceTime 60
ClientAliveInterval 300
ClientAliveCountMax 2

# Forwarding controls
X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding no

# Legal banner
Banner /etc/issue.net

# CIS Strong Cryptography (Post-Quantum hybrid KEX, Modern AEAD ciphers & Elliptic Curves)
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
KexAlgorithms ${KEX_LIST}
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
EOF

chmod 0600 /etc/ssh/sshd_config.d/99-cis-hardening.conf

# Verify sshd syntax before restart
echo "==> [09.7] Verifying SSH syntax..."
sshd -t
systemctl daemon-reload
if systemctl is-active --quiet ssh.socket; then
    systemctl restart ssh.socket
fi
systemctl restart ssh

# ------------------------------------------------------------------------------
# 3. CIS DOCKER BENCHMARK HARDENING
# ------------------------------------------------------------------------------
echo "==> [09.8] CIS: Applying CIS Docker Benchmark daemon controls..."
mkdir -p /etc/docker

cat <<EOF > /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "icc": false,
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 64000,
      "Soft": 64000
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 4096,
      "Soft": 4096
    }
  }
}
EOF

# CIS: Permissions on Docker configuration files
chmod 0600 /etc/docker/daemon.json
chown root:root /etc/docker/daemon.json
chmod 0700 /etc/docker
chown root:root /etc/docker

echo "==> [09.9] Restarting Docker to apply CIS controls..."
systemctl restart docker

echo "=================================================================="
echo " ==> [09] CIS Benchmark Hardening Applied Successfully!"
echo "=================================================================="

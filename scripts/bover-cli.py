#!/usr/bin/env python3
"""
bover (Es Bover) CLI - Server Runtime Worker, Zero-Downtime Deployer & Metrics Engine
Named after the Mallorcan 'es bover' (the oxen driver and tireless worker executing builds and containers on the node).
Features:
- Declarative app routing via app.json (Caddy ALB reverse proxy)
- Zero-downtime Blue/Green deployments with automated healthchecks
- Automated Git pull & build using per-app deploy keys
- Systemd persistence (services automatically recover on server reboot)
- Aggregated Docker resource usage metrics (Now, 24h, 48h, 7d, 30d)
"""

import sys
import os
import re
import json
import time
import shutil
import sqlite3
import argparse
import subprocess
import platform
import pwd
import grp
import hashlib
import hmac
import secrets
import shlex
import getpass
import html
import socket
import fcntl
import signal
import http.client
import tempfile
import tarfile
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple, Union

APPS_DIR = Path("/opt/apps")
GATEWAY_DIR = APPS_DIR / "gateway"
CONF_DIR = GATEWAY_DIR / "conf.d"
DB_PATH = APPS_DIR / "stats.db"
VAULT_DIR = APPS_DIR / ".vault"
DOCKER_NETWORK = "gateway"

# Terminal Formatting & Colors
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GOLD = "\033[38;5;220m"
CADDY_CONTAINER = "caddy-gateway"
DOCKER_SOCKET_PATH = "/var/run/docker.sock"
CONFIG_FILENAMES = ["app.json", "service.json"]
DRAIN_SECONDS = 5


def validate_app_name(name: str) -> str:
    """Validate application name strictly to prevent path traversal and shell injection."""
    if not name or not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$", name):
        raise ValueError(
            f"Invalid application name '{name}'. Must start with alphanumeric and contain only 1-32 chars (alphanumeric, dash, underscore, dot)."
        )
    if ".." in name or "/" in name or "\\" in name:
        raise ValueError(f"Path traversal detected in application name '{name}'.")
    return name


def run_cmd(cmd, check=True, capture=False, cwd=None):
    """Execute shell command cleanly."""
    res = subprocess.run(
        cmd,
        shell=True,
        check=check,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return res.stdout.strip() if capture and res.stdout else ""


class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    """Lightweight HTTP connection over the local Docker Unix domain socket."""

    def __init__(self, socket_path: str = DOCKER_SOCKET_PATH, timeout: float = 2.0):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def docker_api_get(endpoint: str, timeout: float = 2.0) -> Optional[Any]:
    """Query the local Docker Engine API directly over Unix socket without spawning CLI subprocesses."""
    if APPS_DIR != Path("/opt/apps") or not os.path.exists(DOCKER_SOCKET_PATH):
        return None
    conn = None
    try:
        conn = _UnixSocketHTTPConnection(DOCKER_SOCKET_PATH, timeout=timeout)
        conn.request("GET", endpoint, headers={"Host": "localhost", "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read()
        if resp.status == 200 and body:
            return json.loads(body.decode("utf-8", errors="replace"))
        return None
    except Exception:
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def refresh_docker_cache() -> Optional[Dict[str, Any]]:
    """Fetch live containers and images from Docker Unix socket and persist to /opt/apps/.docker-cache.json."""
    containers = docker_api_get("/containers/json?all=1")
    if not isinstance(containers, list):
        return None
    images = docker_api_get("/images/json")
    payload = {
        "timestamp": int(time.time()),
        "containers": containers,
        "images": images if isinstance(images, list) else [],
    }
    try:
        cache_path = APPS_DIR / ".docker-cache.json"
        tmp_path = APPS_DIR / ".docker-cache.json.tmp"
        tmp_path.write_text(json.dumps(payload))
        tmp_path.replace(cache_path)
        running_cnt = sum(1 for c in containers if str(c.get("State", "")).lower() == "running")
        summary_path = APPS_DIR / ".docker-summary.env"
        summary_path.write_text(f"RUNNING_CONTAINERS={running_cnt}\nTOTAL_CONTAINERS={len(containers)}\n")
        os.chmod(summary_path, 0o644)
    except Exception:
        pass
    return payload


def get_docker_cached_data(max_age: int = 180) -> Optional[Dict[str, Any]]:
    """Return cached Docker containers and images snapshot if fresh, otherwise query and refresh."""
    if APPS_DIR != Path("/opt/apps"):
        return None
    cache_path = APPS_DIR / ".docker-cache.json"
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text())
            if isinstance(data, dict) and (int(time.time()) - int(data.get("timestamp", 0))) <= max_age:
                return data
        except Exception:
            pass
    return refresh_docker_cache()


def measure_dir_bytes(target_dir: Path) -> int:
    """Fast native directory size calculation using os.scandir without spawning du subprocesses."""
    if not target_dir.exists():
        return 0
    total = 0
    stack = [str(target_dir)]
    while stack:
        curr = stack.pop()
        try:
            with os.scandir(curr) as it:
                for entry in it:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        else:
                            total += entry.stat(follow_symlinks=False).st_size
                    except Exception:
                        continue
        except Exception:
            continue
    return total


# ==============================================================================
# 0. HOST-SALTED VAULT & SECRETS ENCRYPTION ENGINE
# ==============================================================================

def get_host_machine_id():
    """Read machine-id unique to this host instance, with fallback."""
    for p in [Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")]:
        if p.exists():
            try:
                content = p.read_text().strip()
                if content:
                    return content
            except Exception:
                pass
    nodename = os.uname().nodename if hasattr(os, "uname") else "bover-node"
    return hashlib.sha256(f"bover-host-{nodename}".encode()).hexdigest()


def get_or_create_host_salt():
    """Get or generate the cryptographically random host salt in .vault/.salt."""
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(VAULT_DIR, 0o700)
    except Exception:
        pass

    salt_path = VAULT_DIR / ".salt"
    if salt_path.exists():
        try:
            return salt_path.read_text().strip()
        except Exception:
            pass

    salt = secrets.token_hex(32)
    salt_path.write_text(salt)
    try:
        os.chmod(salt_path, 0o400)
    except Exception:
        pass
    return salt


def derive_vault_passphrase():
    """Derive master encryption key from host machine-id and secret host salt."""
    machine_id = get_host_machine_id()
    salt = get_or_create_host_salt()
    return hmac.new(salt.encode("utf-8"), machine_id.encode("utf-8"), hashlib.sha256).hexdigest()


def vault_encrypt(plaintext: str) -> str:
    """Encrypt plaintext string using OpenSSL AES-256-CBC with PBKDF2 and derived host key."""
    passphrase = derive_vault_passphrase()
    cmd = [
        "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
        "-pass", f"pass:{passphrase}", "-base64", "-A"
    ]
    res = subprocess.run(cmd, input=plaintext, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return res.stdout.strip()


def vault_decrypt(ciphertext: str) -> str:
    """Decrypt ciphertext string using OpenSSL AES-256-CBC with PBKDF2 and derived host key."""
    passphrase = derive_vault_passphrase()
    cmd = [
        "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
        "-pass", f"pass:{passphrase}", "-base64", "-A"
    ]
    res = subprocess.run(cmd, input=ciphertext, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return res.stdout.strip()


def save_vault_secret(name: str, data: dict):
    """Encrypt and save a dictionary of secrets to .vault/<name>.enc."""
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    raw_json = json.dumps(data)
    encrypted_blob = vault_encrypt(raw_json)
    enc_path = VAULT_DIR / f"{name}.enc"
    enc_path.write_text(encrypted_blob + "\n")
    try:
        os.chmod(enc_path, 0o600)
    except Exception:
        pass


def load_vault_secret(name: str) -> dict:
    """Load and decrypt secrets from .vault/<name>.enc."""
    enc_path = VAULT_DIR / f"{name}.enc"
    if not enc_path.exists():
        return {}
    try:
        ciphertext = enc_path.read_text().strip()
        decrypted_json = vault_decrypt(ciphertext)
        return json.loads(decrypted_json)
    except Exception as e:
        print(f"[Vault] Notice: could not decrypt secret '{name}': {e}")
        return {}


# ==============================================================================
# PER-APP DEDICATED USER ISOLATION
# ==============================================================================

def get_or_create_app_user(name: str) -> Tuple[str, int]:
    """
    Ensure each application runs under its own distinct, unprivileged system user.
    Creates 'app_<name>' (with dedicated UID in range 2001-2999) and configures directory permissions.
    Uses scoped /usr/local/bin/bover-helper for least privilege execution.
    """
    validate_app_name(name)
    clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)[:18].lower()
    username = f"app_{clean_name}"
    app_dir = APPS_DIR / name

    # Deterministic UID allocation in range 2001-2999
    name_hash = int(hashlib.md5(name.encode()).hexdigest()[:4], 16)
    uid = 2001 + (name_hash % 998)

    # If user already exists on the system, avoid privileged escalation calls
    try:
        pw = pwd.getpwnam(username)
        return username, pw.pw_uid
    except (KeyError, AttributeError):
        pass

    sudo_pfx = "sudo " if os.geteuid() != 0 else ""
    helper_bin = Path("/usr/local/bin/bover-helper")
    if helper_bin.exists():
        try:
            run_cmd(f"{sudo_pfx}/usr/local/bin/bover-helper user-create {shlex.quote(name)} {uid}")
        except Exception:
            pass
    else:
        # Fallback for environments where helper is not yet deployed or in unit tests
        run_cmd(f"{sudo_pfx}useradd -r -s /usr/sbin/nologin -d {app_dir} -u {uid} {username} 2>/dev/null || true")
        run_cmd(f"{sudo_pfx}chown -R {username}:bover {app_dir} 2>/dev/null || true")
        run_cmd(f"{sudo_pfx}chmod 750 {app_dir} 2>/dev/null || true")

    return username, uid


def get_bover_gid() -> int:
    """Return GID of bover system group (defaults to 987)."""
    try:
        return grp.getgrnam("bover").gr_gid
    except Exception:
        return 987


def reconcile_app_permissions(app_name: str) -> bool:
    """
    Ensure application directory, data volumes and database files are strictly
    owned by app_<name>:bover with mode 2770/660. Uses scoped bover-helper.
    """
    validate_app_name(app_name)
    if APPS_DIR == Path("/opt/apps") and Path("/usr/local/bin/bover-helper").exists():
        sudo_pfx = "sudo -n " if os.geteuid() != 0 else ""
        res = run_cmd(f"{sudo_pfx}/usr/local/bin/bover-helper chown-app {shlex.quote(app_name)}", capture=True, check=False)
        if "OK:" not in res:
            print(f"WARNING: bover-helper chown-app for '{app_name}' failed: {res.strip()}", file=sys.stderr)
            return False
        return True
    return False


# ==============================================================================
# 1. SYSTEMD INTEGRATION & BOOT PERSISTENCE
# ==============================================================================

def drop_privileges_to_bover():
    """Drop root privileges to unprivileged 'bover' daemon user for principle of least privilege."""
    if os.geteuid() != 0:
        return
    try:
        bover_user = pwd.getpwnam("bover")
        bover_groups = [g.gr_gid for g in grp.getgrall() if "bover" in g.gr_mem]
        if bover_user.pw_gid not in bover_groups:
            bover_groups.append(bover_user.pw_gid)
        os.setgroups(bover_groups)
        os.setgid(bover_user.pw_gid)
        os.setuid(bover_user.pw_uid)
        os.environ["HOME"] = "/opt/apps"
        os.environ["USER"] = "bover"
    except (KeyError, PermissionError):
        pass


def install_systemd_units():
    """Install hardened systemd services executing as unprivileged 'bover' daemon user with strict sandboxing."""
    print("==> Installing Bover (Es Bover) hardened systemd service units...")

    # 1. Gateway ALB service
    gateway_unit = """[Unit]
Description=Bover Central Gateway (Caddy ALB)
After=network.target docker.service podman.service podman.socket
Wants=docker.service podman.service podman.socket

[Service]
Type=oneshot
RemainAfterExit=yes
User=bover
Group=bover
WorkingDirectory=/opt/apps/gateway
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/apps/gateway /var/run/docker.sock
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/bover-gateway.service").write_text(gateway_unit)

    # 2. App template service: bover-app@<name>.service
    app_unit = """[Unit]
Description=Bover Managed Application: %i
After=network.target docker.service podman.service podman.socket bover-gateway.service
Wants=docker.service podman.service podman.socket
Requires=bover-gateway.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=bover
Group=bover
WorkingDirectory=/opt/apps/%i
ExecStart=/usr/local/bin/bover start %i
ExecStop=/usr/local/bin/bover stop %i
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/apps /var/run/docker.sock
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
    Path("/etc/systemd/system/bover-app@.service").write_text(app_unit)

    # 3. Metrics sampler service & timer
    metrics_service = """[Unit]
Description=Bover Docker Metrics Sampler
After=docker.service

[Service]
Type=oneshot
User=bover
Group=bover
WorkingDirectory=/opt/apps
ExecStart=/usr/local/bin/bover sample
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/apps /var/run/docker.sock
PrivateTmp=true
"""
    metrics_timer = """[Unit]
Description=Run Bover Docker Metrics Sampler every 2 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=2min

[Install]
WantedBy=timers.target
"""
    Path("/etc/systemd/system/bover-metrics.service").write_text(metrics_service)
    Path("/etc/systemd/system/bover-metrics.timer").write_text(metrics_timer)

    # 4. Continuous Deployment: Auto-deploy timer (polls every 1 minute)
    autodeploy_service = """[Unit]
Description=Bover Git Auto-Deploy Poller
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=bover
Group=bover
WorkingDirectory=/opt/apps
ExecStart=/usr/local/bin/bover autodeploy
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/apps /var/run/docker.sock
PrivateTmp=true
"""
    autodeploy_timer = """[Unit]
Description=Run Bover Git Auto-Deploy check every 1 minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target
"""
    Path("/etc/systemd/system/bover-autodeploy.service").write_text(autodeploy_service)
    Path("/etc/systemd/system/bover-autodeploy.timer").write_text(autodeploy_timer)

    # 5. Automated daily backup service & timer (runs daily at 03:00 UTC)
    backup_service = """[Unit]
Description=Bover Automated Daily Cloudflare R2 / S3 Backup
After=network.target

[Service]
Type=oneshot
User=bover
Group=bover
WorkingDirectory=/opt/apps
ExecStart=/usr/local/bin/bover backup all
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/apps /tmp
"""
    backup_timer = """[Unit]
Description=Bover Daily Cloudflare R2 Automated Backup Timer (03:00 UTC)

[Timer]
OnCalendar=*-*-* 03:00:00 UTC
Persistent=true
RandomizedDelaySec=300

[Install]
WantedBy=timers.target
"""
    Path("/etc/systemd/system/bover-backup.service").write_text(backup_service)
    Path("/etc/systemd/system/bover-backup.timer").write_text(backup_timer)

    # 6. Per-project Cron scheduler service & timer (runs every minute)
    cron_service = """[Unit]
Description=Bover Per-Project Cron Scheduler & Runner
After=docker.service network.target

[Service]
Type=oneshot
User=bover
Group=bover
WorkingDirectory=/opt/apps
ExecStart=/usr/local/bin/bover cron tick
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/apps /var/run/docker.sock /tmp
NoNewPrivileges=true
"""
    cron_timer = """[Unit]
Description=Run Bover Per-Project Cron Scheduler every minute

[Timer]
OnCalendar=*-*-* *:*:00
Persistent=true
AccuracySec=1s

[Install]
WantedBy=timers.target
"""
    Path("/etc/systemd/system/bover-cron.service").write_text(cron_service)
    Path("/etc/systemd/system/bover-cron.timer").write_text(cron_timer)

    # Clean up obsolete legacy units if present
    legacy_units = [
        "pages-gateway.service", "lamo-gateway.service",
        "pages-app@.service", "lamo-app@.service",
        "pages-metrics.service", "pages-metrics.timer",
        "lamo-metrics.service", "lamo-metrics.timer",
        "pages-autodeploy.service", "pages-autodeploy.timer",
        "lamo-autodeploy.service", "lamo-autodeploy.timer",
    ]
    for u in legacy_units:
        run_cmd(f"systemctl disable --now {u} 2>/dev/null || true")
        unit_file = Path(f"/etc/systemd/system/{u}")
        if unit_file.exists():
            try:
                unit_file.unlink()
            except Exception:
                pass

    # Reload systemd and enable baseline services
    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable --now bover-gateway.service 2>/dev/null || true")
    run_cmd("systemctl enable --now bover-metrics.timer 2>/dev/null || true")
    run_cmd("systemctl enable --now bover-autodeploy.timer 2>/dev/null || true")
    run_cmd("systemctl enable --now bover-backup.timer 2>/dev/null || true")
    run_cmd("systemctl enable --now bover-cron.timer 2>/dev/null || true")
    print("==> Hardened systemd units installed: bover-gateway, bover-app@<name>, bover-metrics.timer, bover-autodeploy.timer, bover-backup.timer, bover-cron.timer.")


def enable_app_systemd(name):
    """Enable systemd boot auto-start for a specific application."""
    sudo_pfx = "sudo " if os.geteuid() != 0 else ""
    try:
        run_cmd(f"{sudo_pfx}systemctl enable bover-app@{name}.service 2>/dev/null")
        run_cmd(f"{sudo_pfx}systemctl enable lamo-app@{name}.service 2>/dev/null || true")
    except Exception:
        pass


def disable_app_systemd(name):
    """Disable systemd boot auto-start for a specific application."""
    sudo_pfx = "sudo " if os.geteuid() != 0 else ""
    try:
        run_cmd(f"{sudo_pfx}systemctl disable bover-app@{name}.service 2>/dev/null || true")
        run_cmd(f"{sudo_pfx}systemctl disable lamo-app@{name}.service 2>/dev/null || true")
    except Exception:
        pass


# ==============================================================================
# 2. CADDY GATEWAY (ALB) MANAGEMENT
# ==============================================================================

def init_gateway():
    """Initialize the central Caddy ALB gateway container, network, and systemd units."""
    print("==> Initializing Lamo Gateway (Caddy ALB) and network...")
    nets = run_cmd("docker network ls --format '{{.Name}}'", capture=True)
    if DOCKER_NETWORK not in nets.split():
        run_cmd(f"docker network create {DOCKER_NETWORK}")

    CONF_DIR.mkdir(parents=True, exist_ok=True)
    compose_path = GATEWAY_DIR / "docker-compose.yml"
    caddyfile_path = GATEWAY_DIR / "Caddyfile"

    # Ensure server-wide shared directory and .env exist
    shared_dir = APPS_DIR / "shared"
    shared_dir.mkdir(parents=True, exist_ok=True)
    shared_env = shared_dir / ".env"
    if not shared_env.exists():
        shared_env.write_text("""# Server-Wide Shared Environment Variables & Secrets
# Variables defined here are inherited by all apps unless overridden in /opt/apps/<app>/.env
TZ=Europe/Madrid
NODE_ENV=production
""")
        try:
            os.chmod(shared_env, 0o640)
        except Exception:
            pass

    if not caddyfile_path.exists():
        caddyfile_path.write_text("""# Global Options
{
    servers {
        protocols h1 h2 h3
        strict_sni_host
    }
    log {
        output stdout
        format json
    }
}

(tls-security) {
    tls {
        protocols tls1.2 tls1.3
        curves x25519 secp256r1
        ciphers TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    }
}

(security-headers) {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        X-XSS-Protection "1; mode=block"

        # Strip server signatures and footprints
        -Server
        -X-Powered-By
        -X-AspNet-Version
        -X-AspNetMvc-Version
        -Via
    }
}

import /etc/caddy/conf.d/*.caddy
""")

    if not compose_path.exists():
        compose_path.write_text("""services:
  caddy:
    image: caddy:2-alpine
    container_name: caddy-gateway
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./conf.d:/etc/caddy/conf.d:ro
      - ./logs:/var/log/caddy
      - caddy_data:/data
      - caddy_config:/config
    networks:
      - gateway

volumes:
  caddy_data:
  caddy_config:

networks:
  gateway:
    name: gateway
    external: true
""")

    ps = run_cmd(f"docker ps --filter name={CADDY_CONTAINER} -q", capture=True)
    if not ps:
        run_cmd(f"cd {GATEWAY_DIR} && docker compose up -d")
    else:
        reload_caddy()
    install_systemd_units()
    print("==> Gateway is active on ports 80/443 and systemd services are enabled.")


def reload_caddy():
    """Gracefully reload Caddy configuration with 0 downtime."""
    try:
        ps = run_cmd(f"docker ps --filter name={CADDY_CONTAINER} -q", capture=True)
        if not ps:
            run_cmd(f"sh -c 'cd {GATEWAY_DIR} && docker compose up -d'")
            return
        run_cmd(f"docker exec {CADDY_CONTAINER} caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile", capture=True)
        run_cmd(f"docker exec {CADDY_CONTAINER} caddy reload --config /etc/caddy/Caddyfile", capture=True)
        print("==> Caddy reloaded successfully (0 ms downtime).")
    except Exception as e:
        print(f"Error reloading Caddy: {e}")


def generate_caddy_rule(name, domain, port, target_host, redirects=None):
    """Generate production-hardened Caddyfile snippet routing domain to container target."""
    redir_blocks = ""
    if redirects:
        if isinstance(redirects, str):
            redirect_list = [r.strip() for r in redirects.split(",") if r.strip()]
        elif isinstance(redirects, list):
            redirect_list = [str(r).strip() for r in redirects if str(r).strip()]
        else:
            redirect_list = []

        for r_dom in redirect_list:
            redir_blocks += f"""# Canonical redirection to primary domain
{r_dom} {{
    redir https://{domain}{{uri}} permanent
}}

"""

    return f"""# Managed by Lamo CLI for app '{name}'
{redir_blocks}{domain} {{
    import tls-security
    import security-headers
    encode zstd gzip

    log {{
        output file /var/log/caddy/{name}-access.log {{
            roll_size 20MiB
            roll_keep 5
        }}
        format json
    }}

    reverse_proxy {target_host}:{port} {{
        header_up X-Real-IP {{remote_host}}
        header_down -Server
        header_down -X-Powered-By
        header_down -Via
    }}
}}
"""


def resolve_app_volumes(cfg: Dict[str, Any], app_dir: Path) -> List[str]:
    """
    Resolve host-to-container volume mappings for an application.
    Supports:
    1. Custom 'volumes' list: ["/mnt/storage/app/data:/data", ...]
    2. Custom 'data_dir' path: "/mnt/storage/app/data" (mounted to /data)
    3. Default convention: {app_dir}/data (mounted to /data if directory exists)
    """
    if "volumes" in cfg and isinstance(cfg["volumes"], list) and cfg["volumes"]:
        return [str(v).strip() for v in cfg["volumes"] if str(v).strip()]

    custom_data = cfg.get("data_dir")
    if custom_data:
        p = Path(custom_data).expanduser()
        p.mkdir(parents=True, exist_ok=True)
        return [f"{p.resolve()}:/data"]

    default_data = app_dir / "data"
    if default_data.exists():
        return [f"{default_data.resolve()}:/data"]

    return []


# ==============================================================================
# 3. APP CONFIGURATION & STATE
# ==============================================================================

def load_app_config(name: str) -> Optional[Dict[str, Any]]:
    """Load app.json or service.json from app directory with validation."""
    try:
        validate_app_name(name)
    except ValueError:
        return None
    app_dir = APPS_DIR / name
    if not app_dir.exists():
        return None
    for fname in CONFIG_FILENAMES:
        cfg = app_dir / fname
        if cfg.exists():
            try:
                with open(cfg, "r") as f:
                    data = json.load(f)
                data["_config_path"] = cfg
                data["_app_dir"] = app_dir
                return data
            except (json.JSONDecodeError, OSError) as e:
                print(f"[Config] Error parsing {cfg}: {e}", file=sys.stderr)
                return None
    return None


def save_app_config(name: str, data: Dict[str, Any]) -> Path:
    """Atomically save application configuration to /opt/apps/<name>/app.json."""
    validate_app_name(name)
    app_dir = APPS_DIR / name
    app_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = data.get("_config_path") if isinstance(data.get("_config_path"), Path) else (app_dir / "app.json")
    clean_data = {k: v for k, v in data.items() if not str(k).startswith("_")}
    tmp_path = cfg_path.with_suffix(".json.tmp")
    with open(tmp_path, "w") as f:
        json.dump(clean_data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    try:
        os.chmod(tmp_path, 0o660)
    except Exception:
        pass
    tmp_path.replace(cfg_path)
    return cfg_path


def get_all_app_configs():
    """Retrieve all app configurations found in /opt/apps."""
    configs = []
    if not APPS_DIR.exists():
        return configs
    for app_dir in APPS_DIR.iterdir():
        if app_dir.is_dir() and app_dir.name != "gateway":
            for filename in CONFIG_FILENAMES:
                cfg = app_dir / filename
                if cfg.exists():
                    configs.append(cfg)
                    break
    return configs


def load_app_state(name):
    """Load deployment state from .bover-state.json (with fallback to legacy .lamo-state.json)."""
    canonical_state = APPS_DIR / name / ".bover-state.json"
    legacy_state = APPS_DIR / name / ".lamo-state.json"
    target_file = canonical_state if canonical_state.exists() else legacy_state
    if target_file.exists():
        try:
            with open(target_file, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"active_slot": None, "container": None, "commit": None, "deployed_at": None}


def save_app_state(name, state):
    """Save deployment state to .bover-state.json and clean up legacy state files."""
    canonical_state = APPS_DIR / name / ".bover-state.json"
    tmp_state = APPS_DIR / name / ".bover-state.json.tmp"
    with open(tmp_state, "w") as f:
        json.dump(state, f, indent=2)
    tmp_state.replace(canonical_state)

    legacy_state = APPS_DIR / name / ".lamo-state.json"
    if legacy_state.exists():
        try:
            legacy_state.unlink()
        except Exception:
            pass


def load_deploy_journal(name: str) -> Optional[Dict[str, Any]]:
    """Load crash-recovery deployment journal if an operation was interrupted."""
    journal_file = APPS_DIR / name / ".bover-deploy-journal.json"
    if journal_file.exists():
        try:
            with open(journal_file, "r") as f:
                data = json.load(f)
                if isinstance(data, dict) and data.get("phase"):
                    return data
        except Exception:
            pass
    return None


def save_deploy_journal(name: str, journal: Dict[str, Any]):
    """Atomically persist the current deployment checkpoint phase to disk."""
    app_dir = APPS_DIR / name
    app_dir.mkdir(parents=True, exist_ok=True)
    journal_file = app_dir / ".bover-deploy-journal.json"
    tmp_file = app_dir / ".bover-deploy-journal.json.tmp"
    journal["updated_at"] = int(time.time())
    with open(tmp_file, "w") as f:
        json.dump(journal, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    tmp_file.replace(journal_file)


def clear_deploy_journal(name: str):
    """Remove deployment journal once deployment finishes or permanently aborts."""
    for fname in (".bover-deploy-journal.json", ".bover-deploy-journal.json.tmp"):
        p = APPS_DIR / name / fname
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass


def is_deploy_locked(name: str) -> bool:
    """Return True if another live process currently holds the deployment lock for this app."""
    lock_file = APPS_DIR / name / ".bover-deploy.lock"
    if not lock_file.exists():
        return False
    try:
        fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
            return False
        except (BlockingIOError, IOError):
            return True
        finally:
            os.close(fd)
    except Exception:
        return False


def _is_interrupted_by_shutdown(exc: Exception) -> bool:
    """Detect whether a command failure was caused by OS reboot/shutdown or SIGTERM rather than a build/code error."""
    if isinstance(exc, subprocess.CalledProcessError):
        if exc.returncode in (130, 137, 143, -2, -9, -15):
            return True
    err_str = str(exc).lower()
    if any(k in err_str for k in ("signal: terminated", "signal: killed", "cannot connect to the docker daemon", "server is shutting down")):
        return True
    try:
        res = subprocess.run(["systemctl", "is-system-running"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if res.stdout and res.stdout.strip() in ("stopping", "offline"):
            return True
    except Exception:
        pass
    return False


# ==============================================================================
# 4. ZERO-DOWNTIME BLUE/GREEN DEPLOYMENT ENGINE
# ==============================================================================

def _cleanup_stale_git_locks(git_dir: Path):
    """Remove stale git lock files left behind if a previous git command was interrupted by a reboot."""
    if not git_dir.exists():
        return
    for lock_path in git_dir.rglob("*.lock"):
        try:
            lock_path.unlink()
        except Exception:
            pass


def git_sync(app_dir, repo=None, branch="master"):
    """Fetch and pull latest changes from Git repository."""
    app_name = app_dir.name
    alias_host = f"github.com-{app_name}"
    if repo and "github.com:" in repo:
        repo = repo.replace("github.com:", f"{alias_host}:")

    git_dir = app_dir / ".git"
    _cleanup_stale_git_locks(git_dir)

    if not git_dir.exists() and repo:
        print(f"==> Initializing and fetching repository '{repo}' ({branch})...")
        run_cmd("git init", cwd=app_dir)
        run_cmd(f"git remote add origin {shlex.quote(repo)}", cwd=app_dir)
        run_cmd(f"git fetch origin {branch}", cwd=app_dir)
        run_cmd(f"git checkout -B {branch} origin/{branch}", cwd=app_dir)
    elif git_dir.exists():
        print(f"==> Pulling latest changes from branch '{branch}'...")
        run_cmd("git fetch origin", cwd=app_dir)
        run_cmd(f"git checkout {branch}", cwd=app_dir)
        try:
            run_cmd(f"git pull origin {branch}", cwd=app_dir)
        except Exception:
            run_cmd(f"git reset --hard origin/{branch}", cwd=app_dir)

    commit = "unknown"
    msg = ""
    if git_dir.exists():
        commit = run_cmd("git rev-parse --short HEAD", capture=True, cwd=app_dir)
        msg = run_cmd("git log -1 --pretty=%B", capture=True, cwd=app_dir).split("\n")[0]
        print(f"==> Current commit: {commit} - {msg}")
    return commit, msg


def find_main_compose_service(compose_file):
    """Detect the primary service name inside a docker-compose.yml file."""
    try:
        out = run_cmd(f"docker compose -f {compose_file} config --format json", capture=True)
        data = json.loads(out)
        if "services" in data and isinstance(data["services"], dict):
            return list(data["services"].keys())[0]
    except Exception:
        pass

    # Simple fallback parser
    in_services = False
    with open(compose_file, "r") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("services:"):
                in_services = True
                continue
            if in_services:
                if line.startswith("  ") and not line.startswith("    ") and stripped.endswith(":"):
                    sname = stripped[:-1].strip()
                    if sname not in ["volumes", "networks"]:
                        return sname
    return "app"


def run_healthcheck(container_name, port, path, timeout=30):
    """Poll healthcheck endpoint until 200 OK or timeout reached."""
    health_url = f"http://{container_name}:{port}{path}"
    print(f"==> Waiting for container to become healthy at {health_url} (timeout {timeout}s)...")

    start_time = time.time()
    attempt = 1
    while time.time() - start_time < timeout:
        # Check via caddy-gateway container using wget (built-in BusyBox)
        check_cmd = f"docker exec {CADDY_CONTAINER} wget -q -O - -T 2 {health_url} >/dev/null 2>&1"
        res = subprocess.run(check_cmd, shell=True)
        if res.returncode == 0:
            elapsed = time.time() - start_time
            print(f"==> [HEALTHY] Healthcheck passed in {elapsed:.1f}s (attempt {attempt}).")
            return True

        time.sleep(1)
        attempt += 1

    return False


PHASE_ORDER = ["git_sync", "build", "healthcheck", "switch_traffic", "drain_cleanup"]


def deploy_app(name, no_pull=False, triggered_by="cli", resume=False):
    """
    Execute a full Zero-Downtime Blue/Green deployment with crash-recoverable checkpoints:
    1. [git_sync]       Git pull (if configured)
    2. [build]          Build & start inactive target slot (blue/green) on gateway network
    3. [healthcheck]    Run healthcheck validation (auto-rollback & Telegram alert on failure)
    4. [switch_traffic] Update Caddy upstream, reload with 0 downtime & persist .bover-state.json
    5. [drain_cleanup]  Drain & stop old slot container, record DB success, notify Telegram & prune
    If the VPS reboots mid-deployment, the journal (.bover-deploy-journal.json) is preserved and
    automatically resumed from the exact interrupted phase on boot.
    """
    cfg = load_app_config(name)
    if not cfg:
        print(f"ERROR: App '{name}' not found or missing app.json in /opt/apps/{name}/")
        print("Create /opt/apps/{name}/app.json with at least: {'name': '...', 'domain': '...', 'port': 8080}")
        sys.exit(1)

    app_dir = cfg["_app_dir"]
    domain = cfg.get("domain")
    port = cfg.get("port")
    repo = cfg.get("repo")
    branch = cfg.get("branch", "master")
    health_path = cfg.get("healthcheck", "/")
    health_timeout = int(cfg.get("healthcheck_timeout", 30))

    if not domain or not port:
        print("ERROR: app.json must define both 'domain' and 'port'.")
        sys.exit(1)

    # Acquire per-app exclusive lock so concurrent deploys or boot recovery never collide
    lock_file = app_dir / ".bover-deploy.lock"
    lock_fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o640)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (BlockingIOError, IOError):
        os.close(lock_fd)
        print(f"==> Deployment for '{name}' is already running in another process.")
        return False

    # Preserve journal cleanly if the VPS initiates a reboot/shutdown (SIGTERM/SIGHUP)
    prev_sigterm = signal.getsignal(signal.SIGTERM)
    prev_sighup = signal.getsignal(signal.SIGHUP)

    def _on_shutdown_signal(signum, _frame):
        print(f"\n==> [INTERRUPT] Signal {signum} received — preserving deployment journal for '{name}' to resume after reboot.")
        os._exit(128 + signum)

    signal.signal(signal.SIGTERM, _on_shutdown_signal)
    signal.signal(signal.SIGHUP, _on_shutdown_signal)

    try:
        state = load_app_state(name)
        existing_journal = load_deploy_journal(name)

        if existing_journal and (resume or triggered_by != "rollback"):
            journal = existing_journal
            phase = journal.get("phase", "git_sync")
            if phase not in PHASE_ORDER:
                phase = "git_sync"
            no_pull = bool(journal.get("no_pull", no_pull))
            triggered_by = journal.get("triggered_by") or triggered_by
            current_slot = journal.get("current_slot", state.get("active_slot"))
            target_slot = journal.get("target_slot") or ("green" if current_slot == "blue" else "blue")
            target_container = journal.get("target_container") or f"{name}-{target_slot}"
            old_container = journal.get("old_container") or (f"{name}-{current_slot}" if current_slot else None)
            commit = journal.get("commit") or "n/a"
            commit_msg = journal.get("commit_msg") or ""
            deploy_id = journal.get("deploy_id")
            print("=" * 80)
            print(f" BOVER DEPLOYMENT RECOVERY: {name} (https://{domain})")
            print(f" Resuming from checkpoint phase: [{phase.upper()}]")
            print("=" * 80)
        else:
            current_slot = state.get("active_slot")
            target_slot = "green" if current_slot == "blue" else "blue"
            target_container = f"{name}-{target_slot}"
            old_container = f"{name}-{current_slot}" if current_slot else None
            phase = "git_sync"
            commit = "n/a"
            commit_msg = ""
            deploy_id = None
            journal = {
                "app": name,
                "phase": phase,
                "no_pull": no_pull,
                "triggered_by": triggered_by,
                "current_slot": current_slot,
                "target_slot": target_slot,
                "target_container": target_container,
                "old_container": old_container,
                "commit": None,
                "commit_msg": None,
                "deploy_id": None,
                "started_at": int(time.time()),
            }
            save_deploy_journal(name, journal)
            print("=" * 80)
            print(f" BOVER DEPLOYMENT: {name} (https://{domain})")
            print("=" * 80)

        phase_idx = PHASE_ORDER.index(phase)
        app_user, app_uid = get_or_create_app_user(name)
        compose_file = app_dir / "docker-compose.yml"
        override_file = app_dir / f".lamo-override-{target_slot}.yml"

        # ------------------------------------------------------------------
        # PHASE 1: GIT SYNC
        # ------------------------------------------------------------------
        if phase_idx <= PHASE_ORDER.index("git_sync"):
            try:
                if not no_pull:
                    commit, commit_msg = git_sync(app_dir, repo, branch)
                else:
                    if (app_dir / ".git").exists():
                        _cleanup_stale_git_locks(app_dir / ".git")
                        commit = run_cmd("git rev-parse --short HEAD", capture=True, cwd=app_dir)
                        commit_msg = run_cmd("git log -1 --pretty=%B", capture=True, cwd=app_dir).split("\n")[0]
                sync_repo_crons(name, app_dir)
            except Exception as e:
                if _is_interrupted_by_shutdown(e):
                    print(f"==> [INTERRUPT] Git sync interrupted by system shutdown; journal kept at 'git_sync'.")
                    sys.exit(143)
                clear_deploy_journal(name)
                raise

            if not deploy_id:
                deploy_id = record_deployment_start(name, commit, commit_msg, target_slot, triggered_by, domain)

            journal["commit"] = commit
            journal["commit_msg"] = commit_msg
            journal["deploy_id"] = deploy_id
            journal["phase"] = "build"
            save_deploy_journal(name, journal)
        else:
            if (commit in ("n/a", "unknown", None)) and (app_dir / ".git").exists():
                commit = run_cmd("git rev-parse --short HEAD", capture=True, cwd=app_dir)
                commit_msg = run_cmd("git log -1 --pretty=%B", capture=True, cwd=app_dir).split("\n")[0]
            if not deploy_id:
                deploy_id = record_deployment_start(name, commit, commit_msg, target_slot, triggered_by, domain)
                journal["deploy_id"] = deploy_id
                save_deploy_journal(name, journal)

        print(f"==> Active slot: {current_slot or 'none'} -> Target slot: {target_slot} (Deploy #{deploy_id}, Commit: {commit})")

        # ------------------------------------------------------------------
        # PHASE 2: BUILD & LAUNCH TARGET SLOT
        # ------------------------------------------------------------------
        if phase_idx <= PHASE_ORDER.index("build"):
            try:
                # Computational resource limits: defaults to 0.5 CPU and 512m RAM if not specified
                res_cfg = cfg.get("resources", {}) if isinstance(cfg.get("resources"), dict) else {}
                raw_cpu = cfg.get("cpu") or cfg.get("cpus") or res_cfg.get("cpu") or 0.5
                raw_mem = cfg.get("memory") or cfg.get("mem_limit") or res_cfg.get("memory") or "512m"

                try:
                    cpu_val = float(raw_cpu)
                    cpu_limit = f"{cpu_val:.1f}" if cpu_val != int(cpu_val) else f"{int(cpu_val)}"
                except (ValueError, TypeError):
                    cpu_limit = "0.5"

                mem_str = str(raw_mem).strip().lower()
                if not re.match(r"^[0-9]+[kmg]?$", mem_str):
                    mem_str = "512m"
                mem_limit = mem_str

                # Build priority: idle priority (nice -n 19 ionice -c 3) so live web apps always have priority
                build_prefix = "nice -n 19 ionice -c 3 "

                use_compose = compose_file.exists() and cfg.get("type") != "dockerfile" and cfg.get("builder") != "dockerfile"
                if use_compose:
                    main_svc = cfg.get("service") or find_main_compose_service(compose_file)

                    # Collect environment files: server-wide shared first, then app-specific
                    shared_env = APPS_DIR / "shared" / ".env"
                    app_env = app_dir / ".env"
                    env_files = []
                    if shared_env.exists():
                        env_files.append(str(shared_env))
                    if app_env.exists():
                        try:
                            os.chmod(app_env, 0o640)
                        except Exception:
                            pass
                        env_files.append(str(app_env))

                    env_file_section = ""
                    if env_files:
                        env_file_section = "    env_file:\n" + "\n".join(f'      - "{f}"' for f in env_files) + "\n"

                    vol_section = ""
                    app_vols = resolve_app_volumes(cfg, app_dir)
                    if app_vols:
                        vol_lines = "\n".join(f'      - "{v}"' for v in app_vols)
                        vol_section = f"    volumes:\n{vol_lines}\n"

                    # Create slot-specific docker-compose override:
                    bover_gid = get_bover_gid()
                    override_content = f"""# Auto-generated by Lamo for slot {target_slot}
services:
  {main_svc}:
    container_name: {target_container}
    restart: unless-stopped
    user: "{app_uid}:{app_uid}"
    group_add:
      - "{bover_gid}"
    stop_grace_period: 20s
    security_opt:
      - no-new-privileges:true
    pids_limit: 256
    cpus: {cpu_limit}
    mem_limit: {mem_limit}
    ports: !reset []
    expose:
      - "{port}"
{env_file_section}{vol_section}    networks:
      - gateway

networks:
  gateway:
    name: {DOCKER_NETWORK}
    external: true
"""
                    override_file.write_text(override_content)

                    print(f"==> Building and starting container '{target_container}' via Docker Compose...")
                    compose_cmd = (
                        f"{build_prefix}docker compose -p {name}-{target_slot} "
                        f"-f {compose_file.name} -f {override_file.name} up -d --build"
                    )
                    run_cmd(compose_cmd, cwd=app_dir)

                    # Tag image with commit SHA and latest/slot for version tracking
                    try:
                        img_id = run_cmd(f"docker inspect --format '{{{{.Image}}}}' {target_container}", capture=True)
                        if img_id:
                            if commit and commit not in ("unknown", "n/a"):
                                run_cmd(f"docker tag {img_id} {name}:{commit} 2>/dev/null || true")
                            run_cmd(f"docker tag {img_id} {name}:{target_slot} 2>/dev/null || true")
                            run_cmd(f"docker tag {img_id} {name}:latest 2>/dev/null || true")
                    except Exception:
                        pass
                elif (app_dir / "Dockerfile").exists():
                    print(f"==> Building Dockerfile for '{target_container}' with background priority (nice)...")
                    commit_tag = f"-t {name}:{commit}" if (commit and commit not in ("unknown", "n/a")) else ""
                    run_cmd(f"{build_prefix}docker build -t {name}:{target_slot} -t {name}:latest {commit_tag} .", cwd=app_dir)

                    shared_env = APPS_DIR / "shared" / ".env"
                    app_env = app_dir / ".env"
                    env_args = ""
                    if shared_env.exists():
                        env_args += f" --env-file {shared_env}"
                    if app_env.exists():
                        try:
                            os.chmod(app_env, 0o640)
                        except Exception:
                            pass
                        env_args += f" --env-file {app_env}"

                    app_vols = resolve_app_volumes(cfg, app_dir)
                    vol_arg = (" " + " ".join(f"-v {v}" for v in app_vols)) if app_vols else ""
                    run_cmd(f"docker rm -f {target_container} 2>/dev/null || true")
                    bover_gid = get_bover_gid()
                    run_cmd(
                        f"docker run -d --name {target_container} --network {DOCKER_NETWORK} "
                        f"--user {app_uid}:{app_uid} --group-add {bover_gid} --security-opt no-new-privileges:true --pids-limit 256 "
                        f"--cpus {cpu_limit} -m {mem_limit} "
                        f"--restart unless-stopped {env_args} {vol_arg} {name}:{target_slot}",
                        cwd=app_dir,
                    )
                else:
                    raise RuntimeError("Neither docker-compose.yml nor Dockerfile found in app directory")

                # Ensure container is on gateway network
                run_cmd(f"docker network connect {DOCKER_NETWORK} {target_container} 2>/dev/null || true")

                journal["phase"] = "healthcheck"
                save_deploy_journal(name, journal)

            except Exception as e:
                if _is_interrupted_by_shutdown(e):
                    print(f"\n==> [INTERRUPT] Build interrupted by system reboot/shutdown; journal kept at 'build' for automatic resume.")
                    sys.exit(143)
                err_msg = f"Build/Launch failed: {e}"
                print(f"\n[DEPLOYMENT FAILED] {err_msg}")
                record_deployment_finish(deploy_id, "FAILED", error_message=err_msg)
                notify_deploy_failed(name, target_slot, current_slot, commit, err_msg, triggered_by)
                clear_deploy_journal(name)
                if compose_file.exists() and override_file.exists():
                    run_cmd(f"docker compose -p {name}-{target_slot} -f {compose_file.name} -f {override_file.name} down 2>/dev/null || true", cwd=app_dir)
                else:
                    run_cmd(f"docker rm -f {target_container} 2>/dev/null || true")
                if current_slot:
                    print(f"==> Existing slot '{current_slot}' remains live and serving traffic. Zero downtime maintained.")
                if triggered_by == "autodeploy":
                    return False
                sys.exit(1)

        # ------------------------------------------------------------------
        # PHASE 3: HEALTHCHECK
        # ------------------------------------------------------------------
        if phase_idx <= PHASE_ORDER.index("healthcheck"):
            if phase_idx == PHASE_ORDER.index("healthcheck"):
                # Resumed directly at healthcheck after a reboot: ensure target container is started without rebuilding
                print(f"==> Ensuring already-built target container '{target_container}' is running...")
                if compose_file.exists() and override_file.exists():
                    run_cmd(f"docker compose -p {name}-{target_slot} -f {compose_file.name} -f {override_file.name} up -d", cwd=app_dir)
                else:
                    run_cmd(f"docker start {target_container} 2>/dev/null || true")
                run_cmd(f"docker network connect {DOCKER_NETWORK} {target_container} 2>/dev/null || true")

            healthy = run_healthcheck(target_container, port, health_path, timeout=health_timeout)
            if not healthy:
                if _is_interrupted_by_shutdown(Exception("healthcheck interrupted")):
                    sys.exit(143)
                err_msg = f"Healthcheck timeout ({health_timeout}s) at http://{target_container}:{port}{health_path}"
                print(f"\n[DEPLOYMENT FAILED] Target container '{target_container}' failed healthcheck!")
                print("==> Recent container logs:")
                logs = run_cmd(f"docker logs --tail 30 {target_container}", capture=True)
                print(logs)

                # Record failure in SQLite, alert Telegram & clear journal
                record_deployment_finish(deploy_id, "FAILED", error_message=err_msg)
                notify_deploy_failed(name, target_slot, current_slot, commit, err_msg, triggered_by)
                clear_deploy_journal(name)

                print(f"==> Tearing down failed container '{target_container}'...")
                if compose_file.exists() and override_file.exists():
                    run_cmd(f"docker compose -p {name}-{target_slot} -f {compose_file.name} -f {override_file.name} down", cwd=app_dir)
                else:
                    run_cmd(f"docker rm -f {target_container} 2>/dev/null || true")

                if current_slot:
                    print(f"==> Existing slot '{current_slot}' remains live and serving traffic. Zero downtime maintained.")
                if triggered_by == "autodeploy":
                    return False
                sys.exit(1)

            journal["phase"] = "switch_traffic"
            save_deploy_journal(name, journal)

        # ------------------------------------------------------------------
        # PHASE 4: SWITCH TRAFFIC IN CADDY & PERSIST STATE IMMEDIATELY
        # ------------------------------------------------------------------
        if phase_idx <= PHASE_ORDER.index("switch_traffic"):
            print(f"==> Routing traffic in Caddy to '{target_container}:{port}'...")
            CONF_DIR.mkdir(parents=True, exist_ok=True)
            caddy_file = CONF_DIR / f"{name}.caddy"
            redirects = cfg.get("redirects") or cfg.get("redirect")
            caddy_file.write_text(generate_caddy_rule(name, domain, port, target_container, redirects=redirects))
            reload_caddy()

            # Save state immediately after traffic switch (before connection drain sleep)
            new_state = {
                "active_slot": target_slot,
                "container": target_container,
                "port": port,
                "domain": domain,
                "commit": commit,
                "deployed_at": int(time.time()),
            }
            save_app_state(name, new_state)
            enable_app_systemd(name)

            journal["phase"] = "drain_cleanup"
            save_deploy_journal(name, journal)

        # ------------------------------------------------------------------
        # PHASE 5: DRAIN OLD SLOT, AUDIT LOG & PRUNE
        # ------------------------------------------------------------------
        if old_container and old_container != target_container:
            print(f"==> Draining connections ({DRAIN_SECONDS}s) before stopping old slot '{old_container}'...")
            time.sleep(DRAIN_SECONDS)
            old_override = app_dir / f".lamo-override-{current_slot}.yml"
            if compose_file.exists() and old_override.exists():
                run_cmd(f"docker compose -p {name}-{current_slot} -f {compose_file.name} -f {old_override.name} down", cwd=app_dir)
            else:
                run_cmd(f"docker stop {old_container} >/dev/null 2>&1 && docker rm {old_container} >/dev/null 2>&1 || true")
            print(f"==> Old slot '{old_container}' decommissioned.")

        # Record success in SQLite & alert Telegram
        status_label = "ROLLBACK" if triggered_by == "rollback" else "SUCCESS"
        duration = record_deployment_finish(deploy_id, status_label)
        notify_deploy_success(name, target_slot, commit, commit_msg, domain, duration, triggered_by)

        # Ensure app directory permissions via scoped helper
        reconcile_app_permissions(name)

        # Version Lifecycle: Prune old images according to keep_versions (default 3)
        keep_versions = int(cfg.get("keep_versions", 3))
        prune_app_versions(name, keep_versions=keep_versions)
        refresh_docker_cache()

        # Clear deployment checkpoint journal upon full completion
        clear_deploy_journal(name)

        print("=" * 80)
        print(f" DEPLOYMENT SUCCESSFUL: {name} (#{deploy_id})")
        print(f" URL:         https://{domain}")
        print(f" Slot:        {target_slot} ({target_container})")
        print(f" Commit:      {commit}")
        print(f" Duration:    {duration:.1f}s")
        print(f" Persistence: Systemd service 'bover-app@{name}' enabled")
        print(f" Retention:   Last {keep_versions} version images retained")
        print("=" * 80)
        return True
    finally:
        signal.signal(signal.SIGTERM, prev_sigterm)
        signal.signal(signal.SIGHUP, prev_sighup)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        except Exception:
            pass


def start_app(name: str):
    """Start the active slot of an app (called by systemd bover-app@<name> on boot) and resume any interrupted deploy."""
    validate_app_name(name)
    cfg = load_app_config(name)
    state = load_app_state(name)
    slot = state.get("active_slot") or "blue"
    container = state.get("container") or f"{name}-{slot}"
    app_dir = cfg["_app_dir"] if cfg else APPS_DIR / name

    print(f"==> Starting Bover app '{name}' (slot {slot}, container {container})...")
    compose_file = app_dir / "docker-compose.yml"
    override_file = app_dir / f".lamo-override-{slot}.yml"

    if compose_file.exists() and override_file.exists():
        run_cmd(f"docker compose -p {name}-{slot} -f {compose_file.name} -f {override_file.name} up -d", cwd=app_dir)
    else:
        run_cmd(f"docker start {container} 2>/dev/null || true")

    run_cmd(f"docker network connect {DOCKER_NETWORK} {container} 2>/dev/null || true")

    # Check if an interrupted deployment journal exists from before a reboot
    journal = load_deploy_journal(name)
    if journal and not is_deploy_locked(name):
        phase = journal.get("phase", "git_sync")
        print(f"==> [RECOVERY] Detected interrupted deployment for '{name}' at phase '{phase}'. Resuming in background...")
        subprocess.Popen(
            ["/usr/local/bin/bover", "deploy", name, "--resume"],
            cwd=str(app_dir),
            start_new_session=True,
            close_fds=True,
        )
    elif not journal:
        # Clean up any orphan inactive slot container if no deployment is in progress
        inactive_slot = "green" if slot == "blue" else "blue"
        inactive_container = f"{name}-{inactive_slot}"
        inactive_override = app_dir / f".lamo-override-{inactive_slot}.yml"
        if compose_file.exists() and inactive_override.exists():
            run_cmd(f"docker compose -p {name}-{inactive_slot} -f {compose_file.name} -f {inactive_override.name} down 2>/dev/null || true", cwd=app_dir)
        else:
            run_cmd(f"docker stop {inactive_container} >/dev/null 2>&1 && docker rm {inactive_container} >/dev/null 2>&1 || true")

    refresh_docker_cache()
    print(f"==> App '{name}' is running.")


def stop_app(name: str):
    """Stop all containers for an app."""
    validate_app_name(name)
    print(f"==> Stopping Bover app '{name}'...")
    state = load_app_state(name)
    slot = state.get("active_slot") or "blue"
    app_dir = APPS_DIR / name
    compose_file = app_dir / "docker-compose.yml"
    override_file = app_dir / f".lamo-override-{slot}.yml"

    if compose_file.exists() and override_file.exists():
        run_cmd(f"docker compose -p {name}-{slot} -f {compose_file.name} -f {override_file.name} down", cwd=app_dir)
    else:
        run_cmd(f"docker stop {name}-blue {name}-green 2>/dev/null || true")
    refresh_docker_cache()
    print(f"==> App '{name}' stopped.")


def rollback_app(name: str):
    """Roll back to the previous deployment slot."""
    validate_app_name(name)
    state = load_app_state(name)
    current_slot = state.get("active_slot")
    if not current_slot:
        print(f"ERROR: No previous deployment state found for '{name}'.")
        return

    target_slot = "green" if current_slot == "blue" else "blue"
    print(f"==> Rolling back '{name}' from slot '{current_slot}' to slot '{target_slot}'...")
    deploy_app(name, no_pull=True, triggered_by="rollback")


def prune_app_versions(name, keep_versions=3):
    """
    Enforce application image retention lifecycle:
    Retains the latest N versioned images (default: 3) for the application.
    Prunes older images not in use by active containers and purges dangling layers.
    """
    try:
        keep = int(keep_versions) if keep_versions else 3
    except Exception:
        keep = 3

    print(f"==> Enforcing version lifecycle for '{name}' (retaining last {keep} versions)...")

    # Fetch all docker images with id, repo, tag, created_at
    out = run_cmd("docker images --format '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}'", capture=True)
    if not out:
        return

    # Find unique image IDs belonging to this app
    # Format of line: ID \t Repository \t Tag \t CreatedAt
    # Docker returns images sorted newest first.
    app_image_ids = []
    seen = set()
    img_tags_map = {}

    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        img_id, repo, tag = parts[0], parts[1], parts[2]
        if repo == name or repo.startswith(f"{name}-") or repo.startswith(f"{name}_"):
            if img_id not in img_tags_map:
                img_tags_map[img_id] = []
            img_tags_map[img_id].append(f"{repo}:{tag}")
            if img_id not in seen:
                seen.add(img_id)
                app_image_ids.append(img_id)

    total_versions = len(app_image_ids)
    if total_versions <= keep:
        print(f"==> App '{name}' has {total_versions} version image(s) stored (limit is {keep}). Nothing to prune.")
        run_cmd("docker image prune -f >/dev/null 2>&1 || true")
        return

    # Images beyond the retention limit
    to_prune = app_image_ids[keep:]

    # Retrieve all image IDs and repo:tag currently used by any running container across the system
    running_ancestors = set(run_cmd("docker ps --format '{{.Image}}'", capture=True).split())
    try:
        running_ids = set(run_cmd("docker ps --format '{{.ImageID}}'", capture=True).split())
    except Exception:
        running_ids = set()

    pruned = 0
    for old_id in to_prune:
        # Check if this image is currently running
        if old_id in running_ids:
            continue
        tags = img_tags_map.get(old_id, [])
        if any(t in running_ancestors for t in tags):
            continue

        tag_display = ", ".join(tags) if tags else old_id[:12]
        print(f"  [-] Pruning retired image version: {tag_display} ({old_id[:12]})")
        try:
            run_cmd(f"docker rmi -f {old_id} >/dev/null 2>&1 || true")
            pruned += 1
        except Exception:
            pass

    print(f"==> Version lifecycle complete: {pruned} old image(s) pruned, {min(total_versions, keep)} active version(s) retained.")
    run_cmd("docker image prune -f >/dev/null 2>&1 || true")


def manage_env(target="shared", set_vars=None, unset_vars=None):
    """
    Manage environment variables and secrets:
    - target: 'shared' (for server-wide) or app name (for /opt/apps/<name>/.env)
    - set_vars: list of "KEY=VAL" strings
    - unset_vars: list of "KEY" strings
    """
    if not target or target == "shared":
        env_dir = APPS_DIR / "shared"
        env_dir.mkdir(parents=True, exist_ok=True)
        env_file = env_dir / ".env"
        mode = 0o640
        title = "Server-Wide Shared Secrets & Variables (/opt/apps/shared/.env)"
        target_name = "shared"
    else:
        env_dir = APPS_DIR / target
        if not env_dir.exists():
            print(f"ERROR: App '{target}' not found in {APPS_DIR}.")
            sys.exit(1)
        env_file = env_dir / ".env"
        mode = 0o640
        title = f"App Secrets & Variables for '{target}' (/opt/apps/{target}/.env)"
        target_name = target

    # Parse existing variables from file
    env_map = {}
    if env_file.exists():
        with open(env_file, "r") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    k, v = stripped.split("=", 1)
                    env_map[k.strip()] = v.strip()

    changed = False
    if set_vars:
        for item in set_vars:
            if "=" not in item:
                print(f"WARNING: Skipping invalid format '{item}' (expected KEY=VALUE).")
                continue
            k, v = item.split("=", 1)
            k = k.strip()
            v = v.strip()
            env_map[k] = v
            changed = True
            print(f"  [+] Set {k}")

    if unset_vars:
        for k in unset_vars:
            k = k.strip()
            if k in env_map:
                del env_map[k]
                changed = True
                print(f"  [-] Unset {k}")

    if changed:
        with open(env_file, "w") as f:
            f.write(f"# {title}\n# Last updated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for k, v in sorted(env_map.items()):
                f.write(f"{k}={v}\n")
        try:
            os.chmod(env_file, mode)
        except Exception:
            pass
        print(f"==> Saved changes to {env_file} (mode {oct(mode)}).")
        if target_name != "shared":
            print(f"💡 Tip: Run 'bover restart {target_name}' to apply updated environment variables to the container.")
        else:
            print("💡 Tip: Restart affected apps to apply updated shared environment variables.")
        return

    # If neither set nor unset, display variables with secrets masked
    print("")
    print("=" * 80)
    print(f" BOVER :: {title}")
    print("=" * 80)

    if target_name != "shared":
        shared_file = APPS_DIR / "shared" / ".env"
        if shared_file.exists():
            print("\n  [Server-Wide Shared Variables (/opt/apps/shared/.env)]:")
            with open(shared_file) as f:
                for line in f:
                    s = line.strip()
                    if s and not s.startswith("#") and "=" in s:
                        k, v = s.split("=", 1)
                        is_secret = any(w in k.upper() for w in ["SECRET", "KEY", "PASS", "TOKEN", "AUTH", "CRED"])
                        masked = (v[:3] + "..." + v[-2:]) if is_secret and len(v) > 6 else ("******" if is_secret else v)
                        override_note = " (overridden by app)" if k in env_map else ""
                        print(f"    • {k:<25} = {masked}{override_note}")

    print(f"\n  [{'Shared' if target_name == 'shared' else 'App-Specific'} Variables ({target_name})]:")
    if not env_map:
        print(f"    (No variables defined yet. Use 'bover env {target_name} --set KEY=VAL')")
    else:
        for k, v in sorted(env_map.items()):
            is_secret = any(w in k.upper() for w in ["SECRET", "KEY", "PASS", "TOKEN", "AUTH", "CRED"])
            masked = (v[:3] + "..." + v[-2:]) if is_secret and len(v) > 6 else ("******" if is_secret else v)
            print(f"    • {k:<25} = {masked}")
    print("-" * 80)
    print(f" File path: {env_file} (permissions: {oct(mode)})")
    print("=" * 80)
    print("")


def remove_app(name, keep_data=False, force=False):
    """
    Decommission and remove an application cleanly:
    1. Stop and tear down running containers (blue/green).
    2. Remove Caddy ALB route and reload Caddy with zero downtime.
    3. Stop and disable systemd service.
    4. Remove Docker images for this app.
    5. Clean up SQLite database records.
    6. Create a safety archive before removing /opt/apps/<name>.
    7. Send Telegram notification.
    """
    app_dir = APPS_DIR / name
    if not app_dir.exists():
        print(f"ERROR: Application '{name}' not found in {APPS_DIR}.")
        sys.exit(1)

    cfg = load_app_config(name)
    domain = cfg.get("domain", "n/a") if cfg else "n/a"

    if not force:
        try:
            confirm = input(f"Are you sure you want to decommission and permanently remove '{name}' ({domain})? [y/N]: ").strip().lower()
            if confirm not in ("y", "yes"):
                print("Decommission aborted.")
                return
        except (KeyboardInterrupt, EOFError):
            print("\nDecommission aborted.")
            return

    print("")
    print("=" * 70)
    print(f" ==> Decommissioning Application '{name}'...")
    print("=" * 70)

    # 1. Stop and remove containers
    print(f"==> [1/6] Stopping and tearing down active containers...")
    for slot in ["blue", "green"]:
        override = app_dir / f".lamo-override-{slot}.yml"
        compose = app_dir / "docker-compose.yml"
        if compose.exists() and override.exists():
            run_cmd(f"docker compose -p {name}-{slot} -f {compose.name} -f {override.name} down 2>/dev/null || true", cwd=app_dir)
        run_cmd(f"docker rm -f {name}-{slot} 2>/dev/null || true")

    # 2. Remove Caddy routing and hot-reload
    print(f"==> [2/6] Removing Caddy ALB routing rule...")
    caddy_file = CONF_DIR / f"{name}.caddy"
    if caddy_file.exists():
        caddy_file.unlink()
        reload_caddy()
    print("  [✓] Caddy reloaded. Domain route removed with 0 downtime for other apps.")

    # 3. Stop and disable systemd service
    print(f"==> [3/6] Disabling systemd service...")
    sudo_pfx = "sudo " if os.geteuid() != 0 else ""
    run_cmd(f"{sudo_pfx}systemctl stop bover-app@{name} 2>/dev/null || true")
    run_cmd(f"{sudo_pfx}systemctl disable bover-app@{name} 2>/dev/null || true")

    # 4. Remove Docker images
    print(f"==> [4/6] Pruning Docker images for '{name}'...")
    run_cmd(f"docker rmi -f $(docker images '{name}' -q) 2>/dev/null || true")
    run_cmd("docker image prune -f >/dev/null 2>&1 || true")

    # 5. Create pre-decommission safety backup
    print(f"==> [5/6] Creating pre-decommission safety archive...")
    backup_dir = APPS_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    backup_file = backup_dir / f"{name}-pre-decommission-{ts}.tar.gz"
    run_cmd(f"tar -czf {backup_file} -C {APPS_DIR} {name}")
    print(f"  [✓] Safety backup stored in: {backup_file}")

    # Delete or preserve data
    if keep_data and (app_dir / "data").exists():
        print(f"==> Preserving persistent data in {app_dir / 'data'} as requested.")
        for item in app_dir.iterdir():
            if item.name != "data":
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink(missing_ok=True)
    else:
        shutil.rmtree(app_dir, ignore_errors=True)
        print(f"  [✓] Application folder {app_dir} deleted.")

    # Clean up dedicated app system user via scoped bover-helper
    clean_name = re.sub(r"[^a-zA-Z0-9_]", "_", name)[:18].lower()
    app_username = f"app_{clean_name}"
    sudo_pfx = "sudo " if os.geteuid() != 0 else ""
    helper_bin = Path("/usr/local/bin/bover-helper")
    if helper_bin.exists():
        run_cmd(f"{sudo_pfx}/usr/local/bin/bover-helper user-delete {shlex.quote(name)} 2>/dev/null || true")
    else:
        run_cmd(f"{sudo_pfx}userdel {app_username} 2>/dev/null || true")

    # 6. Clean up SQLite database records
    print(f"==> [6/6] Cleaning up database records...")
    init_db()
    with get_db() as conn:
        conn.execute("DELETE FROM deployments WHERE app = ?", (name,))
        conn.execute("DELETE FROM app_disk_metrics WHERE app = ?", (name,))
        conn.execute("DELETE FROM app_visits WHERE app = ?", (name,))
        conn.execute("DELETE FROM cron_executions WHERE app = ?", (name,))
        conn.execute("DELETE FROM cron_state WHERE app = ?", (name,))

    # Telegram Alert
    hostname = socket.gethostname() or "server"
    refresh_docker_cache()
    alert_text = (
        f"🗑️ <b>App Decommissioned</b>\n"
        f"App: <code>{name}</code>\n"
        f"Domain: <code>{domain}</code>\n"
        f"Node: <code>{hostname}</code>\n"
        f"Archive: <code>{backup_file.name}</code>\n"
        f"Status: Route removed, containers destroyed, zero downtime maintained."
    )
    send_telegram(alert_text)

    print("=" * 70)
    print(f"✨ Application '{name}' has been successfully decommissioned!")
    print("=" * 70)


def check_autodeploy():
    """
    Continuous Deployment & Crash Recovery:
    1. Resume any interrupted deployments (.bover-deploy-journal.json) across all apps.
    2. Poll remote repositories for apps with auto_deploy=true and deploy new commits.
    """
    configs = get_all_app_configs()
    if not configs:
        return

    for cfg_path in configs:
        try:
            with open(cfg_path, "r") as f:
                data = json.load(f)
        except Exception:
            continue

        name = data.get("name")
        if not name:
            continue

        # 1. Crash recovery: if a previous deployment was interrupted by a VPS reboot, resume it first
        journal = load_deploy_journal(name)
        if journal and not is_deploy_locked(name):
            phase = journal.get("phase", "git_sync")
            print(f"[AutoRecovery] Interrupted deployment detected for '{name}' at phase '{phase}'. Resuming...")
            try:
                deploy_app(name, resume=True)
            except Exception as e:
                print(f"[AutoRecovery] Exception while resuming '{name}': {e}")
            continue

        if not data.get("auto_deploy"):
            continue

        repo = data.get("repo")
        branch = data.get("branch", "master")
        app_dir = APPS_DIR / name

        if not repo and not (app_dir / ".git").exists():
            continue

        if (app_dir / ".git").exists():
            remote_target = "origin"
        else:
            alias_host = f"github.com-{name}"
            remote_target = repo.replace("github.com:", f"{alias_host}:") if repo and "github.com:" in repo else (repo or "origin")

        remote_ref = f"refs/heads/{branch}"
        cmd = f"git ls-remote {remote_target} {remote_ref}"
        try:
            out = run_cmd(cmd, capture=True, cwd=app_dir if (app_dir / ".git").exists() else None)
            if not out:
                continue
            remote_sha = out.split()[0].strip()[:7]
        except Exception:
            continue

        state = load_app_state(name)
        deployed_commit = (state.get("commit") or "").strip()

        if not deployed_commit and (app_dir / ".git").exists():
            deployed_commit = run_cmd("git rev-parse --short HEAD", capture=True, cwd=app_dir)

        if remote_sha and remote_sha != deployed_commit:
            print(f"[AutoDeploy] New commit detected on '{name}' ({branch}): {deployed_commit or 'initial'} -> {remote_sha}")
            print(f"[AutoDeploy] Triggering automated zero-downtime deployment for '{name}'...")
            try:
                ok = deploy_app(name, no_pull=False, triggered_by="autodeploy")
                if ok:
                    print(f"[AutoDeploy] Successfully auto-deployed '{name}' ({remote_sha}).")
                else:
                    print(f"[AutoDeploy] Auto-deployment failed for '{name}' ({remote_sha}). Alert delivered.")
            except Exception as e:
                print(f"[AutoDeploy] Deployment exception on '{name}': {e}")


# ==============================================================================
# 5. METRICS & DEPLOYMENT DATABASE ENGINE
# ==============================================================================

@contextmanager
def get_db():
    """Context manager for SQLite connections that guarantees commit and close."""
    conn = sqlite3.connect(DB_PATH)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    """Initialize the SQLite database for historical metrics and deployment audit logs."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        # Container metrics table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                timestamp INTEGER NOT NULL,
                container TEXT NOT NULL,
                cpu_pct REAL NOT NULL,
                mem_bytes INTEGER NOT NULL,
                net_rx_bytes INTEGER NOT NULL,
                net_tx_bytes INTEGER NOT NULL,
                block_read_bytes INTEGER NOT NULL,
                block_write_bytes INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_container_ts ON metrics(container, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_ts ON metrics(timestamp)")

        # Deployment audit log table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app TEXT NOT NULL,
                commit_hash TEXT,
                commit_msg TEXT,
                slot TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                duration_sec REAL,
                triggered_by TEXT,
                error_message TEXT,
                domain TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_deployments_app ON deployments(app, started_at DESC)")

        # Disk consumption & differential metrics table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_disk_metrics (
                timestamp INTEGER NOT NULL,
                app TEXT NOT NULL,
                total_bytes INTEGER NOT NULL,
                data_bytes INTEGER NOT NULL,
                code_bytes INTEGER NOT NULL,
                image_bytes INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_disk_app_ts ON app_disk_metrics(app, timestamp)")

        # Caddy visits & request metrics table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS app_visits (
                timestamp INTEGER NOT NULL,
                app TEXT NOT NULL,
                requests_total INTEGER NOT NULL,
                req_2xx INTEGER NOT NULL,
                req_3xx INTEGER NOT NULL,
                req_4xx INTEGER NOT NULL,
                req_5xx INTEGER NOT NULL,
                unique_ips INTEGER NOT NULL,
                bytes_sent INTEGER NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_visits_app_ts ON app_visits(app, timestamp)")

        # Per-project Cron execution audit log table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cron_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app TEXT NOT NULL,
                job_id TEXT NOT NULL,
                command TEXT NOT NULL,
                schedule TEXT,
                mode TEXT NOT NULL,
                container TEXT,
                status TEXT NOT NULL,
                exit_code INTEGER,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                duration_sec REAL,
                triggered_by TEXT,
                output TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cron_exec_app_ts ON cron_executions(app, started_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cron_exec_job_ts ON cron_executions(app, job_id, started_at DESC)")

        # Per-project Cron scheduler state table (prevents duplicate ticks & enables missed-run catch-up)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cron_state (
                app TEXT NOT NULL,
                job_id TEXT NOT NULL,
                last_slot_ts INTEGER NOT NULL,
                last_run_id INTEGER,
                PRIMARY KEY (app, job_id)
            )
        """)


def record_deployment_start(app, commit_hash, commit_msg, slot, triggered_by, domain):
    """Record deployment beginning and return new deployment ID."""
    init_db()
    started_at = int(time.time())
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO deployments (app, commit_hash, commit_msg, slot, status, started_at, triggered_by, domain)
            VALUES (?, ?, ?, ?, 'IN_PROGRESS', ?, ?, ?)
        """, (app, commit_hash, commit_msg, slot, started_at, triggered_by, domain))
        return cursor.lastrowid


def record_deployment_finish(deploy_id, status, error_message=None):
    """Record deployment result and calculate exact elapsed duration."""
    finished_at = int(time.time())
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT started_at FROM deployments WHERE id = ?", (deploy_id,)).fetchone()
        duration = round(finished_at - row["started_at"], 2) if row else 0.0

        conn.execute("""
            UPDATE deployments
            SET status = ?, finished_at = ?, duration_sec = ?, error_message = ?
            WHERE id = ?
        """, (status, finished_at, duration, error_message, deploy_id))
        return duration


def get_deployment_summary(app):
    """Retrieve aggregated deployment statistics for a given application."""
    init_db()
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COUNT(*) as c FROM deployments WHERE app = ? AND status != 'IN_PROGRESS'", (app,)).fetchone()["c"]
        success = conn.execute("SELECT COUNT(*) as c FROM deployments WHERE app = ? AND status = 'SUCCESS'", (app,)).fetchone()["c"]
        failed = conn.execute("SELECT COUNT(*) as c FROM deployments WHERE app = ? AND status IN ('FAILED', 'ROLLBACK')", (app,)).fetchone()["c"]
        last = conn.execute("SELECT * FROM deployments WHERE app = ? AND status != 'IN_PROGRESS' ORDER BY started_at DESC LIMIT 1", (app,)).fetchone()

    return {
        "total": total,
        "success": success,
        "failed": failed,
        "last": dict(last) if last else None,
    }


def show_history(app=None, limit=20):
    """Display audit log of past deployments, rollbacks, and statuses."""
    init_db()
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        if app:
            rows = conn.execute("SELECT * FROM deployments WHERE app = ? ORDER BY started_at DESC LIMIT ?", (app, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM deployments ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()

    if not rows:
        print("No deployment history recorded yet.")
        return

    print("")
    print("=" * 105)
    print(" BOVER :: Deployment History & Rollback Audit Log")
    print("=" * 105)
    print(f"{'ID':<5} {'APP':<14} {'COMMIT':<10} {'SLOT':<8} {'STATUS':<12} {'DURATION':<10} {'TRIGGER':<12} {'DATE'}")
    print("-" * 105)

    for r in rows:
        date_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(r['started_at']))
        dur_str = f"{r['duration_sec']:.1f}s" if r['duration_sec'] is not None else "-"
        commit_str = r['commit_hash'] or "-"
        print(f"{r['id']:<5} {r['app']:<14} {commit_str:<10} {r['slot']:<8} {r['status']:<12} {dur_str:<10} {r['triggered_by'] or 'cli':<12} {date_str}")
        if r['error_message']:
            print(f"      └── Error: {r['error_message']}")

    print("-" * 105)
    print("")


# ==============================================================================
# TELEGRAM NOTIFICATION HOOKS
# ==============================================================================

def send_telegram(text):
    """Send formatted Telegram HTML notification if configured (reads from encrypted vault)."""
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    # Read from encrypted vault with host salt
    vault_data = load_vault_secret("telegram")
    if vault_data and vault_data.get("enabled", True):
        bot_token = bot_token or vault_data.get("bot_token")
        chat_id = chat_id or vault_data.get("chat_id")

    # Legacy fallback migration
    config_file = APPS_DIR / "telegram.json"
    if not bot_token and config_file.exists():
        try:
            with open(config_file, "r") as f:
                data = json.load(f)
            if data.get("enabled", True):
                bot_token = bot_token or data.get("bot_token")
                chat_id = chat_id or data.get("chat_id")
                # Auto-migrate to encrypted vault
                save_vault_secret("telegram", data)
                config_file.unlink(missing_ok=True)
        except Exception:
            pass

    if not bot_token or not chat_id:
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    import urllib.request
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[Telegram] Notice: could not deliver alert: {e}")
        return False


def notify_deploy_success(app, slot, commit, commit_msg, domain, duration, triggered_by):
    hostname = run_cmd("hostname", capture=True) or "server"
    commit_disp = commit[:7] if commit else "latest"
    safe_app = html.escape(str(app))
    safe_slot = html.escape(str(slot))
    safe_commit = html.escape(str(commit_disp))
    safe_domain = html.escape(str(domain))
    safe_host = html.escape(str(hostname))
    safe_msg = html.escape(str(commit_msg)) if commit_msg else ""
    msg_part = f"\n🔖 <b>Commit:</b> <code>{safe_commit}</code> · <i>{safe_msg}</i>" if safe_msg else f"\n🔖 <b>Commit:</b> <code>{safe_commit}</code>"
    trigger_display = {
        "autodeploy": "🤖 Bover (Auto-Deploy desatendido)",
        "cli": "👤 Manual (L'Amo CLI)",
        "rollback": "🛡️ Auto-Rollback (Fallo de salud)",
    }.get(triggered_by, f"👤 {html.escape(str(triggered_by))}")
    text = (
        f"🚀 <b>ES BOVER · DESPLIEGUE EXITOSO</b>\n"
        f"<i>Aplicación actualizada con 0 downtime</i>\n\n"
        f"📦 <b>App:</b> <code>{safe_app}</code>\n"
        f"🖥️  <b>Nodo:</b> <code>{safe_host}</code>\n"
        f"🌐 <b>URL:</b> https://{safe_domain}\n"
        f"🎯 <b>Slot Activo:</b> <code>{safe_slot}</code> (Nuevo){msg_part}\n"
        f"⏱️ <b>Duración:</b> <code>{duration:.1f}s</code>\n"
        f"⚙️ <b>Disparador:</b> {trigger_display}\n\n"
        f"<blockquote>✨ <b>Salud OK:</b> Contenedor verificado, Caddy ha transferido el 100% del tráfico sin pérdida de peticiones.</blockquote>\n\n"
        f"<i>Es Bover Runtime :: Deployer</i>"
    )
    send_telegram(text)


def notify_deploy_failed(app, target_slot, live_slot, commit, error, triggered_by):
    hostname = run_cmd("hostname", capture=True) or "server"
    commit_disp = commit[:7] if commit else "unknown"
    safe_app = html.escape(str(app))
    safe_target = html.escape(str(target_slot))
    safe_live = html.escape(str(live_slot or 'none'))
    safe_commit = html.escape(str(commit_disp))
    safe_error = html.escape(str(error)[:300])
    safe_host = html.escape(str(hostname))
    trigger_display = {
        "autodeploy": "🤖 Bover (Auto-Deploy desatendido)",
        "cli": "👤 Manual (L'Amo CLI)",
        "rollback": "🛡️ Auto-Rollback (Fallo de salud)",
    }.get(triggered_by, f"👤 {html.escape(str(triggered_by))}")
    text = (
        f"⚠️ <b>ES BOVER · FALLO EN DESPLIEGUE</b>\n"
        f"<i>Healthcheck fallido · Rollback automático</i>\n\n"
        f"📦 <b>App:</b> <code>{safe_app}</code>\n"
        f"🖥️  <b>Nodo:</b> <code>{safe_host}</code>\n"
        f"🎯 <b>Slot Afectado:</b> <code>{safe_target}</code>\n"
        f"🛡️ <b>Slot Activo Protegido:</b> <code>{safe_live}</code>\n"
        f"🔖 <b>Commit:</b> <code>{safe_commit}</code>\n"
        f"⚙️ <b>Disparador:</b> {trigger_display}\n\n"
        f"<blockquote>❌ <b>Error:</b> <code>{safe_error}</code>\n"
        f"El tráfico continúa en el slot sano sin caída de servicio (Zero Downtime).</blockquote>\n\n"
        f"<i>Es Bover Runtime :: Auto-Rollback</i>"
    )
    send_telegram(text)


def configure_telegram(bot_token, chat_id, test=True):
    """Encrypt and store Telegram bot credentials in host-salted encrypted vault."""
    data = {
        "bot_token": bot_token,
        "chat_id": chat_id,
        "enabled": True,
    }
    save_vault_secret("telegram", data)

    # Clean up legacy unencrypted file if present
    legacy_file = APPS_DIR / "telegram.json"
    if legacy_file.exists():
        try:
            legacy_file.unlink()
        except Exception:
            pass

    print(f"==> Telegram credentials encrypted with host salt and stored in {VAULT_DIR / 'telegram.enc'}")

    if test:
        hostname = run_cmd("hostname", capture=True) or "server"
        admin_user = os.environ.get("SUDO_USER") or os.environ.get("USER") or "admin"
        test_text = (
            f"🤖 <b>ES BOVER · CONEXIÓN ESTABLECIDA</b>\n"
            f"<i>Canal de alertas y auditoría operativo</i>\n\n"
            f"🖥️  <b>Nodo:</b> <code>{hostname}</code>\n"
            f"👤 <b>Operador:</b> <code>{admin_user}</code>\n"
            f"🔐 <b>Caja Fuerte:</b> AES-256 (PBKDF2 / Salt de hardware)\n"
            f"📡 <b>Monitoreo:</b> Despliegues, Healthchecks, KVM y SSH\n\n"
            f"<blockquote>✅ <b>Sistema listo:</b> Las alertas críticas y avisos de despliegue se recibirán en este chat.</blockquote>\n\n"
            f"<i>Es Bover Runtime :: L'Amo Orchestrator</i>"
        )
        if send_telegram(test_text):
            print("==> Test notification delivered successfully to Telegram!")
        else:
            print("WARNING: Could not deliver test message. Check bot token and chat ID.")


def parse_bytes(s):
    """Parse byte strings such as '15.4MiB', '1.2GB', '0B' to integer bytes."""
    s = s.strip()
    if not s or s == "0B":
        return 0
    units = {
        "b": 1,
        "k": 1000, "kb": 1000, "kib": 1024,
        "m": 1000**2, "mb": 1000**2, "mib": 1024**2,
        "g": 1000**3, "gb": 1000**3, "gib": 1024**3,
        "t": 1000**4, "tb": 1000**4, "tib": 1024**4,
    }
    s_clean = s.replace(",", ".").lower()
    for unit, mult in sorted(units.items(), key=lambda x: -len(x[0])):
        if s_clean.endswith(unit):
            num = s_clean[:-len(unit)].strip()
            try:
                return int(float(num) * mult)
            except ValueError:
                return 0
    try:
        return int(float(s_clean))
    except ValueError:
        return 0


ANSI_REGEX = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def visible_len(s):
    """Return visible character length of string excluding ANSI escape sequences."""
    return len(ANSI_REGEX.sub("", str(s)))


def format_table(headers, rows, max_width=None):
    """
    Format rows into a clean, aligned table adapting dynamically to terminal width.
    Automatically clips cell content if total width exceeds max_width or terminal columns.
    """
    if max_width is None:
        try:
            term_cols = shutil.get_terminal_size((80, 24)).columns
            max_width = min(max(term_cols, 72), 100)
        except Exception:
            max_width = 80

    num_cols = len(headers)
    widths = [visible_len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            if i < num_cols:
                widths[i] = max(widths[i], visible_len(val))

    total = sum(widths) + (num_cols - 1) * 2
    if total > max_width:
        excess = total - max_width
        widest_idx = widths.index(max(widths))
        widths[widest_idx] = max(8, widths[widest_idx] - excess)

    header_cells = []
    for i, h in enumerate(headers):
        header_cells.append(h + " " * max(0, widths[i] - visible_len(h)))
    header_line = "  ".join(header_cells)
    sep_line = "-" * len(header_line)

    row_lines = []
    for row in rows:
        cells = []
        for i, val in enumerate(row):
            if i >= num_cols:
                continue
            s = str(val)
            v_len = visible_len(s)
            w = widths[i]
            if v_len > w:
                s = s[:w-1] + "…" if w > 2 else s[:w]
                v_len = visible_len(s)
            cells.append(s + " " * max(0, w - v_len))
        row_lines.append("  ".join(cells))

    return header_line, sep_line, row_lines


def format_bytes(b):
    """Format bytes to human-readable MB or GB."""
    if b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024*1024):.1f} MB"
    else:
        return f"{b / (1024*1024*1024):.2f} GB"


def sample_metrics():
    """Take a point-in-time sample from docker stats and persist to SQLite."""
    init_db()
    raw = run_cmd("docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}'", capture=True)
    if not raw:
        return

    now = int(time.time())
    rows = []
    for line in raw.split("\n"):
        parts = line.split("|")
        if len(parts) < 5:
            continue
        c_name = parts[0].strip()
        cpu_str = parts[1].replace("%", "").strip()
        try:
            cpu_pct = float(cpu_str)
        except ValueError:
            cpu_pct = 0.0

        mem_used_str = parts[2].split("/")[0].strip()
        mem_bytes = parse_bytes(mem_used_str)

        net_rx = 0
        net_tx = 0
        if "/" in parts[3]:
            net_p = parts[3].split("/")
            net_rx = parse_bytes(net_p[0])
            net_tx = parse_bytes(net_p[1])

        block_read = 0
        block_write = 0
        if "/" in parts[4]:
            block_p = parts[4].split("/")
            block_read = parse_bytes(block_p[0])
            block_write = parse_bytes(block_p[1])

        rows.append((now, c_name, cpu_pct, mem_bytes, net_rx, net_tx, block_read, block_write))

    with get_db() as conn:
        conn.executemany("INSERT INTO metrics VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        # Prune metrics older than 31 days
        cutoff = now - (31 * 86400)
        conn.execute("DELETE FROM metrics WHERE timestamp < ?", (cutoff,))

    # Sample disk usage, Caddy visits metrics, and Docker container/image snapshot cache
    refresh_docker_cache()
    sample_disk_metrics(now)
    sample_visits_metrics(now)


def _inspect_container_fast(container_name: str) -> Optional[Dict[str, str]]:
    """Fast container state lookup via cached Docker snapshot or Unix socket, with CLI fallback."""
    cached = get_docker_cached_data()
    containers = cached.get("containers") if isinstance(cached, dict) else docker_api_get("/containers/json?all=1")
    if isinstance(containers, list):
        target_slash = f"/{container_name}"
        for c in containers:
            names = c.get("Names") or []
            if target_slash in names or container_name in names:
                c_state = c.get("State", "unknown")
                c_status_str = c.get("Status", c_state)
                h_status = ""
                if "(healthy)" in c_status_str:
                    h_status = "healthy"
                elif "(unhealthy)" in c_status_str:
                    h_status = "unhealthy"
                c_ip = ""
                nets = (c.get("NetworkSettings") or {}).get("Networks") or {}
                for net_info in nets.values():
                    if isinstance(net_info, dict) and net_info.get("IPAddress"):
                        c_ip = net_info["IPAddress"]
                        break
                return {
                    "state": c_state,
                    "status_str": c_status_str,
                    "health": h_status,
                    "ip": c_ip,
                }
        return None
    return None


def probe_app_health(container_name: str, port: int, health_path: str = "/") -> Dict[str, Any]:
    """
    Live health probe against an application container:
    - Inspects container state (running, healthy, IP, uptime) via Unix socket
    - Probes HTTP response code and latency directly over container bridge network
    """
    path = str(health_path or "/").strip()
    if not path.startswith("/"):
        path = "/" + path

    fast_info = _inspect_container_fast(container_name)
    if fast_info is not None:
        c_status = fast_info["state"]
        ps_out = fast_info["status_str"]
        h_status = fast_info["health"]
        c_ip = fast_info["ip"]
    else:
        insp = run_cmd(
            f"docker inspect --format '{{{{.State.Status}}}}|{{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{end}}}}|{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {container_name} 2>/dev/null || true",
            capture=True
        )
        if not insp or "|" not in insp:
            return {
                "alive": False,
                "container_state": "stopped",
                "health_state": "",
                "ip": "-",
                "responding": False,
                "http_code": None,
                "latency_ms": None,
                "error": "Container not found or stopped",
            }
        parts = insp.split("|")
        c_status = parts[0].strip() if len(parts) > 0 else "unknown"
        h_status = parts[1].strip() if len(parts) > 1 and parts[1].strip() else ""
        c_ip = parts[2].strip() if len(parts) > 2 else ""
        ps_out = run_cmd(f"docker ps --filter name={container_name} --format '{{{{.Status}}}}'", capture=True) or c_status

    if c_status != "running":
        return {
            "alive": False,
            "container_state": ps_out,
            "health_state": h_status,
            "ip": c_ip or "-",
            "responding": False,
            "http_code": None,
            "latency_ms": None,
            "error": "Container stopped",
        }

    # Fast path: direct HTTP probe from host to container bridge IP
    if c_ip:
        start_t = time.time()
        hc = None
        try:
            hc = http.client.HTTPConnection(c_ip, int(port), timeout=2.0)
            hc.request("GET", path, headers={"Host": container_name, "User-Agent": "Bover-Probe/1.0", "Connection": "close"})
            hresp = hc.getresponse()
            http_code = hresp.status
            elapsed_ms = round((time.time() - start_t) * 1000, 1)
            responding = http_code is not None and http_code < 500
            return {
                "alive": True,
                "container_state": ps_out,
                "health_state": h_status,
                "ip": c_ip,
                "responding": responding,
                "http_code": http_code,
                "latency_ms": elapsed_ms,
                "endpoint": path,
                "error": None if responding else "HTTP failure",
            }
        except Exception:
            pass
        finally:
            if hc:
                try:
                    hc.close()
                except Exception:
                    pass

    # Fallback: probe via caddy-gateway container on the gateway network
    health_url = f"http://{container_name}:{port}{path}"
    start_t = time.time()
    probe_cmd = f"docker exec {CADDY_CONTAINER} wget -S --spider -T 3 {health_url} 2>&1"
    out = run_cmd(probe_cmd, capture=True)
    elapsed_ms = round((time.time() - start_t) * 1000, 1)

    code_match = re.search(r"HTTP/\d\.\d\s+(\d+)", out)
    http_code = int(code_match.group(1)) if code_match else (200 if "200" in out or "remote file exists" in out else None)
    responding = http_code is not None and http_code < 500

    return {
        "alive": True,
        "container_state": ps_out,
        "health_state": h_status,
        "ip": c_ip or "-",
        "responding": responding,
        "http_code": http_code,
        "latency_ms": elapsed_ms,
        "endpoint": path,
        "error": None if responding else ("HTTP failure" if http_code else "Connection timeout"),
    }


def probe_caddy_health() -> Dict[str, Any]:
    """Inspect Caddy gateway container and probe its internal Admin API."""
    fast_info = _inspect_container_fast(CADDY_CONTAINER)
    if fast_info is not None:
        c_status = fast_info["state"]
        ps_out = fast_info["status_str"]
        c_ip = fast_info["ip"]
    else:
        insp = run_cmd(
            f"docker inspect --format '{{{{.State.Status}}}}|{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {CADDY_CONTAINER} 2>/dev/null || true",
            capture=True,
            check=False
        )
        if not insp or "|" not in insp:
            return {
                "alive": False,
                "container_state": "stopped",
                "ip": "-",
                "responding": False,
                "http_code": None,
                "latency_ms": None,
                "error": "Gateway container not found or stopped",
            }
        parts = insp.split("|")
        c_status = parts[0].strip() if len(parts) > 0 else "unknown"
        c_ip = parts[1].strip() if len(parts) > 1 else ""
        ps_out = run_cmd(f"docker ps --filter name={CADDY_CONTAINER} --format '{{{{.Status}}}}'", capture=True, check=False) or c_status

    if c_status != "running":
        return {
            "alive": False,
            "container_state": ps_out,
            "ip": c_ip or "-",
            "responding": False,
            "http_code": None,
            "latency_ms": None,
            "error": "Gateway container stopped",
        }

    # Probe internal Caddy admin endpoint
    start_t = time.time()
    out = run_cmd(f"docker exec {CADDY_CONTAINER} wget -S --spider -T 3 http://127.0.0.1:2019/config/ 2>&1", capture=True, check=False)
    elapsed_ms = round((time.time() - start_t) * 1000, 1)

    code_match = re.search(r"HTTP/\d\.\d\s+(\d+)", out)
    http_code = int(code_match.group(1)) if code_match else (200 if "200" in out or "remote file exists" in out else None)
    responding = (http_code == 200)

    return {
        "alive": True,
        "container_state": ps_out,
        "ip": c_ip or "-",
        "responding": responding,
        "http_code": http_code or 200,
        "latency_ms": elapsed_ms,
        "error": None if responding else "Admin API unreachable",
    }


def measure_caddy_disk() -> Tuple[int, int, int, int]:
    """Accurately measure disk footprint for Caddy gateway (total, logs, config, image)."""
    logs_dir = GATEWAY_DIR / "logs"
    logs_bytes = measure_dir_bytes(logs_dir)

    cfg_bytes = 0
    cfile = GATEWAY_DIR / "Caddyfile"
    if cfile.exists():
        cfg_bytes += cfile.stat().st_size
    dfile = GATEWAY_DIR / "docker-compose.yml"
    if dfile.exists():
        cfg_bytes += dfile.stat().st_size

    image_bytes = 0
    img_info = docker_api_get("/images/caddy:2-alpine/json")
    if isinstance(img_info, dict) and img_info.get("Size"):
        image_bytes = int(img_info["Size"])
    else:
        try:
            out = run_cmd("docker image inspect caddy:2-alpine --format '{{.Size}}' 2>/dev/null", capture=True)
            if out:
                image_bytes = int(out.strip())
        except Exception:
            pass

    total_bytes = logs_bytes + cfg_bytes + image_bytes
    return total_bytes, logs_bytes, cfg_bytes, image_bytes


def get_caddy_routed_domains() -> List[str]:
    """Extract list of active domains routed by Caddy."""
    domains = []
    for cfg_path in get_all_app_configs():
        try:
            with open(cfg_path) as f:
                d = json.load(f)
            dom = d.get("domain")
            if dom and dom not in domains:
                domains.append(dom)
            for redir in d.get("redirects", []):
                if redir and redir not in domains:
                    domains.append(redir)
        except Exception:
            continue
    if not domains:
        cfile = GATEWAY_DIR / "Caddyfile"
        if cfile.exists():
            for line in cfile.read_text().splitlines():
                line = line.strip()
                if line.endswith("{") and not line.startswith("(") and not line.startswith(":"):
                    name = line[:-1].strip()
                    if "." in name and name not in domains:
                        domains.append(name)
    return domains


def show_caddy_status():
    """Display comprehensive live Caddy gateway ALB state, health probe, and resources."""
    probe = probe_caddy_health()

    if probe["responding"]:
        http_disp = f"🟢 Responding (Admin API HTTP {probe['http_code']} OK · {probe['latency_ms']:.0f}ms · http://127.0.0.1:2019/config/)"
    elif probe["alive"]:
        http_disp = f"🟡 Degraded (Container active · {probe.get('error', 'Admin API unreachable')})"
    else:
        http_disp = f"🔴 Offline ({probe.get('error', 'Container stopped')})"

    if probe["alive"]:
        c_status = f"🟢 {probe['container_state']} (IP: {probe['ip']})"
    else:
        c_status = f"🔴 {probe['container_state']}"

    curr_cpu = "0.0%"
    curr_mem = "-"
    if DB_PATH.exists():
        try:
            with get_db() as conn:
                conn.row_factory = sqlite3.Row
                m_row = conn.execute(
                    "SELECT cpu_pct, mem_bytes FROM metrics WHERE container = ? ORDER BY timestamp DESC LIMIT 1",
                    (CADDY_CONTAINER,)
                ).fetchone()
                if m_row:
                    curr_cpu = f"{m_row['cpu_pct']:.1f}%"
                    curr_mem = format_bytes(m_row['mem_bytes'])
        except Exception:
            pass

    if curr_mem == "-":
        raw_stat = run_cmd(f"docker stats --no-stream --format '{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}' {CADDY_CONTAINER} 2>/dev/null", capture=True)
        if raw_stat and "|" in raw_stat:
            p_cpu, p_mem = raw_stat.split("|", 1)
            curr_cpu = p_cpu.strip()
            curr_mem = p_mem.split("/")[0].strip()

    tot_disk, logs_disk, cfg_disk, img_disk = measure_caddy_disk()

    domains = get_caddy_routed_domains()
    if domains:
        dom_disp = f"{len(domains)} active ({', '.join(domains[:3])}{'…' if len(domains) > 3 else ''})"
    else:
        dom_disp = "0 domains configured"

    now = int(time.time())
    logs_dir = GATEWAY_DIR / "logs"
    tot_24h = 0
    uniq_24h = 0
    tot_all = 0
    if logs_dir.exists():
        for log_f in logs_dir.glob("*-access.log"):
            res_v = parse_caddy_access_log(log_f, since_ts=now - 86400)
            res_a = parse_caddy_access_log(log_f, since_ts=0)
            if res_v:
                tot_24h += res_v.get("total", 0)
                uniq_24h += res_v.get("unique_ips", 0)
            if res_a:
                tot_all += res_a.get("total", 0)
    traffic_disp = f"{tot_24h:,} requests ({uniq_24h:,} unique) | All-time: {tot_all:,}"

    print("")
    print("=" * 80)
    print(" BOVER :: Central Gateway & Reverse Proxy (ALB) Status: 'caddy'")
    print("=" * 80)
    print(" Service:        Caddy 2 (Automated TLS, Reverse Proxy & Load Balancer)")
    print(" Ports:          80/tcp, 443/tcp (HTTP/1.1, HTTP/2, HTTP/3 QUIC), 2019/tcp")
    print(f" HTTP Probe:     {http_disp}")
    print(f" Container:      {c_status}")
    print(f" Resources:      Current: CPU {curr_cpu} / RAM {curr_mem}")
    print(f" Storage:        {format_bytes(tot_disk)} (Logs: {format_bytes(logs_disk)} | Config: {format_bytes(cfg_disk)} | Image: {format_bytes(img_disk)})")
    print(f" Routed Domains: {dom_disp}")
    print(f" Gateway Traffic:{traffic_disp}")
    print("=" * 80)


def show_caddy_stats():
    """Display live Caddy gateway status followed by historical CPU/RAM consumption metrics."""
    show_caddy_status()

    if not DB_PATH.exists():
        print(f"No historical metrics recorded yet for '{CADDY_CONTAINER}'. Ensure 'bover-metrics.timer' is active.")
        return

    init_db()
    now = int(time.time())
    windows = [
        ("Now (current)", 0),
        ("Last 24h", 24 * 3600),
        ("Last 48h", 48 * 3600),
        ("Last 7d", 7 * 86400),
        ("Last 30d", 30 * 86400),
    ]

    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        headers = ["CONTAINER", "WINDOW", "CPU (AVG / PEAK)", "MEMORY (AVG / PEAK)"]
        table_rows = []

        for cont in [CADDY_CONTAINER]:
            for label, duration in windows:
                if duration == 0:
                    q = "SELECT cpu_pct, mem_bytes FROM metrics WHERE container = ? ORDER BY timestamp DESC LIMIT 1"
                    row = conn.execute(q, (cont,)).fetchone()
                    if row:
                        cpu_fmt = f"{row['cpu_pct']:.1f}%"
                        mem_fmt = format_bytes(row['mem_bytes'])
                    else:
                        cpu_fmt = "n/a"
                        mem_fmt = "n/a"
                else:
                    since = now - duration
                    q = """
                        SELECT
                            AVG(cpu_pct) as avg_cpu,
                            MAX(cpu_pct) as max_cpu,
                            AVG(mem_bytes) as avg_mem,
                            MAX(mem_bytes) as max_mem
                        FROM metrics
                        WHERE container = ? AND timestamp >= ?
                    """
                    row = conn.execute(q, (cont, since)).fetchone()
                    if row and row["avg_cpu"] is not None:
                        cpu_fmt = f"{row['avg_cpu']:.1f}% / {row['max_cpu']:.1f}%"
                        mem_fmt = f"{format_bytes(int(row['avg_mem']))} / {format_bytes(int(row['max_mem']))}"
                    else:
                        cpu_fmt = "n/a"
                        mem_fmt = "n/a"
                table_rows.append([cont, label, cpu_fmt, mem_fmt])

        hdr_line, sep_line, row_lines = format_table(headers, table_rows)
        print("")
        print(hdr_line)
        print(sep_line)
        for r in row_lines:
            print(r)
        print("-" * len(hdr_line))
        print("")


def show_app_status(target_app: str):
    """
    Display comprehensive live application state:
    - Domain & public URL
    - Internal port & routing slot
    - Live HTTP probe (response code, latency, health endpoint)
    - Container status (running state, uptime, internal IP)
    - Deployed commit & last message
    - Computational resource limits & current usage
    - Disk footprint breakdown
    - 24h HTTP traffic & visitors
    - Automation settings (Auto-Deploy, Auto-Backup)
    """
    if target_app.lower() in ("caddy", "gateway", "caddy-gateway"):
        show_caddy_status()
        return

    cfg = load_app_config(target_app)
    if not cfg:
        print(f"ERROR: Application '{target_app}' not found in {APPS_DIR}.")
        return

    state = load_app_state(target_app)
    domain = cfg.get("domain", "-")
    port = cfg.get("port", "-")
    slot = state.get("active_slot", "-")
    cont = state.get("container") or f"{target_app}-{slot}"
    commit = (state.get("commit") or "-")[:7]
    health_path = cfg.get("healthcheck", "/")
    auto_cd = "enabled" if cfg.get("auto_deploy") else "disabled"
    auto_bk = "enabled" if cfg.get("auto_backup") else "disabled"
    cpu_lim = cfg.get("cpu", "0.5")
    mem_lim = cfg.get("memory", "512m")

    # 1. Live health probe
    probe = probe_app_health(cont, port, health_path)
    if probe["responding"]:
        http_disp = f"🟢 Responding (HTTP {probe['http_code']} OK · {probe['latency_ms']:.0f}ms · {probe['endpoint']})"
    elif probe["alive"]:
        http_disp = f"🟡 Degraded (HTTP {probe.get('http_code') or 'fail'} · {probe.get('error', 'unhealthy')})"
    else:
        http_disp = f"🔴 Offline ({probe.get('error', 'container down')})"

    health_extra = f" · {probe['health_state']}" if probe.get("health_state") else ""
    if probe["alive"]:
        c_status = f"🟢 {probe['container_state']}{health_extra} (IP: {probe['ip']})"
    else:
        c_status = f"🔴 {probe['container_state']}"

    # 2. Fetch metrics, cached disk, visits, and commit message from SQLite in one connection
    now = int(time.time())
    tot_disk, data_disk, code_disk, img_disk = 0, 0, 0, 0
    disk_found = False
    tot_24h, uniq_24h = 0, 0
    visits_found = False
    commit_msg = state.get("commit_msg", "")
    curr_cpu = "0.0%"
    curr_mem = "-"

    if DB_PATH.exists():
        try:
            with get_db() as conn:
                conn.row_factory = sqlite3.Row
                m_row = conn.execute(
                    "SELECT cpu_pct, mem_bytes FROM metrics WHERE container = ? ORDER BY timestamp DESC LIMIT 1",
                    (cont,)
                ).fetchone()
                if m_row:
                    curr_cpu = f"{m_row['cpu_pct']:.1f}%"
                    curr_mem = format_bytes(m_row["mem_bytes"])

                d_row = conn.execute(
                    "SELECT total_bytes, data_bytes, code_bytes, image_bytes, timestamp FROM app_disk_metrics WHERE app = ? ORDER BY timestamp DESC LIMIT 1",
                    (target_app,)
                ).fetchone()
                if d_row and (now - d_row["timestamp"]) <= 900:
                    tot_disk = d_row["total_bytes"]
                    data_disk = d_row["data_bytes"]
                    code_disk = d_row["code_bytes"]
                    img_disk = d_row["image_bytes"]
                    disk_found = True

                v_row = conn.execute(
                    "SELECT requests_total, unique_ips, timestamp FROM app_visits WHERE app = ? ORDER BY timestamp DESC LIMIT 1",
                    (target_app,)
                ).fetchone()
                if v_row and (now - v_row["timestamp"]) <= 600:
                    tot_24h = v_row["requests_total"]
                    uniq_24h = v_row["unique_ips"]
                    visits_found = True

                if not commit_msg:
                    dep_row = conn.execute(
                        "SELECT commit_msg FROM deployments WHERE app = ? AND commit_msg IS NOT NULL AND commit_msg != '' ORDER BY id DESC LIMIT 1",
                        (target_app,)
                    ).fetchone()
                    if dep_row:
                        commit_msg = dep_row["commit_msg"]
        except Exception:
            pass

    if not disk_found:
        tot_disk, data_disk, code_disk, img_disk = measure_app_disk(target_app)

    log_file = GATEWAY_DIR / "logs" / f"{target_app}-access.log"
    visits_str = "0 requests (0 unique)"
    if visits_found:
        visits_str = f"{tot_24h:,} requests ({uniq_24h:,} unique)"
    elif log_file.exists():
        res_v = parse_caddy_access_log(log_file, since_ts=now - 86400)
        tot_24h = res_v["total"] if res_v else 0
        uniq_24h = res_v["unique_ips"] if res_v else 0
        visits_str = f"{tot_24h:,} requests ({uniq_24h:,} unique)"

    # Commit message fallback
    app_dir = cfg.get("_app_dir") or (APPS_DIR / target_app)
    if not commit_msg and (app_dir / ".git").exists():
        try:
            commit_msg = run_cmd("git log -1 --pretty=%s", capture=True, cwd=app_dir)
        except Exception:
            pass
    if commit_msg and len(commit_msg) > 36:
        commit_msg = commit_msg[:35] + "…"
    commit_disp = f"{commit} (\"{commit_msg}\")" if commit_msg else commit

    print("")
    print("=" * 80)
    print(f" BOVER :: Live Application Status: '{target_app}'")
    print("=" * 80)
    print(f" Domain:         https://{domain}")
    print(f" Internal Port:  {port} (Active Slot: {slot} -> {cont})")
    print(f" HTTP Probe:     {http_disp}")
    print(f" Container:      {c_status}")
    print(f" Commit:         {commit_disp}")
    print(f" Resources:      Limits: CPU {cpu_lim} / RAM {mem_lim} | Current: CPU {curr_cpu} / RAM {curr_mem}")
    print(f" Storage:        {format_bytes(tot_disk)} (Data: {format_bytes(data_disk)} | Code: {format_bytes(code_disk)} | Images: {format_bytes(img_disk)})")
    print(f" Traffic (24h):  {visits_str}")
    crons_list = get_app_crons(cfg)
    enabled_crons = [c for c in crons_list if c.get("enabled", True)]
    cron_disp = f"{len(enabled_crons)} active / {len(crons_list)} configured" if crons_list else "none"
    print(f" Automation:     Auto-Deploy: {auto_cd} | Auto-Backup: {auto_bk} | Crons: {cron_disp}")
    print("=" * 80)


def show_app_config(app_name: str, as_json: bool = False, show_secrets: bool = False):
    """Display comprehensive configuration, routing parameters and metadata for an app."""
    validate_app_name(app_name)
    app_dir = APPS_DIR / app_name
    cfg_file = app_dir / "app.json"
    if not cfg_file.exists():
        print(f"ERROR: Configuration for application '{app_name}' not found at {cfg_file}")
        sys.exit(1)

    with open(cfg_file) as f:
        cfg = json.load(f)

    state = load_app_state(app_name)

    # Read environment keys/secrets from .env
    env_keys = []
    env_vars = {}
    env_file = app_dir / ".env"
    if env_file.exists():
        try:
            with open(env_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        env_keys.append(k)
                        env_vars[k] = v
        except Exception:
            pass

    if as_json:
        full_data = {
            "config": cfg,
            "state": state,
            "environment_keys": env_keys,
        }
        if show_secrets:
            full_data["environment"] = env_vars
        print(json.dumps(full_data, indent=2))
        return

    domain = cfg.get("domain", "-")
    redirects = ", ".join(cfg.get("redirects", [])) if cfg.get("redirects") else "none"
    port = cfg.get("port", 8080)
    healthcheck = cfg.get("healthcheck", "/")
    runtime_type = cfg.get("type", "dockerfile").capitalize()
    repo = cfg.get("repo", "-")
    branch = cfg.get("branch", "master")
    cpu = cfg.get("cpu", 0.5)
    memory = cfg.get("memory", "512m")
    keep_versions = cfg.get("keep_versions", 3)
    auto_deploy = "enabled" if cfg.get("auto_deploy", False) else "disabled"
    auto_backup = "enabled" if cfg.get("auto_backup", False) else "disabled"

    active_slot = state.get("active_slot", "-")
    container = state.get("container", f"{app_name}-{active_slot}" if active_slot != "-" else "-")
    commit = state.get("commit", "-")
    raw_deployed = state.get("deployed_at", "-")
    if raw_deployed != "-":
        try:
            ts = int(raw_deployed)
            deployed_disp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            deployed_disp = str(raw_deployed)
    else:
        deployed_disp = "-"
    data_dir = app_dir / "data"

    env_count = len(env_keys)
    if env_count == 0:
        env_summary = "none configured"
    elif show_secrets:
        env_summary = ", ".join(f"{k}={v}" for k, v in env_vars.items())
    else:
        env_summary = f"{', '.join(env_keys)} ({env_count} variables configured)"

    w = 78
    print("")
    print("=" * w)
    print(f" BOVER :: Application Configuration & Metadata: '{app_name}'")
    print("=" * w)
    print(f" Domain:           https://{domain}")
    print(f" Redirects:        {redirects}")
    print(f" Internal Port:    {port} (Healthcheck Path: {healthcheck})")
    print(f" Build Runtime:    {runtime_type}")
    print(f" Repository:       {repo} (branch: {branch})")
    print(f" Resource Limits:  CPU: {cpu} cores | RAM: {memory}")
    print(f" Image Retention:  Keep {keep_versions} version images")
    print(f" Active Slot:      {active_slot} (Container: {container})")
    if commit != "-":
        print(f" Deployed Commit:  {commit} (deployed: {deployed_disp})")
    print(f" Persistent Data:  {data_dir} -> /data")
    crons_list = get_app_crons(cfg)
    enabled_crons = [c for c in crons_list if c.get("enabled", True)]
    cron_summary = f"{len(enabled_crons)} enabled / {len(crons_list)} total" if crons_list else "none configured"
    print(f" Automation:       Auto-Deploy: {auto_deploy} | Auto-Backup: {auto_backup} | Crons: {cron_summary}")
    print(f" Environment:      {env_summary}")
    if crons_list:
        print(f" Scheduled Crons:")
        for c in crons_list:
            st_lbl = "ON " if c.get("enabled", True) else "OFF"
            print(f"   • [{st_lbl}] {c['id']:<18} {c['schedule']:<14} ({c['mode']}) -> {c['command']}")
    print("=" * w)
    print("")


def get_node_ip():
    """Detect primary IPv4 address of the host node."""
    if os.environ.get("NODE_IP"):
        return os.environ["NODE_IP"].strip()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("1.1.1.1", 80))
            return s.getsockname()[0]
    except Exception:
        pass
    ip_out = run_cmd("hostname -I 2>/dev/null", capture=True)
    if ip_out:
        for part in ip_out.split():
            if ":" not in part and not part.startswith("172.") and not part.startswith("127."):
                return part
        if ip_out.split():
            return ip_out.split()[0]
    return "unknown"


def show_node_stats():
    """Display comprehensive host system telemetry, resource limits, and Docker engine status."""
    hostname = socket.gethostname() or "server"
    node_ip = get_node_ip()

    uptime_str = "unknown"
    if os.path.exists("/proc/uptime"):
        try:
            with open("/proc/uptime") as f:
                up_secs = int(float(f.readline().split()[0]))
            days = up_secs // 86400
            hours = (up_secs % 86400) // 3600
            mins = (up_secs % 3600) // 60
            uptime_str = f"{days} days, {hours} hours, {mins} mins"
        except Exception:
            pass

    os_name = "Linux"
    if os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        os_name = line.split("=", 1)[1].strip().strip("\"'")
                        break
        except Exception:
            pass

    kernel = platform.release()
    cpu_count = os.cpu_count() or 1
    load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

    mem = {}
    if os.path.exists("/proc/meminfo"):
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        mem[parts[0].strip()] = int(parts[1].split()[0])
        except Exception:
            pass
    tot_ram = mem.get("MemTotal", 0) // 1024
    avail_ram = mem.get("MemAvailable", 0) // 1024
    used_ram = tot_ram - avail_ram
    ram_pct = (used_ram / tot_ram * 100) if tot_ram else 0

    tot_swap = mem.get("SwapTotal", 0) // 1024
    free_swap = mem.get("SwapFree", 0) // 1024
    used_swap = tot_swap - free_swap
    swap_pct = (used_swap / tot_swap * 100) if tot_swap else 0

    try:
        disk_tot, disk_used, disk_free = shutil.disk_usage("/")
        disk_pct = (disk_used / disk_tot * 100) if disk_tot else 0
        disk_str = f"{disk_used / (1024**3):.1f}G used / {disk_tot / (1024**3):.1f}G total ({disk_pct:.0f}% used, {disk_free / (1024**3):.1f}G free)"
    except Exception:
        disk_str = "-"

    c_run = "-"
    c_tot = "-"
    c_img = "-"
    cached_docker = get_docker_cached_data()
    if isinstance(cached_docker, dict) and isinstance(cached_docker.get("containers"), list):
        containers_api = cached_docker["containers"]
        c_tot = len(containers_api)
        c_run = sum(1 for c in containers_api if c.get("State") == "running")
        images_api = cached_docker.get("images")
        c_img = len(images_api) if isinstance(images_api, list) else "-"
    else:
        docker_json = run_cmd("docker info --format json 2>/dev/null", capture=True)
        if docker_json:
            try:
                d = json.loads(docker_json)
                c_run = d.get("ContainersRunning", 0)
                c_tot = d.get("Containers", 0)
                c_img = d.get("Images", 0)
            except Exception:
                pass

    w = 76
    print("")
    print("=" * w)
    print(f" BOVER :: Host Node Telemetry & System Metrics: '{hostname}' ({node_ip})")
    print("=" * w)
    print(f" Host IP Address:   {node_ip}")
    print(f" Operating System:  {os_name} (Kernel: {kernel})")
    print(f" System Uptime:     {uptime_str}")
    print(f" CPU & Load (1/5/15): {cpu_count} cores | Load: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}")
    print(f" Memory (RAM):      {used_ram} MB / {tot_ram} MB ({ram_pct:.1f}% utilized)")
    print(f" Swap Storage:      {used_swap} MB / {tot_swap} MB ({swap_pct:.1f}%)")
    print(f" Host Storage (/):  {disk_str}")
    print(f" Docker Engine:     {c_run} running / {c_tot} containers ({c_img} images cached)")
    print("=" * w)
    print("")


def show_stats(target_app=None):
    """Display applications overview and aggregated container resource usage: now, 24h, 48h, 7d, 30d."""
    if target_app and target_app.lower() in ("caddy", "gateway", "caddy-gateway"):
        show_caddy_stats()
        return

    init_db()
    now = int(time.time())
    windows = [
        ("Now (current)", 0),
        ("Last 24h", 24 * 3600),
        ("Last 48h", 48 * 3600),
        ("Last 7d", 7 * 86400),
        ("Last 30d", 30 * 86400),
    ]

    with get_db() as conn:
        conn.row_factory = sqlite3.Row

        # If no specific app requested, print high-level overview table of all applications
        if not target_app:
            configs = get_all_app_configs()
            if configs:
                print("")
                print("=" * 80)
                print(" BOVER :: Applications Overview & Real-Time Stats")
                print("=" * 80)
                print(f"{'APP':<10} {'DOMAIN':<18} {'SLOT':<5} {'CPU':<6} {'RAM':<8} {'DISK':<9} {'VISITS (24h)':<12} {'AUTO'}")
                print("-" * 80)
                for cfg_p in configs:
                    try:
                        with open(cfg_p) as f:
                            d = json.load(f)
                        name = d.get("name")
                        raw_domain = d.get("domain", "-")
                        domain = (raw_domain[:17] + "…") if len(raw_domain) > 18 else raw_domain
                        auto_cd = d.get("auto_deploy")
                        auto_bk = d.get("auto_backup")
                        if auto_cd and auto_bk:
                            auto_s = "cd + bk"
                        elif auto_cd:
                            auto_s = "cd"
                        elif auto_bk:
                            auto_s = "bk"
                        else:
                            auto_s = "-"

                        st = load_app_state(name)
                        slot = st.get("active_slot", "blue")
                        cont = st.get("container", f"{name}-{slot}")

                        m_row = conn.execute("SELECT cpu_pct, mem_bytes FROM metrics WHERE container = ? ORDER BY timestamp DESC LIMIT 1", (cont,)).fetchone()
                        cpu_s = f"{m_row['cpu_pct']:.1f}%" if m_row else "0.0%"
                        mem_s = format_bytes(m_row["mem_bytes"]) if m_row else "-"

                        # Disk (use SQLite cache from bover-metrics.timer if fresh, fallback to live calculation)
                        d_row = conn.execute(
                            "SELECT total_bytes, timestamp FROM app_disk_metrics WHERE app = ? ORDER BY timestamp DESC LIMIT 1",
                            (name,)
                        ).fetchone()
                        if d_row and (now - d_row["timestamp"]) <= 900:
                            tot_disk = d_row["total_bytes"]
                        else:
                            tot_disk, _, _, _ = measure_app_disk(name)
                        disk_s = format_bytes(tot_disk) if tot_disk else "0 B"

                        # Visits (last 24h from SQLite cache if fresh, fallback to log parsing)
                        v_row = conn.execute(
                            "SELECT requests_total, unique_ips, timestamp FROM app_visits WHERE app = ? ORDER BY timestamp DESC LIMIT 1",
                            (name,)
                        ).fetchone()
                        if v_row and (now - v_row["timestamp"]) <= 600:
                            if v_row["requests_total"] > 0:
                                visits_s = f"{v_row['requests_total']:,} ({v_row['unique_ips']:,}u)"
                            else:
                                visits_s = "0"
                        else:
                            log_file = GATEWAY_DIR / "logs" / f"{name}-access.log"
                            if log_file.exists():
                                res_v = parse_caddy_access_log(log_file, since_ts=now - 86400)
                                if res_v and res_v["total"] > 0:
                                    visits_s = f"{res_v['total']:,} ({res_v['unique_ips']:,}u)"
                                else:
                                    visits_s = "0"
                            else:
                                visits_s = "-"

                        print(f"{name:<10} {domain:<18} {slot:<5} {cpu_s:<6} {mem_s:<8} {disk_s:<9} {visits_s:<12} {auto_s}")
                    except Exception:
                        continue
                print("-" * 80)
        else:
            if target_app.lower() in ("caddy", "gateway", "caddy-gateway"):
                show_caddy_stats()
                return

            # Specific app live status and health probe card
            show_app_status(target_app)

        # Resolve containers for metrics table
        if target_app:
            c_rows = conn.execute(
                "SELECT DISTINCT container FROM metrics WHERE container = ? OR container LIKE ? ORDER BY container",
                (target_app, f"{target_app}-%")
            ).fetchall()
            containers = [r["container"] for r in c_rows]
            if not containers:
                state = load_app_state(target_app)
                active_cont = state.get("container") or f"{target_app}-blue"
                containers = [active_cont]
        else:
            c_rows = conn.execute("SELECT DISTINCT container FROM metrics ORDER BY container").fetchall()
            containers = [r["container"] for r in c_rows]

        if not containers:
            print("No historical metrics recorded yet. Ensure 'bover-metrics.timer' is active.")
            return

        headers = ["CONTAINER", "WINDOW", "CPU (AVG / PEAK)", "MEMORY (AVG / PEAK)"]
        table_rows = []

        for cont in containers:
            for label, duration in windows:
                if duration == 0:
                    q = "SELECT cpu_pct, mem_bytes FROM metrics WHERE container = ? ORDER BY timestamp DESC LIMIT 1"
                    row = conn.execute(q, (cont,)).fetchone()
                    if row:
                        cpu_fmt = f"{row['cpu_pct']:.1f}%"
                        mem_fmt = format_bytes(row['mem_bytes'])
                    else:
                        cpu_fmt = "n/a"
                        mem_fmt = "n/a"
                else:
                    since = now - duration
                    q = """
                        SELECT
                            AVG(cpu_pct) as avg_cpu,
                            MAX(cpu_pct) as max_cpu,
                            AVG(mem_bytes) as avg_mem,
                            MAX(mem_bytes) as max_mem
                        FROM metrics
                        WHERE container = ? AND timestamp >= ?
                    """
                    row = conn.execute(q, (cont, since)).fetchone()
                    if row and row["avg_cpu"] is not None:
                        cpu_fmt = f"{row['avg_cpu']:.1f}% / {row['max_cpu']:.1f}%"
                        mem_fmt = f"{format_bytes(row['avg_mem'])} / {format_bytes(row['max_mem'])}"
                    else:
                        cpu_fmt = "-"
                        mem_fmt = "-"

                table_rows.append([cont, label, cpu_fmt, mem_fmt])

        hdr_line, sep_line, row_lines = format_table(headers, table_rows)
        w = max(len(hdr_line), 74)
        print("")
        print("=" * w)
        print(" BOVER :: Aggregated Docker Resource Usage")
        print("=" * w)
        print(hdr_line)
        print(sep_line)
        for r in row_lines:
            print(r)
        print("=" * w)
        print("")


# ==============================================================================
# 5.B DISK USAGE & DIFFERENTIAL TRACKING ENGINE
# ==============================================================================

def measure_app_disk(name):
    """Accurately measure disk usage for an app (code, data/db, images)."""
    app_dir = APPS_DIR / name
    if not app_dir.exists():
        return 0, 0, 0, 0

    # 1. Total directory size
    total_dir_bytes = measure_dir_bytes(app_dir)

    # 2. Data directory / SQLite DB size
    data_bytes = 0
    data_dir = app_dir / "data"
    if data_dir.exists():
        data_bytes = measure_dir_bytes(data_dir)
    else:
        for db_file in app_dir.glob("*.db*"):
            try:
                data_bytes += db_file.stat().st_size
            except Exception:
                pass

    # 3. Code size
    code_bytes = max(0, total_dir_bytes - data_bytes)

    # 4. Docker images size for this app
    image_bytes = 0
    cached_docker = get_docker_cached_data()
    images_api = cached_docker.get("images") if isinstance(cached_docker, dict) else docker_api_get("/images/json")
    if isinstance(images_api, list):
        prefix_colon = f"{name}:"
        prefix_slash = f"{name}/"
        for img in images_api:
            tags = img.get("RepoTags") or []
            if any(isinstance(t, str) and (t.startswith(prefix_colon) or t.startswith(prefix_slash) or t == name) for t in tags):
                image_bytes += int(img.get("Size") or 0)
    else:
        try:
            out = run_cmd(f"docker images --filter reference='{name}*' --format '{{{{.ID}}}}'", capture=True)
            seen_imgs = set()
            for img_id in out.split():
                if img_id not in seen_imgs:
                    seen_imgs.add(img_id)
                    sz_str = run_cmd(f"docker image inspect {img_id} --format '{{{{.Size}}}}'", capture=True)
                    if sz_str and sz_str.isdigit():
                        image_bytes += int(sz_str)
        except Exception:
            pass

    grand_total = total_dir_bytes + image_bytes
    return grand_total, data_bytes, code_bytes, image_bytes


def sample_disk_metrics(now):
    """Sample disk usage for all configured apps and persist to SQLite."""
    configs = get_all_app_configs()
    if not configs:
        return
    rows = []
    for cfg_path in configs:
        try:
            with open(cfg_path) as f:
                d = json.load(f)
            app_name = d.get("name")
            if app_name:
                tot, data, code, img = measure_app_disk(app_name)
                rows.append((now, app_name, tot, data, code, img))
        except Exception:
            pass
    if rows:
        with get_db() as conn:
            conn.executemany("INSERT INTO app_disk_metrics VALUES (?, ?, ?, ?, ?, ?)", rows)
            cutoff = now - (90 * 86400)
            conn.execute("DELETE FROM app_disk_metrics WHERE timestamp < ?", (cutoff,))


def show_disk(target_app=None):
    """
    Display comprehensive disk consumption and historical differential tracking:
    - Current total, data/db, code/git, and docker image sizes.
    - Historical differentials (vs 1h, vs 24h, vs 7d, vs 30d).
    - Storage velocity and growth trend.
    - Host filesystem capacity and headroom.
    Fits neatly within standard 76-80 column terminals.
    """
    init_db()
    now = int(time.time())

    configs = get_all_app_configs()
    app_names = []
    if target_app:
        app_names = [target_app]
    elif configs:
        for c in configs:
            try:
                with open(c) as f:
                    app_names.append(json.load(f)["name"])
            except Exception:
                pass

    if not app_names:
        print("No applications configured yet. Use 'lamo add' to deploy your first app.")
        return

    # Check host root filesystem capacity
    host_disk_info = run_cmd("df -h / | awk 'NR==2 {print $3\" used / \"$2\" total (\"$5\" used, \"$4\" free)\"}'", capture=True)

    headers = ["APP", "TOTAL", "DATA/DB", "CODE", "IMAGES", "Δ 24h", "GROWTH TREND"]
    table_rows = []
    deep_breakdown = None

    with get_db() as conn:
        conn.row_factory = sqlite3.Row

        for app in app_names:
            tot_cur, data_cur, code_cur, img_cur = measure_app_disk(app)

            # Record point-in-time sample
            conn.execute(
                "INSERT INTO app_disk_metrics VALUES (?, ?, ?, ?, ?, ?)",
                (now, app, tot_cur, data_cur, code_cur, img_cur)
            )

            # Query historical points: 1h, 24h, 7d, 30d
            q = "SELECT total_bytes FROM app_disk_metrics WHERE app = ? AND timestamp <= ? ORDER BY timestamp DESC LIMIT 1"
            row_1h = conn.execute(q, (app, now - 3600)).fetchone()
            row_24h = conn.execute(q, (app, now - 86400)).fetchone()
            row_7d = conn.execute(q, (app, now - 7 * 86400)).fetchone()
            row_30d = conn.execute(q, (app, now - 30 * 86400)).fetchone()

            def calc_delta(row):
                if not row:
                    return "-"
                diff = tot_cur - row["total_bytes"]
                sign = "+" if diff > 0 else ""
                return f"{sign}{format_bytes(diff)}"

            d_24h_str = calc_delta(row_24h)
            d_7d_str = calc_delta(row_7d)

            def format_rate_str(diff_mb, suffix="/d"):
                abs_mb = abs(diff_mb)
                sign = "+" if diff_mb > 0 else "-"
                if abs_mb >= 1024:
                    return f"{sign}{abs_mb / 1024:.1f} GB{suffix}"
                return f"{sign}{abs_mb:.0f} MB{suffix}"

            trend_str = "stable"
            if row_24h:
                diff_24h = tot_cur - row_24h["total_bytes"]
                diff_mb = diff_24h / (1024 * 1024)
                if abs(diff_mb) >= 5.0:
                    trend_str = format_rate_str(diff_mb, "/d")
                else:
                    trend_str = "stable"
            elif row_1h:
                diff_1h = tot_cur - row_1h["total_bytes"]
                diff_1h_mb = diff_1h / (1024 * 1024)
                if abs(diff_1h_mb) >= 5.0:
                    trend_str = format_rate_str(diff_1h_mb, " (1h)")
                else:
                    trend_str = "stable"

            table_rows.append([
                app,
                format_bytes(tot_cur),
                format_bytes(data_cur),
                format_bytes(code_cur),
                format_bytes(img_cur),
                d_24h_str,
                trend_str
            ])

            # If user queried a specific app, prepare deep breakdown
            if target_app:
                d_1h_str = calc_delta(row_1h)
                d_30d_str = calc_delta(row_30d)
                deep_breakdown = (
                    f"\n  Disk Breakdown for '{app}':\n"
                    f"  • Total Footprint:   {format_bytes(tot_cur)}\n"
                    f"  • Data / Database:   {format_bytes(data_cur)} (persistent storage & SQLite)\n"
                    f"  • Code / Repository: {format_bytes(code_cur)} (Git repository & build assets)\n"
                    f"  • Docker Images:     {format_bytes(img_cur)} (retained version images)\n\n"
                    f"  Differentials Over Time:\n"
                    f"  • vs 1 hour ago:     {d_1h_str}\n"
                    f"  • vs 24 hours ago:   {d_24h_str}\n"
                    f"  • vs 7 days ago:     {d_7d_str}\n"
                    f"  • vs 30 days ago:    {d_30d_str}\n"
                    f"  • Current Velocity:  {trend_str}\n"
                )

    hdr_line, sep_line, row_lines = format_table(headers, table_rows)
    w = max(len(hdr_line), 74)
    print("")
    print("=" * w)
    print(" BOVER :: Application Disk Footprint & Differential Storage")
    print("=" * w)
    print(hdr_line)
    print(sep_line)
    for r in row_lines:
        print(r)
    print(sep_line)
    print(f" Host Storage (/) :: {host_disk_info}")
    print("=" * w)
    if deep_breakdown:
        print(deep_breakdown)
    print("")


# ==============================================================================
# 5.C CADDY VISITS & HTTP TRAFFIC ANALYTICS
# ==============================================================================

def parse_caddy_access_log(log_path, since_ts=0):
    """Parse a Caddy JSON access log file and aggregate traffic statistics."""
    if not log_path.exists():
        return None

    total_reqs = 0
    status_counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    unique_ips = set()
    bytes_sent = 0
    methods = {}
    top_paths = {}

    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    entry = json.loads(line)
                except Exception:
                    continue

                ts = entry.get("ts", 0)
                if ts < since_ts:
                    continue

                total_reqs += 1
                status = entry.get("status", 200)
                if 200 <= status < 300:
                    status_counts["2xx"] += 1
                elif 300 <= status < 400:
                    status_counts["3xx"] += 1
                elif 400 <= status < 500:
                    status_counts["4xx"] += 1
                elif status >= 500:
                    status_counts["5xx"] += 1

                req = entry.get("request", {})
                ip = req.get("remote_ip", "").split(":")[0]
                if ip:
                    unique_ips.add(ip)

                method = req.get("method", "GET")
                methods[method] = methods.get(method, 0) + 1

                uri = req.get("uri", "/")
                path = uri.split("?")[0]
                top_paths[path] = top_paths.get(path, 0) + 1

                size = entry.get("size", 0) or entry.get("bytes_read", 0) or 0
                bytes_sent += size
    except Exception:
        return None

    return {
        "total": total_reqs,
        "status": status_counts,
        "unique_ips": len(unique_ips),
        "bytes_sent": bytes_sent,
        "methods": methods,
        "top_paths": top_paths,
    }


def sample_visits_metrics(now):
    """Sample visits from Caddy access logs into SQLite."""
    logs_dir = GATEWAY_DIR / "logs"
    if not logs_dir.exists():
        return

    rows = []
    for log_file in logs_dir.glob("*-access.log"):
        app_name = log_file.name.replace("-access.log", "")
        res = parse_caddy_access_log(log_file, since_ts=now - 86400)
        if res:
            rows.append((
                now,
                app_name,
                res["total"],
                res["status"]["2xx"],
                res["status"]["3xx"],
                res["status"]["4xx"],
                res["status"]["5xx"],
                res["unique_ips"],
                res["bytes_sent"],
            ))
    if rows:
        with get_db() as conn:
            conn.executemany("INSERT INTO app_visits VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
            cutoff = now - (90 * 86400)
            conn.execute("DELETE FROM app_visits WHERE timestamp < ?", (cutoff,))


def show_visits(target_app=None):
    """
    Display Caddy HTTP visits, traffic volume, unique visitors, and response code analytics.
    """
    now = int(time.time())
    logs_dir = GATEWAY_DIR / "logs"

    configs = get_all_app_configs()
    apps_info = []
    for c in configs:
        try:
            with open(c) as f:
                d = json.load(f)
                apps_info.append(d)
        except Exception:
            pass

    if target_app:
        apps_info = [a for a in apps_info if a.get("name") == target_app]

    if not apps_info:
        print("No applications configured yet.")
        return

    headers = ["APP", "DOMAIN", "24H", "TODAY", "ALL-TIME", "UNIQ", "HTTP 2xx/4xx/5xx"]
    table_rows = []
    traffic_details = None

    today_start = int(time.time()) - (int(time.time()) % 86400)

    for a in apps_info:
        app_name = a.get("name")
        domain = a.get("domain", "-")
        log_file = logs_dir / f"{app_name}-access.log"

        if not log_file.exists():
            table_rows.append([app_name, domain, "0", "0", "0", "0", "No traffic"])
            continue

        res_all = parse_caddy_access_log(log_file, since_ts=0)
        res_24h = parse_caddy_access_log(log_file, since_ts=now - 86400)
        res_today = parse_caddy_access_log(log_file, since_ts=today_start)

        tot_all = f"{res_all['total']:,}" if res_all else "0"
        tot_24h = f"{res_24h['total']:,}" if res_24h else "0"
        tot_today = f"{res_today['total']:,}" if res_today else "0"
        uniq_24h = f"{res_24h['unique_ips']:,}" if res_24h else "0"

        status_str = "-"
        if res_24h and res_24h["total"] > 0:
            t = res_24h["total"]
            p2 = (res_24h["status"]["2xx"] / t) * 100
            p4 = (res_24h["status"]["4xx"] / t) * 100
            p5 = (res_24h["status"]["5xx"] / t) * 100
            status_str = f"{p2:.0f}% / {p4:.0f}% / {p5:.0f}%"

        table_rows.append([app_name, domain, tot_24h, tot_today, tot_all, uniq_24h, status_str])

        if target_app and res_24h:
            details_lines = [
                f"\n  Traffic Details for '{app_name}' (Last 24 Hours):",
                f"  • Bandwidth Served: {format_bytes(res_24h['bytes_sent'])}",
                f"  • Response Codes:   2xx: {res_24h['status']['2xx']} | 3xx: {res_24h['status']['3xx']} | 4xx: {res_24h['status']['4xx']} | 5xx: {res_24h['status']['5xx']}",
            ]
            if res_24h.get("top_paths"):
                details_lines.append("  • Top Requested Endpoints:")
                sorted_paths = sorted(res_24h["top_paths"].items(), key=lambda x: x[1], reverse=True)[:5]
                for path, count in sorted_paths:
                    details_lines.append(f"    - {path:<30} ({count:,} hits)")
            traffic_details = "\n".join(details_lines)

    hdr_line, sep_line, row_lines = format_table(headers, table_rows)
    w = max(len(hdr_line), 74)
    print("")
    print("=" * w)
    print(" BOVER :: Caddy HTTP Traffic Analytics & Visit Counter")
    print("=" * w)
    print(hdr_line)
    print(sep_line)
    for r in row_lines:
        print(r)
    print(sep_line)
    print(" Caddy Log: /opt/apps/gateway/logs/<app>-access.log")
    print("=" * w)
    if traffic_details:
        print(traffic_details)
    print("")
    print("")


# ==============================================================================
# 6. APP REGISTRATION, WIZARD, SYNC & LISTING
# ==============================================================================

def detect_project_type_and_port(app_dir):
    """Auto-detect runtime type, internal port, and healthcheck path from repo files."""
    detected_type = "Docker"
    detected_port = 8080
    detected_path = "/"

    # 1. Check docker-compose.yml
    for cfile in ["docker-compose.yml", "docker-compose.yaml", "compose.yaml"]:
        cp = app_dir / cfile
        if cp.exists():
            detected_type = "Docker Compose"
            try:
                content = cp.read_text()
                m = re.search(r'["\']?(\d+):(\d+)["\']?', content)
                if m:
                    detected_port = int(m.group(2))
                else:
                    m2 = re.search(r'expose:\s*\n\s*-\s*["\']?(\d+)["\']?', content)
                    if m2:
                        detected_port = int(m2.group(1))
            except Exception:
                pass
            return detected_type, detected_port, detected_path

    # 2. Check Dockerfile
    df = app_dir / "Dockerfile"
    if df.exists():
        detected_type = "Dockerfile"
        try:
            content = df.read_text()
            m = re.search(r'(?i)^EXPOSE\s+(\d+)', content, re.MULTILINE)
            if m:
                detected_port = int(m.group(1))
        except Exception:
            pass

    # 3. Check language markers
    if (app_dir / "go.mod").exists():
        detected_type = "Go"
        detected_port = detected_port if detected_port != 8080 else 8080
        detected_path = "/healthz" if (app_dir / "internal").exists() else "/"
    elif (app_dir / "package.json").exists():
        detected_type = "Node.js"
        detected_port = detected_port if detected_port != 8080 else 3000
    elif (app_dir / "pyproject.toml").exists() or (app_dir / "requirements.txt").exists():
        detected_type = "Python"
        detected_port = detected_port if detected_port != 8080 else 8000
    elif (app_dir / "Cargo.toml").exists():
        detected_type = "Rust"
        detected_port = detected_port if detected_port != 8080 else 8080

    return detected_type, detected_port, detected_path


def setup_deploy_key_for_repo(repo_url, app_name):
    """Ensure an ed25519 deploy key exists for this repo and verify GitHub access."""
    ssh_dir = APPS_DIR / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    try:
        ssh_dir.chmod(0o700)
    except Exception:
        pass

    key_path = ssh_dir / f"id_deploy_{app_name}"
    pub_path = ssh_dir / f"id_deploy_{app_name}.pub"
    ssh_config = ssh_dir / "config"

    # 1. Generate key if not present
    node_host = (run_cmd("hostname", capture=True) or "server").strip()
    if not key_path.exists():
        print(f"==> Generating dedicated ed25519 deploy key for '{app_name}'...")
        run_cmd(f'ssh-keygen -t ed25519 -N "" -f {key_path} -C "deploy@{node_host}-{app_name}"')
        key_path.chmod(0o600)
        pub_path.chmod(0o644)

    # 2. Configure SSH alias in /opt/apps/.ssh/config
    alias_host = f"github.com-{app_name}"
    alias_block = f"""
Host {alias_host}
    HostName github.com
    User git
    IdentityFile {key_path}
    IdentitiesOnly yes
"""
    existing_cfg = ssh_config.read_text() if ssh_config.exists() else ""
    if alias_host not in existing_cfg:
        with open(ssh_config, "a") as f:
            f.write(alias_block)
        ssh_config.chmod(0o600)

    # Also add known_hosts for github.com if missing
    known_hosts = ssh_dir / "known_hosts"
    if not known_hosts.exists() or "github.com" not in known_hosts.read_text():
        run_cmd(f"ssh-keyscan -H github.com >> {known_hosts} 2>/dev/null || true")

    # 3. Rewrite repository URL to use host alias if it points to github.com
    adjusted_url = repo_url
    if "github.com:" in repo_url:
        adjusted_url = repo_url.replace("github.com:", f"{alias_host}:")
    elif "github.com/" in repo_url and repo_url.startswith("https://"):
        clean_path = repo_url.replace("https://github.com/", "")
        adjusted_url = f"git@{alias_host}:{clean_path}"

    # 4. Test connectivity to remote
    print(f"==> Verifying repository access with GitHub...")
    res = subprocess.run(
        f"git ls-remote {adjusted_url} HEAD",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if res.returncode != 0:
        pub_key = pub_path.read_text().strip() if pub_path.exists() else "Key file missing"
        repo_match = re.search(r'[:/]([^/]+/[^/]+?)(?:\.git)?$', repo_url)
        gh_path = repo_match.group(1) if repo_match else app_name
        settings_url = f"https://github.com/{gh_path}/settings/keys"

        print("")
        print("=" * 80)
        print(" 🔑 GITHUB DEPLOY KEY REQUIRED")
        print("=" * 80)
        print(f" GitHub rejected access for repository: {repo_url}")
        print(" (You need to register this deploy key in your repository settings).")
        print("")
        print(" Public Deploy Key:")
        print("-" * 80)
        print(pub_key)
        print("-" * 80)
        print("")
        print(" NEXT STEPS:")
        print(f" 1. Open:  {settings_url}")
        print(" 2. Click: 'Add deploy key'")
        print(f" 3. Title: {node_host}-{app_name}")
        print(" 4. Key:   Paste the public key above (leave 'Allow write access' unchecked)")
        print(f" 5. Re-run command once added: lamo add {repo_url}")
        print("=" * 80)
        print("")
        sys.exit(1)

    print("==> GitHub Deploy Key verified successfully!")
    return adjusted_url


def wizard_add_app(repo_url):
    """Interactive wizard to configure and deploy a new app from a Git repository."""
    raw_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "").lower()
    app_name = re.sub(r'[^a-z0-9\-]', '', raw_name)
    if not app_name:
        app_name = "myapp"

    print("")
    print("=" * 80)
    print(f" BOVER APP WIZARD :: Configuring '{app_name}'")
    print(f" Repository: {repo_url}")
    print("=" * 80)

    # Setup deploy key and verify access
    adjusted_repo = setup_deploy_key_for_repo(repo_url, app_name)

    app_dir = APPS_DIR / app_name
    app_dir.mkdir(parents=True, exist_ok=True)

    # Clone repository
    git_dir = app_dir / ".git"
    if not git_dir.exists():
        print(f"==> Cloning repository into {app_dir}...")
        try:
            run_cmd(f"git clone {adjusted_repo} {app_dir}")
        except Exception as e:
            print(f"ERROR: git clone failed: {e}")
            sys.exit(1)
    else:
        print(f"==> Repository already cloned at {app_dir}. Pulling latest changes...")
        run_cmd("git pull", cwd=app_dir)

    # Detect project type
    proj_type, def_port, def_health = detect_project_type_and_port(app_dir)
    print("")
    print(f" 🔍 Detected stack:    {proj_type}")
    print(f" 🔍 Recommended port:  {def_port}")
    print("")

    # Interactive prompts
    try:
        domain_input = input(f"Enter public domain/subdomain for '{app_name}' (e.g. {app_name}.example.com): ").strip()
        while not domain_input:
            domain_input = input("Domain is required: ").strip()

        port_str = input(f"Internal container port [{def_port}]: ").strip()
        port = int(port_str) if port_str else def_port

        health_str = input(f"Healthcheck path [{def_health}]: ").strip()
        healthcheck = health_str if health_str else def_health

        auto_str = input("Enable Continuous Deployment on git push? [Y/n]: ").strip().lower()
        auto_deploy = False if auto_str == "n" else True

        keep_str = input("Number of version images to retain for rollback [3]: ").strip()
        keep_versions = int(keep_str) if keep_str else 3

        cpu_str = input("Maximum CPU limit [0.5]: ").strip()
        cpu = float(cpu_str) if cpu_str else 0.5

        mem_str = input("Maximum RAM limit [512m]: ").strip()
        memory = mem_str if mem_str else "512m"
    except (KeyboardInterrupt, EOFError):
        print("\nWizard aborted by user.")
        sys.exit(1)

    print("")
    print(f"==> Saving configuration and launching zero-downtime deployment...")
    add_app(
        name=app_name,
        domain=domain_input,
        port=port,
        repo=adjusted_repo,
        branch="master",
        healthcheck=healthcheck,
        auto_deploy=auto_deploy,
        keep_versions=keep_versions,
        cpu=cpu,
        memory=memory,
    )


def add_app(name: str, domain: str, port: int, repo: Optional[str] = None, branch: str = "master", healthcheck: str = "/", auto_deploy: bool = False, keep_versions: int = 3, cpu: float = 0.5, memory: str = "512m", app_type: str = "auto", redirects: Optional[Union[str, List[str]]] = None, data_dir: Optional[str] = None):
    """Register or update an application configuration with strict validation and resource limits."""
    validate_app_name(name)
    app_dir = APPS_DIR / name
    app_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(app_dir, 0o700)
    except Exception:
        pass

    env_file = app_dir / ".env"
    if not env_file.exists():
        env_file.write_text(f"# App-Specific Environment Variables & Secrets for '{name}'\n# Restricted access: mode 0640\n")
        try:
            os.chmod(env_file, 0o640)
        except Exception:
            pass

    config_file = app_dir / "app.json"
    existing_crons = []
    if config_file.exists():
        try:
            with open(config_file) as f:
                prev_cfg = json.load(f)
                if isinstance(prev_cfg.get("crons"), list):
                    existing_crons = prev_cfg["crons"]
        except Exception:
            pass

    app_data = {
        "name": name,
        "domain": domain,
        "port": int(port),
        "healthcheck": healthcheck,
        "auto_deploy": auto_deploy,
        "keep_versions": int(keep_versions) if keep_versions else 3,
        "cpu": cpu,
        "memory": memory,
    }
    if existing_crons:
        app_data["crons"] = existing_crons
    if app_type and app_type != "auto":
        app_data["type"] = app_type
    if repo:
        app_data["repo"] = repo
        app_data["branch"] = branch
    if redirects:
        if isinstance(redirects, str):
            app_data["redirects"] = [r.strip() for r in redirects.split(",") if r.strip()]
        elif isinstance(redirects, list):
            app_data["redirects"] = [str(r).strip() for r in redirects if str(r).strip()]
    if data_dir:
        app_data["data_dir"] = str(data_dir).strip()

    save_app_config(name, app_data)
    print(f"Configuration saved: {config_file}")

    # Initial deployment
    deploy_app(name, no_pull=False if repo else True)


def sync_all():
    """Synchronize all app.json configs into Caddy routes and verify routing."""
    print("==> Synchronizing 'app.json' services with Caddy...")
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    configs = get_all_app_configs()
    found = 0
    for cfg in configs:
        try:
            with open(cfg) as f:
                data = json.load(f)
            name = data.get("name")
            domain = data.get("domain")
            port = data.get("port")
            state = load_app_state(name)
            target = state.get("container") or f"{name}-blue"

            if name and domain and port:
                caddy_file = CONF_DIR / f"{name}.caddy"
                redirects = data.get("redirects") or data.get("redirect")
                caddy_file.write_text(generate_caddy_rule(name, domain, port, target, redirects=redirects))
                run_cmd(f"docker network connect {DOCKER_NETWORK} {target} 2>/dev/null || true")
                print(f"Synchronized: {name} ({domain} -> {target}:{port})")
                found += 1
        except Exception as e:
            print(f"Error processing {cfg}: {e}")

    reload_caddy()
    print(f"==> Synchronization complete ({found} active services).")


def list_apps():
    """List all managed applications, deployment slots, domains, and health status."""
    configs = get_all_app_configs()
    if not configs:
        print("No services configured yet. Use 'lamo add' or create /opt/apps/<name>/app.json.")
        return

    cached_docker = get_docker_cached_data()
    fast_containers = cached_docker.get("containers") if isinstance(cached_docker, dict) else docker_api_get("/containers/json?all=1")
    status_map: Optional[Dict[str, str]] = None
    if isinstance(fast_containers, list):
        status_map = {}
        for c in fast_containers:
            if c.get("State") == "running":
                st_str = c.get("Status", "running")
                for raw_name in (c.get("Names") or []):
                    clean_name = raw_name.lstrip("/")
                    status_map[clean_name] = st_str

    print("")
    print(f"{'SERVICE':<14} {'DOMAIN':<28} {'SLOT':<8} {'DEPLOYS':<12} {'CONTAINER':<18} {'STATUS'}")
    print("-" * 98)
    for cfg in configs:
        try:
            with open(cfg) as f:
                data = json.load(f)
            name = data.get("name", "")
            domain = data.get("domain", "")
            state = load_app_state(name)
            slot = state.get("active_slot") or "-"
            container = state.get("container") or f"{name}-blue"

            summary = get_deployment_summary(name)
            if summary["total"] > 0:
                fails = summary["failed"]
                fail_str = f" ({fails} fail)" if fails > 0 else ""
                deploy_str = f"{summary['total']}{fail_str}"
            else:
                deploy_str = "-"

            if status_map is not None:
                status = status_map.get(container, "stopped")
            else:
                ps = run_cmd(f"docker ps --filter name={container} --format '{{{{.Status}}}}'", capture=True)
                status = ps if ps else "stopped"
            print(f"{name:<14} {domain:<28} {slot:<8} {deploy_str:<12} {container:<18} {status}")
        except Exception:
            continue
    print("")


def logs_app(name: str, lines: int = 100, follow: bool = False):
    """Tail logs for an app's active container safely without shell expansion."""
    validate_app_name(name)
    state = load_app_state(name)
    container = state.get("container") or f"{name}-blue"
    cmd = ["docker", "logs", "--tail", str(int(lines))]
    if follow:
        cmd.append("-f")
    cmd.append(container)
    subprocess.run(cmd)


# ==============================================================================
# 6.5. AUTOMATED R2/S3 BACKUP ENGINE & NOTIFIER
# ==============================================================================

S3_CONFIG_FILE = VAULT_DIR / "s3.json"


def load_s3_config() -> Optional[Dict[str, Any]]:
    """Load S3 / Cloudflare R2 backup credentials securely from vault."""
    if not S3_CONFIG_FILE.exists():
        return None
    try:
        with open(S3_CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return None


def configure_s3(account_id: Optional[str] = None, access_key: Optional[str] = None, secret_key: Optional[str] = None, bucket: Optional[str] = None):
    """Interactive or parameter-based secure Cloudflare R2 / S3 credentials configuration."""
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(VAULT_DIR, 0o700)
    except Exception:
        pass

    existing = load_s3_config() or {}

    if not account_id:
        curr = existing.get("account_id", "")
        prompt = f"Cloudflare Account ID [{curr}]: " if curr else "Cloudflare Account ID: "
        try:
            account_id = input(prompt).strip() or curr
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    if not access_key:
        curr = existing.get("access_key", "")
        prompt = f"R2 Access Key ID [{curr}]: " if curr else "R2 Access Key ID: "
        try:
            access_key = input(prompt).strip() or curr
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    if not secret_key:
        curr = existing.get("secret_key", "")
        prompt = "R2 Secret Access Key [hidden/unchanged]: " if curr else "R2 Secret Access Key (hidden): "
        try:
            secret_key = getpass.getpass(prompt).strip() or curr
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    if not bucket:
        curr = existing.get("bucket", "")
        prompt = f"R2 Bucket Name [{curr}]: " if curr else "R2 Bucket Name: "
        try:
            bucket = input(prompt).strip() or curr
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(1)

    if not all([account_id, access_key, secret_key, bucket]):
        print("ERROR: All 4 fields (Account ID, Access Key, Secret Key, Bucket) are required.")
        sys.exit(1)

    s3_data = {
        "account_id": account_id,
        "access_key": access_key,
        "secret_key": secret_key,
        "bucket": bucket,
        "configured_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(S3_CONFIG_FILE, "w") as f:
        json.dump(s3_data, f, indent=2)
    try:
        os.chmod(S3_CONFIG_FILE, 0o600)
    except Exception:
        pass
    print("✓ Cloudflare R2 backup credentials saved securely in vault (/opt/apps/.vault/s3.json mode 0600).")


def s3_sigv4_put(endpoint_url: str, bucket: str, key: str, data: bytes, access_key: str, secret_key: str, region: str = "auto") -> Tuple[bool, str]:
    """
    Upload payload to S3 / Cloudflare R2 using AWS Signature Version 4.
    Self-contained pure Python implementation with zero third-party pip dependencies.
    """
    clean_endpoint = endpoint_url.strip().rstrip("/")
    # Extract host
    m = re.match(r"^https?://([^/]+)", clean_endpoint)
    if not m:
        return False, f"Invalid S3 endpoint URL: {endpoint_url}"
    host = m.group(1)

    t = datetime.now(timezone.utc)
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    clean_key = key.lstrip("/")
    canonical_uri = f"/{bucket}/{clean_key}"
    full_url = f"{clean_endpoint}{canonical_uri}"

    payload_hash = hashlib.sha256(data).hexdigest()

    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = f"PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign_key(key_bytes, msg):
        return hmac.new(key_bytes, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign_key(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = sign_key(k_date, region)
    k_service = sign_key(k_region, "s3")
    k_signing = sign_key(k_service, "aws4_request")

    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    auth_header = f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        full_url,
        data=data,
        method="PUT",
        headers={
            "Host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": auth_header,
            "Content-Type": "application/gzip",
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            if resp.status in (200, 204):
                return True, "OK"
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return False, f"HTTP {e.code}: {body[:250]}"
    except Exception as e:
        return False, str(e)


def s3_sigv4_get(endpoint_url: str, bucket: str, key: str, access_key: str, secret_key: str, region: str = "auto") -> Tuple[bool, Union[bytes, str]]:
    """
    Download object payload from S3 / Cloudflare R2 using AWS Signature Version 4.
    Self-contained pure Python implementation with zero third-party pip dependencies.
    """
    clean_endpoint = endpoint_url.strip().rstrip("/")
    m = re.match(r"^https?://([^/]+)", clean_endpoint)
    if not m:
        return False, f"Invalid S3 endpoint URL: {endpoint_url}"
    host = m.group(1)

    t = datetime.now(timezone.utc)
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    clean_key = key.lstrip("/")
    canonical_uri = f"/{bucket}/{clean_key}"
    full_url = f"{clean_endpoint}{canonical_uri}"

    payload_hash = hashlib.sha256(b"").hexdigest()

    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = f"GET\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign_key(key_bytes, msg):
        return hmac.new(key_bytes, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign_key(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = sign_key(k_date, region)
    k_service = sign_key(k_region, "s3")
    k_signing = sign_key(k_service, "aws4_request")

    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    auth_header = f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        full_url,
        method="GET",
        headers={
            "Host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": auth_header,
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            if resp.status in (200, 206):
                return True, resp.read()
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return False, f"HTTP {e.code}: {body[:250]}"
    except Exception as e:
        return False, str(e)


def s3_sigv4_list(endpoint_url: str, bucket: str, prefix: str = "", access_key: str = "", secret_key: str = "", region: str = "auto") -> Tuple[bool, Union[List[Dict[str, Any]], str]]:
    """
    List objects in S3 / Cloudflare R2 bucket using AWS Signature Version 4 and ListObjectsV2.
    Returns list of dicts with keys: 'key', 'size', 'last_modified'.
    """
    import urllib.parse
    import xml.etree.ElementTree as ET

    clean_endpoint = endpoint_url.strip().rstrip("/")
    m = re.match(r"^https?://([^/]+)", clean_endpoint)
    if not m:
        return False, f"Invalid S3 endpoint URL: {endpoint_url}"
    host = m.group(1)

    t = datetime.now(timezone.utc)
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    canonical_uri = f"/{bucket}"
    params = [("list-type", "2")]
    if prefix:
        params.append(("prefix", prefix))
    params.sort(key=lambda x: x[0])
    canonical_qs = "&".join(f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}" for k, v in params)

    full_url = f"{clean_endpoint}{canonical_uri}?{canonical_qs}"
    payload_hash = hashlib.sha256(b"").hexdigest()

    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = f"GET\n{canonical_uri}\n{canonical_qs}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"

    def sign_key(key_bytes, msg):
        return hmac.new(key_bytes, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = sign_key(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = sign_key(k_date, region)
    k_service = sign_key(k_region, "s3")
    k_signing = sign_key(k_service, "aws4_request")

    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    auth_header = f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"

    import urllib.request
    import urllib.error
    req = urllib.request.Request(
        full_url,
        method="GET",
        headers={
            "Host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": auth_header,
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
            root = ET.fromstring(data)
            objects = []
            for elem in root.iter():
                if elem.tag.endswith("Contents"):
                    key_val = ""
                    size_val = 0
                    mod_val = ""
                    for child in elem:
                        if child.tag.endswith("Key") and child.text:
                            key_val = child.text
                        elif child.tag.endswith("Size") and child.text:
                            try:
                                size_val = int(child.text)
                            except Exception:
                                size_val = 0
                        elif child.tag.endswith("LastModified") and child.text:
                            mod_val = child.text
                    if key_val:
                        objects.append({
                            "key": key_val,
                            "size": size_val,
                            "last_modified": mod_val,
                        })
            objects.sort(key=lambda x: x.get("last_modified", "") or x.get("key", ""), reverse=True)
            return True, objects
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return False, f"HTTP {e.code}: {body[:250]}"
    except Exception as e:
        return False, str(e)


def inspect_sqlite_database(db_path: Path) -> Dict[str, Any]:
    """
    Run deep integrity checks and schema verification on a SQLite database file.
    Returns structured inspection dict with integrity status, schema, tables, and row counts.
    """
    res = {
        "filename": db_path.name,
        "size_bytes": db_path.stat().st_size if db_path.exists() else 0,
        "integrity_check": "unknown",
        "quick_check": "unknown",
        "foreign_key_check": "unknown",
        "tables": {},
        "total_records": 0,
        "total_tables": 0,
        "total_indexes": 0,
        "valid": False,
        "error": None,
    }
    if not db_path.exists() or db_path.stat().st_size == 0:
        res["integrity_check"] = "empty_or_missing"
        res["error"] = "Database file is empty (0 bytes) or does not exist."
        return res

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
        cursor = conn.cursor()

        # 1. PRAGMA integrity_check
        cursor.execute("PRAGMA integrity_check;")
        rows = cursor.fetchall()
        if rows and len(rows) == 1 and rows[0][0] == "ok":
            res["integrity_check"] = "ok"
        else:
            res["integrity_check"] = "; ".join(str(r[0]) for r in rows)
            res["error"] = f"Integrity check failed: {res['integrity_check']}"

        # 2. PRAGMA quick_check
        cursor.execute("PRAGMA quick_check;")
        q_rows = cursor.fetchall()
        res["quick_check"] = "ok" if (q_rows and q_rows[0][0] == "ok") else "failed"

        # 3. PRAGMA foreign_key_check
        cursor.execute("PRAGMA foreign_key_check;")
        fk_rows = cursor.fetchall()
        res["foreign_key_check"] = "ok" if not fk_rows else f"{len(fk_rows)} violations"

        # 4. Tables and row counts
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';")
        tables = [r[0] for r in cursor.fetchall()]
        res["total_tables"] = len(tables)

        cursor.execute("SELECT count(*) FROM sqlite_master WHERE type='index';")
        res["total_indexes"] = cursor.fetchone()[0]

        total_rows = 0
        table_counts = {}
        for tbl in tables:
            try:
                escaped_tbl = f'"{tbl}"'
                cursor.execute(f"SELECT COUNT(*) FROM {escaped_tbl}")
                cnt = cursor.fetchone()[0]
                table_counts[tbl] = cnt
                total_rows += cnt
            except Exception as e:
                table_counts[tbl] = f"error: {e}"

        res["tables"] = table_counts
        res["total_records"] = total_rows
        res["valid"] = (res["integrity_check"] == "ok")
        conn.close()
    except Exception as e:
        res["error"] = str(e)
        res["integrity_check"] = "exception"

    return res


def verify_backup_archive(tar_path: Path, app_name: Optional[str] = None, source_label: str = "") -> Tuple[bool, Dict[str, Any]]:
    """
    Extract a backup tar.gz archive in a sandbox temp directory, inspect its metadata,
    configuration, secrets, and run deep SQLite PRAGMA integrity checks on all database files.
    """
    import tempfile
    import tarfile

    if not tar_path.exists():
        return False, {"error": f"Backup file '{tar_path}' does not exist."}

    archive_size = tar_path.stat().st_size
    archive_sha256 = hashlib.sha256(tar_path.read_bytes()).hexdigest()

    temp_dir = Path(tempfile.mkdtemp(prefix="bover_verify_"))
    try:
        try:
            with tarfile.open(tar_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if ".." in member.name or member.name.startswith("/"):
                        raise ValueError(f"Dangerous path in archive member: {member.name}")
                tar.extractall(path=temp_dir)
        except Exception as e:
            return False, {"error": f"Archive extraction failed (corrupted gzip or invalid tar): {e}"}

        # 1. Metadata check
        meta_file = temp_dir / "backup-metadata.json"
        metadata = {}
        if meta_file.exists():
            try:
                metadata = json.loads(meta_file.read_text())
            except Exception:
                pass

        # 2. App config & secrets check
        app_json = temp_dir / "app.json"
        app_json_valid = False
        app_json_data = {}
        if app_json.exists():
            try:
                app_json_data = json.loads(app_json.read_text())
                app_json_valid = bool(app_json_data.get("name"))
            except Exception:
                pass

        env_file = temp_dir / ".env"
        env_vars_count = 0
        if env_file.exists():
            try:
                env_vars_count = len([line for line in env_file.read_text().splitlines() if line.strip() and not line.strip().startswith("#")])
            except Exception:
                pass

        # 3. Persistent data & database verification
        data_dir = temp_dir / "data"
        db_reports = []
        non_db_files = []
        if data_dir.exists():
            for item in data_dir.rglob("*"):
                if item.is_file():
                    if item.suffix in (".db", ".sqlite", ".sqlite3"):
                        report = inspect_sqlite_database(item)
                        db_reports.append(report)
                    else:
                        non_db_files.append({
                            "name": item.relative_to(data_dir).as_posix(),
                            "size": item.stat().st_size,
                        })

        all_dbs_ok = True
        if db_reports:
            for rep in db_reports:
                if not rep.get("valid"):
                    all_dbs_ok = False

        is_valid = bool(app_json_valid and all_dbs_ok)
        result = {
            "valid": is_valid,
            "archive_size": archive_size,
            "archive_sha256": archive_sha256,
            "source_label": source_label or tar_path.name,
            "metadata": metadata,
            "app_json_valid": app_json_valid,
            "app_json_data": app_json_data,
            "env_vars_count": env_vars_count,
            "db_reports": db_reports,
            "non_db_files": non_db_files,
        }
        return is_valid, result
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def cmd_backup_verify(app_name: str, key: Optional[str] = None, file_path: Optional[str] = None) -> bool:
    """Download latest backup from Cloudflare R2 (or inspect specific file/key) and verify integrity."""
    validate_app_name(app_name)
    s3_cfg = load_s3_config()

    tar_to_verify = None
    temp_dir_to_clean = None
    source_label = ""

    if file_path:
        tar_to_verify = Path(file_path)
        source_label = f"Local file: {tar_to_verify}"
        if not tar_to_verify.exists():
            print(f"ERROR: Specified backup file '{file_path}' does not exist.")
            return False
    else:
        if not s3_cfg:
            print("ERROR: S3 / Cloudflare R2 credentials not configured. Run './lamo app backup config' first.")
            return False

        endpoint = s3_cfg.get("endpoint_url") or f"https://{s3_cfg['account_id']}.r2.cloudflarestorage.com"
        target_key = key
        if not target_key:
            print(f"==> Querying Cloudflare R2 for latest backup of '{app_name}'...")
            ok, objs = s3_sigv4_list(
                endpoint_url=endpoint,
                bucket=s3_cfg["bucket"],
                prefix=f"{app_name}/",
                access_key=s3_cfg["access_key"],
                secret_key=s3_cfg["secret_key"]
            )
            if not ok or not isinstance(objs, list) or not objs:
                print(f"ERROR: No backups found in Cloudflare R2 for '{app_name}'. Details: {objs}")
                return False
            target_key = objs[0]["key"]

        print(f"==> Downloading backup archive from R2: r2://{s3_cfg['bucket']}/{target_key}...")
        ok, payload_or_err = s3_sigv4_get(
            endpoint_url=endpoint,
            bucket=s3_cfg["bucket"],
            key=target_key,
            access_key=s3_cfg["access_key"],
            secret_key=s3_cfg["secret_key"]
        )
        if not ok or not isinstance(payload_or_err, bytes):
            print(f"ERROR: Failed to download backup archive from Cloudflare R2: {payload_or_err}")
            return False

        temp_dir_to_clean = Path(tempfile.mkdtemp(prefix=f"bover_verify_dl_{app_name}_"))
        tar_to_verify = temp_dir_to_clean / Path(target_key).name
        tar_to_verify.write_bytes(payload_or_err)
        source_label = f"r2://{s3_cfg['bucket']}/{target_key}"

    try:
        ok, res = verify_backup_archive(tar_to_verify, app_name=app_name, source_label=source_label)
        meta = res.get("metadata", {})
        created_at = meta.get("created_at") or "Unknown"
        active_slot = meta.get("active_slot") or "Unknown"
        commit = meta.get("commit") or "Unknown"
        host = meta.get("hostname") or "Unknown"

        print(f"\n{BOLD}{'=' * 82}{RESET}")
        print(f" {GOLD}BOVER :: BACKUP INTEGRITY & DISASTER RECOVERY VERIFICATION{RESET}")
        print(f"{BOLD}{'=' * 82}{RESET}")
        print(f" App Target:    {BOLD}{app_name}{RESET}")
        print(f" Archive:       {source_label}")
        print(f" Archive Size:  {format_bytes(res.get('archive_size', 0))} (SHA-256: {res.get('archive_sha256', '')[:16]}...)")
        print(f" Origin Node:   {host} (Slot: {active_slot} · Commit: {commit})")
        print(f" Created At:    {created_at}")

        cfg_status = "🟢 Valid JSON" if res.get("app_json_valid") else "🔴 Invalid / Missing"
        env_status = f"🟢 Present ({res.get('env_vars_count', 0)} secrets)" if res.get("env_vars_count", 0) > 0 else "⚪ None"
        print(f" Config & Env:  {cfg_status} | .env: {env_status}")
        print(f"{BOLD}{'-' * 82}{RESET}")

        dbs = res.get("db_reports", [])
        if dbs:
            print(f" {CYAN}DATABASE INTEGRITY VERIFICATION ({len(dbs)} database(s) found):{RESET}")
            for db in dbs:
                filename = db.get("filename", "")
                size_str = format_bytes(db.get("size_bytes", 0))
                integ = db.get("integrity_check", "")
                fk = db.get("foreign_key_check", "")
                tables = db.get("tables", {})
                total_recs = db.get("total_records", 0)

                status_icon = "🟢" if db.get("valid") else "🔴"
                print(f" • {status_icon} {BOLD}{filename}{RESET} ({size_str}):")
                print(f"   - PRAGMA integrity_check:   {'🟢 PASSED (ok)' if integ == 'ok' else f'🔴 FAILED ({integ})'}")
                print(f"   - PRAGMA foreign_key_check: {'🟢 PASSED (0 violations)' if fk == 'ok' else f'⚠️  {fk}'}")
                print(f"   - Total Tables:             {len(tables)} tables ({total_recs:,} records total)")
                if tables:
                    tbl_items = list(tables.items())[:8]
                    tbl_summary = ", ".join(f"{t}: {c}" for t, c in tbl_items)
                    if len(tables) > 8:
                        tbl_summary += f", ... (+{len(tables) - 8} more)"
                    print(f"   - Schema Breakdown:         {tbl_summary}")
        else:
            non_dbs = res.get("non_db_files", [])
            print(f" {CYAN}PERSISTENT STORAGE VERIFICATION (Non-SQLite app):{RESET}")
            print(f" • Persistent files: {len(non_dbs)} file(s) found in data archive")
            for nd in non_dbs[:5]:
                print(f"   - {nd['name']} ({format_bytes(nd['size'])})")

        print(f"{BOLD}{'-' * 82}{RESET}")
        if ok:
            print(f" {GREEN}{BOLD}VERDICT: 🟢 BACKUP IS 100% HEALTHY, VALID & DISASTER RECOVERY READY{RESET}")
            print(f"{BOLD}{'=' * 82}{RESET}\n")
            return True
        else:
            print(f" {RED}{BOLD}VERDICT: 🔴 BACKUP INTEGRITY FAILED OR CORRUPTED!{RESET}")
            if res.get("error"):
                print(f" Error: {res.get('error')}")
            print(f"{BOLD}{'=' * 82}{RESET}\n")
            return False
    finally:
        if temp_dir_to_clean:
            shutil.rmtree(temp_dir_to_clean, ignore_errors=True)


def cmd_backup_list(app_name: Optional[str] = None):
    """List available backups in Cloudflare R2 / S3."""
    s3_cfg = load_s3_config()
    if not s3_cfg:
        print("ERROR: S3 / Cloudflare R2 credentials not configured. Run './lamo app backup config' first.")
        return

    endpoint = s3_cfg.get("endpoint_url") or f"https://{s3_cfg['account_id']}.r2.cloudflarestorage.com"
    prefix = f"{app_name}/" if app_name else ""
    print(f"==> Querying Cloudflare R2 backups bucket '{s3_cfg['bucket']}'...")
    ok, objs = s3_sigv4_list(
        endpoint_url=endpoint,
        bucket=s3_cfg["bucket"],
        prefix=prefix,
        access_key=s3_cfg["access_key"],
        secret_key=s3_cfg["secret_key"]
    )
    if not ok or not isinstance(objs, list):
        print(f"ERROR: Failed to list backups in R2: {objs}")
        return

    if not objs:
        target_str = f" for '{app_name}'" if app_name else ""
        print(f"No backup archives found in Cloudflare R2{target_str}.")
        return

    headers = ["APP", "BACKUP ARCHIVE KEY", "SIZE", "LAST MODIFIED (UTC)"]
    rows = []
    for o in objs:
        key = o.get("key", "")
        parts = key.split("/", 1)
        app_tag = parts[0] if len(parts) > 1 else "-"
        size_str = format_bytes(o.get("size", 0))
        mod = o.get("last_modified", "").replace("T", " ").replace(".000Z", " UTC")
        rows.append([app_tag, key, size_str, mod])

    hdr_line, sep_line, row_lines = format_table(headers, rows, max_width=110)
    w = max(len(hdr_line), 82)
    print(f"\n{BOLD}{'=' * w}{RESET}")
    print(f" {GOLD}BOVER :: CLOUDFLARE R2 REMOTE BACKUP REGISTRY{RESET}")
    print(f"{BOLD}{'=' * w}{RESET}")
    print(hdr_line)
    print(sep_line)
    for r in row_lines:
        print(r)
    print(f"{BOLD}{'=' * w}{RESET}")
    print(f"\n💡 Run './lamo app backup verify <app>' to test recovery integrity of the latest backup.\n")


def parse_backup_timestamp(filename: str, file_path: Optional[Path] = None) -> datetime:
    """Extract timestamp from backup filename or fallback to file modification time."""
    # Pattern 1: backup_<app>_YYYY-MM-DD_HH-MM-SS.tar.gz
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})_(\d{2})-(\d{2})-(\d{2})", filename)
    if m:
        try:
            return datetime(
                int(m.group(1)), int(m.group(2)), int(m.group(3)),
                int(m.group(4)), int(m.group(5)), int(m.group(6)),
                tzinfo=timezone.utc
            )
        except Exception:
            pass
    # Pattern 2: <app>-pre-decommission-YYYYMMDD-HHMMSS.tar.gz
    m2 = re.search(r"(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})", filename)
    if m2:
        try:
            return datetime(
                int(m2.group(1)), int(m2.group(2)), int(m2.group(3)),
                int(m2.group(4)), int(m2.group(5)), int(m2.group(6)),
                tzinfo=timezone.utc
            )
        except Exception:
            pass
    if file_path and file_path.exists():
        try:
            return datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def rotate_local_backups(app_name: str, keep_days: int = 5) -> Tuple[int, int]:
    """
    Rotate and prune local backup archives stored on disk for an application.
    Enforces retention window (default: 5 days) while always guaranteeing at least
    the newest backup is preserved. Returns (pruned_count, freed_bytes).
    """
    validate_app_name(app_name)
    backups_base = APPS_DIR / "backups"
    app_backup_dir = backups_base / app_name

    candidates: List[Tuple[Path, datetime, int]] = []

    # 1. Inspect app-specific backup folder
    if app_backup_dir.exists():
        for p in app_backup_dir.glob("*.tar.gz"):
            ts = parse_backup_timestamp(p.name, p)
            candidates.append((p, ts, p.stat().st_size))

    # 2. Inspect root backups folder for pre-decommission archives
    if backups_base.exists():
        for p in backups_base.glob(f"{app_name}-pre-decommission-*.tar.gz"):
            ts = parse_backup_timestamp(p.name, p)
            candidates.append((p, ts, p.stat().st_size))

    if not candidates:
        return 0, 0

    # Sort descending by timestamp (newest first)
    candidates.sort(key=lambda x: x[1], reverse=True)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=keep_days)

    pruned_count = 0
    freed_bytes = 0

    # Always preserve candidates[0] (the newest backup) so an app never loses its only backup
    for p, ts, size in candidates[1:]:
        if ts < cutoff:
            try:
                p.unlink(missing_ok=True)
                pruned_count += 1
                freed_bytes += size
            except Exception as e:
                print(f"Warning: Failed to prune local backup {p}: {e}")

    return pruned_count, freed_bytes


def rotate_all_local_backups(keep_days: int = 5) -> Tuple[int, int]:
    """Prune old local backups for all applications and legacy archives in /opt/apps/backups/."""
    backups_base = APPS_DIR / "backups"
    if not backups_base.exists():
        return 0, 0

    total_pruned = 0
    total_freed = 0

    # Rotate per app directory
    for item in backups_base.iterdir():
        if item.is_dir():
            pruned, freed = rotate_local_backups(item.name, keep_days=keep_days)
            total_pruned += pruned
            total_freed += freed

    # Also clean orphaned root archives older than keep_days
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    for p in backups_base.glob("*.tar.gz"):
        ts = parse_backup_timestamp(p.name, p)
        if ts < cutoff:
            try:
                size = p.stat().st_size
                p.unlink(missing_ok=True)
                total_pruned += 1
                total_freed += size
            except Exception:
                pass

    return total_pruned, total_freed


def cmd_backup_prune(app_name: Optional[str] = None, keep_days: int = 5):
    """CLI handler to manually or automatically prune local backups on disk."""
    print(f"==> Pruning local backup archives older than {keep_days} days on disk...")
    if app_name:
        validate_app_name(app_name)
        pruned, freed = rotate_local_backups(app_name, keep_days=keep_days)
        print(f"✓ Pruned {pruned} old local backup archive(s) for '{app_name}' (freed {format_bytes(freed)}, retaining last {keep_days} days).")
    else:
        pruned, freed = rotate_all_local_backups(keep_days=keep_days)
        print(f"✓ Pruned {pruned} old local backup archive(s) across all applications (freed {format_bytes(freed)}, retaining last {keep_days} days).")


def notify_backup_result(app_name: str, success: bool, destination_key: Optional[str] = None, file_size_bytes: int = 0, error: Optional[str] = None, duration: float = 0.0, integrity_summary: Optional[str] = None):
    """Notify operator via Telegram with Es Bover avatar."""
    hostname = run_cmd("hostname", capture=True) or "server"
    status_icon = "✅" if success else "❌"
    status_text = "Completado correctamente" if success else "Fallo en copia de seguridad"
    size_str = format_bytes(file_size_bytes) if file_size_bytes else ""
    dur_str = f"{duration:.1f}s" if duration else "0s"

    text = (
        f"💾 <b>ES BOVER · COPIA DE SEGURIDAD</b>\n"
        f"<i>Respaldo cifrado en Cloudflare R2</i>\n\n"
        f"📦 <b>App:</b> <code>{app_name}</code>\n"
        f"🖥️  <b>Nodo:</b> <code>{hostname}</code>\n"
        f"📊 <b>Estado:</b> {status_icon} <b>{status_text}</b>\n"
    )
    if destination_key:
        text += f"☁️  <b>Destino R2:</b> <code>{destination_key}</code>\n"
    if integrity_summary:
        text += f"🔍 <b>Verificación:</b> {integrity_summary}\n"
    if size_str:
        text += f"📦 <b>Tamaño:</b> <code>{size_str}</code>\n"
    if duration:
        text += f"⏱️ <b>Duración:</b> <code>{dur_str}</code>\n"
    if error:
        text += f"\n<blockquote>⚠️ <b>Error:</b> <code>{html.escape(str(error))}</code></blockquote>\n"

    text += f"\n<i>Es Bover Runtime :: Backup Engine</i>"
    send_telegram(text)


def run_app_backup(app_name: str, notify: bool = True) -> Tuple[bool, str, int, float]:
    """
    Perform a consistent hot backup of an app's data directory and upload to Cloudflare R2.
    For SQLite databases, runs non-blocking hot backup (sqlite3.backup).
    Includes app.json, environment secrets (.env), shared variables, and backup metadata.
    """
    validate_app_name(app_name)
    cfg = load_app_config(app_name)
    if not cfg:
        err = f"App '{app_name}' configuration not found in /opt/apps/"
        print(f"ERROR: {err}")
        return False, err, 0, 0.0

    s3_cfg = load_s3_config()
    if not s3_cfg:
        err = "S3 / Cloudflare R2 credentials not configured. Run './lamo app backup config' first."
        print(f"ERROR: {err}")
        return False, err, 0, 0.0

    app_dir = APPS_DIR / app_name
    vols = resolve_app_volumes(cfg, app_dir)
    host_data_dir = None
    if vols:
        host_data_str = vols[0].split(":")[0]
        host_data_dir = Path(host_data_str)

    import tarfile
    import tempfile
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    temp_dir = Path(tempfile.mkdtemp(prefix=f"bover_backup_{app_name}_"))
    tar_path = temp_dir / f"backup_{app_name}_{timestamp}.tar.gz"

    start_time = time.time()
    try:
        staging_dir = temp_dir / "staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        data_staging = staging_dir / "data"
        data_staging.mkdir(parents=True, exist_ok=True)

        # 1. Hot-backup persistent data files & databases
        reconcile_app_permissions(app_name)
        verified_databases = []
        if host_data_dir and host_data_dir.exists():
            for item in host_data_dir.iterdir():
                if item.is_file():
                    if item.suffix in (".db", ".sqlite", ".sqlite3"):
                        hot_dest = data_staging / item.name
                        try:
                            conn = sqlite3.connect(f"file:{item}?mode=ro", uri=True, timeout=30.0)
                            dest_conn = sqlite3.connect(str(hot_dest))
                            conn.backup(dest_conn)
                            dest_conn.close()
                            conn.close()
                        except Exception:
                            shutil.copy2(item, hot_dest)
                        finally:
                            reconcile_app_permissions(app_name)

                        # Deep integrity verification on the backed up copy before upload
                        db_report = inspect_sqlite_database(hot_dest)
                        if not db_report.get("valid"):
                            raise RuntimeError(f"Database backup integrity check failed for '{item.name}': {db_report.get('error') or db_report.get('integrity_check')}")
                        verified_databases.append(db_report)
                    else:
                        shutil.copy2(item, data_staging / item.name)
                elif item.is_dir() and item.name != "lost+found":
                    shutil.copytree(item, data_staging / item.name)

        # 2. Include application configuration (app.json)
        app_json_path = app_dir / "app.json"
        if app_json_path.exists():
            shutil.copy2(app_json_path, staging_dir / "app.json")

        # 3. Include application secrets (.env)
        app_env_path = app_dir / ".env"
        if app_env_path.exists():
            shutil.copy2(app_env_path, staging_dir / ".env")

        # 4. Include server-wide shared environment if present
        shared_env_path = APPS_DIR / "shared" / ".env"
        if shared_env_path.exists() and shared_env_path.stat().st_size > 0:
            shutil.copy2(shared_env_path, staging_dir / "shared.env")

        # 5. Include self-documenting backup manifest
        app_state = load_app_state(app_name)
        metadata = {
            "app": app_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "active_slot": app_state.get("active_slot"),
            "commit": app_state.get("commit"),
            "deployed_at": app_state.get("deployed_at"),
            "hostname": run_cmd("hostname", capture=True) or "server",
            "backup_version": 2,
            "databases": verified_databases,
        }
        (staging_dir / "backup-metadata.json").write_text(json.dumps(metadata, indent=2))

        # 6. Build archive with all components
        with tarfile.open(tar_path, "w:gz") as tar:
            for item in staging_dir.iterdir():
                tar.add(item, arcname=item.name)

        # Verify archive can be opened cleanly
        with tarfile.open(tar_path, "r:gz") as tar_test:
            if not tar_test.getmembers():
                raise RuntimeError("Backup archive is unexpectedly empty.")

        file_size = tar_path.stat().st_size
        tar_data = tar_path.read_bytes()

        r2_key = f"{app_name}/backup_{app_name}_{timestamp}.tar.gz"
        endpoint = s3_cfg.get("endpoint_url") or f"https://{s3_cfg['account_id']}.r2.cloudflarestorage.com"
        success, err = s3_sigv4_put(
            endpoint_url=endpoint,
            bucket=s3_cfg["bucket"],
            key=r2_key,
            data=tar_data,
            access_key=s3_cfg["access_key"],
            secret_key=s3_cfg["secret_key"]
        )

        duration = time.time() - start_time
        integ_summary = ""
        if verified_databases:
            integ_summary = f"🟢 {len(verified_databases)} SQLite DB(s) verified (PRAGMA integrity_check: ok)"

        if notify:
            notify_backup_result(
                app_name=app_name,
                success=success,
                destination_key=f"r2://{s3_cfg['bucket']}/{r2_key}" if success else None,
                file_size_bytes=file_size if success else 0,
                error=err if not success else None,
                duration=duration,
                integrity_summary=integ_summary,
            )

        if success:
            # Store local rolling copy for instant offline restore
            local_backup_dir = APPS_DIR / "backups" / app_name
            try:
                local_backup_dir.mkdir(parents=True, exist_ok=True)
                local_dest = local_backup_dir / tar_path.name
                shutil.copy2(tar_path, local_dest)
                try:
                    os.chmod(local_dest, 0o640)
                except Exception:
                    pass
            except Exception as e:
                print(f"Warning: Failed to save local backup copy: {e}")

            # Enforce local disk rotation (default: retain last 5 days)
            retention_days = int(cfg.get("backup_retention_days") or cfg.get("keep_local_backups_days") or 5)
            pruned_count, freed_bytes = rotate_local_backups(app_name, keep_days=retention_days)

            db_report_str = ""
            if verified_databases:
                db_names = ", ".join(f"{d['filename']}: ok ({d['total_tables']} tables, {d['total_records']} rows)" for d in verified_databases)
                db_report_str = f"\n  • Integrity:     🟢 Verified ({db_names})"
            local_rot_str = f" · rotated: {pruned_count} old file(s) pruned, {format_bytes(freed_bytes)} freed" if pruned_count > 0 else ""
            print(f"✓ Backup for '{app_name}' completed in {duration:.1f}s: r2://{s3_cfg['bucket']}/{r2_key} ({format_bytes(file_size)}){db_report_str}")
            print(f"  • Local Storage: 🟢 Retained in backups/{app_name}/ (retention: last {retention_days} days{local_rot_str})")
            return True, r2_key, file_size, duration
        else:
            print(f"ERROR: Backup upload failed for '{app_name}': {err}")
            return False, err, 0, duration
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        # Ensure that any SQLite WAL/SHM files touched or created during hot backup
        # are restored to app ownership so the container user never loses access.
        reconcile_app_permissions(app_name)


def notify_backup_summary(results: List[Dict[str, Any]]):
    """
    Send a single consolidated Telegram notification summarizing backup results
    for one or multiple applications on this server node.
    """
    if not results:
        return
    if len(results) == 1:
        r = results[0]
        notify_backup_result(
            app_name=r["app"],
            success=r["success"],
            destination_key=r.get("destination_key"),
            file_size_bytes=r.get("file_size_bytes", 0),
            error=r.get("error"),
            duration=r.get("duration", 0.0),
        )
        return

    hostname = run_cmd("hostname", capture=True) or "server"
    total_apps = len(results)
    success_count = sum(1 for r in results if r.get("success"))
    fail_count = total_apps - success_count
    total_size = sum(r.get("file_size_bytes", 0) for r in results if r.get("success"))
    total_dur = sum(r.get("duration", 0.0) for r in results)

    if fail_count == 0:
        header_icon = "💾"
        status_line = f"🟢 <b>{success_count}/{total_apps} completadas correctamente</b>"
    elif success_count == 0:
        header_icon = "⚠️"
        status_line = f"🔴 <b>0/{total_apps} completadas (todas fallaron)</b>"
    else:
        header_icon = "⚠️"
        status_line = f"🟡 <b>{success_count}/{total_apps} completadas ({fail_count} con fallos)</b>"

    lines = [
        f"{header_icon} <b>ES BOVER · COPIAS DE SEGURIDAD</b>",
        f"<i>Informe consolidado de nodo</i>\n",
        f"🖥️  <b>Nodo:</b> <code>{hostname}</code>",
        f"📊 <b>Resumen:</b> {status_line}",
        f"⏱️ <b>Tiempo total:</b> <code>{total_dur:.1f}s</code>",
    ]
    if total_size > 0:
        lines.append(f"📦 <b>Tamaño total:</b> <code>{format_bytes(total_size)}</code>")
    lines.append("")
    lines.append("<b>Detalle por aplicación:</b>")

    for r in results:
        app = r["app"]
        success = r.get("success", False)
        dur = r.get("duration", 0.0)
        dur_str = f"{dur:.1f}s"
        if success:
            sz_str = format_bytes(r.get("file_size_bytes", 0))
            dest = r.get("destination_key") or ""
            lines.append(f"• ✅ <code>{app}</code>: {sz_str} en {dur_str}")
            if dest:
                lines.append(f"   ↳ <code>{dest}</code>")
        else:
            err = r.get("error") or "Unknown error"
            lines.append(f"• ❌ <code>{app}</code>: Fallo en {dur_str}")
            lines.append(f"   ↳ <blockquote>⚠️ {html.escape(str(err)[:200])}</blockquote>")

    lines.append("")
    lines.append("<i>Es Bover Runtime :: Backup Engine</i>")

    text = "\n".join(lines)
    send_telegram(text)


def run_backups_batch(app_names: List[str]) -> List[Dict[str, Any]]:
    """
    Run backups sequentially for multiple applications on this server node,
    and deliver a single consolidated Telegram notification for the whole server.
    """
    results = []
    s3_cfg = load_s3_config() or {}
    bucket = s3_cfg.get("bucket", "")
    for app in app_names:
        print(f"==> Running backup for '{app}'...")
        success, r2_key_or_err, file_size, duration = run_app_backup(app, notify=False)
        dest_key = f"r2://{bucket}/{r2_key_or_err}" if success else None
        error = None if success else r2_key_or_err
        results.append({
            "app": app,
            "success": success,
            "destination_key": dest_key,
            "file_size_bytes": file_size,
            "error": error,
            "duration": duration,
        })
    notify_backup_summary(results)
    return results


def backup_all():
    """Run automated backup for all applications with auto_backup enabled."""
    configs = get_all_app_configs()
    apps_to_backup = []
    for cfg_path in configs:
        try:
            with open(cfg_path) as f:
                d = json.load(f)
            if d.get("auto_backup") in (True, "yes", "true", 1):
                name = d.get("name")
                if name:
                    apps_to_backup.append(name)
        except Exception as e:
            print(f"Error checking {cfg_path}: {e}")

    if not apps_to_backup:
        print("No applications currently have 'auto_backup: true' enabled in app.json.")
        return

    print(f"==> Starting automated backup batch for {len(apps_to_backup)} application(s): {', '.join(apps_to_backup)}")
    run_backups_batch(apps_to_backup)
    # Ensure local backup storage is cleanly rotated (retaining last 5 days)
    rotate_all_local_backups(keep_days=5)


# ==============================================================================
# 6.8. PER-PROJECT CRON SCHEDULER, EXECUTION ENGINE & AUDIT LOG
# ==============================================================================

CRON_MACROS = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
}

MONTH_NAMES = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

DOW_NAMES = {
    "sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6,
}

MAX_CRON_OUTPUT_BYTES = 16384


def validate_cron_id(job_id: str) -> str:
    """Validate cron job identifier to prevent path traversal or shell injection."""
    clean = str(job_id or "").strip()
    if not clean or not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,47}$", clean) or ".." in clean:
        raise ValueError(
            f"Invalid cron job ID '{job_id}'. Must be 1-48 alphanumeric characters, dashes, underscores, or dots."
        )
    return clean


def normalize_cron_schedule(expr: str) -> str:
    """Normalize shorthand cron macros (@daily, @hourly, @every Xm/Xh) into standard 5-field cron syntax."""
    s = " ".join(str(expr or "").strip().split())
    if not s:
        raise ValueError("Cron schedule expression cannot be empty.")
    low = s.lower()
    if low in CRON_MACROS:
        return CRON_MACROS[low]
    m_every = re.match(r"^@every\s+(\d+)\s*([mh])$", low)
    if m_every:
        val = int(m_every.group(1))
        unit = m_every.group(2)
        if unit == "m":
            if val < 1 or val > 59:
                raise ValueError("Interval in '@every <N>m' must be between 1 and 59 minutes.")
            return f"*/{val} * * * *" if val > 1 else "* * * * *"
        else:
            if val < 1 or val > 23:
                raise ValueError("Interval in '@every <N>h' must be between 1 and 23 hours.")
            return f"0 */{val} * * *" if val > 1 else "0 * * * *"
    return s


def _parse_cron_field(field_str: str, min_val: int, max_val: int, names_map: Optional[Dict[str, int]] = None, is_dow: bool = False) -> Tuple[set, bool]:
    """Parse a single cron field into a set of matching integers and a boolean indicating if it was wildcard '*'."""
    f = field_str.strip().lower()
    if not f:
        raise ValueError("Empty cron field")

    if names_map:
        for name_k, name_v in names_map.items():
            f = re.sub(rf"\b{name_k}\b", str(name_v), f)

    is_wildcard = (f == "*")
    values = set()

    for part in f.split(","):
        part = part.strip()
        if not part:
            raise ValueError(f"Invalid empty list element in '{field_str}'")

        step = 1
        if "/" in part:
            range_part, step_str = part.split("/", 1)
            if not step_str.isdigit() or int(step_str) <= 0:
                raise ValueError(f"Invalid step '/{step_str}' in cron field '{field_str}'")
            step = int(step_str)
        else:
            range_part = part

        if range_part == "*":
            start, end = min_val, max_val
        elif "-" in range_part:
            a_str, b_str = range_part.split("-", 1)
            if not (a_str.isdigit() and b_str.isdigit()):
                raise ValueError(f"Invalid range '{range_part}' in cron field '{field_str}'")
            start, end = int(a_str), int(b_str)
            if is_dow and end == 7:
                end = 7
        else:
            if not range_part.isdigit():
                raise ValueError(f"Invalid value '{range_part}' in cron field '{field_str}'")
            val = int(range_part)
            if is_dow and val == 7:
                val = 0
            if val < min_val or val > max_val:
                raise ValueError(f"Value {val} out of bounds ({min_val}-{max_val}) in '{field_str}'")
            values.add(val)
            continue

        max_allowed = 7 if is_dow else max_val
        if start < min_val or end > max_allowed or start > end:
            raise ValueError(f"Range {start}-{end} out of bounds ({min_val}-{max_val}) in '{field_str}'")

        for v in range(start, end + 1, step):
            values.add(0 if (is_dow and v == 7) else v)

    return values, is_wildcard


def validate_cron_schedule(expr: str) -> str:
    """Validate a cron schedule expression (5-field standard syntax or @macro) and return normalized string."""
    norm = normalize_cron_schedule(expr)
    fields = norm.split()
    if len(fields) != 5:
        raise ValueError(
            f"Invalid cron schedule '{expr}': expected 5 fields (minute hour day month weekday) or macro (@hourly, @daily, @weekly, @monthly, @every 5m)."
        )
    _parse_cron_field(fields[0], 0, 59)
    _parse_cron_field(fields[1], 0, 23)
    _parse_cron_field(fields[2], 1, 31)
    _parse_cron_field(fields[3], 1, 12, names_map=MONTH_NAMES)
    _parse_cron_field(fields[4], 0, 6, names_map=DOW_NAMES, is_dow=True)
    return str(expr).strip()


def cron_matches_dt(expr: str, dt: datetime) -> bool:
    """Return True if the given datetime matches the cron schedule expression."""
    norm = normalize_cron_schedule(expr)
    fields = norm.split()
    if len(fields) != 5:
        return False

    mins, _ = _parse_cron_field(fields[0], 0, 59)
    hours, _ = _parse_cron_field(fields[1], 0, 23)
    doms, dom_wild = _parse_cron_field(fields[2], 1, 31)
    months, _ = _parse_cron_field(fields[3], 1, 12, names_map=MONTH_NAMES)
    dows, dow_wild = _parse_cron_field(fields[4], 0, 6, names_map=DOW_NAMES, is_dow=True)

    if dt.minute not in mins or dt.hour not in hours or dt.month not in months:
        return False

    # Python weekday(): Monday=0..Sunday=6 -> Cron weekday: Sunday=0, Monday=1..Saturday=6
    cron_dow = (dt.weekday() + 1) % 7
    dom_match = dt.day in doms
    dow_match = cron_dow in dows

    if not dom_wild and not dow_wild:
        return dom_match or dow_match
    return dom_match and dow_match


def normalize_cron_job(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize a cron job definition dictionary."""
    if not isinstance(raw, dict):
        raise ValueError("Cron job definition must be a JSON object.")
    job_id = validate_cron_id(raw.get("id") or raw.get("name") or "")
    schedule = validate_cron_schedule(raw.get("schedule") or "")
    command = str(raw.get("command") or "").strip()
    if not command:
        raise ValueError(f"Cron job '{job_id}' must define a non-empty 'command'.")

    raw_mode = str(raw.get("mode") or "exec").strip().lower()
    if raw_mode in ("exec", "active", "container_exec"):
        mode = "exec"
    elif raw_mode in ("run", "ephemeral", "isolated", "docker_run"):
        mode = "run"
    else:
        raise ValueError(f"Invalid mode '{raw_mode}' for cron '{job_id}'. Must be 'exec' or 'run'.")

    try:
        timeout = max(5, int(raw.get("timeout", 3600)))
    except (TypeError, ValueError):
        timeout = 3600

    enabled_val = raw.get("enabled", True)
    enabled = bool(enabled_val) if not isinstance(enabled_val, str) else (enabled_val.strip().lower() not in ("false", "0", "no", "off"))

    notify_val = str(raw.get("notify") or "on_failure").strip().lower()
    if notify_val in ("failure", "fail", "on_failure", "error"):
        notify = "on_failure"
    elif notify_val in ("always", "all", "true", "yes"):
        notify = "always"
    elif notify_val in ("never", "none", "false", "no", "silent"):
        notify = "never"
    else:
        notify = "on_failure"

    allow_overlap = bool(raw.get("allow_overlap", False))
    description = str(raw.get("description") or "").strip()

    job_dict = {
        "id": job_id,
        "schedule": schedule,
        "command": command,
        "mode": mode,
        "timeout": timeout,
        "enabled": enabled,
        "notify": notify,
        "allow_overlap": allow_overlap,
    }
    if description:
        job_dict["description"] = description
    return job_dict


def get_app_crons(cfg: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return normalized list of cron jobs from an app config dictionary."""
    if not isinstance(cfg, dict):
        return []
    raw_list = cfg.get("crons") or cfg.get("cron") or []
    if isinstance(raw_list, dict):
        # Support map format {"job-id": {"schedule": "...", "command": "..."}}
        converted = []
        for k, v in raw_list.items():
            if isinstance(v, dict):
                item = dict(v)
                item.setdefault("id", k)
                converted.append(item)
        raw_list = converted
    if not isinstance(raw_list, list):
        return []

    normalized = []
    for item in raw_list:
        try:
            normalized.append(normalize_cron_job(item))
        except Exception as e:
            print(f"[Cron] Warning: skipping invalid cron entry in {cfg.get('name', 'app')}: {e}", file=sys.stderr)
    return normalized


def sync_repo_crons(name: str, app_dir: Path):
    """
    Synchronize declarative crons from repository files (crons.json or bover.json)
    into /opt/apps/<name>/app.json during deployment while preserving CLI-defined crons.
    """
    repo_crons_raw = None
    for candidate_name in ("crons.json", "bover.json"):
        candidate_path = app_dir / candidate_name
        if candidate_path.exists():
            try:
                data = json.loads(candidate_path.read_text())
                if isinstance(data, list) and candidate_name == "crons.json":
                    repo_crons_raw = data
                    break
                elif isinstance(data, dict) and isinstance(data.get("crons"), list):
                    repo_crons_raw = data["crons"]
                    break
            except Exception as e:
                print(f"[Cron] Notice: failed to parse {candidate_path}: {e}", file=sys.stderr)

    if repo_crons_raw is None:
        return

    cfg = load_app_config(name)
    if not cfg:
        return

    existing_crons = get_app_crons(cfg)
    merged_by_id = {c["id"]: c for c in existing_crons}
    synced_count = 0
    for item in repo_crons_raw:
        try:
            norm = normalize_cron_job(item)
            merged_by_id[norm["id"]] = norm
            synced_count += 1
        except Exception as e:
            print(f"[Cron] Warning: invalid repo cron in '{name}': {e}", file=sys.stderr)

    cfg["crons"] = list(merged_by_id.values())
    save_app_config(name, cfg)
    print(f"==> Synchronized {synced_count} declarative cron job(s) from repository into app.json.")


def notify_cron_result(app: str, job: Dict[str, Any], status: str, exit_code: Optional[int], duration: float, output: str, triggered_by: str, run_id: int):
    """Deliver Telegram notification for cron job execution according to job's notify policy."""
    policy = job.get("notify", "on_failure")
    if policy == "never":
        return
    if policy == "on_failure" and status == "SUCCESS":
        return

    hostname = run_cmd("hostname", capture=True) or "server"
    safe_app = html.escape(str(app))
    safe_job = html.escape(str(job["id"]))
    safe_cmd = html.escape(str(job["command"])[:120])
    safe_sched = html.escape(str(job["schedule"]))
    safe_mode = html.escape(str(job.get("mode", "exec")))
    safe_host = html.escape(str(hostname))
    safe_out = html.escape(str(output or "").strip()[-400:])

    if status == "SUCCESS":
        header = "✅ <b>ES BOVER · CRON COMPLETADO</b>"
        sub = "<i>Tarea programada ejecutada con éxito</i>"
    elif status == "TIMEOUT":
        header = "⏱️ <b>ES BOVER · TIMEOUT EN CRON</b>"
        sub = "<i>Tarea cancelada por superar el tiempo límite</i>"
    else:
        header = "⚠️ <b>ES BOVER · FALLO EN CRON</b>"
        sub = "<i>La tarea programada terminó con código de error</i>"

    out_block = f"\n<blockquote><code>{safe_out}</code></blockquote>" if safe_out else ""
    text = (
        f"{header}\n"
        f"{sub}\n\n"
        f"📦 <b>App:</b> <code>{safe_app}</code>\n"
        f"🖥️  <b>Nodo:</b> <code>{safe_host}</code>\n"
        f"⏰ <b>Tarea:</b> <code>{safe_job}</code> (<code>{safe_sched}</code>)\n"
        f"⚙️ <b>Modo:</b> <code>{safe_mode}</code> · <b>Run:</b> <code>#{run_id}</code>\n"
        f"💻 <b>Comando:</b> <code>{safe_cmd}</code>\n"
        f"📊 <b>Estado:</b> <b>{status}</b> (Exit: <code>{exit_code if exit_code is not None else '-'}</code>)\n"
        f"⏱️ <b>Duración:</b> <code>{duration:.2f}s</code>"
        f"{out_block}\n\n"
        f"<i>Es Bover Runtime :: Cron Scheduler</i>"
    )
    send_telegram(text)


def _resolve_active_container_for_cron(name: str) -> str:
    """Resolve the active running container for an app (handling Blue/Green slots dynamically)."""
    state = load_app_state(name)
    candidate = state.get("container")
    if candidate:
        fast = _inspect_container_fast(candidate)
        if fast and fast.get("state") == "running":
            return candidate
        ps = run_cmd(f"docker ps --filter name=^/{candidate}$ --format '{{{{.Names}}}}' 2>/dev/null || true", capture=True)
        if ps:
            return candidate

    for slot in ("blue", "green"):
        c_name = f"{name}-{slot}"
        fast = _inspect_container_fast(c_name)
        if fast and fast.get("state") == "running":
            return c_name
        ps = run_cmd(f"docker ps --filter name=^/{c_name}$ --format '{{{{.Names}}}}' 2>/dev/null || true", capture=True)
        if ps:
            return c_name

    return candidate or f"{name}-blue"


def execute_cron_job(app_name: str, job: Dict[str, Any], triggered_by: str = "schedule", stream_output: bool = False) -> Dict[str, Any]:
    """
    Execute a single per-project cron job, guaranteeing overlap protection, timeout enforcement,
    container isolation (exec in active slot or ephemeral docker run), SQLite audit logging, and Telegram alerting.
    """
    validate_app_name(app_name)
    cfg = load_app_config(app_name)
    if not cfg:
        raise RuntimeError(f"Application '{app_name}' configuration not found.")

    norm_job = normalize_cron_job(job)
    job_id = norm_job["id"]
    command = norm_job["command"]
    schedule = norm_job["schedule"]
    mode = norm_job["mode"]
    timeout = norm_job["timeout"]
    allow_overlap = norm_job["allow_overlap"]

    app_dir = cfg.get("_app_dir") or (APPS_DIR / app_name)
    app_dir.mkdir(parents=True, exist_ok=True)
    init_db()

    # 1. Overlap lock protection
    lock_fd = None
    if not allow_overlap:
        lock_file = app_dir / f".bover-cron-{job_id}.lock"
        lock_fd = os.open(str(lock_file), os.O_CREAT | os.O_RDWR, 0o660)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, IOError):
            os.close(lock_fd)
            now_ts = int(time.time())
            skip_msg = f"Skipped: previous execution of '{job_id}' is still running (allow_overlap=false)."
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    INSERT INTO cron_executions
                    (app, job_id, command, schedule, mode, container, status, exit_code, started_at, finished_at, duration_sec, triggered_by, output)
                    VALUES (?, ?, ?, ?, ?, ?, 'SKIPPED', NULL, ?, ?, 0.0, ?, ?)
                    """,
                    (app_name, job_id, command, schedule, mode, "-", now_ts, now_ts, triggered_by, skip_msg),
                )
                run_id = cur.lastrowid
            return {
                "run_id": run_id,
                "app": app_name,
                "job_id": job_id,
                "status": "SKIPPED",
                "exit_code": None,
                "duration_sec": 0.0,
                "output": skip_msg,
                "container": "-",
            }

    try:
        _, app_uid = get_or_create_app_user(app_name)
        state = load_app_state(app_name)
        active_slot = state.get("active_slot") or "blue"

        if mode == "exec":
            target_container = _resolve_active_container_for_cron(app_name)
            exec_cmd = [
                "docker", "exec",
                "-u", f"{app_uid}:{app_uid}",
                target_container,
                "sh", "-c", command,
            ]
        else:
            # Isolated ephemeral container ('run') with identical security boundaries, env files & volumes
            ephemeral_suffix = f"{int(time.time())}-{os.getpid()}"
            clean_job = re.sub(r"[^a-zA-Z0-9_.-]", "-", job_id)[:20]
            target_container = f"{app_name}-cron-{clean_job}-{ephemeral_suffix}"

            res_cfg = cfg.get("resources", {}) if isinstance(cfg.get("resources"), dict) else {}
            raw_cpu = cfg.get("cpu") or cfg.get("cpus") or res_cfg.get("cpu") or 0.5
            raw_mem = cfg.get("memory") or cfg.get("mem_limit") or res_cfg.get("memory") or "512m"
            try:
                cpu_val = float(raw_cpu)
                cpu_limit = f"{cpu_val:.1f}" if cpu_val != int(cpu_val) else f"{int(cpu_val)}"
            except (ValueError, TypeError):
                cpu_limit = "0.5"
            mem_str = str(raw_mem).strip().lower()
            mem_limit = mem_str if re.match(r"^[0-9]+[kmg]?$", mem_str) else "512m"

            exec_cmd = [
                "docker", "run", "--rm",
                "--name", target_container,
                "--network", DOCKER_NETWORK,
                "--user", f"{app_uid}:{app_uid}",
                "--group-add", str(get_bover_gid()),
                "--security-opt", "no-new-privileges:true",
                "--pids-limit", "256",
                "--cpus", cpu_limit,
                "-m", mem_limit,
            ]

            shared_env = APPS_DIR / "shared" / ".env"
            app_env = app_dir / ".env"
            if shared_env.exists():
                exec_cmd.extend(["--env-file", str(shared_env)])
            if app_env.exists():
                exec_cmd.extend(["--env-file", str(app_env)])

            for vol in resolve_app_volumes(cfg, app_dir):
                exec_cmd.extend(["-v", vol])

            # Resolve best available image for app
            image_ref = f"{app_name}:{active_slot}"
            img_check = run_cmd(f"docker image inspect {shlex.quote(image_ref)} >/dev/null 2>&1 && echo OK || true", capture=True)
            if "OK" not in img_check:
                image_ref = f"{app_name}:latest"

            exec_cmd.extend([image_ref, "sh", "-c", command])

        started_at = int(time.time())
        t0 = time.monotonic()

        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO cron_executions
                (app, job_id, command, schedule, mode, container, status, exit_code, started_at, triggered_by)
                VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', NULL, ?, ?)
                """,
                (app_name, job_id, command, schedule, mode, target_container, started_at, triggered_by),
            )
            run_id = cur.lastrowid

        status = "SUCCESS"
        exit_code = 0
        output_text = ""

        try:
            res = subprocess.run(
                exec_cmd,
                cwd=app_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
            exit_code = res.returncode
            output_text = (res.stdout or "").strip()
            status = "SUCCESS" if exit_code == 0 else "FAILED"
        except subprocess.TimeoutExpired as te:
            status = "TIMEOUT"
            exit_code = 124
            partial = ""
            if te.stdout:
                partial = te.stdout.decode("utf-8", errors="replace") if isinstance(te.stdout, bytes) else str(te.stdout)
            output_text = (partial.strip() + f"\n[Bover Cron] Command timed out after {timeout}s.").strip()
            if mode == "run":
                run_cmd(f"docker rm -f {shlex.quote(target_container)} >/dev/null 2>&1 || true")
        except Exception as exc:
            status = "FAILED"
            exit_code = 1
            output_text = f"[Bover Cron] Execution error: {exc}"

        duration_sec = round(time.monotonic() - t0, 2)
        finished_at = int(time.time())

        if len(output_text) > MAX_CRON_OUTPUT_BYTES:
            output_text = "...[truncated]...\n" + output_text[-MAX_CRON_OUTPUT_BYTES:]

        with get_db() as conn:
            conn.execute(
                """
                UPDATE cron_executions
                SET status = ?, exit_code = ?, finished_at = ?, duration_sec = ?, output = ?
                WHERE id = ?
                """,
                (status, exit_code, finished_at, duration_sec, output_text, run_id),
            )
            # Prune old cron execution records beyond 500 per app or 90 days
            cutoff = finished_at - (90 * 86400)
            conn.execute("DELETE FROM cron_executions WHERE finished_at IS NOT NULL AND finished_at < ?", (cutoff,))

        if stream_output and output_text:
            print(output_text)

        notify_cron_result(
            app=app_name,
            job=norm_job,
            status=status,
            exit_code=exit_code,
            duration=duration_sec,
            output=output_text,
            triggered_by=triggered_by,
            run_id=run_id,
        )

        return {
            "run_id": run_id,
            "app": app_name,
            "job_id": job_id,
            "command": command,
            "schedule": schedule,
            "mode": mode,
            "container": target_container,
            "status": status,
            "exit_code": exit_code,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_sec": duration_sec,
            "output": output_text,
        }
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except Exception:
                pass


def cron_tick(now_ts: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Evaluate all configured cron jobs across all applications for the current minute tick.
    Includes a 15-minute catch-up window using 'cron_state' in SQLite so delayed systemd ticks
    or brief reboots never drop a scheduled task and never double-execute within the same minute.
    """
    init_db()
    now = int(now_ts if now_ts is not None else time.time())
    current_slot_ts = (now // 60) * 60

    configs = get_all_app_configs()
    if not configs:
        return []

    due_tasks: List[Tuple[str, Dict[str, Any], str]] = []

    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        for cfg_path in configs:
            try:
                with open(cfg_path, "r") as f:
                    cfg = json.load(f)
            except Exception:
                continue

            app_name = cfg.get("name")
            if not app_name:
                continue

            for job in get_app_crons(cfg):
                if not job.get("enabled", True):
                    continue

                job_id = job["id"]
                schedule = job["schedule"]

                row = conn.execute(
                    "SELECT last_slot_ts FROM cron_state WHERE app = ? AND job_id = ?",
                    (app_name, job_id),
                ).fetchone()

                if row is None:
                    dt_now = datetime.fromtimestamp(current_slot_ts)
                    if cron_matches_dt(schedule, dt_now):
                        conn.execute(
                            "INSERT OR REPLACE INTO cron_state (app, job_id, last_slot_ts) VALUES (?, ?, ?)",
                            (app_name, job_id, current_slot_ts),
                        )
                        due_tasks.append((app_name, job, "schedule"))
                    else:
                        conn.execute(
                            "INSERT OR REPLACE INTO cron_state (app, job_id, last_slot_ts) VALUES (?, ?, ?)",
                            (app_name, job_id, current_slot_ts),
                        )
                else:
                    last_slot_ts = int(row["last_slot_ts"])
                    if current_slot_ts <= last_slot_ts:
                        continue

                    # Check slots from max(last_slot_ts + 60, current_slot_ts - 15m) up to current_slot_ts
                    start_check = max(last_slot_ts + 60, current_slot_ts - (15 * 60))
                    matched_slot = None
                    slot_cursor = start_check
                    while slot_cursor <= current_slot_ts:
                        dt_slot = datetime.fromtimestamp(slot_cursor)
                        if cron_matches_dt(schedule, dt_slot):
                            matched_slot = slot_cursor
                        slot_cursor += 60

                    conn.execute(
                        "UPDATE cron_state SET last_slot_ts = ? WHERE app = ? AND job_id = ?",
                        (current_slot_ts, app_name, job_id),
                    )
                    if matched_slot is not None:
                        trig = "schedule" if matched_slot == current_slot_ts else "catchup"
                        due_tasks.append((app_name, job, trig))

    if not due_tasks:
        return []

    import concurrent.futures
    results = []
    max_workers = min(8, len(due_tasks))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(execute_cron_job, app_name, job, trig, False): (app_name, job["id"])
            for app_name, job, trig in due_tasks
        }
        for fut in concurrent.futures.as_completed(future_map):
            app_name, job_id = future_map[fut]
            try:
                res = fut.result()
                results.append(res)
                with get_db() as conn:
                    conn.execute(
                        "UPDATE cron_state SET last_run_id = ? WHERE app = ? AND job_id = ?",
                        (res.get("run_id"), app_name, job_id),
                    )
            except Exception as e:
                print(f"[Cron] Error executing {app_name}/{job_id}: {e}", file=sys.stderr)

    return results


def cron_add(app_name: str, job_id: str, schedule: str, command: str, mode: str = "exec", timeout: int = 3600, notify: str = "on_failure", description: str = "", allow_overlap: bool = False):
    """Add or update a cron job in /opt/apps/<app>/app.json."""
    validate_app_name(app_name)
    cfg = load_app_config(app_name)
    if not cfg:
        print(f"ERROR: Application '{app_name}' not found in {APPS_DIR}.", file=sys.stderr)
        sys.exit(1)

    new_job = normalize_cron_job({
        "id": job_id,
        "schedule": schedule,
        "command": command,
        "mode": mode,
        "timeout": timeout,
        "enabled": True,
        "notify": notify,
        "allow_overlap": allow_overlap,
        "description": description,
    })

    crons = get_app_crons(cfg)
    updated = False
    for i, existing in enumerate(crons):
        if existing["id"] == new_job["id"]:
            crons[i] = new_job
            updated = True
            break
    if not updated:
        crons.append(new_job)

    cfg["crons"] = crons
    save_app_config(app_name, cfg)
    action_word = "Updated" if updated else "Added"
    print(f"✓ {action_word} cron job '{new_job['id']}' for app '{app_name}':")
    print(f"  • Schedule: {new_job['schedule']}")
    print(f"  • Command:  {new_job['command']}")
    print(f"  • Mode:     {new_job['mode']} (timeout: {new_job['timeout']}s, notify: {new_job['notify']})")


def cron_remove(app_name: str, job_id: str):
    """Remove a cron job from /opt/apps/<app>/app.json."""
    validate_app_name(app_name)
    validate_cron_id(job_id)
    cfg = load_app_config(app_name)
    if not cfg:
        print(f"ERROR: Application '{app_name}' not found in {APPS_DIR}.", file=sys.stderr)
        sys.exit(1)

    crons = get_app_crons(cfg)
    filtered = [c for c in crons if c["id"] != job_id]
    if len(filtered) == len(crons):
        print(f"ERROR: Cron job '{job_id}' not found in app '{app_name}'.", file=sys.stderr)
        sys.exit(1)

    cfg["crons"] = filtered
    save_app_config(app_name, cfg)
    init_db()
    with get_db() as conn:
        conn.execute("DELETE FROM cron_state WHERE app = ? AND job_id = ?", (app_name, job_id))
    print(f"✓ Removed cron job '{job_id}' from application '{app_name}'.")


def cron_toggle(app_name: str, job_id: str, enabled: bool):
    """Enable or disable a cron job in /opt/apps/<app>/app.json."""
    validate_app_name(app_name)
    validate_cron_id(job_id)
    cfg = load_app_config(app_name)
    if not cfg:
        print(f"ERROR: Application '{app_name}' not found in {APPS_DIR}.", file=sys.stderr)
        sys.exit(1)

    crons = get_app_crons(cfg)
    found = False
    for c in crons:
        if c["id"] == job_id:
            c["enabled"] = bool(enabled)
            found = True
            break
    if not found:
        print(f"ERROR: Cron job '{job_id}' not found in app '{app_name}'.", file=sys.stderr)
        sys.exit(1)

    cfg["crons"] = crons
    save_app_config(app_name, cfg)
    state_word = "enabled" if enabled else "disabled"
    print(f"✓ Cron job '{job_id}' ({app_name}) is now {state_word}.")


def cron_run_manual(app_name: str, job_id: str):
    """Manually trigger an immediate run of a configured cron job and stream/display its result."""
    validate_app_name(app_name)
    validate_cron_id(job_id)
    cfg = load_app_config(app_name)
    if not cfg:
        print(f"ERROR: Application '{app_name}' not found in {APPS_DIR}.", file=sys.stderr)
        sys.exit(1)

    crons = get_app_crons(cfg)
    target_job = next((c for c in crons if c["id"] == job_id), None)
    if not target_job:
        print(f"ERROR: Cron job '{job_id}' not found in app '{app_name}'.", file=sys.stderr)
        sys.exit(1)

    print("=" * 80)
    print(f" BOVER CRON EXECUTION :: {app_name} / {job_id} (mode: {target_job['mode']})")
    print(f" Command: {target_job['command']}")
    print("=" * 80)
    res = execute_cron_job(app_name, target_job, triggered_by="manual", stream_output=True)
    print("-" * 80)
    print(
        f" Run #{res['run_id']} | Status: {res['status']} | "
        f"Exit Code: {res['exit_code']} | Duration: {res['duration_sec']:.2f}s | Container: {res['container']}"
    )
    print("=" * 80)
    if res["status"] != "SUCCESS":
        sys.exit(res["exit_code"] or 1)


def cron_list(target_app: Optional[str] = None):
    """Display all configured cron jobs across apps (or for a specific app) with last execution status."""
    init_db()
    if target_app:
        validate_app_name(target_app)
        cfg = load_app_config(target_app)
        if not cfg:
            print(f"ERROR: Application '{target_app}' not found in {APPS_DIR}.", file=sys.stderr)
            sys.exit(1)
        configs_data = [cfg]
    else:
        configs_data = []
        for p in get_all_app_configs():
            try:
                with open(p) as f:
                    configs_data.append(json.load(f))
            except Exception:
                pass

    headers = ["APP", "JOB ID", "SCHEDULE", "MODE", "STATE", "LAST RUN", "STATUS", "DURATION", "COMMAND"]
    table_rows = []

    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        for cfg in configs_data:
            app_name = cfg.get("name", "-")
            for job in get_app_crons(cfg):
                jid = job["id"]
                sched = job["schedule"]
                mode = job["mode"]
                state_str = "ON" if job.get("enabled", True) else "OFF"
                cmd_str = job["command"]

                last_row = conn.execute(
                    "SELECT status, exit_code, started_at, duration_sec FROM cron_executions WHERE app = ? AND job_id = ? ORDER BY id DESC LIMIT 1",
                    (app_name, jid),
                ).fetchone()

                if last_row:
                    last_time = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_row["started_at"]))
                    st = last_row["status"]
                    if st == "SUCCESS":
                        st_disp = "SUCCESS (0)"
                    elif last_row["exit_code"] is not None:
                        st_disp = f"{st} ({last_row['exit_code']})"
                    else:
                        st_disp = st
                    dur_disp = f"{last_row['duration_sec']:.2f}s" if last_row["duration_sec"] is not None else "-"
                else:
                    last_time = "never"
                    st_disp = "-"
                    dur_disp = "-"

                table_rows.append([app_name, jid, sched, mode, state_str, last_time, st_disp, dur_disp, cmd_str])

    if not table_rows:
        scope = f"for app '{target_app}'" if target_app else "across applications"
        print(f"No cron jobs configured {scope}. Add one with: lamo app cron add <app> <id> '<schedule>' '<command>'")
        return

    hdr_line, sep_line, row_lines = format_table(headers, table_rows, max_width=115)
    w = max(len(hdr_line), 80)
    print("")
    print("=" * w)
    title_scope = f"App '{target_app}'" if target_app else "All Applications"
    print(f" BOVER :: Per-Project Scheduled Cron Jobs ({title_scope})")
    print("=" * w)
    print(hdr_line)
    print(sep_line)
    for r in row_lines:
        print(r)
    print("-" * w)
    print("")


def cron_history(target_app: Optional[str] = None, job_id: Optional[str] = None, limit: int = 25):
    """Display audit log of past cron executions, statuses, exit codes, and durations."""
    init_db()
    query = "SELECT * FROM cron_executions"
    params: List[Any] = []
    clauses = []
    if target_app:
        validate_app_name(target_app)
        clauses.append("app = ?")
        params.append(target_app)
    if job_id:
        validate_cron_id(job_id)
        clauses.append("job_id = ?")
        params.append(job_id)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))

    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, tuple(params)).fetchall()

    if not rows:
        print("No cron execution history recorded yet.")
        return

    print("")
    print("=" * 115)
    print(" BOVER :: Cron Execution History & Audit Registry")
    print("=" * 115)
    print(f"{'ID':<6} {'APP':<12} {'JOB ID':<16} {'MODE':<6} {'STATUS':<10} {'EXIT':<6} {'DURATION':<10} {'TRIGGER':<10} {'DATE':<19} {'COMMAND'}")
    print("-" * 115)

    for r in rows:
        date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["started_at"]))
        dur_str = f"{r['duration_sec']:.2f}s" if r["duration_sec"] is not None else "-"
        exit_str = str(r["exit_code"]) if r["exit_code"] is not None else "-"
        cmd_disp = (r["command"][:28] + "…") if len(r["command"]) > 29 else r["command"]
        print(
            f"{r['id']:<6} {r['app']:<12} {r['job_id']:<16} {r['mode']:<6} "
            f"{r['status']:<10} {exit_str:<6} {dur_str:<10} {(r['triggered_by'] or 'schedule'):<10} {date_str:<19} {cmd_disp}"
        )
        if r["status"] in ("FAILED", "TIMEOUT") and r["output"]:
            last_line = [ln.strip() for ln in r["output"].splitlines() if ln.strip()][-1:]
            if last_line:
                snippet = last_line[0][:90]
                print(f"       └── Output: {snippet} (inspect full log: lamo app cron show {r['id']})")

    print("-" * 115)
    print("")


def cron_show(run_id: int):
    """Display full execution metadata and captured stdout/stderr for a specific cron run ID."""
    init_db()
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM cron_executions WHERE id = ?", (int(run_id),)).fetchone()

    if not row:
        print(f"ERROR: Cron execution record #{run_id} not found.", file=sys.stderr)
        sys.exit(1)

    start_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["started_at"]))
    fin_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row["finished_at"])) if row["finished_at"] else "-"
    dur_str = f"{row['duration_sec']:.2f}s" if row["duration_sec"] is not None else "-"

    print("")
    print("=" * 80)
    print(f" BOVER :: Cron Execution Record #{row['id']}")
    print("=" * 80)
    print(f" Application:   {row['app']}")
    print(f" Job ID:        {row['job_id']} (Schedule: {row['schedule'] or '-'})")
    print(f" Execution Mode:{row['mode']} (Container: {row['container'] or '-'})")
    print(f" Command:       {row['command']}")
    print(f" Triggered By:  {row['triggered_by'] or 'schedule'}")
    print(f" Started At:    {start_str}")
    print(f" Finished At:   {fin_str}")
    print(f" Duration:      {dur_str}")
    print(f" Status:        {row['status']} (Exit Code: {row['exit_code'] if row['exit_code'] is not None else '-'})")
    print("-" * 80)
    print(" Captured Output (stdout / stderr):")
    print("-" * 80)
    print(row["output"] if row["output"] else "(no output)")
    print("=" * 80)
    print("")


# ==============================================================================
# 7. MAIN CLI ENTRYPOINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="bover (Es Bover) CLI - Node Runtime Worker & Container Deployer"
    )
    subparsers = parser.add_subparsers(dest="command")

    # init
    subparsers.add_parser("init", help="Initialize Caddy ALB gateway, systemd units, and metrics timer")

    # add
    add_p = subparsers.add_parser("add", help="Add an application (interactive wizard or flag-based)")
    add_p.add_argument("target", nargs="?", help="Git repository URL (e.g. git@github.com:...) or service name")
    add_p.add_argument("--domain", "-d", help="Domain or subdomain (required in non-interactive mode)")
    add_p.add_argument("--port", "-p", type=int, help="Internal container port")
    add_p.add_argument("--repo", "-r", help="Git repository URL")
    add_p.add_argument("--branch", "-b", default="master", help="Git branch (default: master)")
    add_p.add_argument("--healthcheck", default="/", help="Healthcheck URL path (default: /)")
    add_p.add_argument("--auto-deploy", action="store_true", help="Enable automatic continuous deployment on git push")
    add_p.add_argument("--keep-versions", "-k", type=int, default=3, help="Number of version images to retain (default: 3)")
    add_p.add_argument("--cpu", type=float, default=0.5, help="Maximum CPU limit (default: 0.5)")
    add_p.add_argument("--memory", "-m", default="512m", help="Maximum RAM limit (default: 512m)")
    add_p.add_argument("--type", choices=["auto", "dockerfile", "compose"], default="auto", help="Build type (default: auto)")
    add_p.add_argument("--redirect", "--redirects", help="Domain(s) to redirect permanently to primary domain")
    add_p.add_argument("--data-dir", help="Custom host storage directory (e.g. /mnt/storage/app/data)")

    # prune
    prune_p = subparsers.add_parser("prune", help="Enforce version retention lifecycle and prune old images")
    prune_p.add_argument("app", nargs="?", help="Specific app name (optional, prunes all apps if omitted)")

    # autodeploy
    subparsers.add_parser("autodeploy", help="Poll remote git repos and auto-deploy new commits")

    # deploy
    deploy_p = subparsers.add_parser("deploy", help="Deploy an app with zero-downtime Blue/Green strategy")
    deploy_p.add_argument("name", help="Application name")
    deploy_p.add_argument("--no-pull", action="store_true", help="Deploy without pulling from git")
    deploy_p.add_argument("--resume", action="store_true", help="Resume an interrupted deployment from its checkpoint journal")

    # rollback
    rb_p = subparsers.add_parser("rollback", help="Roll back to previous deployment slot")
    rb_p.add_argument("name", help="Application name")

    # start / stop / restart
    start_p = subparsers.add_parser("start", help="Start the active slot of an app (systemd integration)")
    start_p.add_argument("name", help="Application name")

    stop_p = subparsers.add_parser("stop", help="Stop an app")
    stop_p.add_argument("name", help="Application name")

    restart_p = subparsers.add_parser("restart", help="Restart an app with zero-downtime")
    restart_p.add_argument("name", help="Application name")

    # logs
    logs_p = subparsers.add_parser("logs", help="Tail logs for an app")
    logs_p.add_argument("name", nargs="?", default="gateway", help="App name (or 'gateway')")
    logs_p.add_argument("-f", "--follow", action="store_true", help="Follow log output")
    logs_p.add_argument("-n", "--lines", type=int, default=100, help="Number of lines to show")

    # remove / destroy
    rm_p = subparsers.add_parser("remove", aliases=["rm", "destroy"], help="Decommission and remove an application")
    rm_p.add_argument("name", help="Application name")
    rm_p.add_argument("--keep-data", action="store_true", help="Preserve persistent data directory (/data)")
    rm_p.add_argument("--force", "-f", action="store_true", help="Force decommission without interactive prompt")

    # env
    env_p = subparsers.add_parser("env", help="Manage application and server-shared environment variables & secrets")
    env_p.add_argument("target", nargs="?", default="shared", help="App name or 'shared' (default: shared)")
    env_p.add_argument("--set", "-s", metavar="KEY=VAL", action="append", help="Set environment variable(s)")
    env_p.add_argument("--unset", "-u", metavar="KEY", action="append", help="Unset environment variable(s)")

    # stats
    stats_p = subparsers.add_parser("stats", help="Display aggregated container resource usage (Now, 24h, 48h, 7d, 30d)")
    stats_p.add_argument("app", nargs="?", help="Specific app name (optional)")

    # disk
    disk_p = subparsers.add_parser("disk", help="Display app disk usage, data/db size and historical differentials")
    disk_p.add_argument("app", nargs="?", help="Specific app name (optional)")

    # visits
    visits_p = subparsers.add_parser("visits", help="Display Caddy HTTP traffic, visit counts, and status breakdown")
    visits_p.add_argument("app", nargs="?", help="Specific app name (optional)")

    # systemd
    subparsers.add_parser("systemd", help="Reinstall and reload systemd service units")

    # history
    hist_p = subparsers.add_parser("history", help="Show deployment and rollback audit history")
    hist_p.add_argument("app", nargs="?", help="Specific app name (optional)")
    hist_p.add_argument("-n", "--limit", type=int, default=20, help="Number of records to show (default: 20)")

    # telegram
    tg_p = subparsers.add_parser("telegram", help="Configure or test Telegram deployment notifications")
    tg_p.add_argument("action", choices=["test", "send", "config"], nargs="?", default=None, help="Action ('test', 'send', 'config')")
    tg_p.add_argument("message", nargs="?", default=None, help="Message text if action is 'send'")
    tg_p.add_argument("--token", help="Telegram Bot Token (from @BotFather)")
    tg_p.add_argument("--chat-id", help="Telegram Chat ID")
    tg_p.add_argument("--test", action="store_true", help="Send a test notification")
    tg_p.add_argument("--send", help="Send a custom alert notification to Telegram")

    # backup
    bk_p = subparsers.add_parser("backup", help="Manage automated Cloudflare R2 / S3 backups")
    bk_sub = bk_p.add_subparsers(dest="backup_action", help="Backup action")
    bk_sub.add_parser("all", help="Run automated backup for all apps with auto_backup enabled")
    bk_run_p = bk_sub.add_parser("run", help="Run immediate backup for one or more applications")
    bk_run_p.add_argument("apps", nargs="+", help="Application name(s) to back up")
    bk_cfg_p = bk_sub.add_parser("config", help="Configure Cloudflare R2 / S3 credentials securely")
    bk_cfg_p.add_argument("--account-id", help="Cloudflare Account ID")
    bk_cfg_p.add_argument("--access-key", help="R2 Access Key ID")
    bk_cfg_p.add_argument("--secret-key", help="R2 Secret Access Key")
    bk_cfg_p.add_argument("--bucket", help="R2 Bucket Name")

    bk_ls_p = bk_sub.add_parser("list", aliases=["ls"], help="List backup archives available in Cloudflare R2")
    bk_ls_p.add_argument("app", nargs="?", default=None, help="Optional application name")

    bk_ver_p = bk_sub.add_parser("verify", aliases=["check", "test"], help="Download and verify backup integrity (SQLite PRAGMA, schema, and files)")
    bk_ver_p.add_argument("app", help="Application name to verify")
    bk_ver_p.add_argument("--key", default=None, help="Specific R2 key to verify (defaults to latest)")
    bk_ver_p.add_argument("--file", default=None, help="Local backup tar.gz file to verify instead of downloading from R2")

    bk_prune_p = bk_sub.add_parser("prune", help="Rotate and prune local backup archives on disk (default: retain last 5 days)")
    bk_prune_p.add_argument("app", nargs="?", default=None, help="Optional application name")
    bk_prune_p.add_argument("--days", type=int, default=5, help="Number of days of local backups to retain (default: 5)")

    # cron
    cron_p = subparsers.add_parser("cron", aliases=["crons"], help="Manage per-project scheduled cron jobs & execution history")
    cron_sub = cron_p.add_subparsers(dest="cron_action", help="Cron action")

    cron_ls_p = cron_sub.add_parser("list", aliases=["ls"], help="List configured cron jobs and last execution status")
    cron_ls_p.add_argument("app", nargs="?", default=None, help="Optional application name")

    cron_add_p = cron_sub.add_parser("add", help="Add or update a scheduled cron job for an application")
    cron_add_p.add_argument("app", help="Application name")
    cron_add_p.add_argument("job_id", help="Unique cron job identifier (e.g. daily-cleanup)")
    cron_add_p.add_argument("schedule", help="5-field cron schedule (e.g. '0 3 * * *') or macro (@daily, @hourly, @every 5m)")
    cron_add_p.add_argument("job_command", help="Command to execute inside container")
    cron_add_p.add_argument("--mode", choices=["exec", "run"], default="exec", help="Execution mode: 'exec' (active container) or 'run' (ephemeral isolated container)")
    cron_add_p.add_argument("--timeout", type=int, default=3600, help="Maximum execution timeout in seconds (default: 3600)")
    cron_add_p.add_argument("--notify", choices=["on_failure", "always", "never"], default="on_failure", help="Telegram notification policy (default: on_failure)")
    cron_add_p.add_argument("--description", default="", help="Optional description for the cron job")
    cron_add_p.add_argument("--overlap", action="store_true", help="Allow overlapping concurrent executions of this job")

    cron_rm_p = cron_sub.add_parser("remove", aliases=["rm", "delete"], help="Remove a cron job from an application")
    cron_rm_p.add_argument("app", help="Application name")
    cron_rm_p.add_argument("job_id", help="Cron job ID to remove")

    cron_en_p = cron_sub.add_parser("enable", help="Enable a cron job")
    cron_en_p.add_argument("app", help="Application name")
    cron_en_p.add_argument("job_id", help="Cron job ID to enable")

    cron_dis_p = cron_sub.add_parser("disable", help="Disable/pause a cron job")
    cron_dis_p.add_argument("app", help="Application name")
    cron_dis_p.add_argument("job_id", help="Cron job ID to disable")

    cron_run_p = cron_sub.add_parser("run", help="Manually trigger a cron job immediately and inspect output")
    cron_run_p.add_argument("app", help="Application name")
    cron_run_p.add_argument("job_id", help="Cron job ID to execute now")

    cron_hist_p = cron_sub.add_parser("history", aliases=["logs", "runs"], help="Show cron execution audit history, status & durations")
    cron_hist_p.add_argument("app", nargs="?", default=None, help="Optional application name")
    cron_hist_p.add_argument("--job", "-j", dest="job_id", default=None, help="Filter by specific cron job ID")
    cron_hist_p.add_argument("-n", "--limit", type=int, default=25, help="Number of execution records to show (default: 25)")

    cron_show_p = cron_sub.add_parser("show", aliases=["output", "inspect"], help="Inspect full details and stdout/stderr of a cron execution")
    cron_show_p.add_argument("run_id", type=int, help="Execution run ID (#)")

    cron_sub.add_parser("tick", help="Internal: evaluate and run due cron jobs for the current minute")

    # utility commands
    subparsers.add_parser("sample", help="Internal: record point-in-time container metrics to SQLite")
    subparsers.add_parser("sync", help="Synchronize app.json files with Caddy")
    list_p = subparsers.add_parser("list", help="List active apps, domains, slots and status")
    list_p.add_argument("app", nargs="?", help="Specific app name (optional)")
    status_p = subparsers.add_parser("status", help="Inspect live application health, HTTP response & routing state")
    status_p.add_argument("app", nargs="?", help="Specific app name (optional)")
    cfg_p = subparsers.add_parser("config", help="Display full app configuration, routing and metadata")
    cfg_p.add_argument("app", help="Application name")
    cfg_p.add_argument("--json", action="store_true", help="Output raw JSON configuration")
    cfg_p.add_argument("--show-secrets", action="store_true", help="Display unmasked environment secrets")
    subparsers.add_parser("node-stats", help="Display host node system telemetry and metrics")
    subparsers.add_parser("reload", help="Reload Caddy configuration with 0 downtime")
    caddy_p = subparsers.add_parser("caddy", help="Manage central Caddy reverse proxy gateway")
    caddy_p.add_argument("action", choices=["status", "stats", "reload", "logs"], default="status", nargs="?")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Principle of least privilege: drop root privileges to 'bover' daemon user
    if args.command not in ("init", "systemd"):
        drop_privileges_to_bover()

    if args.command == "init":
        init_gateway()
    elif args.command == "systemd":
        install_systemd_units()
    elif args.command == "deploy":
        deploy_app(args.name, no_pull=args.no_pull, resume=args.resume)
    elif args.command == "rollback":
        rollback_app(args.name)
    elif args.command == "start":
        start_app(args.name)
    elif args.command == "stop":
        stop_app(args.name)
    elif args.command == "restart":
        deploy_app(args.name, no_pull=True)
    elif args.command == "logs":
        if args.name == "gateway":
            run_cmd(f"docker logs {'-f' if args.follow else ''} --tail {args.lines} {CADDY_CONTAINER}")
        else:
            logs_app(args.name, lines=args.lines, follow=args.follow)
    elif args.command == "sample":
        sample_metrics()
    elif args.command == "stats":
        show_stats(args.app)
    elif args.command == "disk":
        show_disk(args.app)
    elif args.command == "visits":
        show_visits(args.app)
    elif args.command in ("remove", "rm", "destroy"):
        remove_app(args.name, keep_data=args.keep_data, force=args.force)
    elif args.command == "env":
        manage_env(target=args.target, set_vars=args.set, unset_vars=args.unset)
    elif args.command == "add":
        target = args.target
        if not target:
            try:
                target = input("Enter Git repository URL (e.g. git@github.com:owner/repo.git): ").strip()
            except (KeyboardInterrupt, EOFError):
                sys.exit(1)

        is_repo_url = any(target.startswith(prefix) for prefix in ["git@", "http://", "https://", "ssh://"]) or target.endswith(".git")

        if is_repo_url and not (args.domain and args.port):
            wizard_add_app(target)
        else:
            if not args.domain or not args.port:
                print("ERROR: In non-interactive mode, both --domain and --port are required.")
                print(f"Usage: bover add {target} --domain <domain> --port <port> [--repo <repo>]")
                sys.exit(1)
            add_app(
                name=target,
                domain=args.domain,
                port=args.port,
                repo=args.repo or (target if is_repo_url else None),
                branch=args.branch,
                healthcheck=args.healthcheck,
                auto_deploy=args.auto_deploy,
                keep_versions=args.keep_versions,
                cpu=args.cpu,
                memory=args.memory,
                app_type=getattr(args, "type", "auto"),
                redirects=getattr(args, "redirect", None),
                data_dir=getattr(args, "data_dir", None),
            )
    elif args.command == "prune":
        if args.app:
            cfg = load_app_config(args.app)
            keep = int(cfg.get("keep_versions", 3)) if cfg else 3
            prune_app_versions(args.app, keep_versions=keep)
        else:
            configs = get_all_app_configs()
            for c_path in configs:
                try:
                    with open(c_path) as f:
                        d = json.load(f)
                    aname = d.get("name")
                    keep = int(d.get("keep_versions", 3))
                    if aname:
                        prune_app_versions(aname, keep_versions=keep)
                except Exception:
                    pass
            run_cmd("docker image prune -f >/dev/null 2>&1 || true")
    elif args.command == "autodeploy":
        check_autodeploy()
    elif args.command == "history":
        show_history(args.app, limit=args.limit)
    elif args.command == "telegram":
        action = getattr(args, "action", None)
        if args.token and args.chat_id:
            configure_telegram(args.token, args.chat_id, test=True)
        elif getattr(args, "send", None) or action == "send":
            msg = getattr(args, "send", None) or getattr(args, "message", None)
            if not msg:
                print("ERROR: Message text required for 'telegram send <message>'")
                sys.exit(1)
            if send_telegram(msg):
                print("==> Alert delivered to Telegram successfully!")
            else:
                sys.exit(1)
        elif args.test or action == "test":
            hostname = run_cmd("hostname", capture=True) or "server"
            test_text = (
                f"🤖 <b>ES BOVER · TEST DE NOTIFICACIÓN</b>\n"
                f"<i>Canal de alertas operativo</i>\n\n"
                f"🖥️  <b>Nodo:</b> <code>{hostname}</code>\n"
                f"Las notificaciones de alertas y copias de seguridad están operativas."
            )
            if send_telegram(test_text):
                print("==> Test alert delivered to Telegram successfully!")
            else:
                print("ERROR: Failed to send test alert. Run 'bover telegram' to configure.")
        else:
            print("==> Configuring Telegram bot notifications securely...")
            try:
                token = getpass.getpass("Telegram Bot Token (hidden): ").strip()
                chat_id = input("Telegram Chat ID: ").strip()
            except (KeyboardInterrupt, EOFError):
                print("\nAborted.")
                sys.exit(1)
            if not token or not chat_id:
                print("ERROR: Both Bot Token and Chat ID are required.")
                sys.exit(1)
            configure_telegram(token, chat_id, test=True)
    elif args.command == "backup":
        if args.backup_action == "config":
            configure_s3(
                account_id=getattr(args, "account_id", None),
                access_key=getattr(args, "access_key", None),
                secret_key=getattr(args, "secret_key", None),
                bucket=getattr(args, "bucket", None),
            )
        elif args.backup_action in ("all", "run-all"):
            backup_all()
        elif args.backup_action == "run":
            run_backups_batch(args.apps)
        elif args.backup_action in ("list", "ls"):
            cmd_backup_list(getattr(args, "app", None))
        elif args.backup_action in ("verify", "check", "test"):
            ok = cmd_backup_verify(
                app_name=args.app,
                key=getattr(args, "key", None),
                file_path=getattr(args, "file", None)
            )
            if not ok:
                sys.exit(1)
        elif args.backup_action in ("prune", "rotate", "clean"):
            cmd_backup_prune(getattr(args, "app", None), keep_days=getattr(args, "days", 5))
        else:
            bk_p.print_help()
    elif args.command in ("cron", "crons"):
        c_act = getattr(args, "cron_action", None)
        if c_act in (None, "list", "ls"):
            cron_list(getattr(args, "app", None))
        elif c_act == "add":
            try:
                cron_add(
                    app_name=args.app,
                    job_id=args.job_id,
                    schedule=args.schedule,
                    command=args.job_command,
                    mode=args.mode,
                    timeout=args.timeout,
                    notify=args.notify,
                    description=args.description,
                    allow_overlap=args.overlap,
                )
            except ValueError as ve:
                print(f"ERROR: {ve}", file=sys.stderr)
                sys.exit(1)
        elif c_act in ("remove", "rm", "delete"):
            cron_remove(args.app, args.job_id)
        elif c_act == "enable":
            cron_toggle(args.app, args.job_id, enabled=True)
        elif c_act == "disable":
            cron_toggle(args.app, args.job_id, enabled=False)
        elif c_act == "run":
            cron_run_manual(args.app, args.job_id)
        elif c_act in ("history", "logs", "runs"):
            cron_history(target_app=getattr(args, "app", None), job_id=getattr(args, "job_id", None), limit=getattr(args, "limit", 25))
        elif c_act in ("show", "output", "inspect"):
            cron_show(args.run_id)
        elif c_act == "tick":
            cron_tick()
        else:
            cron_p.print_help()
    elif args.command == "sync":
        sync_all()
    elif args.command in ("list", "status"):
        if getattr(args, "app", None):
            show_app_status(args.app)
        else:
            list_apps()
    elif args.command == "config":
        show_app_config(args.app, as_json=args.json, show_secrets=args.show_secrets)
    elif args.command == "node-stats":
        show_node_stats()
    elif args.command == "reload":
        reload_caddy()
    elif args.command == "caddy":
        act = getattr(args, "action", "status")
        if act == "status":
            show_caddy_status()
        elif act == "stats":
            show_caddy_stats()
        elif act == "reload":
            reload_caddy()
        elif act == "logs":
            tail_logs("gateway", follow=True)


if __name__ == "__main__":
    main()

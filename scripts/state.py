#!/usr/bin/env python3
"""
VPS Node Provisioning State Manager & Change Tracker
Tracks step execution, calculates SHA-256 script checksums, and enables
idempotent incremental provisioning (only executing pending or changed steps).
"""

import sys
import os
import re
import json
import time
import hashlib
import argparse
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = BASE_DIR / "scripts"
CONFIG_CANDIDATES = [
    BASE_DIR / "inventory" / "config.env",
    BASE_DIR / ".lamo" / "config.env",
    BASE_DIR / "config.env",
]
CONFIG_FILE = next((p for p in CONFIG_CANDIDATES if p.exists()), BASE_DIR / "config.env")
STATE_FILE_REMOTE = "/etc/node-state.json"
SSH_MUX_DIR = f"/tmp/ssh-mux-{os.getuid()}"


def load_config():
    """Load variables from config.env with environment variable overrides."""
    cfg = {
        "SERVER_IP": "",
        "BOOTSTRAP_USER": "root",
        "BOOTSTRAP_PORT": "22",
        "ADMIN_USER": "admin",
        "SSH_PORT": "2245",
        "SERVER_HOSTNAME": "myserver",
        "SWAP_SIZE_GB": "2",
        "NODE_NAME": "default",
        "USER_AUDIT_RETENTION_DAYS": "7",
        "JOURNALD_MAX_USE_MB": "150",
        "DOCKER_LOG_MAX_SIZE": "10m",
        "DOCKER_LOG_MAX_FILES": "3",
        "CONTAINER_RUNTIME": "docker",
    }
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    cfg[k] = v

    # Environment variables override config.env (allows lamo to target any cattle node dynamically)
    env_keys = [
        "SERVER_IP", "BOOTSTRAP_USER", "BOOTSTRAP_PORT", "ADMIN_USER",
        "SSH_PORT", "SERVER_HOSTNAME", "SWAP_SIZE_GB", "NODE_NAME",
        "USER_AUDIT_RETENTION_DAYS", "JOURNALD_MAX_USE_MB",
        "DOCKER_LOG_MAX_SIZE", "DOCKER_LOG_MAX_FILES",
        "CONTAINER_RUNTIME",
    ]
    for key in env_keys:
        if os.environ.get(key):
            cfg[key] = os.environ[key]

    return cfg


# Definition of all provisioning steps in strict logical dependency order
ALL_STEPS = [
    {
        "id": "step-user",
        "name": "Create Admin User & Sudo",
        "script": "01-create-user.sh",
        "args": ["ADMIN_USER"],
        "bootstrap": True,
        "depends_on": [],
    },
    {
        "id": "step-ssh",
        "name": "Harden SSH Port & Key Auth",
        "script": "02-harden-ssh.sh",
        "args": ["SSH_PORT", "ADMIN_USER"],
        "bootstrap": True,
        "depends_on": ["step-user"],
    },
    {
        "id": "step-system",
        "name": "Kernel Sysctl, Fail2ban & Auto-updates",
        "script": "03-harden-system.sh",
        "args": ["SSH_PORT", "USER_AUDIT_RETENTION_DAYS", "JOURNALD_MAX_USE_MB"],
        "bootstrap": False,
        "depends_on": ["step-ssh"],
    },
    {
        "id": "step-swap",
        "name": "Swapfile Allocation & OOM Memory Policies",
        "script": "11-setup-swap-and-memory.sh",
        "args": ["SWAP_SIZE_GB"],
        "bootstrap": False,
        "depends_on": ["step-system"],
    },
    {
        "id": "step-docker",
        "name": "Container Engine (Docker / Podman)",
        "script": "04-install-docker.sh",
        "args": ["ADMIN_USER", "CONTAINER_RUNTIME"],
        "bootstrap": False,
        "depends_on": ["step-system", "step-swap"],
    },
    {
        "id": "step-app-user",
        "name": "Isolated 'bover' Daemon User & Docker Hardening",
        "script": "08-setup-app-user-and-docker-hardening.sh",
        "extra_files": ["scripts/bover-helper.sh"],
        "args": ["ADMIN_USER", "DOCKER_LOG_MAX_SIZE", "DOCKER_LOG_MAX_FILES"],
        "bootstrap": False,
        "depends_on": ["step-docker"],
    },
    {
        "id": "step-keys",
        "name": "GitHub Deploy Keys Isolation",
        "script": "05-setup-deploy-keys.sh",
        "args": ["ADMIN_USER"],
        "bootstrap": False,
        "depends_on": ["step-app-user"],
    },
    {
        "id": "step-prompt",
        "name": "Custom Prompt, MOTD Dashboard & Tools",
        "script": "06-custom-prompt-motd.sh",
        "args": ["SERVER_HOSTNAME", "ADMIN_USER"],
        "bootstrap": False,
        "depends_on": ["step-user"],
    },
    {
        "id": "step-tmux",
        "name": "Tmux Vi-Mode & Vim Setup",
        "script": "07-tmux-vim-setup.sh",
        "args": ["ADMIN_USER"],
        "bootstrap": False,
        "depends_on": ["step-user"],
    },
    {
        "id": "step-cis",
        "name": "CIS Benchmark Hardening & Post-Quantum SSH",
        "script": "09-cis-hardening.sh",
        "args": ["ADMIN_USER", "SSH_PORT"],
        "bootstrap": False,
        "depends_on": ["step-ssh", "step-system"],
    },
    {
        "id": "step-gateway",
        "name": "Caddy Gateway ALB, Bover CLI & Timers",
        "script": "10-setup-gateway-and-cli.sh",
        "extra_files": ["scripts/bover-cli.py", "templates/gateway"],
        "args": ["ADMIN_USER"],
        "bootstrap": False,
        "depends_on": ["step-docker", "step-app-user"],
    },
]


def calculate_local_hash(step):
    """Compute SHA-256 hash of the step script and any extra files."""
    hasher = hashlib.sha256()
    main_script = SCRIPTS_DIR / step["script"]
    if not main_script.exists():
        return "missing"
    hasher.update(main_script.read_bytes())

    for extra in step.get("extra_files", []):
        extra_path = BASE_DIR / extra
        if extra_path.is_file():
            hasher.update(extra_path.read_bytes())
        elif extra_path.is_dir():
            for f in sorted(extra_path.glob("**/*")):
                if f.is_file():
                    hasher.update(f.read_bytes())

    return hasher.hexdigest()[:12]


def ssh_run(cmd, cfg, bootstrap=False, capture=True, input_str=None):
    """Execute command over SSH with connection multiplexing and automatic bootstrap/hardened fallback."""
    Path(SSH_MUX_DIR).mkdir(parents=True, exist_ok=True)
    mux_opts = (
        f"-o ControlMaster=auto -o ControlPath={SSH_MUX_DIR}/%C -o ControlPersist=10m "
        f"-o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR"
    )
    cmd_arg = cmd if input_str is not None else json.dumps(cmd)

    # Always prefer hardened port first (instant Connection Refused if not hardened yet),
    # then fallback to bootstrap port if bootstrap=True or hardened port is unreachable.
    ports_to_try = [(cfg['ADMIN_USER'], cfg['SSH_PORT'], False)]
    if bootstrap or (cfg.get('BOOTSTRAP_PORT') and cfg.get('BOOTSTRAP_USER')):
        boot_pair = (cfg['BOOTSTRAP_USER'], cfg['BOOTSTRAP_PORT'], True)
        if boot_pair[:2] != ports_to_try[0][:2]:
            ports_to_try.append(boot_pair)

    res = None
    for target_user, target_port, _is_boot in ports_to_try:
        ssh_cmd = f"ssh {mux_opts} -p {target_port} {target_user}@{cfg['SERVER_IP']} {cmd_arg}"
        res = subprocess.run(
            ssh_cmd,
            shell=True,
            input=input_str,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            text=True,
        )
        if res.returncode == 0:
            break

    if capture and res:
        return res.returncode == 0, res.stdout.strip(), res.stderr.strip()
    return (res.returncode == 0) if res else False, "", ""


def scp_upload(local_path, remote_path, cfg, bootstrap=False):
    """Upload file via SCP with automatic fallback between hardened and bootstrap credentials."""
    Path(SSH_MUX_DIR).mkdir(parents=True, exist_ok=True)
    mux_opts = (
        f"-o ControlMaster=auto -o ControlPath={SSH_MUX_DIR}/%C -o ControlPersist=10m "
        f"-o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR"
    )
    is_dir = "-r" if Path(local_path).is_dir() else ""

    ports_to_try = [(cfg['ADMIN_USER'], cfg['SSH_PORT'], False)]
    if bootstrap or (cfg.get('BOOTSTRAP_PORT') and cfg.get('BOOTSTRAP_USER')):
        boot_pair = (cfg['BOOTSTRAP_USER'], cfg['BOOTSTRAP_PORT'], True)
        if boot_pair[:2] != ports_to_try[0][:2]:
            ports_to_try.append(boot_pair)

    for target_user, target_port, _is_boot in ports_to_try:
        scp_cmd = f"scp {mux_opts} -P {target_port} {is_dir} {local_path} {target_user}@{cfg['SERVER_IP']}:{remote_path}"
        res = subprocess.run(scp_cmd, shell=True)
        if res.returncode == 0:
            return True

    return False


def fetch_remote_state(cfg):
    """Fetch remote /etc/node-state.json (with legacy fallback), merging auto-detected facts for missing steps."""
    admin_user = cfg.get("ADMIN_USER", "admin")
    probe_code = f"""
import json, os, subprocess, glob

state_file = '{STATE_FILE_REMOTE}'
data = {{}}
candidates = ['{STATE_FILE_REMOTE}']
for sf in candidates:
    if os.path.exists(sf):
        try:
            with open(sf) as f:
                data.update(json.load(f))
        except Exception:
            pass

def run(c):
    r = subprocess.run(c, shell=True, stdout=subprocess.PIPE, text=True)
    return r.stdout.strip() if r.returncode == 0 else ''

changed = False

if 'step-user' not in data and os.path.exists('/home/{admin_user}'):
    data['step-user'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-ssh' not in data and os.path.exists('/etc/ssh/sshd_config.d/99-hardening.conf'):
    data['step-ssh'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-system' not in data and run('systemctl is-active fail2ban') == 'active':
    data['step-system'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-docker' not in data and (run('docker --version') or run('podman --version')):
    data['step-docker'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-keys' not in data and (os.path.exists('/home/{admin_user}/.ssh/config') or glob.glob('/opt/apps/.ssh/id_deploy_*') or glob.glob('/home/{admin_user}/.ssh/id_deploy_*')):
    data['step-keys'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-prompt' not in data and os.path.exists('/etc/update-motd.d/10-sysinfo'):
    data['step-prompt'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-tmux' not in data and os.path.exists('/home/{admin_user}/.tmux.conf'):
    data['step-tmux'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-app-user' not in data and (os.path.exists('/opt/apps') and (os.path.exists('/etc/sudoers.d/91-{admin_user}-as-bover') or os.path.exists('/etc/sudoers.d/91-{admin_user}-as-app'))):
    data['step-app-user'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-cis' not in data and os.path.exists('/etc/modprobe.d/cis-blacklist.conf'):
    data['step-cis'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-swap' not in data and (os.path.exists('/swapfile') and 'swap' in run('swapon --show')):
    data['step-swap'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if 'step-gateway' not in data and (os.path.exists('/usr/local/bin/bover') and os.path.exists('/opt/apps/gateway/docker-compose.yml')):
    data['step-gateway'] = {{'status': 'COMPLETED', 'detected': True, 'executed_at': 'detected'}}
    changed = True

if changed:
    try:
        with open(state_file, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

print(json.dumps(data))
"""

    ok, out, _ = ssh_run("sudo python3 -", cfg, bootstrap=False, capture=True, input_str=probe_code)
    if not ok or not out:
        return {}
    try:
        return json.loads(out)
    except Exception:
        return {}


def update_remote_state(step_id, script_hash, cfg):
    """Record completed step and hash into /etc/node-state.json on server."""
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    update_code = f"""
import json, os

state_file = '{STATE_FILE_REMOTE}'
data = {{}}
if os.path.exists(state_file):
    try:
        with open(state_file) as f:
            data = json.load(f)
    except Exception:
        pass

data['{step_id}'] = {{
    'status': 'COMPLETED',
    'hash': '{script_hash}',
    'executed_at': '{now_str}'
}}

with open(state_file, 'w') as f:
    json.dump(data, f, indent=2)
"""
    ssh_run("sudo python3 -", cfg, bootstrap=False, capture=True, input_str=update_code)


def get_step_status(step, local_hash, remote_record):
    """Determine step state: COMPLETED, CHANGED, or PENDING."""
    if not remote_record or remote_record.get("status") != "COMPLETED":
        return "PENDING"
    remote_hash = remote_record.get("hash")
    if not remote_hash or remote_record.get("detected"):
        # Auto-detected from facts but without recorded hash -> consider completed unless forced
        return "COMPLETED (detected)"
    if remote_hash == local_hash:
        return "COMPLETED"
    return "CHANGED"


def is_step_completed(status):
    """Check if step status indicates completion (either hash-verified or fact-detected)."""
    return status.startswith("COMPLETED")


def show_status(cfg):
    """Display comprehensive provisioning state table."""
    print("==> Contacting server to verify provisioning state...")
    remote_state = fetch_remote_state(cfg)
    if not remote_state:
        print(f"⚠️  Could not retrieve remote state over SSH (host: {cfg['SERVER_IP']}, port: {cfg['SSH_PORT']}).")
        print("   Verify that the host is reachable and your SSH key is authorized.")

    print("")
    print("=" * 105)
    print(f" NODE PROVISIONING STATE :: Node: {cfg.get('NODE_NAME', cfg.get('SERVER_HOSTNAME', 'host'))} ({cfg.get('SERVER_IP')})")
    print("=" * 105)
    print(f"{'STEP':<15} {'SCRIPT':<38} {'STATUS':<20} {'HASH (LOC/REM)':<18} {'EXECUTED AT'}")
    print("-" * 105)

    pending_count = 0
    changed_count = 0
    completed_count = 0

    for step in ALL_STEPS:
        local_hash = calculate_local_hash(step)
        record = remote_state.get(step["id"])
        status = get_step_status(step, local_hash, record)
        remote_hash = record.get("hash", "-") if record else "-"
        executed_at = record.get("executed_at", "-") if record else "-"
        hash_disp = f"{local_hash} / {remote_hash}"

        status_disp = status
        if status == "COMPLETED" or status == "COMPLETED (detected)":
            completed_count += 1
            status_disp = f"✅ {status}"
        elif status == "CHANGED":
            changed_count += 1
            status_disp = "⚠️  CHANGED"
        else:
            pending_count += 1
            status_disp = "⏳ PENDING"

        print(f"{step['id']:<15} {step['script']:<38} {status_disp:<20} {hash_disp:<18} {executed_at}")

    print("-" * 105)
    print(f"Summary: {completed_count} completed, {changed_count} changed (needs re-run), {pending_count} pending.")
    if changed_count > 0 or pending_count > 0:
        print("💡 Run './lamo node setup' to execute pending or changed steps in order.")
    else:
        print("✨ All provisioning steps are fully completed and up to date!")
    print("")


def check_dependencies(step, remote_state):
    """Verify that all prerequisite steps have completed successfully."""
    deps = step.get("depends_on", [])
    for dep_id in deps:
        rec = remote_state.get(dep_id) if remote_state else None
        if not rec:
            return False, f"Prerequisite step '{dep_id}' is not completed."
        status = rec.get("status", "")
        if not ("COMPLETED" in status):
            return False, f"Prerequisite step '{dep_id}' is in status '{status}' (must be COMPLETED)."
    return True, ""


def execute_step(step, cfg, force=False, remote_state=None):
    """Run a single step if needed."""
    local_hash = calculate_local_hash(step)
    record = remote_state.get(step["id"]) if remote_state else None
    status = get_step_status(step, local_hash, record)

    if not force and is_step_completed(status):
        print(f"==> [{step['id']}] Already completed and unchanged (hash: {local_hash}). Skipping.")
        return True

    # Validate prerequisite dependencies before running
    if remote_state is not None:
        deps_ok, dep_err = check_dependencies(step, remote_state)
        if not deps_ok:
            print(f"\nERROR: Cannot execute [{step['id']}]. {dep_err}")
            return False

    reason = "forced" if force else ("script changed" if status == "CHANGED" else "pending")
    print(f"\n------------------------------------------------------------------")
    print(f" ==> [{step['id']}] Executing {step['script']} ({reason}, hash: {local_hash})...")
    print(f"------------------------------------------------------------------")

    # 1. Upload files
    ssh_run("mkdir -p /tmp/provision-scripts/templates", cfg, bootstrap=step["bootstrap"])
    main_file = SCRIPTS_DIR / step["script"]
    if not scp_upload(str(main_file), "/tmp/provision-scripts/", cfg, bootstrap=step["bootstrap"]):
        print(f"ERROR: Failed to upload {main_file}")
        return False

    for extra in step.get("extra_files", []):
        extra_path = BASE_DIR / extra
        dest = "/tmp/provision-scripts/templates/" if "templates" in extra else "/tmp/provision-scripts/"
        scp_upload(str(extra_path), dest, cfg, bootstrap=step["bootstrap"])

    # 2. Build command arguments
    cmd_args = [cfg.get(arg_key, "") for arg_key in step.get("args", [])]
    args_str = " ".join(cmd_args)
    remote_cmd = (
        f"chmod +x /tmp/provision-scripts/*.sh /tmp/provision-scripts/*.py 2>/dev/null || true && "
        f"sudo /tmp/provision-scripts/{step['script']} {args_str}"
    )

    # 3. Execute
    ok, _, _ = ssh_run(remote_cmd, cfg, bootstrap=step["bootstrap"], capture=False)
    if not ok:
        print(f"ERROR: Execution failed for {step['id']}")
        return False

    # 4. Update state
    update_remote_state(step["id"], local_hash, cfg)
    print(f"==> [{step['id']}] Step succeeded and recorded in remote state.")

    # 5. Clean up temporary uploaded scripts
    ssh_run("rm -rf /tmp/provision-scripts", cfg, bootstrap=step["bootstrap"], capture=True)
    return True


def run_pipeline(steps_filter, cfg, force=False):
    """Run a list of steps, automatically skipping completed/unchanged ones."""
    print("==> Checking remote provisioning state...")
    remote_state = fetch_remote_state(cfg)
    steps_to_run = [s for s in ALL_STEPS if steps_filter(s)]

    executed = 0
    skipped = 0

    for step in steps_to_run:
        local_hash = calculate_local_hash(step)
        record = remote_state.get(step["id"])
        status = get_step_status(step, local_hash, record)

        if not force and is_step_completed(status):
            print(f"  [✓] {step['id']:<15} (completed & unchanged, skipping)")
            skipped += 1
            continue

        success = execute_step(step, cfg, force=force, remote_state=remote_state)
        if not success:
            print(f"\nABORTING pipeline due to failure in {step['id']}.")
            sys.exit(1)
        executed += 1

    print("\n" + "=" * 65)
    print(f" PIPELINE SUMMARY: {executed} executed, {skipped} skipped.")
    print("=" * 65)


def main():
    parser = argparse.ArgumentParser(description="VPS Node Provisioning State Manager")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", help="Show current state of all provisioning steps")

    run_p = subparsers.add_parser("run", help="Run a specific step if pending/changed")
    run_p.add_argument("step_id", help="Step identifier (e.g. step-prompt, step-cis)")
    run_p.add_argument("--force", action="store_true", help="Force re-running even if unchanged")

    finish_p = subparsers.add_parser("finish-setup", help="Run pending post-bootstrap steps")
    finish_p.add_argument("--force", action="store_true", help="Force re-running all steps")

    apply_p = subparsers.add_parser("apply", help="Run all pending/changed steps")
    apply_p.add_argument("--force", action="store_true", help="Force re-running all steps")

    args = parser.parse_args()
    cfg = load_config()

    if not args.command or args.command == "status":
        show_status(cfg)
    elif args.command == "run":
        target_step = next((s for s in ALL_STEPS if s["id"] == args.step_id), None)
        if not target_step:
            print(f"ERROR: Unknown step '{args.step_id}'. Valid steps:")
            for s in ALL_STEPS:
                print(f"  - {s['id']}")
            sys.exit(1)
        remote_state = fetch_remote_state(cfg)
        success = execute_step(target_step, cfg, force=args.force, remote_state=remote_state)
        sys.exit(0 if success else 1)
    elif args.command in ("apply", "finish-setup"):
        run_pipeline(lambda s: True, cfg, force=args.force)


if __name__ == "__main__":
    main()

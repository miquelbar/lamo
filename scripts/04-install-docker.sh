#!/usr/bin/env bash
set -euo pipefail

# Script 04: Install Container Engine (Docker CE or Podman)
# - If docker: Adds official Docker CE repository and plugins, installs daemon & CLI
# - If podman: Installs podman, podman-compose, podman-docker (compat wrapper & socket)
# - Adds admin user to docker group

ADMIN_USER="${1:-${ADMIN_USER:-admin}}"
CONTAINER_RUNTIME="${2:-${CONTAINER_RUNTIME:-docker}}"
CONTAINER_RUNTIME="$(echo "${CONTAINER_RUNTIME}" | tr '[:upper:]' '[:lower:]')"

if [[ "${CONTAINER_RUNTIME}" == "podman" ]]; then
    if command -v podman >/dev/null 2>&1 && systemctl is-active --quiet podman.socket; then
        echo "==> [04] Podman is already installed and socket is active. Ensuring group membership and skipping reinstall."
        if ! getent group docker >/dev/null 2>&1; then
            groupadd -r docker
        fi
        usermod -aG docker "${ADMIN_USER}"
        podman --version
        exit 0
    fi

    echo "==> [04] Installing Podman container runtime and Compose / Docker compatibility..."
    apt-get update -qq
    apt-get install -y -qq podman podman-compose podman-docker uidmap dbus-user-session

    # Ensure system-wide podman socket is enabled (provides Docker-compatible API socket at /run/podman/podman.sock)
    systemctl daemon-reload
    systemctl enable --now podman.socket || true

    # Symlink /var/run/docker.sock to /run/podman/podman.sock if not present
    if [[ ! -S /var/run/docker.sock ]] && [[ -S /run/podman/podman.sock ]]; then
        ln -sf /run/podman/podman.sock /var/run/docker.sock
    fi

    # Ensure docker group exists and add admin user
    if ! getent group docker >/dev/null 2>&1; then
        groupadd -r docker
    fi
    usermod -aG docker "${ADMIN_USER}"

    echo "==> [04] Podman installation complete."
    podman --version
    if command -v docker >/dev/null 2>&1; then
        docker --version || true
    fi
else
    if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker; then
        echo "==> [04] Docker is already installed and daemon is active. Ensuring group membership and skipping reinstall."
        usermod -aG docker "${ADMIN_USER}"
        docker --version
        docker compose version
        exit 0
    fi

    echo "==> [04] Installing Docker dependencies..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg

    echo "==> [04] Installing official Docker GPG key and repository..."
    install -m 0755 -d /etc/apt/keyrings
    if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
        curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc
    fi

    # Detect Debian release codename (trixie, bookworm, etc.)
    . /etc/os-release
    DEBIAN_CODENAME="${VERSION_CODENAME:-bookworm}"

    cat <<EOF > /etc/apt/sources.list.d/docker.list
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian ${DEBIAN_CODENAME} stable
EOF

    # Note: If trixie repository isn't published yet in stable, fallback to bookworm automatically
    if ! apt-get update -qq; then
        echo "Notice: Falling back docker repository to bookworm for Debian testing/trixie compatibility..."
        cat <<EOF > /etc/apt/sources.list.d/docker.list
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable
EOF
        apt-get update -qq
    fi

    echo "==> [04] Installing Docker packages..."
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    echo "==> [04] Configuring Docker daemon log rotation (max-size=10m, max-file=3)..."
    mkdir -p /etc/docker
    if [[ ! -f /etc/docker/daemon.json ]]; then
        cat <<EOF > /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
EOF
    fi

    systemctl daemon-reload
    systemctl enable --now docker

    echo "==> [04] Adding user '${ADMIN_USER}' to 'docker' group..."
    usermod -aG docker "${ADMIN_USER}"

    echo "==> [04] Docker installation complete."
    docker --version
    docker compose version
fi

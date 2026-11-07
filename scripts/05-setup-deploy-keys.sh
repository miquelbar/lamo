#!/usr/bin/env bash
set -euo pipefail

# Script 05: Setup dedicated GitHub Deploy Keys for repositories
# Runs under the admin user
# Creates separate, read-only SSH keys per repository so the VPS has ZERO access
# to your personal GitHub account or any other repositories.

ADMIN_USER="${1:-${ADMIN_USER:-admin}}"
USER_HOME="/home/${ADMIN_USER}"
SSH_DIR="${USER_HOME}/.ssh"

echo "==> [05] Generating dedicated GitHub Deploy Keys for '${ADMIN_USER}'..."

mkdir -p "${SSH_DIR}"
chmod 700 "${SSH_DIR}"

generate_key() {
    local repo_name="$1"
    local key_file="${SSH_DIR}/id_deploy_${repo_name}"

    if [[ -f "${key_file}" ]]; then
        echo "Deploy key for '${repo_name}' already exists: ${key_file}"
    else
        echo "Generating ed25519 deploy key for '${repo_name}'..."
        ssh-keygen -t ed25519 -N "" -C "deploy-${repo_name}@${SERVER_HOSTNAME:-vps}" -f "${key_file}"
        chmod 600 "${key_file}"
        chmod 644 "${key_file}.pub"
    fi

    # Add host alias if not already in config
    if [[ ! -f "${SSH_DIR}/config" ]] || ! grep -q "Host github.com-${repo_name}" "${SSH_DIR}/config"; then
        cat <<EOF >> "${SSH_DIR}/config"

Host github.com-${repo_name}
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_deploy_${repo_name}
    IdentitiesOnly yes
EOF
    fi
}

# If DEPLOY_REPOS env is defined, generate keys for each repo name (comma or space separated)
DEPLOY_REPOS="${DEPLOY_REPOS:-}"
if [[ -n "${DEPLOY_REPOS}" ]]; then
    IFS=', ' read -r -a repos <<< "${DEPLOY_REPOS}"
    for repo in "${repos[@]}"; do
        [[ -n "${repo}" ]] && generate_key "${repo}"
    done
fi

touch "${SSH_DIR}/config"
chmod 600 "${SSH_DIR}/config"
chown -R "${ADMIN_USER}:${ADMIN_USER}" "${SSH_DIR}"

echo "==> [05] GitHub Deploy Keys structure initialized successfully."
echo "💡 Note: When using 'lamo add <repo>', dedicated ed25519 deploy keys are also generated automatically on demand."

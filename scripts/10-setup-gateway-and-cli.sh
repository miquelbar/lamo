#!/usr/bin/env bash
set -euo pipefail

# Script 10: Setup Central Gateway (Caddy ALB) & Install 'bover' CLI (Es Bover)
# Must be executed as root on the server

ADMIN_USER="${1:-${ADMIN_USER:-admin}}"
BOVER_USER="bover"
APPS_DIR="/opt/apps"
GATEWAY_DIR="${APPS_DIR}/gateway"

echo "==> [10] Installing and precompiling 'bover' CLI into /usr/local/lib/bover and /usr/local/bin/bover..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p /usr/local/lib/bover
cp "${SCRIPT_DIR}/bover-cli.py" /usr/local/lib/bover/bover_cli.py
python3 -m compileall -f -q /usr/local/lib/bover
chmod -R 755 /usr/local/lib/bover
cat <<'EOF' > /usr/local/bin/bover
#!/usr/bin/env python3
import sys
sys.path.insert(0, "/usr/local/lib/bover")
from bover_cli import main
if __name__ == "__main__":
    main()
EOF
chmod 755 /usr/local/bin/bover
# Clean up obsolete legacy symlinks if present
rm -f /usr/local/bin/pages /usr/local/bin/lamo /usr/local/bin/appctl

echo "==> [10] Deploying Caddy Gateway ALB templates..."
mkdir -p "${GATEWAY_DIR}/conf.d" "${GATEWAY_DIR}/logs"
if [[ -d "${SCRIPT_DIR}/templates/gateway" ]]; then
    cp -r "${SCRIPT_DIR}/templates/gateway/"* "${GATEWAY_DIR}/"
elif [[ -d "${SCRIPT_DIR}/../templates/gateway" ]]; then
    cp -r "${SCRIPT_DIR}/../templates/gateway/"* "${GATEWAY_DIR}/"
fi

# Initialize gateway using the new CLI
echo "==> [10] Initializing gateway network, Caddy container and metrics timer via 'bover'..."
/usr/local/bin/bover init

# Ensure correct ownership of gateway directory
chown -R "${BOVER_USER}:${BOVER_USER}" "${GATEWAY_DIR}"

echo "==> [10] 'bover' CLI, Gateway ALB and Metrics Sampler installed successfully."
/usr/local/bin/bover --help

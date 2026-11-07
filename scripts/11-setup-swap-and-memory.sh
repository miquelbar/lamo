#!/usr/bin/env bash
set -euo pipefail

# Script 11: Setup Swapfile & Kernel Memory / OOM Killer Tuning
# - Creates secure swapfile (default: 2GB) with 0600 permissions
# - Registers swapfile in /etc/fstab for persistence across reboots
# - Tunes kernel memory sysctl policies: swappiness, cache pressure, panic_on_oom=0

SWAP_SIZE_GB="${1:-2}"

echo "=================================================================="
echo " ==> [11] Configuring Swap & Kernel Memory Policies (${SWAP_SIZE_GB} GB)"
echo "=================================================================="

# 1. Check existing swap
SWAP_FILE="/swapfile"
DESIRED_MB=$((SWAP_SIZE_GB * 1024))
CURRENT_SWAP=$(free -m | awk '/Swap:/ {print $2}')

NEED_RECREATE=0

if [ "${CURRENT_SWAP}" -gt 0 ]; then
    DIFF=$((CURRENT_SWAP - DESIRED_MB))
    [ $DIFF -lt 0 ] && DIFF=$((-DIFF))
    if [ $DIFF -le 100 ]; then
        echo "==> [11] Swap is already active and matches configured capacity (${CURRENT_SWAP} MB)."
    else
        echo "==> [11] Reconfiguring swap size: current=${CURRENT_SWAP} MB -> desired=${DESIRED_MB} MB (${SWAP_SIZE_GB} GB)..."
        swapoff "${SWAP_FILE}" 2>/dev/null || swapoff -a 2>/dev/null || true
        rm -f "${SWAP_FILE}"
        NEED_RECREATE=1
    fi
else
    NEED_RECREATE=1
fi

if [ "${NEED_RECREATE}" -eq 1 ]; then
    echo "==> [11] Allocating ${SWAP_SIZE_GB} GB swapfile at ${SWAP_FILE}..."

    # Allocate file (fallocate with dd fallback)
    if ! fallocate -l "${SWAP_SIZE_GB}G" "${SWAP_FILE}" 2>/dev/null; then
        echo "==> fallocate failed, falling back to dd..."
        dd if=/dev/zero of="${SWAP_FILE}" bs=1M count=$((SWAP_SIZE_GB * 1024)) status=progress
    fi

    # Strict security permissions (CIS benchmark compliance)
    chmod 600 "${SWAP_FILE}"
    chown root:root "${SWAP_FILE}"

    # Format and activate swap
    echo "==> [11] Formatting swapfile..."
    mkswap "${SWAP_FILE}"

    echo "==> [11] Activating swapfile..."
    swapon "${SWAP_FILE}"

    # Persist in /etc/fstab
    if ! grep -q "${SWAP_FILE}" /etc/fstab; then
        echo "==> [11] Adding swapfile to /etc/fstab..."
        echo "${SWAP_FILE} none swap sw 0 0" >> /etc/fstab
    fi
    echo "==> [11] Swapfile created and activated successfully."
fi

# 2. Kernel Memory & OOM Hardening Policies
echo "==> [11] Applying kernel memory and OOM killer protection via sysctl..."
cat <<'EOF' > /etc/sysctl.d/98-memory-tuning.conf
# ==============================================================================
# Linux Kernel Memory Management & OOM Killer Tuning
# ==============================================================================

# 1. Swappiness: 10 (Don't aggressively swap to SSD; prioritize RAM, swap only under real pressure)
vm.swappiness = 10

# 2. VFS Cache Pressure: 50 (Preserve directory and inode caches in memory to keep SQLite & disk fast)
vm.vfs_cache_pressure = 50

# 3. OOM Killer: Never kernel panic on memory exhaustion
vm.panic_on_oom = 0

# 4. OOM Killer: Target the largest memory hog, not the allocating task
vm.oom_kill_allocating_task = 0

# 5. Overcommit Memory: 1 (Standard for Go runtimes, web backends, and Redis without spurious allocation failures)
vm.overcommit_memory = 1
EOF

sysctl --system >/dev/null

echo "==> [11] Current Memory & Swap status:"
free -m

echo "=================================================================="
echo " ==> [11] Swap and Kernel Memory Policies configured successfully!"
echo "=================================================================="

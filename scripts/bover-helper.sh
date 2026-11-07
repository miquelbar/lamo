#!/usr/bin/env bash
set -euo pipefail

# bover-helper: Scoped privileged helper for Es Bover daemon
# Restricts per-app user lifecycle and permissions strictly to /opt/apps/
# Must be executed as root via sudo by 'bover'

ACTION="${1:-}"
APP_NAME="${2:-}"

# Strict validation: app name must start with alphanumeric and contain only 1-32 chars
if [[ -z "${APP_NAME}" ]] || [[ ! "${APP_NAME}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$ ]] || [[ "${APP_NAME}" == *".."* ]]; then
    echo "ERROR: Invalid application name '${APP_NAME}'" >&2
    exit 1
fi

CLEAN_NAME="$(echo "${APP_NAME}" | tr -cd 'a-zA-Z0-9_' | cut -c1-18 | tr '[:upper:]' '[:lower:]')"
APP_USER="app_${CLEAN_NAME}"
APP_DIR="/opt/apps/${APP_NAME}"

case "${ACTION}" in
    user-create)
        UID_VAL="${3:-}"
        # Validate UID is an integer in 2001-2999 range
        if [[ ! "${UID_VAL}" =~ ^[0-9]+$ ]] || [ "${UID_VAL}" -lt 2001 ] || [ "${UID_VAL}" -gt 2999 ]; then
            echo "ERROR: Invalid UID '${UID_VAL}' (must be 2001-2999)" >&2
            exit 1
        fi

        # Create unprivileged system user if it does not exist
        if ! id "${APP_USER}" >/dev/null 2>&1; then
            useradd -r -s /usr/sbin/nologin -d "${APP_DIR}" -u "${UID_VAL}" "${APP_USER}" 2>/dev/null || true
        fi

        # Ensure directory exists within /opt/apps
        mkdir -p "${APP_DIR}"

        # Strictly set ownership and permissions (group write allows bover daemon state & config tracking)
        chown -R "${APP_USER}:bover" "${APP_DIR}"
        chmod 770 "${APP_DIR}"
        if [[ -f "${APP_DIR}/app.json" ]]; then
            chmod 660 "${APP_DIR}/app.json"
        fi
        echo "OK: User '${APP_USER}' (UID ${UID_VAL}) configured for '${APP_DIR}'."
        ;;

    user-delete)
        if id "${APP_USER}" >/dev/null 2>&1; then
            userdel "${APP_USER}" 2>/dev/null || true
            echo "OK: User '${APP_USER}' removed."
        fi
        ;;

    chown-app)
        # Safely re-chown app directory to app_<clean_name>:bover
        if [[ -d "${APP_DIR}" ]]; then
            chown -R "${APP_USER}:bover" "${APP_DIR}"
            chmod 770 "${APP_DIR}"
            if [[ -f "${APP_DIR}/app.json" ]]; then
                chmod 660 "${APP_DIR}/app.json"
            fi
            echo "OK: Ownership refreshed on '${APP_DIR}'."
        fi
        ;;

    *)
        echo "Usage: $0 {user-create <app> <uid>|user-delete <app>|chown-app <app>}" >&2
        exit 1
        ;;
esac

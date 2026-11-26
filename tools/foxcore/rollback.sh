#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

DRY_RUN=0
PURGE_CERTS=0
TARGET_USER_ARG=""
INSTALL_PREFIX_ARG=""

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Roll back FOXCORE KRdp native AF_VSOCK installation and restore prior state
(including user systemd units, stock TCP KRdp state, and backed-up socat unit).

Options:
  --dry-run       Show every rollback action without modifying the system
  --user USER     Target non-root desktop user (default: manifest, \$SUDO_USER, or current user)
  --prefix DIR    Override FOXCORE install prefix
  --purge-certs   Also delete generated FOXCORE TLS certificates
  -h, --help      Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --user) TARGET_USER_ARG="$2"; shift 2 ;;
        --prefix) INSTALL_PREFIX_ARG="$2"; shift 2 ;;
        --purge-certs) PURGE_CERTS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ "${EUID}" -eq 0 ]]; then
    STATE_DIR="/var/lib/foxcore-krdp"
else
    STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/foxcore-krdp"
fi

TARGET_USER=""
TARGET_UID=""
USER_HOME=""
INSTALL_PREFIX=""
USER_UNIT_PATH=""
CERT_DIR=""
BACKUP_DIR=""
REPLACED_SOCAT=0
DISABLED_TCP_KRDP=0
PRIOR_TCP_KRDP_ENABLED=0
PRIOR_TCP_KRDP_ACTIVE=0

if [[ -f "${STATE_DIR}/install-manifest.env" ]]; then
    # shellcheck disable=SC1090
    source "${STATE_DIR}/install-manifest.env"
fi

if [[ -n "${TARGET_USER_ARG}" ]]; then
    TARGET_USER="${TARGET_USER_ARG}"
elif [[ -z "${TARGET_USER}" ]]; then
    if [[ "${EUID}" -eq 0 ]]; then
        TARGET_USER="${SUDO_USER:-}"
    else
        TARGET_USER="$(id -un)"
    fi
fi

if [[ -n "${TARGET_USER}" && "${TARGET_USER}" != "root" ]]; then
    PASSWD_LINE="$(getent passwd "${TARGET_USER}" || true)"
    if [[ -n "${PASSWD_LINE}" ]]; then
        TARGET_UID="$(cut -d: -f3 <<< "${PASSWD_LINE}")"
        USER_HOME="$(cut -d: -f6 <<< "${PASSWD_LINE}")"
    fi
fi

if [[ -z "${USER_HOME}" ]]; then
    USER_HOME="${HOME}"
fi

if [[ -n "${INSTALL_PREFIX_ARG}" ]]; then
    INSTALL_PREFIX="${INSTALL_PREFIX_ARG}"
elif [[ -z "${INSTALL_PREFIX}" ]]; then
    if [[ "${EUID}" -eq 0 ]]; then
        INSTALL_PREFIX="/opt/foxcore-krdp"
    else
        INSTALL_PREFIX="${USER_HOME}/.local/opt/foxcore-krdp"
    fi
fi

USER_UNIT_PATH="${USER_UNIT_PATH:-${USER_HOME}/.config/systemd/user/app-org.kde.krdpserver-vsock.service}"
CERT_DIR="${CERT_DIR:-${USER_HOME}/.local/share/krdp-foxcore}"
TARGET_RUNTIME_DIR="/run/user/${TARGET_UID:-${UID}}"
TARGET_DBUS_ADDR="unix:path=${TARGET_RUNTIME_DIR}/bus"

run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

run_user_systemctl() {
    if [[ -z "${TARGET_USER}" || "${TARGET_USER}" == "root" ]]; then
        return 1
    fi
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run][as ${TARGET_USER}] systemctl --user $*"
        return 0
    fi
    if [[ ! -S "${TARGET_RUNTIME_DIR}/bus" ]]; then
        echo "[foxcore-rollback] NOTE: User bus ${TARGET_RUNTIME_DIR}/bus not active; skipping 'systemctl --user $*'."
        return 1
    fi
    if [[ "${EUID}" -eq 0 ]]; then
        runuser -u "${TARGET_USER}" -- env \
            HOME="${USER_HOME}" \
            XDG_RUNTIME_DIR="${TARGET_RUNTIME_DIR}" \
            DBUS_SESSION_BUS_ADDRESS="${TARGET_DBUS_ADDR}" \
            systemctl --user "$@"
    else
        env \
            HOME="${USER_HOME}" \
            XDG_RUNTIME_DIR="${TARGET_RUNTIME_DIR}" \
            DBUS_SESSION_BUS_ADDRESS="${TARGET_DBUS_ADDR}" \
            systemctl --user "$@"
    fi
}

echo "[foxcore-rollback] Mode           : $( [[ "${DRY_RUN}" -eq 1 ]] && echo DRY-RUN || echo APPLY )"
echo "[foxcore-rollback] Target user    : ${TARGET_USER:-unknown} (home=${USER_HOME})"
echo "[foxcore-rollback] Install prefix : ${INSTALL_PREFIX}"
echo "[foxcore-rollback] User unit      : ${USER_UNIT_PATH}"

# 1. Stop and disable FOXCORE user unit
if command -v systemctl >/dev/null 2>&1; then
    run_user_systemctl disable --now app-org.kde.krdpserver-vsock.service || true
fi

# 2. Remove or restore user unit
if [[ -n "${BACKUP_DIR}" && -f "${BACKUP_DIR}/app-org.kde.krdpserver-vsock.service" ]]; then
    echo "[foxcore-rollback] Restoring backed-up user unit..."
    run cp -a "${BACKUP_DIR}/app-org.kde.krdpserver-vsock.service" "${USER_UNIT_PATH}"
elif [[ -f "${USER_UNIT_PATH}" ]]; then
    run rm -f "${USER_UNIT_PATH}"
fi

# 3. Restore stock TCP app-org.kde.krdpserver.service if install.sh disabled it
if [[ "${DISABLED_TCP_KRDP}" -eq 1 ]]; then
    echo "[foxcore-rollback] Restoring stock TCP app-org.kde.krdpserver.service..."
    if [[ "${PRIOR_TCP_KRDP_ENABLED}" -eq 1 ]]; then
        run_user_systemctl enable app-org.kde.krdpserver.service || true
    fi
    if [[ "${PRIOR_TCP_KRDP_ACTIVE}" -eq 1 ]]; then
        run_user_systemctl start app-org.kde.krdpserver.service || true
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    run_user_systemctl daemon-reload || true
fi

# 4. Remove FOXCORE side-by-side prefix (never touches /usr)
if [[ -d "${INSTALL_PREFIX}" ]]; then
    case "${INSTALL_PREFIX}" in
        /|/usr|/usr/local|/opt|/home|"${USER_HOME}")
            echo "ERROR: Refusing to delete unsafe prefix: ${INSTALL_PREFIX}" >&2
            exit 1
            ;;
    esac
    run rm -rf "${INSTALL_PREFIX}"
fi

# 5. Optionally purge generated certificates
if [[ "${PURGE_CERTS}" -eq 1 && -d "${CERT_DIR}" ]]; then
    run rm -rf "${CERT_DIR}"
fi

# 6. Restore socat bridge if it was disabled by install.sh --replace-socat
if [[ "${REPLACED_SOCAT}" -eq 1 ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
        echo "[foxcore-rollback] NOTE: krdp-vsock.service was disabled during root install."
        echo "[foxcore-rollback]       Re-run rollback as root (sudo $0) or execute:"
        echo "  sudo systemctl enable --now krdp-vsock.service"
    else
        if [[ -n "${BACKUP_DIR}" && -f "${BACKUP_DIR}/krdp-vsock.service" ]]; then
            run cp -a "${BACKUP_DIR}/krdp-vsock.service" /etc/systemd/system/krdp-vsock.service
            run systemctl daemon-reload
        fi
        run systemctl enable --now krdp-vsock.service
    fi
fi

# 7. Verify stock system krdp package integrity
echo "[foxcore-rollback] Checking stock pacman krdp package integrity..."
pacman -Qkk krdp || true
echo "[foxcore-rollback] Rollback complete."

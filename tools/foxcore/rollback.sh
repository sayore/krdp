#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

DRY_RUN=0
PURGE_CERTS=0

if [[ "${EUID}" -eq 0 ]]; then
    DEFAULT_PREFIX="/opt/foxcore-krdp"
    STATE_DIR="/var/lib/foxcore-krdp"
else
    DEFAULT_PREFIX="${HOME}/.local/opt/foxcore-krdp"
    STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/foxcore-krdp"
fi

INSTALL_PREFIX="${DEFAULT_PREFIX}"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Roll back FOXCORE KRdp native AF_VSOCK installation and restore prior state.

Options:
  --dry-run       Show every rollback action without modifying the system
  --prefix DIR    Override FOXCORE install prefix (default: ${DEFAULT_PREFIX})
  --purge-certs   Also delete generated FOXCORE TLS certificates
  -h, --help      Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --prefix) INSTALL_PREFIX="$2"; shift 2 ;;
        --purge-certs) PURGE_CERTS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

USER_UNIT_PATH="${HOME}/.config/systemd/user/app-org.kde.krdpserver-vsock.service"
CERT_DIR="${HOME}/.local/share/krdp-foxcore"
BACKUP_DIR=""
REPLACED_SOCAT=0

if [[ -f "${STATE_DIR}/install-manifest.env" ]]; then
    # shellcheck disable=SC1090
    source "${STATE_DIR}/install-manifest.env"
fi

echo "[foxcore-rollback] Mode           : $( [[ "${DRY_RUN}" -eq 1 ]] && echo DRY-RUN || echo APPLY )"
echo "[foxcore-rollback] Install prefix : ${INSTALL_PREFIX}"
echo "[foxcore-rollback] User unit      : ${USER_UNIT_PATH}"

# 1. Stop and disable user unit if running as desktop user
if [[ "${EUID}" -ne 0 ]] && command -v systemctl >/dev/null 2>&1; then
    if systemctl --user list-unit-files app-org.kde.krdpserver-vsock.service >/dev/null 2>&1; then
        run systemctl --user disable --now app-org.kde.krdpserver-vsock.service || true
    fi
fi

# 2. Remove or restore user unit
if [[ -n "${BACKUP_DIR}" && -f "${BACKUP_DIR}/app-org.kde.krdpserver-vsock.service" ]]; then
    echo "[foxcore-rollback] Restoring backed-up user unit..."
    run cp -a "${BACKUP_DIR}/app-org.kde.krdpserver-vsock.service" "${USER_UNIT_PATH}"
elif [[ -f "${USER_UNIT_PATH}" ]]; then
    run rm -f "${USER_UNIT_PATH}"
fi

if [[ "${EUID}" -ne 0 ]] && command -v systemctl >/dev/null 2>&1; then
    run systemctl --user daemon-reload || true
fi

# 3. Remove FOXCORE side-by-side prefix (never touches /usr)
if [[ -d "${INSTALL_PREFIX}" ]]; then
    case "${INSTALL_PREFIX}" in
        /|/usr|/usr/local|/opt|/home|"${HOME}")
            echo "ERROR: Refusing to delete unsafe prefix: ${INSTALL_PREFIX}" >&2
            exit 1
            ;;
    esac
    run rm -rf "${INSTALL_PREFIX}"
fi

# 4. Optionally purge generated certificates
if [[ "${PURGE_CERTS}" -eq 1 && -d "${CERT_DIR}" ]]; then
    run rm -rf "${CERT_DIR}"
fi

# 5. Restore socat bridge if it was disabled by install.sh --replace-socat
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

# 6. Verify stock system krdp package integrity
echo "[foxcore-rollback] Checking stock pacman krdp package integrity..."
pacman -Qkk krdp || true
echo "[foxcore-rollback] Rollback complete."

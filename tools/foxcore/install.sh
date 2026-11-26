#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build-foxcore"
ARTIFACT_DIR="${BUILD_DIR}/artifacts"

DRY_RUN=0
REPLACE_SOCAT=0
ENABLE_USER_UNIT=1
VSOCK_PORT=3389
VSOCK_PEER_CID=2

if [[ "${EUID}" -eq 0 ]]; then
    INSTALL_PREFIX="/opt/foxcore-krdp"
    STATE_DIR="/var/lib/foxcore-krdp"
    TARGET_USER="${SUDO_USER:-}"
else
    INSTALL_PREFIX="${HOME}/.local/opt/foxcore-krdp"
    STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/foxcore-krdp"
    TARGET_USER="$(id -un)"
fi

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Install FOXCORE KRdp native AF_VSOCK Enhanced Session integration side-by-side
without overwriting pacman-managed KDE/KRdp files.

Options:
  --dry-run          Show every planned action without modifying the system
  --prefix DIR       Install prefix (default: /opt/foxcore-krdp as root, ~/.local/opt/foxcore-krdp as user)
  --port PORT        AF_VSOCK port to listen on (default: 3389)
  --peer-cid CID     Authorized AF_VSOCK peer CID (default: 2 / VMADDR_CID_HOST)
  --replace-socat    (Root only) Back up and disable /etc/systemd/system/krdp-vsock.service
                     after verifying the new krdpserver binary
  --no-enable-unit   Install systemd user unit without enabling/starting it
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --prefix) INSTALL_PREFIX="$2"; shift 2 ;;
        --port) VSOCK_PORT="$2"; shift 2 ;;
        --peer-cid) VSOCK_PEER_CID="$2"; shift 2 ;;
        --replace-socat) REPLACE_SOCAT=1; shift ;;
        --no-enable-unit) ENABLE_USER_UNIT=0; shift ;;
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

VERSION="$(awk -F'"' '/set\(PROJECT_VERSION/ {print $2; exit}' "${REPO_ROOT}/CMakeLists.txt")"
ARCH="$(uname -m)"
ARTIFACT_PATH="${ARTIFACT_DIR}/krdp-foxcore-${VERSION}-${ARCH}.tar.zst"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${STATE_DIR}/backups/${TIMESTAMP}"

echo "[foxcore-install] Mode            : $( [[ "${DRY_RUN}" -eq 1 ]] && echo DRY-RUN || echo APPLY )"
echo "[foxcore-install] Install prefix  : ${INSTALL_PREFIX}"
echo "[foxcore-install] State/Backups   : ${STATE_DIR}"
echo "[foxcore-install] AF_VSOCK target : port=${VSOCK_PORT}, allowed_peer_cid=${VSOCK_PEER_CID}"
echo "[foxcore-install] Replace socat   : ${REPLACE_SOCAT}"

if [[ ! -f "${ARTIFACT_PATH}" ]]; then
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] Would run: ${SCRIPT_DIR}/build.sh --prefix ${INSTALL_PREFIX}"
    else
        echo "[foxcore-install] No built artifact found at ${ARTIFACT_PATH}; building now..."
        "${SCRIPT_DIR}/build.sh" --prefix "${INSTALL_PREFIX}"
    fi
else
    echo "[foxcore-install] Verifying artifact checksum..."
    if [[ -f "${ARTIFACT_PATH}.sha256" ]]; then
        (cd "${ARTIFACT_DIR}" && sha256sum -c "$(basename "${ARTIFACT_PATH}").sha256")
    fi
fi

# Backup existing FOXCORE installation if present
if [[ -d "${INSTALL_PREFIX}" ]]; then
    echo "[foxcore-install] Backing up existing ${INSTALL_PREFIX} -> ${BACKUP_DIR}/prefix.tar.zst"
    run mkdir -p "${BACKUP_DIR}"
    run tar --zstd -cf "${BACKUP_DIR}/prefix.tar.zst" -C "${INSTALL_PREFIX}" .
fi

# Extract side-by-side artifact (never touches /usr/bin/krdpserver or /usr/lib/libKRdp.so.6)
run mkdir -p "${INSTALL_PREFIX}" "${STATE_DIR}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[dry-run] tar --zstd -xf ${ARTIFACT_PATH} -C ${INSTALL_PREFIX}"
else
    tar --zstd -xf "${ARTIFACT_PATH}" -C "${INSTALL_PREFIX}"
fi

# Verify installed binary runs and enforces security policies before touching any service
INSTALLED_BIN="${INSTALL_PREFIX}/bin/krdpserver"
if [[ "${DRY_RUN}" -eq 0 ]]; then
    echo "[foxcore-install] Self-checking ${INSTALLED_BIN}..."
    HELP_OUT="$("${INSTALLED_BIN}" --help 2>&1)"
    if ! grep -q -- "--transport" <<< "${HELP_OUT}"; then
        echo "ERROR: Installed krdpserver lacks --transport support!" >&2
        exit 1
    fi
    if "${INSTALLED_BIN}" --transport tcp --vmconnect >/dev/null 2>&1; then
        echo "ERROR: Security check failed: --transport tcp --vmconnect must be rejected!" >&2
        exit 1
    fi
    echo "[foxcore-install] Binary self-check PASSED."
else
    echo "[dry-run] Would verify ${INSTALLED_BIN} --help and security CLI rejection"
fi

# Resolve user config/data directories (avoid modifying root home if invoked via sudo)
if [[ "${EUID}" -eq 0 && -n "${TARGET_USER}" ]]; then
    USER_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6)"
else
    USER_HOME="${HOME}"
fi

USER_UNIT_DIR="${USER_HOME}/.config/systemd/user"
USER_UNIT_PATH="${USER_UNIT_DIR}/app-org.kde.krdpserver-vsock.service"
CERT_DIR="${USER_HOME}/.local/share/krdp-foxcore"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"

# Generate dedicated self-signed TLS certificate for FreeRDP peer initialization if absent
if [[ ! -f "${CERT_FILE}" || ! -f "${KEY_FILE}" ]]; then
    echo "[foxcore-install] Generating dedicated TLS certificate in ${CERT_DIR} (required by freerdp_peer_initialize)..."
    run mkdir -p "${CERT_DIR}"
    run chmod 700 "${CERT_DIR}"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] openssl req -x509 -newkey rsa:2048 -nodes -keyout ${KEY_FILE} -out ${CERT_FILE} -days 3650 -subj /CN=foxcore-krdp-vsock"
    else
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "${KEY_FILE}" -out "${CERT_FILE}" \
            -days 3650 -subj "/CN=foxcore-krdp-vsock" >/dev/null 2>&1
        chmod 600 "${KEY_FILE}"
        chmod 644 "${CERT_FILE}"
        if [[ "${EUID}" -eq 0 && -n "${TARGET_USER}" ]]; then
            chown -R "${TARGET_USER}:${TARGET_USER}" "${CERT_DIR}"
        fi
    fi
fi

# Backup existing user unit if present
if [[ -f "${USER_UNIT_PATH}" ]]; then
    run mkdir -p "${BACKUP_DIR}"
    run cp -a "${USER_UNIT_PATH}" "${BACKUP_DIR}/app-org.kde.krdpserver-vsock.service"
fi

# Render user systemd unit from template
run mkdir -p "${USER_UNIT_DIR}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[dry-run] Would write systemd user unit: ${USER_UNIT_PATH}"
    echo "[dry-run]   ExecStart=${INSTALLED_BIN} --transport vsock --port ${VSOCK_PORT} --vsock-peer-cid ${VSOCK_PEER_CID} --pam --certificate ${CERT_FILE} --certificate-key ${KEY_FILE}"
else
    sed \
        -e "s|@KRDPSERVER_BIN@|${INSTALLED_BIN}|g" \
        -e "s|@VSOCK_PORT@|${VSOCK_PORT}|g" \
        -e "s|@VSOCK_PEER_CID@|${VSOCK_PEER_CID}|g" \
        -e "s|@CERT_FILE@|${CERT_FILE}|g" \
        -e "s|@KEY_FILE@|${KEY_FILE}|g" \
        "${SCRIPT_DIR}/systemd/app-org.kde.krdpserver-vsock.service" > "${USER_UNIT_PATH}"
    if [[ "${EUID}" -eq 0 && -n "${TARGET_USER}" ]]; then
        chown "${TARGET_USER}:${TARGET_USER}" "${USER_UNIT_PATH}"
    fi
    echo "[foxcore-install] Installed user unit: ${USER_UNIT_PATH}"
fi

# Record installation metadata for clean rollback
if [[ "${DRY_RUN}" -eq 0 ]]; then
    cat > "${STATE_DIR}/install-manifest.env" <<EOF
INSTALL_PREFIX=${INSTALL_PREFIX}
USER_UNIT_PATH=${USER_UNIT_PATH}
CERT_DIR=${CERT_DIR}
BACKUP_DIR=${BACKUP_DIR}
REPLACED_SOCAT=0
INSTALL_TIMESTAMP=${TIMESTAMP}
EOF
fi

# Handle existing socat bridge (/etc/systemd/system/krdp-vsock.service) ONLY when explicitly requested
SOCAT_UNIT="/etc/systemd/system/krdp-vsock.service"
if [[ "${REPLACE_SOCAT}" -eq 1 ]]; then
    if [[ "${EUID}" -ne 0 ]]; then
        echo "ERROR: --replace-socat requires root privileges (use sudo)." >&2
        exit 1
    fi
    if [[ -f "${SOCAT_UNIT}" ]]; then
        echo "[foxcore-install] Backing up ${SOCAT_UNIT} -> ${BACKUP_DIR}/krdp-vsock.service"
        run mkdir -p "${BACKUP_DIR}"
        run cp -a "${SOCAT_UNIT}" "${BACKUP_DIR}/krdp-vsock.service"
        run systemctl disable --now krdp-vsock.service
        if [[ "${DRY_RUN}" -eq 0 ]]; then
            sed -i 's/^REPLACED_SOCAT=0$/REPLACED_SOCAT=1/' "${STATE_DIR}/install-manifest.env"
        fi
    else
        echo "[foxcore-install] ${SOCAT_UNIT} not found; nothing to disable."
    fi
else
    if systemctl is-active --quiet krdp-vsock.service 2>/dev/null; then
        echo "[foxcore-install] NOTE: Legacy socat bridge (krdp-vsock.service) is still active on AF_VSOCK:${VSOCK_PORT}."
        echo "[foxcore-install]       It was NOT modified (run with sudo + --replace-socat when ready to switch port ${VSOCK_PORT})."
    fi
fi

# Reload user systemd daemon (and enable only if socat is not holding the same port)
if [[ "${EUID}" -ne 0 ]]; then
    run systemctl --user daemon-reload
    if [[ "${ENABLE_USER_UNIT}" -eq 1 ]]; then
        if systemctl is-active --quiet krdp-vsock.service 2>/dev/null && [[ "${VSOCK_PORT}" -eq 3389 ]]; then
            echo "[foxcore-install] Skipping immediate start of app-org.kde.krdpserver-vsock.service because krdp-vsock.service holds AF_VSOCK:3389."
            echo "[foxcore-install] To switch over safely:"
            echo "  sudo systemctl disable --now krdp-vsock.service"
            echo "  systemctl --user enable --now app-org.kde.krdpserver-vsock.service"
        else
            run systemctl --user enable --now app-org.kde.krdpserver-vsock.service
        fi
    fi
else
    echo "[foxcore-install] Installed as root. Reload/enable the user unit as your desktop user:"
    echo "  systemctl --user daemon-reload && systemctl --user enable --now app-org.kde.krdpserver-vsock.service"
fi

echo "[foxcore-install] Done (no reboot performed)."

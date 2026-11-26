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
DISABLE_TCP_KRDP=1
VSOCK_PORT=3389
VSOCK_PEER_CID=2
TARGET_USER_ARG=""
INSTALL_PREFIX_ARG=""

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Install FOXCORE KRdp native AF_VSOCK Enhanced Session integration side-by-side
without overwriting pacman-managed KDE/KRdp files.

Options:
  --dry-run          Show every planned action without modifying the system
  --user USER        Target non-root desktop user (default: \$SUDO_USER under sudo, else current user)
  --prefix DIR       Install prefix (default: /opt/foxcore-krdp as root, ~/.local/opt/foxcore-krdp as user)
  --port PORT        AF_VSOCK port to listen on (default: 3389)
  --peer-cid CID     Authorized AF_VSOCK peer CID (default: 2 / VMADDR_CID_HOST)
  --replace-socat    (Root only) Back up and disable /etc/systemd/system/krdp-vsock.service
                     after verifying the new krdpserver binary
  --disable-tcp-krdp Disable stock TCP app-org.kde.krdpserver.service (default: ON, prevents
                     unnecessary *:3389 TCP listener; backed up for rollback)
  --keep-tcp-krdp    Keep stock TCP app-org.kde.krdpserver.service untouched
  --no-enable-unit   Install systemd user unit without enabling/starting it
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --user) TARGET_USER_ARG="$2"; shift 2 ;;
        --prefix) INSTALL_PREFIX_ARG="$2"; shift 2 ;;
        --port) VSOCK_PORT="$2"; shift 2 ;;
        --peer-cid) VSOCK_PEER_CID="$2"; shift 2 ;;
        --replace-socat) REPLACE_SOCAT=1; shift ;;
        --disable-tcp-krdp) DISABLE_TCP_KRDP=1; shift ;;
        --keep-tcp-krdp) DISABLE_TCP_KRDP=0; shift ;;
        --no-enable-unit) ENABLE_USER_UNIT=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# Resolve target desktop user safely — never rely on $HOME when invoked via sudo!
if [[ -n "${TARGET_USER_ARG}" ]]; then
    TARGET_USER="${TARGET_USER_ARG}"
elif [[ "${EUID}" -eq 0 ]]; then
    TARGET_USER="${SUDO_USER:-}"
else
    TARGET_USER="$(id -un)"
fi

if [[ -z "${TARGET_USER}" || "${TARGET_USER}" == "root" ]]; then
    echo "ERROR: Refusing to install desktop user unit/certs for root." >&2
    echo "       Invoke via 'sudo $0' from your desktop user or pass '--user <non-root-user>'." >&2
    exit 1
fi

PASSWD_LINE="$(getent passwd "${TARGET_USER}" || true)"
if [[ -z "${PASSWD_LINE}" ]]; then
    echo "ERROR: Target user '${TARGET_USER}' does not exist." >&2
    exit 1
fi

TARGET_UID="$(cut -d: -f3 <<< "${PASSWD_LINE}")"
TARGET_GID="$(cut -d: -f4 <<< "${PASSWD_LINE}")"
USER_HOME="$(cut -d: -f6 <<< "${PASSWD_LINE}")"
if [[ "${TARGET_UID}" -eq 0 || -z "${USER_HOME}" || "${USER_HOME}" == "/root" ]]; then
    echo "ERROR: Refusing UID 0 or /root home directory for desktop user '${TARGET_USER}'." >&2
    exit 1
fi

TARGET_RUNTIME_DIR="/run/user/${TARGET_UID}"
TARGET_DBUS_ADDR="unix:path=${TARGET_RUNTIME_DIR}/bus"

if [[ "${EUID}" -eq 0 ]]; then
    INSTALL_PREFIX="${INSTALL_PREFIX_ARG:-/opt/foxcore-krdp}"
    STATE_DIR="/var/lib/foxcore-krdp"
else
    INSTALL_PREFIX="${INSTALL_PREFIX_ARG:-${USER_HOME}/.local/opt/foxcore-krdp}"
    STATE_DIR="${XDG_STATE_HOME:-${USER_HOME}/.local/state}/foxcore-krdp"
fi

run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] $*"
    else
        "$@"
    fi
}

run_as_target_user() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run][as ${TARGET_USER}] $*"
        return 0
    fi
    if [[ "${EUID}" -eq 0 ]]; then
        runuser -u "${TARGET_USER}" -- env HOME="${USER_HOME}" "$@"
    else
        env HOME="${USER_HOME}" "$@"
    fi
}

user_bus_available() {
    [[ -S "${TARGET_RUNTIME_DIR}/bus" ]]
}

run_user_systemctl() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run][as ${TARGET_USER}] systemctl --user $*"
        return 0
    fi
    if ! user_bus_available; then
        echo "[foxcore-install] NOTE: User D-Bus socket ${TARGET_RUNTIME_DIR}/bus not active; skipping live 'systemctl --user $*'."
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

VERSION="$(awk -F'"' '/set\(PROJECT_VERSION/ {print $2; exit}' "${REPO_ROOT}/CMakeLists.txt")"
ARCH="$(uname -m)"
ARTIFACT_PATH="${ARTIFACT_DIR}/krdp-foxcore-${VERSION}-${ARCH}.tar.zst"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${STATE_DIR}/backups/${TIMESTAMP}"

echo "[foxcore-install] Mode              : $( [[ "${DRY_RUN}" -eq 1 ]] && echo DRY-RUN || echo APPLY )"
echo "[foxcore-install] Invoking EUID     : ${EUID}"
echo "[foxcore-install] Target user       : ${TARGET_USER} (uid=${TARGET_UID}, gid=${TARGET_GID}, home=${USER_HOME})"
echo "[foxcore-install] Install prefix    : ${INSTALL_PREFIX}"
echo "[foxcore-install] State/Backups     : ${STATE_DIR}"
echo "[foxcore-install] AF_VSOCK target   : port=${VSOCK_PORT}, allowed_peer_cid=${VSOCK_PEER_CID}"
echo "[foxcore-install] Disable TCP KRdp  : ${DISABLE_TCP_KRDP}"
echo "[foxcore-install] Replace socat     : ${REPLACE_SOCAT}"

if [[ ! -f "${ARTIFACT_PATH}" ]]; then
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run] Would run: ${SCRIPT_DIR}/build.sh --prefix ${INSTALL_PREFIX}"
    else
        echo "[foxcore-install] No built artifact found at ${ARTIFACT_PATH}; building now..."
        if [[ "${EUID}" -eq 0 ]]; then
            runuser -u "${TARGET_USER}" -- "${SCRIPT_DIR}/build.sh" --prefix "${INSTALL_PREFIX}"
        else
            "${SCRIPT_DIR}/build.sh" --prefix "${INSTALL_PREFIX}"
        fi
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
    if [[ "${EUID}" -eq 0 ]]; then
        echo "[dry-run] chown -R root:root ${INSTALL_PREFIX} && chmod -R a+rX ${INSTALL_PREFIX}"
    fi
else
    tar --zstd -xf "${ARTIFACT_PATH}" -C "${INSTALL_PREFIX}"
    if [[ "${EUID}" -eq 0 ]]; then
        chown -R root:root "${INSTALL_PREFIX}"
        chmod -R a+rX "${INSTALL_PREFIX}"
    fi
fi

# Verify installed binary runs as target user and enforces security policies before touching any service
INSTALLED_BIN="${INSTALL_PREFIX}/bin/krdpserver"
if [[ "${DRY_RUN}" -eq 0 ]]; then
    echo "[foxcore-install] Self-checking ${INSTALLED_BIN} as ${TARGET_USER}..."
    HELP_OUT="$(run_as_target_user "${INSTALLED_BIN}" --help 2>&1)"
    if ! grep -q -- "--transport" <<< "${HELP_OUT}"; then
        echo "ERROR: Installed krdpserver lacks --transport support!" >&2
        exit 1
    fi
    if ! grep -q -- "--in-band-greeter" <<< "${HELP_OUT}"; then
        echo "ERROR: Installed krdpserver lacks --in-band-greeter support!" >&2
        exit 1
    fi
    if run_as_target_user "${INSTALLED_BIN}" --transport tcp --vmconnect >/dev/null 2>&1; then
        echo "ERROR: Security check failed: --transport tcp --vmconnect must be rejected!" >&2
        exit 1
    fi
    if run_as_target_user "${INSTALLED_BIN}" --transport tcp --in-band-greeter >/dev/null 2>&1; then
        echo "ERROR: Security check failed: --transport tcp --in-band-greeter must be rejected!" >&2
        exit 1
    fi
    echo "[foxcore-install] Binary self-check PASSED."
else
    echo "[dry-run] Would verify ${INSTALLED_BIN} --help and security CLI rejection as ${TARGET_USER}"
fi

USER_UNIT_DIR="${USER_HOME}/.config/systemd/user"
USER_UNIT_PATH="${USER_UNIT_DIR}/app-org.kde.krdpserver-vsock.service"
CERT_DIR="${USER_HOME}/.local/share/krdp-foxcore"
CERT_FILE="${CERT_DIR}/server.crt"
KEY_FILE="${CERT_DIR}/server.key"

# Generate dedicated self-signed TLS certificate for FreeRDP peer initialization if absent
# Always run as target user so parent directories (~/.local, ~/.local/share) are never root-owned!
if [[ ! -f "${CERT_FILE}" || ! -f "${KEY_FILE}" ]]; then
    echo "[foxcore-install] Generating dedicated TLS certificate in ${CERT_DIR} (owned by ${TARGET_USER})..."
    run_as_target_user mkdir -p "${CERT_DIR}"
    run_as_target_user chmod 700 "${CERT_DIR}"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        echo "[dry-run][as ${TARGET_USER}] openssl req -x509 -newkey rsa:2048 -nodes -keyout ${KEY_FILE} -out ${CERT_FILE} -days 3650 -subj /CN=foxcore-krdp-vsock"
    else
        run_as_target_user openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "${KEY_FILE}" -out "${CERT_FILE}" \
            -days 3650 -subj "/CN=foxcore-krdp-vsock" >/dev/null 2>&1
        run_as_target_user chmod 600 "${KEY_FILE}"
        run_as_target_user chmod 644 "${CERT_FILE}"
    fi
fi

# Backup existing user unit if present
if [[ -f "${USER_UNIT_PATH}" ]]; then
    run mkdir -p "${BACKUP_DIR}"
    run cp -a "${USER_UNIT_PATH}" "${BACKUP_DIR}/app-org.kde.krdpserver-vsock.service"
fi

# Render user systemd unit strictly as target user (guarantees proper ownership of ~/.config/systemd/user)
run_as_target_user mkdir -p "${USER_UNIT_DIR}"
if [[ "${DRY_RUN}" -eq 1 ]]; then
    echo "[dry-run][as ${TARGET_USER}] Would write systemd user unit: ${USER_UNIT_PATH}"
    echo "[dry-run]   ExecStart=${INSTALLED_BIN} --transport vsock --port ${VSOCK_PORT} --vsock-peer-cid ${VSOCK_PEER_CID} --pam --certificate ${CERT_FILE} --certificate-key ${KEY_FILE}"
else
    UNIT_CONTENT="$(sed \
        -e "s|@KRDPSERVER_BIN@|${INSTALLED_BIN}|g" \
        -e "s|@VSOCK_PORT@|${VSOCK_PORT}|g" \
        -e "s|@VSOCK_PEER_CID@|${VSOCK_PEER_CID}|g" \
        -e "s|@CERT_FILE@|${CERT_FILE}|g" \
        -e "s|@KEY_FILE@|${KEY_FILE}|g" \
        "${SCRIPT_DIR}/systemd/app-org.kde.krdpserver-vsock.service")"
    printf '%s\n' "${UNIT_CONTENT}" | run_as_target_user tee "${USER_UNIT_PATH}" >/dev/null
    run_as_target_user chmod 644 "${USER_UNIT_PATH}"
    echo "[foxcore-install] Installed user unit: ${USER_UNIT_PATH}"
fi

# Inspect stock TCP KRdp user service (default listens on *:3389 across all interfaces)
PRIOR_TCP_KRDP_ENABLED=0
PRIOR_TCP_KRDP_ACTIVE=0
if user_bus_available; then
    if run_user_systemctl is-enabled --quiet app-org.kde.krdpserver.service 2>/dev/null; then
        PRIOR_TCP_KRDP_ENABLED=1
    fi
    if run_user_systemctl is-active --quiet app-org.kde.krdpserver.service 2>/dev/null; then
        PRIOR_TCP_KRDP_ACTIVE=1
    fi
fi

# Record installation metadata for clean rollback
if [[ "${DRY_RUN}" -eq 0 ]]; then
    cat > "${STATE_DIR}/install-manifest.env" <<EOF
TARGET_USER=${TARGET_USER}
TARGET_UID=${TARGET_UID}
TARGET_GID=${TARGET_GID}
USER_HOME=${USER_HOME}
INSTALL_PREFIX=${INSTALL_PREFIX}
USER_UNIT_PATH=${USER_UNIT_PATH}
CERT_DIR=${CERT_DIR}
BACKUP_DIR=${BACKUP_DIR}
REPLACED_SOCAT=0
DISABLED_TCP_KRDP=0
PRIOR_TCP_KRDP_ENABLED=${PRIOR_TCP_KRDP_ENABLED}
PRIOR_TCP_KRDP_ACTIVE=${PRIOR_TCP_KRDP_ACTIVE}
INSTALL_TIMESTAMP=${TIMESTAMP}
EOF
fi

if [[ "${DISABLE_TCP_KRDP}" -eq 1 ]]; then
    if [[ "${PRIOR_TCP_KRDP_ENABLED}" -eq 1 || "${PRIOR_TCP_KRDP_ACTIVE}" -eq 1 ]]; then
        echo "[foxcore-install] Disabling stock TCP app-org.kde.krdpserver.service (was listening on *:3389)..."
        if run_user_systemctl disable --now app-org.kde.krdpserver.service; then
            if [[ "${DRY_RUN}" -eq 0 ]]; then
                sed -i 's/^DISABLED_TCP_KRDP=0$/DISABLED_TCP_KRDP=1/' "${STATE_DIR}/install-manifest.env"
            fi
        fi
    else
        echo "[foxcore-install] Stock TCP app-org.kde.krdpserver.service is already inactive/disabled."
    fi
else
    if [[ "${PRIOR_TCP_KRDP_ACTIVE}" -eq 1 ]]; then
        echo "[foxcore-install] WARNING: --keep-tcp-krdp set; stock app-org.kde.krdpserver.service remains active on TCP *:3389."
    fi
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

# Reload & optionally enable/start user unit via target user's systemd instance
run_user_systemctl daemon-reload || true
if [[ "${ENABLE_USER_UNIT}" -eq 1 ]]; then
    if [[ "${REPLACE_SOCAT}" -eq 0 ]] && systemctl is-active --quiet krdp-vsock.service 2>/dev/null && [[ "${VSOCK_PORT}" -eq 3389 ]]; then
        echo "[foxcore-install] Skipping immediate start of app-org.kde.krdpserver-vsock.service because krdp-vsock.service holds AF_VSOCK:3389."
        echo "[foxcore-install] To switch over cleanly:"
        echo "  sudo ${SCRIPT_DIR}/install.sh --replace-socat"
    else
        run_user_systemctl enable --now app-org.kde.krdpserver-vsock.service || {
            echo "[foxcore-install] NOTE: Could not enable/start user unit now (no active user session bus). Run as ${TARGET_USER}:"
            echo "  systemctl --user daemon-reload && systemctl --user enable --now app-org.kde.krdpserver-vsock.service"
        }
    fi
fi

echo "[foxcore-install] Done (no reboot performed)."

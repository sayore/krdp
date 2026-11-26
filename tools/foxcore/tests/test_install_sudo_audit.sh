#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FOXCORE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CURRENT_USER="$(id -un)"
CURRENT_HOME="$(getent passwd "${CURRENT_USER}" | cut -d: -f6)"

echo "[sudo-audit] 1. Verify install.sh rejects --user root..."
if "${FOXCORE_DIR}/install.sh" --dry-run --user root >/dev/null 2>&1; then
    echo "FAIL: install.sh accepted --user root!" >&2
    exit 1
fi
echo "PASS: --user root rejected."

echo "[sudo-audit] 2. Verify HOME=/root does not pollute user unit/cert paths when --user ${CURRENT_USER} is set..."
DRY_OUT="$(HOME=/root "${FOXCORE_DIR}/install.sh" --dry-run --user "${CURRENT_USER}" 2>&1)"
if grep -q "/root/" <<< "${DRY_OUT}"; then
    echo "FAIL: /root/ path leaked into dry-run output!" >&2
    echo "${DRY_OUT}" >&2
    exit 1
fi
if ! grep -q "${CURRENT_HOME}/.config/systemd/user/app-org.kde.krdpserver-vsock.service" <<< "${DRY_OUT}"; then
    echo "FAIL: Expected target user unit path under ${CURRENT_HOME}!" >&2
    echo "${DRY_OUT}" >&2
    exit 1
fi
if ! grep -q "${CURRENT_HOME}/.local/share/krdp-foxcore/server.key" <<< "${DRY_OUT}"; then
    echo "FAIL: Expected target user cert path under ${CURRENT_HOME}!" >&2
    echo "${DRY_OUT}" >&2
    exit 1
fi
echo "PASS: HOME=/root safely ignored in favor of getent passwd home (${CURRENT_HOME})."

echo "[sudo-audit] 3. Verify install.sh checks stock TCP KRdp listener by default (--disable-tcp-krdp=1)..."
if ! grep -q "Disable TCP KRdp  : 1" <<< "${DRY_OUT}"; then
    echo "FAIL: Expected Disable TCP KRdp : 1 by default!" >&2
    exit 1
fi
echo "PASS: Stock TCP KRdp disabling enabled by default."

echo "[sudo-audit] 4. Verify rollback.sh --dry-run resolves target user home cleanly even with HOME=/root..."
RB_OUT="$(HOME=/root "${FOXCORE_DIR}/rollback.sh" --dry-run --user "${CURRENT_USER}" 2>&1)"
if grep -q "/root/" <<< "${RB_OUT}"; then
    echo "FAIL: /root/ path leaked into rollback dry-run output!" >&2
    echo "${RB_OUT}" >&2
    exit 1
fi
echo "PASS: rollback.sh resolves user home cleanly."

echo "[sudo-audit] 5. Verify --replace-socat requires root..."
if "${FOXCORE_DIR}/install.sh" --dry-run --replace-socat >/dev/null 2>&1; then
    echo "FAIL: --replace-socat should fail without root!" >&2
    exit 1
fi
echo "PASS: --replace-socat enforces root check."

echo "[sudo-audit] All install/rollback sudo & ownership audits PASSED."

#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build-foxcore"
REPORT_PATH="${BUILD_DIR}/reports/foxcore-verify-report.json"

KRDP_BIN=""
LIB_DIR=""
SKIP_CTEST=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Run FOXCORE KRdp verification suite (CTest, security invariants, native AF_VSOCK,
local TCP E2E auth + reconnect + 1080p llvmpipe performance) and write JSON report.

Options:
  --krdp-bin PATH    Path to krdpserver binary (default: auto-detect build-foxcore/bin/krdpserver)
  --report PATH      Output JSON report path (default: ${REPORT_PATH})
  --skip-ctest       Skip running ctest
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --krdp-bin) KRDP_BIN="$2"; shift 2 ;;
        --report) REPORT_PATH="$2"; shift 2 ;;
        --skip-ctest) SKIP_CTEST=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "${KRDP_BIN}" ]]; then
    if [[ -x "${BUILD_DIR}/bin/krdpserver" ]]; then
        KRDP_BIN="${BUILD_DIR}/bin/krdpserver"
        LIB_DIR="${BUILD_DIR}/bin"
    elif [[ -x "${HOME}/.local/opt/foxcore-krdp/bin/krdpserver" ]]; then
        KRDP_BIN="${HOME}/.local/opt/foxcore-krdp/bin/krdpserver"
    elif [[ -x "/opt/foxcore-krdp/bin/krdpserver" ]]; then
        KRDP_BIN="/opt/foxcore-krdp/bin/krdpserver"
    else
        echo "[foxcore-verify] No built krdpserver found; invoking build.sh first..."
        "${SCRIPT_DIR}/build.sh"
        KRDP_BIN="${BUILD_DIR}/bin/krdpserver"
        LIB_DIR="${BUILD_DIR}/bin"
    fi
fi

CTEST_ARGS=()
if [[ "${SKIP_CTEST}" -eq 0 && -d "${BUILD_DIR}" ]]; then
    echo "[foxcore-verify] Running CTest suite in ${BUILD_DIR}..."
    ctest --test-dir "${BUILD_DIR}" --output-on-failure
    CTEST_ARGS+=(--ctest-passed)
fi

LIB_ARGS=()
if [[ -n "${LIB_DIR}" ]]; then
    LIB_ARGS+=(--lib-dir "${LIB_DIR}")
fi

python3 "${SCRIPT_DIR}/tests/run_local_e2e_and_perf.py" \
    --krdp-bin "${KRDP_BIN}" \
    "${LIB_ARGS[@]}" \
    "${CTEST_ARGS[@]}" \
    --report "${REPORT_PATH}"

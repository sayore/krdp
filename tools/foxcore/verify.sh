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
BENCH_SECONDS=15

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Run FOXCORE KRdp Final Gate verification suite:
- CTest (appstreamtest, kcm_smoketest, vsocktransporttest, vmconnectauthtest)
- install.sh / rollback.sh sudo & ownership audit
- CLI security policies & native AF_VSOCK listener (zero TCP listener)
- 100-cycle VmConnectMode & krdpserver soak / resource leak analysis
- 15s active-motion 1080p benchmark (KRdp, KWin, PipeWire, total system CPU)

Options:
  --krdp-bin PATH      Path to krdpserver binary (default: auto-detect build-foxcore/bin/krdpserver)
  --report PATH        Output JSON report path (default: ${REPORT_PATH})
  --bench-seconds SEC  Duration of each active-motion benchmark (default: 15)
  --skip-ctest         Skip running ctest
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --krdp-bin) KRDP_BIN="$2"; shift 2 ;;
        --report) REPORT_PATH="$2"; shift 2 ;;
        --bench-seconds) BENCH_SECONDS="$2"; shift 2 ;;
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

echo "[foxcore-verify] Running install/rollback sudo & ownership audit..."
"${SCRIPT_DIR}/tests/test_install_sudo_audit.sh"
SUDO_AUDIT_ARGS=(--sudo-audit-passed)

LIB_ARGS=()
if [[ -n "${LIB_DIR}" ]]; then
    LIB_ARGS+=(--lib-dir "${LIB_DIR}")
fi

VMC_TEST_ARGS=()
if [[ -x "${BUILD_DIR}/bin/vmconnectauthtest" ]]; then
    VMC_TEST_ARGS+=(--vmconnect-test-bin "${BUILD_DIR}/bin/vmconnectauthtest")
fi

python3 "${SCRIPT_DIR}/tests/run_local_e2e_and_perf.py" \
    --krdp-bin "${KRDP_BIN}" \
    "${LIB_ARGS[@]}" \
    "${VMC_TEST_ARGS[@]}" \
    "${CTEST_ARGS[@]}" \
    "${SUDO_AUDIT_ARGS[@]}" \
    --bench-seconds "${BENCH_SECONDS}" \
    --report "${REPORT_PATH}"

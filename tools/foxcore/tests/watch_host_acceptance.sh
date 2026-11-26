#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
REPORT_DIR="${REPO_ROOT}/build-foxcore/reports"
mkdir -p "${REPORT_DIR}"

TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${REPORT_DIR}/host-acceptance-${TS}.log"
SUMMARY_FILE="${REPORT_DIR}/host-acceptance-${TS}.json"

echo "[foxcore-host-watch] Pre-flight guest status:"
echo "  AF_VSOCK listeners:"
ss --vsock -ln | sed 's/^/    /'
echo "  TCP krdpserver listeners:"
ss -tlpn | grep krdpserver | sed 's/^/    /' || echo "    (none)"
echo "  User unit state: $(systemctl --user is-active app-org.kde.krdpserver-vsock.service 2>/dev/null || true)"
echo ""
echo "[foxcore-host-watch] Streaming app-org.kde.krdpserver-vsock.service journal to ${LOG_FILE}"
echo "[foxcore-host-watch] Execute Tests H1-H4 from the Windows Hyper-V host now. Press Ctrl+C when finished."

summarize() {
    echo ""
    echo "[foxcore-host-watch] Generating acceptance summary: ${SUMMARY_FILE}"
    python3 - "${LOG_FILE}" "${SUMMARY_FILE}" <<'PY'
import json, pathlib, re, sys, datetime as dt
log_path = pathlib.Path(sys.argv[1])
out_path = pathlib.Path(sys.argv[2])
text = log_path.read_text(errors="replace") if log_path.exists() else ""

def has(pat):
    return bool(re.search(pat, text))

summary = {
    "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
    "log_file": str(log_path),
    "signals_observed": {
        "af_vsock_host_cid2_accepted": has(r"Accepted AF_VSOCK connection from CID 2"),
        "tls_wrong_version_error_present": has(r"wrong version number"),
        "in_band_greeter_entered": has(r"entering isolated in-band login greeter"),
        "root_rejected": has(r"rejected disallowed.*root|Rejecting disallowed RDP login user.*root"),
        "invalid_auth_rejected": has(r"Authentication failed|In-band greeter authentication failed"),
        "guest_authenticated": has(r"PAM authentication succeeded|In-band greeter authenticated guest user|authenticated successfully"),
        "plasma_session_started": has(r"Started Plasma session|Started portal session"),
    },
}
out_path.write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY
}

trap summarize EXIT
journalctl --user -u app-org.kde.krdpserver-vsock.service -f --since "now" --no-pager | tee "${LOG_FILE}"

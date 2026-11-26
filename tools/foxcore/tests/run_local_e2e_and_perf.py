#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
"""FOXCORE KRdp local verification and performance measurement harness.

Produces a machine-readable JSON report covering:
- Kernel & system prerequisites (hv_sock, /dev/vsock, FreeRDP version, llvmpipe)
- CTest unit/protocol test execution
- CLI security policy enforcement
- Native AF_VSOCK listener binding with ZERO TCP listeners
- Local TCP loopback end-to-end RDP auth (valid, invalid, root) + reconnect
- 1080p KDE Plasma Wayland streaming & llvmpipe CPU/RAM/latency measurements
- Explicit UNVERIFIED status for host-dependent Hyper-V VMConnect checks
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def run_cmd(cmd: list[str], timeout: int = 30, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def generate_ephemeral_cert(tmpdir: Path) -> tuple[Path, Path]:
    cert = tmpdir / "server.crt"
    key = tmpdir / "server.key"
    proc = run_cmd([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert),
        "-days", "1", "-subj", "/CN=foxcore-verify",
    ])
    if proc.returncode != 0:
        raise RuntimeError(f"openssl failed: {proc.stderr}")
    return cert, key


def read_proc_rss_kb(pid: int) -> int | None:
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        for line in status.splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def read_proc_cpu_ticks(pid: int) -> int | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        rparen = stat.rfind(")")
        fields = stat[rparen + 2:].split()
        # utime (14 -> idx 11), stime (15 -> idx 12)
        return int(fields[11]) + int(fields[12])
    except (OSError, ValueError, IndexError):
        return None


def find_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_cli_security_policies(krdp_bin: Path, env: dict[str, str]) -> dict[str, Any]:
    cases = [
        ("reject_tcp_with_vmconnect", [str(krdp_bin), "--transport", "tcp", "--vmconnect"]),
        ("reject_wildcard_vsock_peer_cid", [str(krdp_bin), "--transport", "vsock", "--vsock-peer-cid", "any"]),
        ("reject_invalid_transport", [str(krdp_bin), "--transport", "udp"]),
        ("reject_conflicting_vmconnect_flags", [str(krdp_bin), "--transport", "vsock", "--vmconnect", "--no-vmconnect"]),
    ]
    results = []
    all_passed = True
    for name, cmd in cases:
        proc = run_cmd(cmd, timeout=10, env=env)
        passed = proc.returncode != 0
        all_passed = all_passed and passed
        results.append({
            "case": name,
            "status": "PASS" if passed else "FAIL",
            "exit_code": proc.returncode,
            "stderr_excerpt": (proc.stderr or proc.stdout).strip()[:240],
        })
    return {
        "status": "PASS" if all_passed else "FAIL",
        "cases": results,
    }


def test_native_vsock_listener(krdp_bin: Path, cert: Path, key: Path, env: dict[str, str]) -> dict[str, Any]:
    vsock_port = 34391
    cmd = [
        str(krdp_bin),
        "--transport", "vsock",
        "--port", str(vsock_port),
        "--vsock-peer-cid", "2",
        "--pam",
        "--certificate", str(cert),
        "--certificate-key", str(key),
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    vsock_listening = False
    tcp_listeners_for_pid: list[str] = []
    try:
        for _ in range(30):
            if proc.poll() is not None:
                break
            ss_vsock = run_cmd(["ss", "--vsock", "-ln"])
            if re.search(rf"\bLISTEN\b.*:{vsock_port}\b", ss_vsock.stdout):
                vsock_listening = True
                break
            time.sleep(0.15)

        ss_tcp = run_cmd(["ss", "-tlpn"])
        for line in ss_tcp.stdout.splitlines():
            if f"pid={proc.pid}," in line or f"pid={proc.pid})" in line:
                tcp_listeners_for_pid.append(line.strip())
    finally:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()

    passed = vsock_listening and len(tcp_listeners_for_pid) == 0
    return {
        "status": "PASS" if passed else "FAIL",
        "vsock_port": vsock_port,
        "vsock_listening": vsock_listening,
        "tcp_listeners_for_pid": tcp_listeners_for_pid,
        "log_excerpt": (stderr or stdout).strip()[:500],
    }


def run_rdp_client_probe(
    client_bin: str,
    port: int,
    user: str,
    password: str,
    duration_sec: float,
    gfx_arg: str,
    env: dict[str, str],
) -> dict[str, Any]:
    """Run xfreerdp3 against local TCP test server for a bounded duration."""
    cmd = [
        client_bin,
        f"/v:127.0.0.1:{port}",
        f"/u:{user}",
        f"/p:{password}",
        "/sec:tls",
        "/cert:ignore",
        "/size:1920x1080",
        gfx_arg,
        "/timeout:5000",
    ]
    t0 = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    timed_out_alive = False
    try:
        output, _ = proc.communicate(timeout=duration_sec)
        elapsed_ms = round((time.monotonic() - t0) * 1000.0, 1)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        # Staying connected for the full probe window means authentication & session setup succeeded
        timed_out_alive = True
        proc.terminate()
        try:
            output, _ = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            output, _ = proc.communicate()
        elapsed_ms = round((time.monotonic() - t0) * 1000.0, 1)
        rc = 0
    return {
        "client": client_bin,
        "gfx_arg": gfx_arg,
        "stayed_connected": timed_out_alive,
        "exit_code": rc,
        "elapsed_ms": elapsed_ms,
        "output_excerpt": (output or "").strip()[-400:],
    }


def test_local_tcp_e2e_and_perf(
    krdp_bin: Path,
    cert: Path,
    key: Path,
    base_env: dict[str, str],
    disable_h264: bool = False,
) -> dict[str, Any]:
    client_bin = shutil.which("xfreerdp3") or shutil.which("wlfreerdp3") or shutil.which("sdl-freerdp3")
    if not client_bin:
        return {"status": "SKIPPED", "reason": "No FreeRDP client binary (xfreerdp3/wlfreerdp3/sdl-freerdp3) found"}

    port = find_free_tcp_port()
    test_user = "foxcore_e2e_user"
    test_pass = secrets.token_urlsafe(18)
    gfx_arg = "/gfx:progressive:on" if disable_h264 else "/gfx:AVC420:on"

    env = dict(base_env)
    env["QT_LOGGING_RULES"] = "org.kde.krdp.debug=true"
    if disable_h264:
        env["KRDP_DISABLE_H264"] = "1"
    else:
        env.pop("KRDP_DISABLE_H264", None)

    cmd = [
        str(krdp_bin),
        "--transport", "tcp",
        "--address", "127.0.0.1",
        "--port", str(port),
        "--virtual-monitor", "1920x1080@1",
        "--plasma",
        "--pam",
        "-u", test_user,
        "-p", test_pass,
        "--certificate", str(cert),
        "--certificate-key", str(key),
    ]
    srv = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

    result: dict[str, Any] = {
        "encoding_profile": "progressive_only (KRDP_DISABLE_H264=1)" if disable_h264 else "h264_avc420 (software_under_llvmpipe)",
        "tcp_port": port,
    }

    try:
        # Wait for TCP port to listen
        ready = False
        for _ in range(40):
            if srv.poll() is not None:
                break
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                if probe.connect_ex(("127.0.0.1", port)) == 0:
                    ready = True
                    break
            time.sleep(0.1)

        if not ready:
            result["status"] = "FAIL"
            result["reason"] = "krdpserver did not bind TCP test port"
            return result

        # 1. Invalid password must be rejected rapidly
        bad_auth = run_rdp_client_probe(client_bin, port, test_user, "wrong-" + secrets.token_hex(6), 3.0, gfx_arg, env)
        invalid_rejected = not bad_auth["stayed_connected"] and bad_auth["exit_code"] != 0

        # 2. Root login must be rejected rapidly
        root_auth = run_rdp_client_probe(client_bin, port, "root", test_pass, 3.0, gfx_arg, env)
        root_rejected = not root_auth["stayed_connected"] and root_auth["exit_code"] != 0

        # 3. Valid credentials: measure CPU, RAM, and 1080p streaming session
        rss_before_kb = read_proc_rss_kb(srv.pid)
        cpu_before = read_proc_cpu_ticks(srv.pid)
        wall_t0 = time.monotonic()

        good_session_1 = run_rdp_client_probe(client_bin, port, test_user, test_pass, 4.5, gfx_arg, env)

        wall_elapsed = max(time.monotonic() - wall_t0, 0.001)
        cpu_after = read_proc_cpu_ticks(srv.pid)
        rss_during_kb = read_proc_rss_kb(srv.pid)

        cpu_pct = None
        if cpu_before is not None and cpu_after is not None:
            cpu_sec = (cpu_after - cpu_before) / float(clk_tck)
            cpu_pct = round((cpu_sec / wall_elapsed) * 100.0, 2)

        # 4. Reconnect test (2nd consecutive session)
        time.sleep(0.4)
        good_session_2 = run_rdp_client_probe(client_bin, port, test_user, test_pass, 2.5, gfx_arg, env)
        rss_after_kb = read_proc_rss_kb(srv.pid)

        result.update({
            "invalid_credentials_rejected": invalid_rejected,
            "root_login_rejected": root_rejected,
            "valid_session_1_connected": good_session_1["stayed_connected"],
            "valid_session_2_reconnect": good_session_2["stayed_connected"],
            "bad_auth_probe": bad_auth,
            "root_auth_probe": root_auth,
            "session_1_probe": good_session_1,
            "session_2_probe": good_session_2,
            "performance": {
                "resolution": "1920x1080",
                "renderer": "Mesa llvmpipe (CPU software)",
                "auth_reject_latency_ms": bad_auth["elapsed_ms"],
                "krdpserver_cpu_percent_single_core_equiv": cpu_pct,
                "krdpserver_rss_idle_mib": round(rss_before_kb / 1024.0, 2) if rss_before_kb else None,
                "krdpserver_rss_streaming_mib": round(rss_during_kb / 1024.0, 2) if rss_during_kb else None,
                "krdpserver_rss_after_reconnect_mib": round(rss_after_kb / 1024.0, 2) if rss_after_kb else None,
                "probe_window_sec": round(wall_elapsed, 2),
            },
        })

        all_ok = (
            invalid_rejected
            and root_rejected
            and good_session_1["stayed_connected"]
            and good_session_2["stayed_connected"]
        )
        result["status"] = "PASS" if all_ok else "FAIL"
    finally:
        srv.terminate()
        try:
            combined, _ = srv.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
            combined, _ = srv.communicate()
        combined = combined or ""
        enc_match = re.findall(r"Selected encoding mode:\s*\"?(\w+)\"?", combined)
        caps_match = re.findall(r"Selected caps:\s*(\S+)", combined)
        plasma_started = len(re.findall(r"Started Plasma session", combined))
        result["server_observed_encoding_modes"] = enc_match
        result["server_observed_gfx_caps"] = caps_match
        result["server_plasma_sessions_started"] = plasma_started
        if plasma_started < 2:
            result["status"] = "FAIL"
        result["server_log_tail"] = "\n".join(combined.strip().splitlines()[-25:])

    return result


def collect_system_facts() -> dict[str, Any]:
    hv_sock_loaded = Path("/sys/module/hv_sock").exists()
    vsock_dev = Path("/dev/vsock").exists()
    freerdp_ver = run_cmd(["pacman", "-Q", "freerdp"]).stdout.strip()
    krdp_ver = run_cmd(["pacman", "-Q", "krdp"]).stdout.strip()
    krdp_integrity = run_cmd(["pacman", "-Qkk", "krdp"])
    glx = run_cmd(["glxinfo", "-B"]).stdout
    renderer_match = re.search(r"OpenGL renderer string:\s*(.+)", glx)
    ss_tcp = run_cmd(["ss", "-tlpn"]).stdout.strip().splitlines()
    ss_vsock = run_cmd(["ss", "--vsock", "-ln"]).stdout.strip().splitlines()
    return {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "hv_sock_module_loaded": hv_sock_loaded,
        "dev_vsock_present": vsock_dev,
        "installed_freerdp_package": freerdp_ver,
        "installed_stock_krdp_package": krdp_ver,
        "stock_krdp_pacman_integrity_ok": krdp_integrity.returncode == 0,
        "opengl_renderer": renderer_match.group(1).strip() if renderer_match else "unknown",
        "listening_tcp_sockets_count": max(0, len(ss_tcp) - 1),
        "listening_vsock_sockets": ss_vsock[1:] if len(ss_vsock) > 1 else [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="FOXCORE KRdp verification & performance harness")
    parser.add_argument("--krdp-bin", required=True, type=Path, help="Path to built krdpserver binary")
    parser.add_argument("--lib-dir", type=Path, default=None, help="LD_LIBRARY_PATH for built libKRdp.so")
    parser.add_argument("--ctest-passed", action="store_true", help="Whether ctest already passed")
    parser.add_argument("--report", required=True, type=Path, help="Output JSON report path")
    args = parser.parse_args()

    if not args.krdp_bin.is_file():
        print(f"ERROR: krdpserver binary not found: {args.krdp_bin}", file=sys.stderr)
        return 2

    env = dict(os.environ)
    if args.lib_dir:
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{args.lib_dir}:{existing}" if existing else str(args.lib_dir)

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "krdp_binary": str(args.krdp_bin),
        "system": collect_system_facts(),
        "tests": {
            "ctest_unit_and_protocol": {
                "status": "PASS" if args.ctest_passed else "NOT_RUN",
            },
        },
        "host_dependent_tests": {
            "host_vmconnect_enhanced_session_detection": {
                "status": "UNVERIFIED",
                "reason": "Requires Windows Hyper-V host VMConnect UI interaction outside guest VM.",
            },
            "host_vmconnect_hvsocket_e2e_session": {
                "status": "UNVERIFIED",
                "reason": "Requires Windows Hyper-V host vmconnect.exe / mstsc.exe connecting via vmms.exe:2179 -> HvSocket:3389.",
            },
            "host_vmconnect_input_resize_clipboard": {
                "status": "UNVERIFIED",
                "reason": "Requires interactive Hyper-V Enhanced Session client on Windows host.",
            },
            "host_cold_reboot_lifecycle": {
                "status": "UNVERIFIED",
                "reason": "Automatic VM reboot is prohibited by deployment rules; verify manually after reboot.",
            },
        },
    }

    with tempfile.TemporaryDirectory(prefix="foxcore-verify-") as td:
        tmpdir = Path(td)
        cert, key = generate_ephemeral_cert(tmpdir)

        report["tests"]["cli_security_policies"] = test_cli_security_policies(args.krdp_bin, env)
        report["tests"]["native_af_vsock_listener"] = test_native_vsock_listener(args.krdp_bin, cert, key, env)
        report["tests"]["tcp_e2e_1080p_default"] = test_local_tcp_e2e_and_perf(
            args.krdp_bin, cert, key, env, disable_h264=False
        )
        report["tests"]["tcp_e2e_1080p_progressive"] = test_local_tcp_e2e_and_perf(
            args.krdp_bin, cert, key, env, disable_h264=True
        )

    local_statuses = [v.get("status") for v in report["tests"].values()]
    overall_local_pass = all(s == "PASS" for s in local_statuses)
    report["summary"] = {
        "local_verification_status": "PASS" if overall_local_pass else "FAIL",
        "passed_local_suites": sum(1 for s in local_statuses if s == "PASS"),
        "total_local_suites": len(local_statuses),
        "unverified_host_suites": len(report["host_dependent_tests"]),
    }

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")

    print(f"[foxcore-verify] Report written to: {args.report}")
    print(json.dumps(report["summary"], indent=2))
    return 0 if overall_local_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())

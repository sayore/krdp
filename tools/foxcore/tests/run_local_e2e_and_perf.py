#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 FOXCORE Integration
# SPDX-License-Identifier: BSD-2-Clause
"""FOXCORE KRdp Final Integration Gate verification, soak & performance harness.

Produces a machine-readable JSON report covering:
- Kernel & system prerequisites (hv_sock, /dev/vsock, FreeRDP version, llvmpipe)
- CTest suites including explicit VmConnectMode wire-protocol auth matrix & In-Band Greeter
- CLI security policy enforcement (tcp/vsock/vmconnect/in-band-greeter/peer-cid)
- Native AF_VSOCK listener binding with ZERO TCP listeners
- Stock TCP *:3389 listener audit (app-org.kde.krdpserver.service)
- install.sh / rollback.sh sudo & ownership audit
- 100-cycle connect/disconnect soak & leak analysis (RSS, open FDs, Threads)
  for BOTH VmConnectMode (via vmconnectauthtest) AND live krdpserver process
- 15-second active-motion 1080p benchmark (QML Wayland animation) measuring
  KRdp, KWin, PipeWire, and total system CPU% across H.264 vs Progressive under llvmpipe
- Explicit UNVERIFIED status for host-dependent Windows Hyper-V VMConnect checks
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
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


def run_cmd(cmd: list[str], timeout: int = 60, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
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
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def read_proc_threads(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("Threads:"):
                return int(line.split()[1])
    except OSError:
        return None
    return None


def read_proc_fd_count(pid: int) -> int | None:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def read_proc_cpu_ticks(pid: int) -> int | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        rparen = stat.rfind(")")
        fields = stat[rparen + 2:].split()
        return int(fields[11]) + int(fields[12])
    except (OSError, ValueError, IndexError):
        return None


def read_total_cpu_jiffies() -> tuple[int, int]:
    """Return (busy_jiffies, total_jiffies) from /proc/stat aggregate cpu line."""
    line = Path("/proc/stat").read_text().splitlines()[0]
    vals = [int(x) for x in line.split()[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    total = sum(vals)
    return total - idle, total


def find_pid_by_comm(comm: str) -> int | None:
    proc = run_cmd(["pgrep", "-x", "-u", str(os.getuid()), comm])
    if proc.returncode == 0 and proc.stdout.strip():
        try:
            return int(proc.stdout.strip().splitlines()[0])
        except ValueError:
            return None
    return None


def find_free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_tcp_port(port: int, proc: subprocess.Popen[str], timeout_sec: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.08)
    return False


def test_cli_security_policies(krdp_bin: Path, env: dict[str, str]) -> dict[str, Any]:
    cases = [
        ("reject_tcp_with_vmconnect", [str(krdp_bin), "--transport", "tcp", "--vmconnect"]),
        ("reject_tcp_with_in_band_greeter", [str(krdp_bin), "--transport", "tcp", "--in-band-greeter"]),
        ("reject_vsock_no_vmconnect_with_in_band_greeter", [str(krdp_bin), "--transport", "vsock", "--no-vmconnect", "--in-band-greeter"]),
        ("reject_wildcard_vsock_peer_cid", [str(krdp_bin), "--transport", "vsock", "--vsock-peer-cid", "any"]),
        ("reject_invalid_transport", [str(krdp_bin), "--transport", "udp"]),
        ("reject_conflicting_vmconnect_flags", [str(krdp_bin), "--transport", "vsock", "--vmconnect", "--no-vmconnect"]),
        ("reject_conflicting_greeter_flags", [str(krdp_bin), "--transport", "vsock", "--in-band-greeter", "--no-in-band-greeter"]),
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


def run_vmconnect_auth_and_soak_binary(vmconnect_test_bin: Path | None, env: dict[str, str]) -> dict[str, Any]:
    if not vmconnect_test_bin or not vmconnect_test_bin.is_file():
        return {"status": "SKIPPED", "reason": "vmconnectauthtest binary not found"}
    proc = run_cmd([str(vmconnect_test_bin)], timeout=120, env=env)
    combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
    soak_match = re.search(
        r"VMCONNECT_SOAK_100:\s*rss_warm_mib=\s*([\d.]+)\s*rss_end_mib=\s*([\d.]+)\s*rss_delta_mib=\s*([-\d.]+)\s*fds_warm=\s*(\d+)\s*fds_end=\s*(\d+)\s*threads_warm=\s*(\d+)\s*threads_end=\s*(\d+)",
        combined,
    )
    soak_metrics = None
    if soak_match:
        soak_metrics = {
            "cycles": 100,
            "rss_warm_mib": round(float(soak_match.group(1)), 2),
            "rss_end_mib": round(float(soak_match.group(2)), 2),
            "rss_delta_mib": round(float(soak_match.group(3)), 2),
            "fds_warm": int(soak_match.group(4)),
            "fds_end": int(soak_match.group(5)),
            "fds_delta": int(soak_match.group(5)) - int(soak_match.group(4)),
            "threads_warm": int(soak_match.group(6)),
            "threads_end": int(soak_match.group(7)),
            "threads_delta": int(soak_match.group(7)) - int(soak_match.group(6)),
        }

    passed_cases = re.findall(r"PASS\s+:\s+VmConnectAuthTest::(\w+)\(\)", combined)
    failed_cases = re.findall(r"FAIL!\s+:\s+VmConnectAuthTest::(\w+)\(\)", combined)
    return {
        "status": "PASS" if proc.returncode == 0 and not failed_cases else "FAIL",
        "exit_code": proc.returncode,
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "vmconnect_100_cycle_soak": soak_metrics,
    }


def run_krdpserver_100_cycle_soak(krdp_bin: Path, cert: Path, key: Path, base_env: dict[str, str]) -> dict[str, Any]:
    """Run 100 real TCP X.224/RDP connect/disconnect cycles against live krdpserver and track RSS, FDs, Threads."""
    port = find_free_tcp_port()
    env = dict(base_env)
    cmd = [
        str(krdp_bin),
        "--transport", "tcp",
        "--address", "127.0.0.1",
        "--port", str(port),
        "--pam",
        "--certificate", str(cert),
        "--certificate-key", str(key),
    ]
    soak_log_path = cert.parent / "krdpserver_soak_100.log"
    soak_log_fp = open(soak_log_path, "w", encoding="utf-8")
    srv = subprocess.Popen(cmd, stdout=soak_log_fp, stderr=subprocess.STDOUT, env=env)
    cr_tpdu = bytes.fromhex("030000130ee00000000000010008000b000000")
    snapshots: dict[str, dict[str, Any]] = {}
    completed = 0

    def snap(label: str) -> None:
        time.sleep(0.15)
        rss = read_proc_rss_kb(srv.pid)
        snapshots[label] = {
            "rss_mib": round(rss / 1024.0, 2) if rss is not None else None,
            "open_fds": read_proc_fd_count(srv.pid),
            "threads": read_proc_threads(srv.pid),
        }

    try:
        if not wait_tcp_port(port, srv):
            return {"status": "FAIL", "reason": "krdpserver failed to bind soak port"}
        snap("cycle_0_idle")

        for i in range(1, 101):
            with socket.create_connection(("127.0.0.1", port), timeout=3.0) as cli:
                cli.sendall(cr_tpdu)
                resp = cli.recv(64)
                if len(resp) < 19 or resp[5] != 0xD0:
                    return {"status": "FAIL", "reason": f"Bad X.224 CC-TPDU at cycle {i}"}
                # Send non-TLS bytes so server cleanly tears down TLS & session
                cli.sendall(b"\x03\x00\x00\x08\x02\xf0\x80\x00")
                try:
                    cli.recv(16)
                except OSError:
                    pass
            completed += 1
            if i in (10, 50, 100):
                snap(f"cycle_{i}")

        # Let final session cleanup settle
        time.sleep(0.35)
        snap("post_settle")
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait()
        soak_log_fp.close()

    s10 = snapshots.get("cycle_10", {})
    send = snapshots.get("post_settle", {})
    rss_delta = round((send.get("rss_mib") or 0.0) - (s10.get("rss_mib") or 0.0), 2)
    fd_delta = (send.get("open_fds") or 0) - (s10.get("open_fds") or 0)
    thread_delta = (send.get("threads") or 0) - (s10.get("threads") or 0)

    no_leak = (completed == 100) and (fd_delta <= 2) and (thread_delta <= 1) and (rss_delta < 20.0)
    return {
        "status": "PASS" if no_leak else "FAIL",
        "cycles_completed": completed,
        "snapshots": snapshots,
        "delta_from_cycle_10_to_post_settle": {
            "rss_mib": rss_delta,
            "open_fds": fd_delta,
            "threads": thread_delta,
        },
    }


def start_qml_motion_generator(tmpdir: Path, env: dict[str, str]) -> subprocess.Popen[str] | None:
    qml_bin = shutil.which("qml6")
    if not qml_bin:
        return None
    qml_file = tmpdir / "motion_bench.qml"
    qml_file.write_text(
        """import QtQuick
import QtQuick.Window

Window {
    visible: true
    width: 1280
    height: 720
    title: "FOXCORE Motion Benchmark"
    color: "#111620"

    Repeater {
        model: 12
        Rectangle {
            id: bar
            width: 180
            height: 60
            radius: 10
            y: index * 58 + 10
            color: Qt.hsla((index * 0.08), 0.75, 0.5, 1.0)
            SequentialAnimation on x {
                loops: Animation.Infinite
                NumberAnimation { from: 10; to: 1080; duration: 900 + index * 70 }
                NumberAnimation { from: 1080; to: 10; duration: 900 + index * 70 }
            }
        }
    }
    Rectangle {
        width: 120; height: 120; radius: 60
        anchors.centerIn: parent
        color: "#3daee9"
        NumberAnimation on rotation {
            from: 0; to: 360; duration: 800; loops: Animation.Infinite
        }
        Rectangle { width: 20; height: 100; color: "#ffffff"; anchors.centerIn: parent }
    }
}
"""
    )
    return subprocess.Popen(
        [qml_bin, str(qml_file)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        env=env,
    )


def run_rdp_client_probe(
    client_bin: str,
    port: int,
    user: str,
    password: str,
    duration_sec: float,
    gfx_arg: str,
    env: dict[str, str],
) -> dict[str, Any]:
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


def run_active_motion_1080p_benchmark(
    krdp_bin: Path,
    cert: Path,
    key: Path,
    tmpdir: Path,
    base_env: dict[str, str],
    disable_h264: bool,
    duration_sec: float = 15.0,
) -> dict[str, Any]:
    """Run active-motion 1080p benchmark measuring KRdp, KWin, PipeWire, and total CPU%."""
    client_bin = shutil.which("xfreerdp3") or shutil.which("wlfreerdp3")
    if not client_bin:
        return {"status": "SKIPPED", "reason": "No FreeRDP client binary found"}

    port = find_free_tcp_port()
    test_user = "foxcore_bench_user"
    test_pass = secrets.token_urlsafe(18)
    gfx_arg = "/gfx:progressive:on" if disable_h264 else "/gfx:AVC420:on"

    env = dict(base_env)
    env["QT_LOGGING_RULES"] = "org.kde.krdp.debug=true"
    if disable_h264:
        env["KRDP_DISABLE_H264"] = "1"
    else:
        env.pop("KRDP_DISABLE_H264", None)

    # Stream primary active workspace (--plasma without --virtual-monitor) so the active QML motion
    # generator window actually drives real KWin llvmpipe compositing + PipeWire + KRdp encoding!
    cmd = [
        str(krdp_bin),
        "--transport", "tcp",
        "--address", "127.0.0.1",
        "--port", str(port),
        "--plasma",
        "--pam",
        "-u", test_user,
        "-p", test_pass,
        "--certificate", str(cert),
        "--certificate-key", str(key),
    ]
    srv = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
    num_cpus = os.cpu_count() or 1
    kwin_pid = find_pid_by_comm("kwin_wayland")
    pw_pid = find_pid_by_comm("pipewire")
    motion_proc: subprocess.Popen[str] | None = None

    result: dict[str, Any] = {
        "encoding_profile": "progressive_only (KRDP_DISABLE_H264=1)" if disable_h264 else "h264_avc420 (libx264_software)",
        "duration_sec": duration_sec,
        "motion_generator": "qml6 animated Wayland window (12 moving bars + rotating disc)",
    }

    try:
        if not wait_tcp_port(port, srv):
            return {"status": "FAIL", "reason": "krdpserver did not bind benchmark port"}

        # Quick auth verification on TCP path too
        bad_auth = run_rdp_client_probe(client_bin, port, test_user, "wrong-" + secrets.token_hex(4), 3.0, gfx_arg, env)
        root_auth = run_rdp_client_probe(client_bin, port, "root", test_pass, 3.0, gfx_arg, env)
        invalid_rejected = not bad_auth["stayed_connected"] and bad_auth["exit_code"] != 0
        root_rejected = not root_auth["stayed_connected"] and root_auth["exit_code"] != 0

        motion_proc = start_qml_motion_generator(tmpdir, env)
        time.sleep(0.5)

        rss_krdp_idle = read_proc_rss_kb(srv.pid)
        cpu_krdp_0 = read_proc_cpu_ticks(srv.pid)
        cpu_kwin_0 = read_proc_cpu_ticks(kwin_pid) if kwin_pid else None
        cpu_pw_0 = read_proc_cpu_ticks(pw_pid) if pw_pid else None
        sys_busy_0, sys_tot_0 = read_total_cpu_jiffies()
        t0 = time.monotonic()

        sess1 = run_rdp_client_probe(client_bin, port, test_user, test_pass, duration_sec, gfx_arg, env)

        wall = max(time.monotonic() - t0, 0.001)
        sys_busy_1, sys_tot_1 = read_total_cpu_jiffies()
        cpu_krdp_1 = read_proc_cpu_ticks(srv.pid)
        cpu_kwin_1 = read_proc_cpu_ticks(kwin_pid) if kwin_pid else None
        cpu_pw_1 = read_proc_cpu_ticks(pw_pid) if pw_pid else None

        rss_krdp_stream = read_proc_rss_kb(srv.pid)
        rss_kwin = read_proc_rss_kb(kwin_pid) if kwin_pid else None
        rss_pw = read_proc_rss_kb(pw_pid) if pw_pid else None

        def proc_cpu_pct(c0: int | None, c1: int | None) -> float | None:
            if c0 is None or c1 is None:
                return None
            return round(((c1 - c0) / float(clk_tck)) / wall * 100.0, 2)

        total_sys_cpu_pct = round(((sys_busy_1 - sys_busy_0) / max(1, sys_tot_1 - sys_tot_0)) * 100.0, 2)

        # Reconnect verification
        time.sleep(0.4)
        sess2 = run_rdp_client_probe(client_bin, port, test_user, test_pass, 2.5, gfx_arg, env)
        rss_krdp_after = read_proc_rss_kb(srv.pid)

        result.update({
            "invalid_credentials_rejected": invalid_rejected,
            "root_login_rejected": root_rejected,
            "valid_session_1_connected": sess1["stayed_connected"],
            "valid_session_2_reconnect": sess2["stayed_connected"],
            "performance": {
                "resolution_requested": "1920x1080",
                "renderer": "Mesa llvmpipe (CPU software)",
                "vcpus": num_cpus,
                "measured_window_sec": round(wall, 2),
                "total_system_cpu_percent_all_vcpus": total_sys_cpu_pct,
                "krdpserver_cpu_percent_1core": proc_cpu_pct(cpu_krdp_0, cpu_krdp_1),
                "kwin_wayland_cpu_percent_1core": proc_cpu_pct(cpu_kwin_0, cpu_kwin_1),
                "pipewire_cpu_percent_1core": proc_cpu_pct(cpu_pw_0, cpu_pw_1),
                "krdpserver_rss_idle_mib": round(rss_krdp_idle / 1024.0, 2) if rss_krdp_idle else None,
                "krdpserver_rss_streaming_mib": round(rss_krdp_stream / 1024.0, 2) if rss_krdp_stream else None,
                "krdpserver_rss_after_reconnect_mib": round(rss_krdp_after / 1024.0, 2) if rss_krdp_after else None,
                "kwin_wayland_rss_mib": round(rss_kwin / 1024.0, 2) if rss_kwin else None,
                "pipewire_rss_mib": round(rss_pw / 1024.0, 2) if rss_pw else None,
                "auth_reject_latency_ms": bad_auth["elapsed_ms"],
            },
        })

        all_ok = invalid_rejected and root_rejected and sess1["stayed_connected"] and sess2["stayed_connected"]
        result["status"] = "PASS" if all_ok else "FAIL"
    finally:
        if motion_proc is not None:
            motion_proc.terminate()
            try:
                motion_proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                motion_proc.kill()
                motion_proc.communicate()
        srv.terminate()
        try:
            combined, _ = srv.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()
            combined, _ = srv.communicate()
        combined = combined or ""
        result["server_observed_encoding_modes"] = re.findall(r"Selected encoding mode:\s*\"?(\w+)\"?", combined)
        result["server_observed_gfx_caps"] = re.findall(r"Selected caps:\s*(\S+)", combined)
        result["server_plasma_sessions_started"] = len(re.findall(r"Started Plasma session", combined))
        x264_kbps = re.findall(r"\[libx264[^\]]*\]\s*kb/s:([\d.,]+)", combined)
        x264_frames = re.findall(r"\[libx264[^\]]*\]\s*frame ([IP]):(\d+)", combined)
        if x264_kbps:
            result["libx264_measured_kbps"] = x264_kbps
        if x264_frames:
            result["libx264_encoded_frames"] = [{"type": t, "count": int(c)} for t, c in x264_frames]
        if result["server_plasma_sessions_started"] < 2:
            result["status"] = "FAIL"

    return result


def audit_tcp_listeners() -> dict[str, Any]:
    ss_tcp = run_cmd(["ss", "-tlpn"]).stdout.strip().splitlines()
    wildcard_3389 = []
    for line in ss_tcp[1:]:
        if ":3389 " in line and ("*:3389" in line or "0.0.0.0:3389" in line or "[::]:3389" in line):
            wildcard_3389.append(line.strip())
    stock_unit_active = run_cmd(["systemctl", "--user", "is-active", "app-org.kde.krdpserver.service"]).stdout.strip()
    stock_unit_enabled = run_cmd(["systemctl", "--user", "is-enabled", "app-org.kde.krdpserver.service"]).stdout.strip()
    return {
        "stock_krdp_tcp_unit_active": stock_unit_active,
        "stock_krdp_tcp_unit_enabled": stock_unit_enabled,
        "wildcard_tcp_3389_listeners": wildcard_3389,
        "finding": (
            "Stock app-org.kde.krdpserver.service currently listens on TCP *:3389 (all interfaces); "
            "install.sh now disables it by default (--disable-tcp-krdp) and restores it on rollback."
            if wildcard_3389
            else "No wildcard TCP *:3389 listener active."
        ),
    }


def collect_system_facts() -> dict[str, Any]:
    hv_sock_loaded = Path("/sys/module/hv_sock").exists()
    vsock_dev = Path("/dev/vsock").exists()
    freerdp_ver = run_cmd(["pacman", "-Q", "freerdp"]).stdout.strip()
    krdp_ver = run_cmd(["pacman", "-Q", "krdp"]).stdout.strip()
    krdp_integrity = run_cmd(["pacman", "-Qkk", "krdp"])
    glx = run_cmd(["glxinfo", "-B"]).stdout
    renderer_match = re.search(r"OpenGL renderer string:\s*(.+)", glx)
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
        "listening_vsock_sockets": ss_vsock[1:] if len(ss_vsock) > 1 else [],
        "tcp_listener_audit": audit_tcp_listeners(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="FOXCORE KRdp final gate verification & benchmark harness")
    parser.add_argument("--krdp-bin", required=True, type=Path, help="Path to built krdpserver binary")
    parser.add_argument("--lib-dir", type=Path, default=None, help="LD_LIBRARY_PATH for built libKRdp.so")
    parser.add_argument("--vmconnect-test-bin", type=Path, default=None, help="Path to vmconnectauthtest binary")
    parser.add_argument("--ctest-passed", action="store_true", help="Whether ctest already passed")
    parser.add_argument("--sudo-audit-passed", action="store_true", help="Whether test_install_sudo_audit.sh passed")
    parser.add_argument("--bench-seconds", type=float, default=15.0, help="Active-motion benchmark duration (default: 15s)")
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
        "schema_version": "2.0",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "krdp_binary": str(args.krdp_bin),
        "system": collect_system_facts(),
        "tests": {
            "ctest_unit_and_protocol": {
                "status": "PASS" if args.ctest_passed else "NOT_RUN",
            },
            "install_rollback_sudo_audit": {
                "status": "PASS" if args.sudo_audit_passed else "NOT_RUN",
            },
        },
        "host_dependent_tests": {
            "host_vmconnect_enhanced_session_detection": {
                "status": "UNVERIFIED",
                "reason": "Requires Windows Hyper-V host VMConnect UI interaction outside guest VM.",
            },
            "host_vmconnect_direct_in_band_greeter_login": {
                "status": "UNVERIFIED",
                "reason": "Requires interactive Windows vmconnect.exe Enhanced Session test (Test H1).",
            },
            "host_mstsc_pcb_preauth_hvsocket_session": {
                "status": "UNVERIFIED",
                "reason": "Requires Windows host mstsc.exe / msrdc.exe via vmms.exe:2179 -> HvSocket:3389 (Test H2).",
            },
            "host_vmconnect_input_resize_clipboard_reconnect": {
                "status": "UNVERIFIED",
                "reason": "Requires interactive Hyper-V Enhanced Session client on Windows host (Test H3).",
            },
            "host_cold_reboot_lifecycle": {
                "status": "UNVERIFIED",
                "reason": "Automatic VM reboot is prohibited; verify manually after cold start (Test H4).",
            },
        },
    }

    with tempfile.TemporaryDirectory(prefix="foxcore-verify-") as td:
        tmpdir = Path(td)
        cert, key = generate_ephemeral_cert(tmpdir)

        report["tests"]["cli_security_policies"] = test_cli_security_policies(args.krdp_bin, env)
        report["tests"]["native_af_vsock_listener"] = test_native_vsock_listener(args.krdp_bin, cert, key, env)
        report["tests"]["vmconnect_mode_explicit_auth_and_soak"] = run_vmconnect_auth_and_soak_binary(
            args.vmconnect_test_bin, env
        )
        report["tests"]["krdpserver_100_cycle_soak"] = run_krdpserver_100_cycle_soak(args.krdp_bin, cert, key, env)
        report["tests"]["active_motion_1080p_h264"] = run_active_motion_1080p_benchmark(
            args.krdp_bin, cert, key, tmpdir, env, disable_h264=False, duration_sec=args.bench_seconds
        )
        report["tests"]["active_motion_1080p_progressive"] = run_active_motion_1080p_benchmark(
            args.krdp_bin, cert, key, tmpdir, env, disable_h264=True, duration_sec=args.bench_seconds
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

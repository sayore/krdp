# Security Policy — Experimental Hyper-V Enhanced Session Fork

> **Project Status: Experimental**
> This repository is an experimental fork of [KDE/krdp](https://invent.kde.org/plasma/krdp) (GitHub mirror: [github.com/KDE/krdp](https://github.com/KDE/krdp)) adding native Linux `AF_VSOCK` (`hv_sock`), FreeRDP `VmConnectMode`, and an isolated in-band guest login greeter for Microsoft Hyper-V Enhanced Session Mode on KDE Plasma Wayland.

---

## 1. Upstream KDE Security Policy (Preserved)

This document **supplements** and does **not** replace upstream KDE security policies.

- For vulnerabilities affecting **upstream KRdp** (standard TCP/TLS/NLA RDP server, KCM, PipeWire screencast, portal/Plasma session integration, or core KDE libraries), please follow the official KDE Security Process:
  - **Policy**: <https://kde.org/info/security/>
  - **Contact**: `security@kde.org`
- For vulnerabilities specific to the **experimental Hyper-V / `AF_VSOCK` / `InBandGreeter` / `tools/foxcore/` extensions** in this fork:
  - Do **not** open a public issue with exploit details before triage.
  - Report privately via GitHub Security Advisories (**Security → Report a vulnerability**) on this fork repository.

---

## 2. Trust Boundary & Security Architecture

### Why `FreeRDP_VmConnectMode` Exists and How It Is Scoped

In Microsoft Hyper-V Enhanced Session Mode (`EnhancedSessionTransportType = HvSocket`):
1. On the Windows host, `vmconnect.exe` / `mstsc.exe` connects to `vmms.exe` (TCP/2179) using TLS/CredSSP, where the host authenticates the Windows user and terminates the outer TLS layer.
2. `vmms.exe` relays the inner RDP stream over VMBus `HvSocket` (`AF_VSOCK` port `3389`, kernel-verified peer `svm_cid == VMADDR_CID_HOST == 2`).
3. Because `vmms.exe` does **not** perform a second TLS handshake over `HvSocket`, FreeRDP's `FreeRDP_VmConnectMode` skips the guest-side TLS handshake after `RDP_NEG_RSP`.

**Critical Security Invariant**: Skipping guest-side TLS is **only** safe across the Hyper-V VMBus host-to-guest boundary and **must never** be enabled on TCP sockets or unverified `AF_VSOCK` peers.

### Enforced Controls

| Control | Enforcement Point |
| :--- | :--- |
| **Strict Transport Isolation** | `--vmconnect` and `--in-band-greeter` are rejected at CLI parsing (`server/main.cpp`), rejected in `KRdp::Server::start()`, and re-verified via kernel `getpeername()` inside `KRdp::RdpConnection::initialize()` (`ss_family == AF_VSOCK && svm_cid == allowedVsockPeerCid`, default `VMADDR_CID_HOST = 2`). |
| **Unchanged Standard TCP Mode** | Standard `--transport tcp` mode never enables `FreeRDP_VmConnectMode` or `InBandGreeter`. TLS/NLA remains mandatory on TCP. |
| **Zero TCP Exposure in VSOCK Mode** | `--transport vsock` never calls `QTcpServer::listen()`. Additionally, `tools/foxcore/install.sh` disables the stock `app-org.kde.krdpserver.service` TCP `*:3389` listener by default (`--disable-tcp-krdp`). |
| **No Unauthenticated Desktop Access** | `SessionController` refuses to create `SessionWrapper`, PipeWire screencast, or KWin EIS input until `RdpConnection::isAuthenticated() == true`. `RdpConnection::run()` refuses to initialize `Clipboard` until authenticated. |
| **Isolated In-Band Guest Login (`InBandGreeter`)** | When `vmconnect.exe` omits a password in `TS_INFO_PACKET` on a verified `AF_VSOCK` `CID=2` peer, `RdpConnection` enters `AuthState::PendingInBandGreeter` and renders an isolated `QPainter` login screen via Progressive RFX frames with zero desktop visibility. Enforces PAM/KWallet validation, `1000 ms` failure cooldown, max `5` attempts (auto-disconnect), `120 s` idle timeout, and `explicit_bzero()` password wiping. |
| **Explicit Rejection of Wrong Credentials** | Even when `--in-band-greeter` is enabled, any non-empty invalid password in `TS_INFO_PACKET` causes immediate disconnection in `onPostConnect()`. |
| **Root Login Prohibition** | `RdpConnection::isDisallowedLoginUser()` blocks `root` (including `DOMAIN\root`, `.\root`, case-insensitive) and any UID `0` account across PAM, KWallet/custom users, SAM file generation, and `InBandGreeter`. |
| **No Autologin / No Firewall Modifications** | Neither `plasmalogin` autologin nor UFW/firewall/WireGuard modifications are performed. |
| **Safe Privilege Separation in Installer** | `tools/foxcore/install.sh` and `rollback.sh` reject `--user root` / UID `0` / `/root`, resolve user homes strictly via `getent passwd` (never `$HOME`), and drop privileges via `runuser` for user-home files and `systemd --user` units (`0700` cert dir, `0600` private key). |

---

## 3. Known Limitations, Unverified Security Items & Release-Blockers

This fork is **experimental** and **not yet approved for production deployment** until the following items are verified/resolved:

1. **Unverified Host-Side E2E Tests (`H1–H4`, Release-Blocker)**:
   - While guest-side authentication (`VmConnectMode` empty/invalid/`root`/valid, `InBandGreeter` lockout & unlock, 100-cycle soak) is verified locally via wire-protocol unit tests (`vmconnectauthtest`), live interactive acceptance tests from a Windows Hyper-V host (`vmconnect.exe`, `mstsc.exe`/`msrdc.exe` via `vmms.exe:2179`, keyboard/mouse/resize/clipboard/reconnect, and full VM cold-boot lifecycle) have **not** been executed in automated CI. See [`tools/foxcore/tests/host-vmconnect-acceptance.md`](tools/foxcore/tests/host-vmconnect-acceptance.md).
2. **Pre-Login Remote Session Handoff (`P1`, Architectural Release-Blocker for Headless Pre-Login)**:
   - Remote Enhanced Session connections currently require an already logged-in KDE Plasma Wayland user session.
   - `plasma-login-manager` 6.8.3 and upstream KDE WIP (`krdp-daemon`) do not yet implement a privileged `AF_VSOCK` greeter-to-user-session broker/handoff protocol. Automatic login is intentionally **not** used as a workaround.
3. **Hyper-V Host Trust Assumption**:
   - In `VmConnectMode`, confidentiality and host-side authentication on the `HvSocket` channel rely on the Windows Hyper-V host (`vmms.exe`) and hypervisor VMBus isolation. If the Hyper-V host itself is compromised, guest-side `HvSocket` traffic is visible to the host (inherent to Hyper-V Enhanced Session architecture). Guest-side PAM authentication still prevents unauthenticated desktop access from host processes that do not possess the Linux guest password.
4. **Test Harness Build Isolation**:
   - The compile-time macro `KRDP_VMCONNECT_TEST_HARNESS` is strictly scoped to the `vmconnectauthtest` test executable in `autotests/CMakeLists.txt` and must **never** be enabled for production builds of `libKRdp` or `krdpserver`.

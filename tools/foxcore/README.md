# FOXCORE — Native KDE Plasma Wayland Hyper-V Enhanced Session Integration

> **Project Status: Experimental**
> Canonical Upstream: <https://invent.kde.org/plasma/krdp> · GitHub Upstream: <https://github.com/KDE/krdp>
> Development Branch: `foxcore/hyperv-vsock-enhanced-session` · Security Policy: [`SECURITY.md`](../../SECURITY.md)

Native `AF_VSOCK` (`hv_sock`), Hyper-V `FreeRDP_VmConnectMode`, and an isolated in-band guest login greeter (`KRdp::InBandGreeter`) for KDE Plasma 6.8.3 (`KRdp`) on Linux / CachyOS — without Xorg, XRDP, XFCE, autologin, or an externally reachable TCP port.

---

## 0. Architecture Overview

```text
Windows Hyper-V Host                         Linux Guest (KDE Plasma Wayland)
────────────────────                         ────────────────────────────────
vmconnect.exe / mstsc.exe
  │  TLS / CredSSP (Host Auth)
  ▼
vmms.exe (TCP :2179, PCB EnhancedMode=1)
  │  VMBus HvSocket (AF_VSOCK :3389, CID=2)
  ▼
KRdp::Server (--transport vsock --port 3389, zero TCP socket)
  ├─ Verifies getpeername(): ss_family == AF_VSOCK && svm_cid == 2 (VMADDR_CID_HOST)
  ├─ Enables FreeRDP_VmConnectMode + PROTOCOL_SSL + RestrictedAdminModeSupported
  ▼
KRdp::RdpConnection::onPostConnect()
  ├─ Root / UID 0 user                     ──► REJECT & CLOSE immediately
  ├─ Non-empty password in TS_INFO_PACKET  ──► PAM / KWallet check
  │    ├─ Invalid                          ──► REJECT & CLOSE immediately
  │    └─ Valid                            ──► AuthState::Authenticated
  └─ Empty password (vmconnect.exe)        ──► AuthState::PendingInBandGreeter
       │  (NO PipeWire, NO KWin EIS, NO Clipboard!)
       ▼
     KRdp::InBandGreeter (Progressive RFX QPainter UI, xkbcommon, 5-try lockout)
       ├─ Root / Invalid / Timeout         ──► Cooldown (1s) / Close after 5 failures
       └─ Valid Guest PAM/KWallet Login    ──► AuthState::Authenticated
                                                 │
                                                 ▼
SessionController::onNewConnection() ──► Attaches PlasmaScreencastV1 / Portal
                                         (PipeWire + KWin EIS + Clipboard + DisplayControl)
```

---

## 1. Root Cause Analysis (Verified in FreeRDP 3.33.1 & XRDP)

Previously, `vmconnect.exe` connected over Hyper-V `HvSocket` (`AF_VSOCK` port 3389, peer `CID=2` / `VMADDR_CID_HOST`) via a `socat` TCP bridge to KRdp on `127.0.0.1:3389`, and failed in `CONNECTION_STATE_NEGO`:

```text
RDP_NEG_REQ: RequestedProtocol: [SSL|HYBRID|HYBRID_EX][0x0000000b]
Negotiated Security: RDSTLS:0 NLA:0 EXT:0 TLS:1 RDP:0
BIO_do_handshake failed: tls_validate_record_header:wrong version number
CONNECTION_STATE_NEGO - rdp_server_accept_nego() fail
```

### Exact Protocol & Source Cause

1. **Hyper-V Enhanced Session Wire Protocol**:
   - On the Windows host, `vmconnect.exe` connects to `vmms.exe` (TCP/2179) with Pre-Connection Blob `<VM_GUID>;EnhancedMode=1`.
   - `vmms.exe` authenticates the host user and terminates TLS/CredSSP on the host side, then relays the inner RDP stream over VMBus `HvSocket` (`00000d3d-facb-11e6-bd58-64006a7986d3` -> Linux `AF_VSOCK:3389`).
   - After the guest sends `X.224 CC-TPDU` with `RDP_NEG_RSP` selecting a non-RDP security protocol (`PROTOCOL_SSL`), **`vmms.exe` does NOT run a second TLS handshake over HvSocket**; it immediately transmits plaintext TPKT (`0x03 0x00 ...`) `MCS Connect Initial`.
   - OpenSSL attempted to parse the TPKT byte `0x03` as a TLS record header -> `tls_validate_record_header:wrong version number`.

2. **FreeRDP 3.33.1 Server Implementation**:
   - `libfreerdp/core/connection.c:1683-1686` (`rdp_server_accept_nego`):
     ```c
     if (freerdp_settings_get_bool(rdp->settings, FreeRDP_VmConnectMode) &&
         SelectedProtocol != PROTOCOL_RDP)
         /* When behind a Hyper-V proxy, security != RDP is handled by the host. */
         status = TRUE;
     ```
   - `libfreerdp/core/peer.c:831-848` (`peer_recv_callback_internal`):
     If `SelectedProtocol & PROTOCOL_HYBRID` is selected while `FreeRDP_VmConnectMode == TRUE`, FreeRDP skips `transport_accept_nla()` so `nego_get_identity()` returns `NULL` and `sspi_CopyAuthIdentity()` fails immediately (`STATE_RUN_FAILED`).
     **Fix**: In `VmConnectMode`, KRdp selects `PROTOCOL_SSL` (`FreeRDP_TlsSecurity = true`, `FreeRDP_NlaSecurity = false`, `FreeRDP_ExtSecurity = false`, `FreeRDP_RdpSecurity = false`, `FreeRDP_RdstlsSecurity = false`) and advertises `FreeRDP_RestrictedAdminModeSupported = true` (matching XRDP PR #3514 `libxrdp/xrdp_iso.c:453-457`).
   - `libfreerdp/core/peer.c:254-260` (`freerdp_peer_initialize`):
     Still requires a valid `FreeRDP_RdpServerCertificate`, which KRdp continues to load.

3. **Why a Transparent `socat` Proxy Is Insufficient & Unsafe**:
   - `socat` converts `AF_VSOCK` (`CID=2`) into `TCP 127.0.0.1:<ephemeral>`, stripping the Hyper-V host transport identity.
   - Enabling `FreeRDP_VmConnectMode` on a TCP listener would allow any local guest process (or network peer) to bypass TLS/NLA.
   - Integrating `AF_VSOCK` natively in `KRdp::Server` binds `FreeRDP_VmConnectMode` strictly to verified `AF_VSOCK` connections from `VMADDR_CID_HOST` (`CID=2`) with **zero TCP listener opened**.

---

## 2. Interfaces & CLI

Normal TCP mode is **100% unchanged**:

```bash
krdpserver                           # Standard TCP/TLS/NLA mode (unchanged)
```

Native Hyper-V Enhanced Session mode:

```bash
krdpserver --transport vsock --port 3389 --vsock-peer-cid 2 --pam \
    --certificate ~/.local/share/krdp-foxcore/server.crt \
    --certificate-key ~/.local/share/krdp-foxcore/server.key
```

### New CLI Flags

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--transport <tcp\|vsock>` | `tcp` | Select listening transport (`tcp` or native Linux `AF_VSOCK`). |
| `--vmconnect` / `--no-vmconnect` | `true` for `vsock`, forbidden for `tcp` | Enable/disable `FreeRDP_VmConnectMode` on `AF_VSOCK`. Hard error if combined with `--transport tcp`. |
| `--in-band-greeter` / `--no-in-band-greeter` | `true` for `vsock` + `--vmconnect`, forbidden otherwise | Enable/disable the isolated in-band guest login screen when `vmconnect.exe` omits credentials in `TS_INFO_PACKET`. |
| `--vsock-cid <cid\|any>` | `any` (`VMADDR_CID_ANY`) | Local `AF_VSOCK` CID to bind. |
| `--vsock-peer-cid <cid>` | `2` (`VMADDR_CID_HOST`) | Only authorized `AF_VSOCK` peer CID. Wildcard `any` is rejected. |
| `--pam` | KCM config (`SystemUserEnabled`) | Explicitly enable PAM authentication for the current non-root user. |

---

## 3. Security Model, Isolated In-Band Greeter & Trust Boundary

- **Transport Isolation**: `FreeRDP_VmConnectMode` and `--in-band-greeter` are rejected at CLI parsing, `Server::start()`, AND re-verified via `getpeername()` inside `RdpConnection::initialize()` (`ss_family == AF_VSOCK && svm_cid == allowedVsockPeerCid`, default `VMADDR_CID_HOST = 2`).
- **No Global TLS/NLA Weakening**: TCP connections never set `VmConnectMode`; plaintext TPKT after `RDP_NEG_RSP` on TCP is still rejected by OpenSSL.
- **No Unauthenticated Desktop Exposure (Strict Gate in `SessionController` & `RdpConnection`)**:
  - If `TS_INFO_PACKET` carries a **non-empty password**, `RdpConnection::onPostConnect()` validates it immediately via PAM / non-root KWallet users. Invalid passwords and `root` are rejected immediately (even when `--in-band-greeter` is enabled).
  - If `TS_INFO_PACKET` carries an **empty password** (standard Windows `vmconnect.exe` behavior):
    - With `--no-in-band-greeter`: connection is rejected immediately in `onPostConnect()`.
    - With `--in-band-greeter` (default on `vsock` + `vmconnect`): connection enters `AuthState::PendingInBandGreeter`.
    - **Zero desktop exposure while unauthenticated**: `SessionController` does **not** create `SessionWrapper`, PipeWire screencast, or KWin EIS input; `RdpConnection` does **not** initialize `Clipboard`.
    - `KRdp::InBandGreeter` renders a self-contained Qt `QPainter` login screen directly into `VideoStream` Progressive RFX frames, decodes keyboard scancodes via `xkbcommon` + mouse clicks, enforces max 5 attempts, 1000 ms cooldown, 120 s idle timeout, `root`/UID 0 rejection, and wipes password buffers with `explicit_bzero()`.
    - Only after guest PAM/KWallet authentication succeeds does `RdpConnection` emit `authenticatedChanged(true)`, switch `VideoStream` to the negotiated desktop codec, initialize `Clipboard`, and trigger `SessionController` to attach the Plasma Wayland session.
- **No Root RDP Login**: `RdpConnection::isDisallowedLoginUser()` blocks `root` (including `DOMAIN\root` / `.\root`) and any UID `0` account across PAM, custom users, SAM file generation, and `InBandGreeter`.
- **No Unnecessary TCP `*:3389` Listener**: Audit confirmed stock `app-org.kde.krdpserver.service` listens on `TCP *:3389` across all interfaces. `install.sh` disables it by default (`--disable-tcp-krdp`, opt-out `--keep-tcp-krdp`) and `rollback.sh` restores its prior state.
- **Sudo & Ownership Hardening**: `install.sh` and `rollback.sh` resolve the target non-root desktop user via `--user` / `$SUDO_USER` + `getent passwd` (never trusting `$HOME`, rejecting `root` / UID 0 / `/root`) and execute user-home file/cert/unit operations via `runuser -u "$TARGET_USER"`.
- **No UFW/WireGuard Changes**: Firewall and network rules remain untouched.

---

## 4. Session Lifecycle & `plasma-login-manager` Handoff Analysis

- **Logged-in Plasma Wayland Session (Implemented)**:
  `app-org.kde.krdpserver-vsock.service` (user unit, `WantedBy=plasma-workspace.target`) starts `krdpserver --transport vsock --port 3389 --pam` once the user logs into Plasma Wayland.
- **Pre-Login Greeter-to-User-Session Handoff (`plasma-login-manager 6.8.3`) Analysis**:
  - `plasma-login-manager 6.8.3-1` exposes `org.freedesktop.DisplayManager` (`/org/freedesktop/DisplayManager/Seat0`, methods `SwitchToGreeter`, `SwitchToUser`, `Lock`, `AddSeat` restricted to `root`) and runs a `plasmalogin` Wayland greeter (`plasma-login-wayland.target` -> `plasma-login-kwin_wayland.service` + `plasma-login.service`).
  - Upstream KRdp 6.8.3 (`src/RdpConnection.cpp`, commit `0535fbd2`) allows any valid non-root PAM user when running as `plasmalogin`.
  - Upstream KDE WIP (`origin/work/olib-tp/krdp-daemon`) explores a privileged system broker using `freerdp_peer::SendServerRedirection` and D-Bus `SessionAdaptor::GetNextSession()` (`QDBusUnixFileDescriptor`), **but `GetNextSession()` is currently an empty stub (`{}`)**, and `plasma-login-manager 6.8.3` ships no greeter-to-user RDP handoff protocol.
  - Furthermore, Hyper-V `vmms.exe` (TCP/2179 -> `HvSocket:3389`) cannot follow standard RDP Server Redirection to an arbitrary guest TCP IP. A true pre-login handoff over `HvSocket` requires a privileged system `AF_VSOCK:3389` broker that owns the HvSocket FD, launches/activates the user's `logind` Wayland session upon PAM auth, and hands off or proxies the session cleanly across the greeter -> user transition.
  - Per security requirements, **automatic login is NOT enabled** (`/etc/plasmalogin.conf` untouched). Pre-login remote session creation remains an explicit **architectural Release-Blocker** for headless pre-login use cases.

---

## 5. Measured Soak & Active-Motion 1080p Performance (`llvmpipe`, 7 vCPUs)

Captured via `./tools/foxcore/verify.sh` (`build-foxcore/reports/foxcore-verify-report.json`):

### 100-Cycle Connect/Disconnect Soak (Leak Audit)

| Suite | Cycles | RSS Warm -> End (Delta) | Open FDs Warm -> End (Delta) | Threads Warm -> End (Delta) | Result |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `VmConnectAuthTest::testVmConnect100CycleSoakNoLeak` (full Hyper-V wire protocol, 50 valid + 50 invalid) | 100 | `106.11` -> `106.11 MiB` (`+0.00 MiB`) | `16` -> `16` (`0`) | `5` -> `5` (`0`) | **PASS** |
| Live `krdpserver` 100-cycle soak (idle -> cycle 10 -> 50 -> 100 -> post-settle) | 100 | `91.38` -> `91.41 MiB` (`+0.03 MiB`) | `17` -> `17` (`0`) | `4` -> `4` (`0`) | **PASS** |

### 15-Second Active-Motion 1080p Benchmark (`qml6` 12 animated bars + rotating disc, Mesa `llvmpipe`)

| Profile | Total System CPU (7 vCPUs) | `krdpserver` CPU (1-core) | `kwin_wayland` CPU (1-core) | `pipewire` CPU (1-core) | `krdpserver` RSS (idle -> stream -> reconn) | `kwin_wayland` / `pipewire` RSS | Auth Reject Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **H.264 (`libx264` SW)** | `13.16 %` | `16.30 %` | `41.72 %` | `0.07 %` | `93.5` -> `240.3` -> `228.6 MiB` | `374.5` / `14.8 MiB` | `99.2 ms` |
| **Progressive (`KRDP_DISABLE_H264=1`)** | `6.97 %` | `1.40 %` | `28.08 %` | `0.00 %` | `93.2` -> `223.3` -> `245.5 MiB` | `374.8` / `14.7 MiB` | `90.3 ms` |

---

## 6. Build, Install, Verify & Rollback

```bash
# 1. Local build + CTest + tarball (+ optional Arch .pkg.tar.zst)
./tools/foxcore/build.sh --pkg

# 2. Dry-run installation preview (modifies nothing)
./tools/foxcore/install.sh --dry-run

# 3. Install side-by-side (non-root -> ~/.local/opt/foxcore-krdp; root -> /opt/foxcore-krdp)
#    Disables stock TCP *:3389 KRdp listener by default (pass --keep-tcp-krdp to keep it)
./tools/foxcore/install.sh

# 4. Switch port 3389 from legacy socat bridge to native FOXCORE KRdp (requires sudo)
sudo ./tools/foxcore/install.sh --replace-socat --user "$USER"

# 5. Run automated local verification, 100-cycle soaks & active-motion benchmarks
./tools/foxcore/verify.sh

# 6. Full rollback to prior state (add sudo if --replace-socat was used)
./tools/foxcore/rollback.sh
```

---

## 7. Interactive Windows Host Acceptance Test

Execute the host-side acceptance guide on the Windows Hyper-V host (Tests **H1–H4**):
- Guide: `tools/foxcore/tests/host-vmconnect-acceptance.md`
- Guest live log/socket monitor: `./tools/foxcore/tests/watch_host_acceptance.sh`

---

## 8. Qualification Matrix

| ID | Category | Test / Requirement | Status | Evidence / Blocker |
| :--- | :--- | :--- | :---: | :--- |
| **L1** | Build & ABI | Compiles against FreeRDP `3.33.1-2.1` + Arch `.pkg.tar.zst` + zero `VMCONNECT_TEST_HARNESS` in `libKRdp.so` | **PASS** | `build.sh --pkg`, `ldd`, `strings` |
| **L2** | Transport | Native `AF_VSOCK` listener binds port with zero TCP sockets; `CID=2` enforced | **PASS** | `vsocktransporttest`, `verify.sh` (`ss -tlpn`) |
| **L3** | CLI / Policy | TCP rejects `--vmconnect` & `--in-band-greeter`; wildcard `--vsock-peer-cid any` rejected | **PASS** | `vsocktransporttest`, `verify.sh` (7/7 cases) |
| **L4** | Auth (`VmConnectMode`) | Explicit wire-protocol `VmConnectMode`: empty (greeter off), invalid password, and `root` variants rejected; valid accepted | **PASS** | `vmconnectauthtest` (full X.224->MCS->TS_INFO->Finalization) |
| **L5** | In-Band Greeter | `VmConnectMode` empty password enters isolated `InBandGreeter` (no PipeWire/EIS/Clipboard), rejects `root`/wrong pass, enforces cooldown & 5-attempt lockout, unlocks on valid keyboard input | **PASS** | `vmconnectauthtest` |
| **L6** | Reliability (Soak) | 100-cycle connect/disconnect soak (`VmConnectMode` + live `krdpserver`): RSS, FD & Thread leak audit | **PASS** | `0.00`/`+0.03 MiB` RSS, `0` FD delta, `0` Thread delta |
| **L7** | Performance | 15s active-motion 1080p H.264 & Progressive benchmarks on `llvmpipe` (KRdp, KWin, PipeWire, total CPU) | **PASS** | `foxcore-verify-report.json` |
| **L8** | TCP Surface | Stock `app-org.kde.krdpserver.service` TCP `*:3389` audited; disabled by default in `install.sh` & restored on `rollback.sh` | **PASS** | `verify.sh`, `test_install_sudo_audit.sh` |
| **L9** | Deployment / Sudo | `sudo` user resolution (`$SUDO_USER`/`getent`), `runuser` ownership (`0700`/`0600`), RUNPATH & clean rollback (`pacman -Qkk krdp` = 0 modified) | **PASS** | `test_install_sudo_audit.sh` + live install/rollback |
| **H1** | Host E2E (VMConnect) | Windows `vmconnect.exe` Enhanced Session -> `InBandGreeter` -> invalid/root rejected -> valid unlocks Plasma Wayland | **UNVERIFIED (Release-Blocker)** | Requires interactive Windows Hyper-V host execution |
| **H2** | Host E2E (`mstsc.exe`) | Windows `mstsc.exe`/`msrdc.exe` via `vmms.exe:2179` (`pcb:s:<GUID>;EnhancedMode=1`) pre-auth | **UNVERIFIED (Release-Blocker)** | Requires Windows Hyper-V host execution |
| **H3** | Host E2E (UX) | Mouse, keyboard (DE/US), dynamic resize, clipboard & reconnect over live `HvSocket` | **UNVERIFIED (Release-Blocker)** | Requires Windows Hyper-V host execution |
| **H4** | Host Lifecycle | Full VM cold-boot Enhanced Session detection & service startup | **UNVERIFIED (Release-Blocker)** | Automatic reboot prohibited; verify manually |
| **P1** | Pre-Login Lifecycle | Remote login before local Plasma login via `plasma-login-manager` Greeter-to-User-Session Handoff | **UNVERIFIED / BLOCKED (Release-Blocker for pre-login)** | Upstream `plasma-login-manager 6.8.3` & `krdp-daemon` (`GetNextSession()` stub) lack HvSocket broker/handoff; autologin prohibited |

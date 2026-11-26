# FOXCORE — Native KDE Plasma Wayland Hyper-V Enhanced Session Integration

Native `AF_VSOCK` (`hv_sock`) and Hyper-V `FreeRDP_VmConnectMode` support for KDE Plasma 6.8.3 (`KRdp`) on CachyOS, without Xorg, XRDP, XFCE, or an externally reachable TCP port.

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
| `--vsock-cid <cid\|any>` | `any` (`VMADDR_CID_ANY`) | Local `AF_VSOCK` CID to bind. |
| `--vsock-peer-cid <cid>` | `2` (`VMADDR_CID_HOST`) | Only authorized `AF_VSOCK` peer CID. Wildcard `any` is rejected. |
| `--pam` | KCM config (`SystemUserEnabled`) | Explicitly enable PAM authentication for the current non-root user. |

## 3. Security Model & Trust Boundary

- **Transport Isolation**: `FreeRDP_VmConnectMode` is rejected at CLI parsing, `Server::start()`, AND re-verified via `getpeername()` inside `RdpConnection::initialize()` (`ss_family == AF_VSOCK && svm_cid == allowedVsockPeerCid`, default `VMADDR_CID_HOST = 2`).
- **No Global TLS/NLA Weakening**: TCP connections never set `VmConnectMode`; plaintext TPKT after `RDP_NEG_RSP` on TCP is still rejected by OpenSSL.
- **No Unauthenticated Sessions**: In `VmConnectMode`, `RdpConnection::onPostConnect()` **never** takes the NLA-bypass shortcut. Non-empty credentials in `TS_INFO_PACKET` are strictly validated via PAM (with proper `pam_end()` cleanup and `explicit_bzero` of password buffers) and/or configured non-root KRdp KWallet users.
- **No Root RDP Login**: `RdpConnection::isDisallowedLoginUser()` blocks `root` (including `DOMAIN\root` / `.\root`) and any UID `0` account across PAM, custom users, and SAM file generation.
- **No External TCP Listener**: In `--transport vsock` mode, `QTcpServer::listen()` is never called (`ss -tlpn` confirms zero TCP sockets).
- **No UFW/WireGuard Changes**: Firewall and network rules remain untouched.

> **Important Host Client Note (Release-Blocker Assessment)**:
> Because KRdp enforces strict guest-side authentication and does not render an in-band pre-desktop login dialog (unlike XRDP or Windows LogonUI), the connecting client **must** supply valid guest credentials in `TS_INFO_PACKET`:
> - **`mstsc.exe` / `msrdc.exe` / `xfreerdp3`** with `pcb:s:<VM_GUID>;EnhancedMode=1` on host TCP/2179 prompt for and transmit guest credentials -> authenticated by KRdp PAM/KWallet.
> - **Windows `vmconnect.exe`** directly only shows a display-size dialog and may send empty or Windows-host credentials in `TS_INFO_PACKET`; KRdp will **strictly reject** empty/invalid credentials rather than opening an unauthenticated desktop. See Section 5 ("Remaining Blockers").

## 4. Session Lifecycle (Pre-Login vs. Logged-In Session)

- **Logged-in Plasma Wayland Session (Implemented)**:
  `app-org.kde.krdpserver-vsock.service` (user unit, `WantedBy=plasma-workspace.target`) starts `krdpserver --transport vsock --port 3389 --pam` once the user logs into Plasma Wayland.
- **Pre-Login Access (`plasmalogin`) Analysis**:
  - `plasma-login-manager` 6.8.3 runs `kwin_wayland` under the `plasmalogin` user (`plasma-login-wayland.target`).
  - Upstream KRdp 6.8.3 (`src/RdpConnection.cpp`, commit `0535fbd2`) already allows any valid non-root PAM user when running as `plasmalogin`.
  - However, `plasma-login-manager` 6.8.3 does **not** yet ship a greeter-side KRdp broker or RDP handoff mechanism to transition an active RDP connection from the `plasmalogin` greeter compositor to the newly started user `kwin_wayland` session without dropping the connection.
  - Per security requirements, **automatic login is NOT enabled** as a workaround (`/etc/plasmalogin.conf` remains untouched).

## 5. Build, Install, Verify & Rollback

```bash
# 1. Local build + CTest + side-by-side tarball artifact (no root required)
./tools/foxcore/build.sh

# Optional: also build an Arch/CachyOS .pkg.tar.zst package
./tools/foxcore/build.sh --pkg

# 2. Dry-run installation preview (modifies nothing)
./tools/foxcore/install.sh --dry-run

# 3. Install side-by-side (non-root -> ~/.local/opt/foxcore-krdp; root -> /opt/foxcore-krdp)
./tools/foxcore/install.sh

# 4. Switch port 3389 from legacy socat bridge to native FOXCORE KRdp (requires sudo)
sudo ./tools/foxcore/install.sh --replace-socat
systemctl --user daemon-reload
systemctl --user enable --now app-org.kde.krdpserver-vsock.service

# 5. Run automated local verification & performance measurement (writes JSON report)
./tools/foxcore/verify.sh

# 6. Full rollback to prior state (add sudo if --replace-socat was used)
./tools/foxcore/rollback.sh
```

## 6. Host-Side Connection (Windows Hyper-V Host)

Ensure HvSocket transport is configured on the host (already done for `FOXCORE`):

```powershell
Set-VM -VMName "FOXCORE" -EnhancedSessionTransportType HvSocket
```

To connect with explicit guest credentials via `mstsc.exe` / `msrdc.exe` (recommended when `vmconnect.exe` does not forward Linux credentials):

```powershell
(Get-VM -Name "FOXCORE").Id
```

Save as `foxcore.rdp`:

```ini
full address:s:localhost
server port:i:2179
pcb:s:<VM_GUID>;EnhancedMode=1
negotiate security layer:i:0
dynamic resolution:i:1
```

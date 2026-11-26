# FOXCORE — Interactive Windows Host VMConnect Acceptance Test

This guide provides a reproducible acceptance test to execute from a **Windows Hyper-V Host** against a Linux KDE Plasma 6.8.3 guest VM (examples below use `FOXCORE` as the VM name; replace with your VM name).

## Prerequisites (Guest Side — Inside the Linux VM)

1. Switch port `3389` from any legacy `socat` bridge to native FOXCORE KRdp (creates timestamped backups and disables stock TCP `*:3389` `app-org.kde.krdpserver.service`):

```bash
cd /path/to/krdp
sudo ./tools/foxcore/install.sh --replace-socat
```

2. Verify guest transport & listener posture (must show `AF_VSOCK *:3389` and **zero** `krdpserver` TCP listeners):

```bash
ss --vsock -ln | grep 3389
ss -tlpn | grep krdpserver || echo "OK: zero TCP krdpserver listeners"
systemctl --user status app-org.kde.krdpserver-vsock.service --no-pager
```

3. Start the guest-side evidence watcher in a terminal before running the Windows host tests:

```bash
./tools/foxcore/tests/watch_host_acceptance.sh
```

---

## Host-Side Test Cases (Execute on Windows Hyper-V Host)

Verify HvSocket transport is enabled on the host (PowerShell as Administrator):

```powershell
(Get-VM -Name "FOXCORE").EnhancedSessionTransportType
# Expected: HvSocket
```

### Test H1 — Direct `vmconnect.exe` Enhanced Session + In-Band Greeter

1. Open **Hyper-V Manager** → double-click **FOXCORE** → ensure **View → Enhanced session** is enabled.
2. Select desired display resolution (e.g., `1920x1080`) and click **Connect**.
3. **Expected**:
   - No TLS `wrong version number` disconnect.
   - The isolated **FOXCORE — KDE Plasma Wayland** login screen renders inside VMConnect (NO desktop content visible yet, clipboard inactive).
4. **Negative check H1a (Root rejection)**: Enter username `root` + any password → press Enter.
   - **Expected**: Rejected with `"Root login is not permitted"`.
5. **Negative check H1b (Invalid password)**: Enter your non-root Linux username (`<your-linux-username>`) + wrong password → press Enter.
   - **Expected**: Rejected with `"Authentication failed (2/5 attempts)"`, 1 s cooldown enforced.
6. **Positive check H1c (Valid PAM login)**: Wait 1 s, enter your valid Linux guest password → press Enter.
   - **Expected**: Greeter closes and transitions cleanly to the live **KDE Plasma 6.8.3 Wayland** desktop.

### Test H2 — Direct Pre-Authenticated Connection via `mstsc.exe` / `msrdc.exe`

1. Obtain the VM GUID on the Windows host:
   ```powershell
   (Get-VM -Name "FOXCORE").Id
   ```
2. Create `foxcore-enhanced.rdp`:
   ```ini
   full address:s:localhost
   server port:i:2179
   pcb:s:<VM_GUID>;EnhancedMode=1
   negotiate security layer:i:0
   dynamic resolution:i:1
   ```
3. Launch `mstsc.exe foxcore-enhanced.rdp` and supply:
   - **H2a**: Wrong Linux password → **Expected**: Immediate disconnect before desktop/greeter.
   - **H2b**: Username `root` → **Expected**: Immediate disconnect before desktop/greeter.
   - **H2c**: Valid Linux user + password → **Expected**: Direct PAM auth in `onPostConnect()`, live KDE Plasma Wayland desktop opens immediately (greeter bypassed).

### Test H3 — Interactive Usability (Input, Resize, Clipboard, Reconnect)

Inside an active Enhanced Session (from H1 or H2):

- **H3a (Keyboard & Mouse)**: Open Konsole, type text including Shift/symbols, scroll with mouse wheel.
- **H3b (Dynamic Resize)**: Resize the VMConnect / `mstsc` window → verify KDE Plasma output resizes cleanly via `DisplayControl`.
- **H3c (Clipboard)**: Copy text on Windows host → paste into Konsole; copy text in Konsole → paste on Windows host.
- **H3d (Reconnect)**: Close VMConnect window (without logging out of Plasma), reconnect via VMConnect → verify In-Band Greeter appears again and unlocks the existing Plasma session cleanly.

### Test H4 — Cold Reboot & Rollback Check

1. Perform a full VM shutdown (`systemctl poweroff`) and cold start from Hyper-V Manager.
2. Log in locally on the Basic Session console (until `plasma-login-manager` broker handoff exists), then switch to Enhanced Session → verify `app-org.kde.krdpserver-vsock.service` automatically started on `AF_VSOCK:3389` and Enhanced Session connects cleanly.
3. Optional rollback test:
   ```bash
   sudo ./tools/foxcore/rollback.sh
   ```
   Verify `krdp-vsock.service` and stock `krdp` package integrity (`pacman -Qkk krdp`) are restored.

---

## Recording Evidence

Stop `watch_host_acceptance.sh` with `Ctrl+C` after completing H1–H4. It saves a timestamped log bundle under `build-foxcore/reports/host-acceptance-<timestamp>.log` and checks for:
- `Accepted AF_VSOCK connection from CID 2`
- `In-band greeter rejected disallowed login user`
- `In-band greeter authenticated guest user` (H1) / `PAM authentication succeeded` (H2)
- Zero `tls_validate_record_header:wrong version number` errors

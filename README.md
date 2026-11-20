# SentinelShield (v1.1.0)

**SentinelShield** is an active anti-ransomware and endpoint containment agent for Windows 11. It combines real-time dual-zone filesystem telemetry with automated process neutralization, recovery-wipe interception, self-defense ACL hardening, and instant network isolation.

---

## Architecture (`v1.1.0`)

```text
Sentinel_Shield_2026/
├── sentinel_all_in_one.py          # Core Dual-Zone watcher, lockdown coordinator & webhook dispatcher
├── SentinelShield.spec             # PyInstaller standalone Windows executable build specification
├── sentinel_modules/
│   ├── process_killer.py           # Windows Restart Manager (rstrtmgr.dll) + psutil handle terminator
│   ├── vss_guard.py                # Real-time WMI Win32_ProcessStartTrace shadow-copy & recovery guard
│   ├── tamper_guard.py             # Explicit DACL hardening for SentinelShield.exe & config.json
│   └── tray_ui.py                  # Live system tray shield UI & one-click network restoration
├── Restore_Network.bat             # Emergency network adapter re-enable script
└── config.json                     # Runtime configuration (canary/work directories, thresholds, webhook)
```

---

## Core Defensive Capabilities

1. **Dual-Zone Dynamic Filesystem Monitoring (`sentinel_all_in_one.py`)**
   - **Canary Zone (`CANARY`):** Zero-tolerance tripwire directories; any unauthorized access or modification immediately triggers full containment.
   - **Work Zone (`WORK`):** Tracks rapid mass-modification velocity across active user directories (`Desktop`, `Documents`) while filtering benign office temp files.
2. **Active Process Termination (`sentinel_modules/process_killer.py`)**
   - Queries the Windows Restart Manager API (`rstrtmgr.dll`) and active process file handles to identify and terminate non-system processes locking or encrypting protected files prior to network cutoff.
3. **Volume Shadow Copy & Recovery Guard (`sentinel_modules/vss_guard.py`)**
   - Monitors `Win32_ProcessStartTrace` events via WMI in real time to block and kill pre-encryption recovery sabotage commands (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set recoveryenabled no`, `wbadmin delete`).
4. **Tamper Protection & ACL Hardening (`sentinel_modules/tamper_guard.py`)**
   - Enforces explicit Windows DACLs on `SentinelShield.exe` and `config.json`, granting Full Control (`F`) exclusively to `NT AUTHORITY\SYSTEM` and `BUILTIN\Administrators` while restricting `BUILTIN\Users` to Read/Execute (`RX`).
5. **Automated Network Isolation & System Tray UI (`sentinel_modules/tray_ui.py`)**
   - Disables the active network adapter to halt C2 communication and lateral spread, dispatches a webhook alert, and updates the live taskbar shield icon from **Active Green** to **Lockdown Red** with one-click access to `Restore_Network.bat`.

---

## Quick Start (Windows 11)

1. Download `SentinelShield_v1.1.0_Win64.zip` from the [Releases](https://github.com/Fikashongwe/Sentinel_Shield_2026/releases) page.
2. Verify the archive checksum:
   ```powershell
   Get-FileHash .\SentinelShield_v1.1.0_Win64.zip -Algorithm SHA256
   # Expected: 6EFF373935E879FA4AF705C37D8005981890D6BD8EA6F23A36A4DD7301AD12F8
   ```
3. Extract the archive, configure `config.json` with your directories and webhook URL, and run `SentinelShield.exe` as Administrator.

import threading
import re
import pythoncom
import wmi
import psutil

MALICIOUS_CMD_PATTERNS = [
    re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE),
    re.compile(r"wmic(\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE),
    re.compile(r"bcdedit(\.exe)?\s+/set\s+.*recoveryenabled\s+no", re.IGNORECASE),
    re.compile(r"wbadmin(\.exe)?\s+delete\s+(catalog|backup|systemstatebackup)", re.IGNORECASE),
    re.compile(r"Get-WmiObject\s+Win32_ShadowCopy.*Delete", re.IGNORECASE),
]

def _vss_monitor_loop(on_threat_callback):
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        watcher = c.Win32_ProcessStartTrace.watch_for()
        while True:
            proc_event = watcher()
            pid = proc_event.ProcessID
            cmd = getattr(proc_event, "CommandLine", "") or ""
            if not cmd:
                try:
                    cmd = " ".join(psutil.Process(pid).cmdline())
                except Exception:
                    continue

            for pattern in MALICIOUS_CMD_PATTERNS:
                if pattern.search(cmd):
                    try:
                        p = psutil.Process(pid)
                        parent = p.parent()
                        p.kill()
                        if parent and parent.name().lower() not in ("explorer.exe", "services.exe", "svchost.exe", "sentinelshield.exe"):
                            parent.kill()
                    except Exception:
                        pass
                    on_threat_callback(
                        f"Blocked recovery-wipe command (PID {pid}): {cmd}",
                        "VSS_RECOVERY_SABOTAGE"
                    )
                    break
    finally:
        pythoncom.CoUninitialize()

def start_vss_guard(on_threat_callback):
    t = threading.Thread(target=_vss_monitor_loop, args=(on_threat_callback,), daemon=True)
    t.start()
    return t

import os
import ctypes
from ctypes import wintypes
import psutil

rstrtmgr = ctypes.WinDLL("rstrtmgr", use_last_error=True)

CCH_RM_SESSION_KEY = 32
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63
ERROR_MORE_DATA = 234

class RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", wintypes.FILETIME)]

class RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", RM_UNIQUE_PROCESS),
        ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
        ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
        ("ApplicationType", wintypes.DWORD),
        ("AppStatus", wintypes.ULONG),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]

PROTECTED_PROCESSES = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
    "explorer.exe", "dwm.exe", "taskmgr.exe", "sentinelshield.exe"
}

def find_locking_pids(file_path: str) -> set[int]:
    pids = set()
    session_handle = wintypes.DWORD()
    session_key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)

    if rstrtmgr.RmStartSession(ctypes.byref(session_handle), 0, session_key) == 0:
        try:
            res_array = (wintypes.LPCWSTR * 1)(os.path.abspath(file_path))
            if rstrtmgr.RmRegisterResources(session_handle, 1, res_array, 0, None, 0, None) == 0:
                needed = wintypes.UINT(0)
                count = wintypes.UINT(0)
                reasons = wintypes.DWORD(0)
                err = rstrtmgr.RmGetList(session_handle, ctypes.byref(needed), ctypes.byref(count), None, ctypes.byref(reasons))
                if err == ERROR_MORE_DATA and needed.value > 0:
                    count.value = needed.value
                    proc_info = (RM_PROCESS_INFO * count.value)()
                    if rstrtmgr.RmGetList(session_handle, ctypes.byref(needed), ctypes.byref(count), proc_info, ctypes.byref(reasons)) == 0:
                        for i in range(count.value):
                            pids.add(proc_info[i].Process.dwProcessId)
        finally:
            rstrtmgr.RmEndSession(session_handle)

    target = os.path.abspath(file_path).lower()
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for f in proc.open_files():
                if f.path.lower().removeprefix("\\\\?\\") == target:
                    pids.add(proc.info["pid"])
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    return pids

def neutralize_offending_processes(target_paths: list[str]) -> list[dict]:
    my_pid = os.getpid()
    parent_pid = psutil.Process(my_pid).ppid()
    candidate_pids = set()

    for path in target_paths:
        if os.path.exists(path):
            candidate_pids.update(find_locking_pids(path))

    terminated = []
    for pid in candidate_pids:
        if pid in (0, 4, my_pid, parent_pid):
            continue
        try:
            proc = psutil.Process(pid)
            raw_name = proc.name() or "unknown"
            if raw_name.lower() in PROTECTED_PROCESSES:
                continue
            exe_path = proc.exe()
            proc.kill()
            proc.wait(timeout=3)
            terminated.append({"pid": pid, "name": raw_name, "exe": exe_path})
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            continue

    return terminated

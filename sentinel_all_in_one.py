import os
import sys
import time
import json
import ctypes
import logging
import threading
import subprocess
from collections import deque
import urllib3
import win32con
import win32file
from ctypes import wintypes

ERROR_ALREADY_EXISTS = 183

def enforce_single_instance(mutex_name: str = "Global\\SentinelShield_SingleInstance_Mutex"):
    """Ensure only one SentinelShield worker instance runs across all Windows sessions."""
    if sys.platform != "win32":
        return None

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE

    handle = kernel32.CreateMutexW(None, False, mutex_name)
    last_error = ctypes.get_last_error()

    if not handle or last_error == ERROR_ALREADY_EXISTS:
        if handle:
            kernel32.CloseHandle(handle)
        sys.exit(0)

    return handle

# Keep mutex handle alive for the entire lifetime of the process
_INSTANCE_MUTEX = enforce_single_instance()

from sentinel_modules.process_killer import neutralize_offending_processes
from sentinel_modules.vss_guard import start_vss_guard
from sentinel_modules.tamper_guard import apply_tamper_protection
from sentinel_modules.tray_ui import SentinelTray

tray = None

# ==============================================================================
# PATH & CONFIGURATION LOADER
# ==============================================================================
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
LOG_PATH = os.path.join(BASE_DIR, "sentinel_activity.log")

DEFAULT_CONFIG = {
    "canary_directories": [os.path.join(BASE_DIR, "test_sandbox")],
    "work_directories": [
        "%USERPROFILE%\\Documents",
        "%USERPROFILE%\\Desktop",
    ],
    "work_threshold_count": 5,
    "work_threshold_window_seconds": 3,
    "allowed_extensions": [".docx", ".xlsx"],
    "target_adapter": "auto",
    "webhook_url": "",
    "cooldown_seconds": 10,
}


def get_active_adapters():
    """Queries Windows netsh to find all currently Connected network adapters."""
    adapters = []
    try:
        output = subprocess.check_output(
            ["netsh", "interface", "show", "interface"],
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1].lower() == "connected":
                adapters.append(" ".join(parts[3:]))
    except Exception as e:
        logging.error(f"[-] Failed to enumerate network adapters: {e}")
    return adapters

def isolate_network(target_adapter):
    adapters = get_active_adapters() if target_adapter.lower() == "auto" else [target_adapter]
    if not adapters:
        logging.warning("[!] No active network adapters found to isolate.")
        return "None"

    isolated = []
    for adapter in adapters:
        try:
            subprocess.run(
                ["netsh", "interface", "set", "interface", adapter, "admin=disable"],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f"[+] Target network isolation successful: {adapter} adapter disabled.")
            isolated.append(adapter)
        except Exception as e:
            logging.error(f"[-] Failed to disable adapter '{adapter}': {e}")

    return ", ".join(isolated) if isolated else "Failed"

def get_active_adapters():
    adapters = []
    try:
        output = subprocess.check_output(
            ["netsh", "interface", "show", "interface"],
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1].lower() == "connected":
                adapters.append(" ".join(parts[3:]))
    except Exception as e:
        logging.error(f"[-] Failed to enumerate network adapters: {e}")
    return adapters

def isolate_network(target_adapter):
    adapters = get_active_adapters() if target_adapter.lower() == "auto" else [target_adapter]
    if not adapters:
        logging.warning("[!] No active network adapters found to isolate.")
        return "None"

    isolated = []
    for adapter in adapters:
        try:
            subprocess.run(
                ["netsh", "interface", "set", "interface", adapter, "admin=disable"],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f"[+] Target network isolation successful: {adapter} adapter disabled.")
            isolated.append(adapter)
        except Exception as e:
            logging.error(f"[-] Failed to disable adapter '{adapter}': {e}")

    return ", ".join(isolated) if isolated else "Failed"

def trigger_lockdown(target_file: str, event_type: str):
    """Coordinates process termination, isolation, webhook notification, and user alert."""
    global last_trigger_time
    with lockdown_lock:
        now = time.time()
        if now - last_trigger_time < COOLDOWN_SECONDS:
            return
        last_trigger_time = now

    killed_procs = neutralize_offending_processes([target_file])
    killed_summary = (
        ", ".join(f"{p['name']} (PID {p['pid']})" for p in killed_procs)
        if killed_procs else "None"
    )

    if tray:
        tray.set_lockdown_state()

    logger.critical(
        f"[*] Emergency lockdown triggered by {event_type.lower()}: {target_file} | Killed: {killed_summary}"
    )
    send_webhook_alert(f"{event_type} on {target_file} | Neutralized: {killed_summary}")
    isolate_network(TARGET_ADAPTER)
    show_emergency_popup(target_file, event_type)


def load_config():
    """Loads settings from config.json or creates a default file if missing."""
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        return DEFAULT_CONFIG
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def resolve_paths(path_list):
    """Expands Windows environment variables like %USERPROFILE% and normalizes paths."""
    resolved = []
    for raw_path in path_list:
        expanded = os.path.abspath(os.path.expandvars(raw_path))
        resolved.append(expanded)
    return resolved


CONFIG = load_config()
CANARY_DIRS = resolve_paths(CONFIG.get("canary_directories", DEFAULT_CONFIG["canary_directories"]))
WORK_DIRS = resolve_paths(CONFIG.get("work_directories", DEFAULT_CONFIG["work_directories"]))
WORK_THRESHOLD_COUNT = int(CONFIG.get("work_threshold_count", 5))
WORK_THRESHOLD_WINDOW = float(CONFIG.get("work_threshold_window_seconds", 3))
ALLOWED_EXTENSIONS = tuple(
    ext.lower() for ext in CONFIG.get("allowed_extensions", DEFAULT_CONFIG["allowed_extensions"])
)
TARGET_ADAPTER = CONFIG.get("target_adapter", DEFAULT_CONFIG["target_adapter"])
WEBHOOK_URL = CONFIG.get("webhook_url", DEFAULT_CONFIG["webhook_url"])
COOLDOWN_SECONDS = float(CONFIG.get("cooldown_seconds", 10))

FILE_NOTIFY_CHANGE_LAST_ACCESS = 0x00000020

ACTION_MAP = {
    1: "Created / File Opened",
    2: "Deleted",
    3: "Accessed / Modified",
    4: "Renamed (Old Name)",
    5: "Renamed (New Name)",
}

# ==============================================================================
# LOGGING SETUP
# ==============================================================================
logger = logging.getLogger("SentinelShield")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

file_handler = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)

# ==============================================================================
# CORE DEFENSE & RESPONSE FUNCTIONS
# ==============================================================================
lockdown_lock = threading.Lock()
last_trigger_time = 0.0
import certifi
http = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())


def get_active_adapters():
    adapters = []
    try:
        output = subprocess.check_output(
            ["netsh", "interface", "show", "interface"],
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1].lower() == "connected":
                adapters.append(" ".join(parts[3:]))
    except Exception as e:
        logging.error(f"[-] Failed to enumerate network adapters: {e}")
    return adapters

def isolate_network(target_adapter):
    adapters = get_active_adapters() if target_adapter.lower() == "auto" else [target_adapter]
    if not adapters:
        logging.warning("[!] No active network adapters found to isolate.")
        return "None"

    isolated = []
    for adapter in adapters:
        try:
            subprocess.run(
                ["netsh", "interface", "set", "interface", adapter, "admin=disable"],
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f"[+] Target network isolation successful: {adapter} adapter disabled.")
            isolated.append(adapter)
        except Exception as e:
            logging.error(f"[-] Failed to disable adapter '{adapter}': {e}")

    return ", ".join(isolated) if isolated else "Failed"

def send_webhook_alert(event_detail: str):
    """Sends an HTTP JSON alert if WEBHOOK_URL is configured."""
    if not WEBHOOK_URL:
        return
    try:
        payload = json.dumps({"text": f"CRITICAL - SentinelShield Alert: {event_detail}"}).encode("utf-8")
        http.request(
            "POST",
            WEBHOOK_URL,
            body=payload,
            headers={"Content-Type": "application/json"},
            timeout=3.0,
        )
        logger.info("[+] Webhook alert dispatched.")
    except Exception as exc:
        logger.error(f"[-] Webhook dispatch failed ({type(exc).__name__}): unable to reach webhook endpoint.")


def show_emergency_popup(target_file: str, event_type: str):
    """Displays a top-most Windows alert box without blocking the watcher thread."""
    def _popup():
        message = (
            f"SECURITY ALERT: Protected Asset Triggered!\n\n"
            f"Event: {event_type}\n"
            f"Target: {target_file}\n\n"
            f"Automated network isolation has been executed on '{TARGET_ADAPTER}'."
        )
        ctypes.windll.user32.MessageBoxW(0, message, "SentinelShield Emergency Lockdown", 0x10 | 0x1000)

    threading.Thread(target=_popup, daemon=True).start()


def trigger_lockdown(target_file: str, event_type: str):
    """Coordinates logging, isolation, webhook notification, and user alert."""
    global last_trigger_time
    with lockdown_lock:
        now = time.time()
        if now - last_trigger_time < COOLDOWN_SECONDS:
            return
        last_trigger_time = now

    logger.critical(
        f"[*] Emergency lockdown triggered by {event_type.lower()}: {target_file}"
    )
    isolate_network(TARGET_ADAPTER)
    send_webhook_alert(f"{event_type} on {target_file}")
    show_emergency_popup(target_file, event_type)


# ==============================================================================
# DUAL-MODE DIRECTORY WATCHER (CANARY VS. WORK DIRECTORIES)
# ==============================================================================
def watch_directory(target_dir: str, mode: str = "canary"):
    """Monitors a directory in 'canary' (instant) or 'work' (burst-threshold) mode."""
    os.makedirs(target_dir, exist_ok=True)
    notify_filter = (
        win32con.FILE_NOTIFY_CHANGE_FILE_NAME
        | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE
    )
    if mode == "canary":
        notify_filter |= FILE_NOTIFY_CHANGE_LAST_ACCESS

    dir_handle = win32file.CreateFile(
        target_dir,
        win32con.GENERIC_READ,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )

    recent_work_events = deque()
    logger.info(f"[*] Watching [{mode.upper()}] directory: {target_dir}")

    try:
        while True:
            events = win32file.ReadDirectoryChangesW(
                dir_handle,
                4096,
                True,
                notify_filter,
                None,
                None,
            )
            for action, rel_filename in events:
                if not rel_filename:
                    continue

                basename = os.path.basename(rel_filename)
                if basename.startswith("~$") or not basename.lower().endswith(ALLOWED_EXTENSIONS):
                    continue

                full_target = os.path.join(target_dir, rel_filename)
                event_desc = ACTION_MAP.get(action, f"Unknown Action ({action})")

                if mode == "canary":
                    trigger_lockdown(full_target, f"Canary {event_desc}")
                else:
                    # Work mode: only count write/rename/delete actions, ignore normal single reads
                    if action in (1, 2, 3, 5):
                        now = time.time()
                        recent_work_events.append((now, full_target))
                        while recent_work_events and (now - recent_work_events[0][0]) > WORK_THRESHOLD_WINDOW:
                            recent_work_events.popleft()

                        unique_files = {item[1] for item in recent_work_events}
                        if len(unique_files) >= WORK_THRESHOLD_COUNT:
                            recent_work_events.clear()
                            trigger_lockdown(
                                full_target,
                                f"Rapid Mass Modification ({len(unique_files)} files in {WORK_THRESHOLD_WINDOW}s)",
                            )
    finally:
        win32file.CloseHandle(dir_handle)


if __name__ == "__main__":
    logger.info("[*] SentinelShield Engine Started (Dual-Zone Dynamic Mode).")
    apply_tamper_protection(BASE_DIR)
    tray = SentinelTray(BASE_DIR, on_exit_callback=lambda: os._exit(0))
    tray.run_detached()
    start_vss_guard(on_threat_callback=trigger_lockdown)

    for c_dir in CANARY_DIRS:
        threading.Thread(target=watch_directory, args=(c_dir, "canary"), daemon=True).start()

    for w_dir in WORK_DIRS:
        # Avoid double-watching if a canary directory sits inside Desktop
        threading.Thread(target=watch_directory, args=(w_dir, "work"), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[*] SentinelShield Engine stopped by operator.")

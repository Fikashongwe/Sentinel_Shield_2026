import os
import sys
import time
import threading
from collections import deque

# --- CONFIGURATION & PATHS ---
USER_PROFILE = os.environ.get("USERPROFILE", "C:\\")
PROTECTED_TARGET = os.path.join(USER_PROFILE, "Desktop\\Sentinel_Test")

# DIRECT LINK TO DESKTOP LOG FILE
REPORT_PATH = os.path.join(USER_PROFILE, "Desktop\\INCIDENT_REPORT.txt")

# Detection Thresholds: 10 file changes within a rolling 5-second window
BURST_THRESHOLD = 10
TIME_WINDOW = 5.0

# Global tracking metrics
change_events = deque()
lock_mutex = threading.Lock()

def write_incident(status_level, description):
    """Appends messages matching your exact active log file syntax format."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp} - {status_level}: {description}\n"
    
    try:
        # Guarantee file access regardless of directory execution context
        with open(REPORT_PATH, "a", encoding="utf-8") as f:
            f.write(log_entry)
            f.flush() # Force write to disk immediately
    except Exception:
        pass

def lock_workstation():
    """Invokes the native Windows user32 library to instantly lock the desktop."""
    write_incident("CRITICAL", "Mass file manipulation profile match. Triggering system lockdown.")
    os.system("rundll32.exe user32.dll,LockWorkStation")

def monitor_directory(target_path):
    """Main background worker thread tracking rapid file modifications."""
    global change_events
    write_incident("INFO", f"Mass file monitoring module initialized on path: {target_path}")
    
    if not os.path.exists(target_path):
        try:
            os.makedirs(target_path)
        except Exception:
            pass

    try:
        last_snapshot = set(os.listdir(target_path))
    except Exception:
        last_snapshot = set()

    while True:
        try:
            time.sleep(0.1)
            
            if not os.path.exists(target_path):
                continue
                
            current_snapshot = set(os.listdir(target_path))
            
            if current_snapshot != last_snapshot:
                current_time = time.time()
                diff_count = len(current_snapshot ^ last_snapshot)
                
                with lock_mutex:
                    for _ in range(diff_count):
                        change_events.append(current_time)
                    
                    while change_events and (current_time - change_events[0] > TIME_WINDOW):
                        change_events.popleft()
                    
                    if len(change_events) >= BURST_THRESHOLD:
                        lock_workstation()
                        
                        change_events.clear()
                        time.sleep(2.0)
                        try:
                            current_snapshot = set(os.listdir(target_path))
                        except Exception:
                            current_snapshot = set()
                
                last_snapshot = current_snapshot
                
        except Exception as e:
            write_incident("ERROR", f"Exception caught in file engine loop: {str(e)}")
            time.sleep(1)

if __name__ == "__main__":
    monitor_thread = threading.Thread(target=monitor_directory, args=(PROTECTED_TARGET,), daemon=True)
    monitor_thread.start()

    # PERMANENT BACKGROUND ANCHOR
    while True:
        time.sleep(5)
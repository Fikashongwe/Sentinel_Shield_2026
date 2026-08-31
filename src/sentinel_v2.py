import os
import time
import threading
from collections import deque
import datetime

# --- CONFIGURATION & PATHS ---
# Using absolute paths is required for stability when running as a System Service
BASE_DIR = "C:\\Sentinel_Shield_2026"
PROTECTED_TARGET = os.path.join(BASE_DIR, "Sentinel_Test")
REPORT_DIR = os.path.join(BASE_DIR, "Reports")
CLEANUP_THRESHOLD_HOURS = 48

# Thresholds
BURST_THRESHOLD = 10
TIME_WINDOW = 5.0

# Thread-safe primitives
log_mutex = threading.Lock()
metrics_mutex = threading.Lock()
change_events = deque()

def cleanup_old_reports():
    """Background thread to remove forensic reports older than 48 hours."""
    while True:
        try:
            now = time.time()
            if os.path.exists(REPORT_DIR):
                for filename in os.listdir(REPORT_DIR):
                    filepath = os.path.join(REPORT_DIR, filename)
                    if os.path.getmtime(filepath) < now - (CLEANUP_THRESHOLD_HOURS * 3600):
                        os.remove(filepath)
        except Exception:
            pass 
        time.sleep(3600) # Run cleanup check every hour

def write_incident(sensor_name, incident_type, details):
    """Generates a comprehensive forensic report."""
    timestamp = datetime.datetime.now()
    time_str = timestamp.strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"Incident_{sensor_name}_{time_str}.txt"
    filepath = os.path.join(REPORT_DIR, log_filename)
    
    report_content = f"""
--- SENTINEL V2 INCIDENT REPORT ---
TIMESTAMP: {timestamp.strftime("%Y-%m-%d %H:%M:%S")}
SENSOR: {sensor_name}
TYPE: {incident_type}

NARRATIVE:
{details}

SYSTEM CONTEXT:
- Host: {os.environ.get('COMPUTERNAME', 'Unknown')}
-----------------------------------
"""
    with log_mutex:
        try:
            if not os.path.exists(REPORT_DIR):
                os.makedirs(REPORT_DIR)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(report_content)
        except Exception:
            pass 

def lock_workstation(sensor_name, reason):
    """Executes the security lockdown and logs the event."""
    write_incident(sensor_name, "CRITICAL BREACH", f"{reason}. Enforcing system lock.")
    os.system("rundll32.exe user32.dll,LockWorkStation")

def run_mass_encryption_sensor():
    """Background file integrity engine."""
    write_incident("MASS_FILE_MONITOR", "STATUS_INIT", f"Active. Protecting: {PROTECTED_TARGET}")
    
    if not os.path.exists(PROTECTED_TARGET):
        try: os.makedirs(PROTECTED_TARGET)
        except: pass

    try:
        last_snapshot = set(os.listdir(PROTECTED_TARGET))
    except Exception:
        last_snapshot = set()

    while True:
        try:
            time.sleep(0.1)
            if not os.path.exists(PROTECTED_TARGET): continue
                
            current_snapshot = set(os.listdir(PROTECTED_TARGET))
            
            if current_snapshot != last_snapshot:
                current_time = time.time()
                diff_count = len(current_snapshot ^ last_snapshot)
                
                with metrics_mutex:
                    for _ in range(diff_count):
                        change_events.append(current_time)
                    
                    while change_events and (current_time - change_events[0] > TIME_WINDOW):
                        change_events.popleft()
                    
                    if len(change_events) >= BURST_THRESHOLD:
                        lock_workstation("MASS_FILE_MONITOR", f"Detected {len(change_events)} burst operations.")
                        change_events.clear()
                        time.sleep(2.0)
                
                last_snapshot = set(os.listdir(PROTECTED_TARGET))
        except Exception as e:
            write_incident("MASS_FILE_MONITOR", "SYSTEM_ERROR", str(e))
            time.sleep(1)

if __name__ == "__main__":
    # Ensure environment is ready
    for path in [BASE_DIR, PROTECTED_TARGET, REPORT_DIR]:
        if not os.path.exists(path):
            os.makedirs(path)
        
    # Start Cleanup Thread
    threading.Thread(target=cleanup_old_reports, daemon=True).start()
    
    # Start Sensors
    threading.Thread(target=run_mass_encryption_sensor, daemon=True).start()
    
    # Keep-Alive Anchor
    while True:
        time.sleep(5)
import os
import json
import logging
import math
import psutil
import requests
import threading
import time
import urllib3
import win32security
from pathlib import Path
import wmi
import sys

# Configure Webhook URL and Helper Function

WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
def send_to_channel(channel_name, message):
    http = urllib3.PoolManager()
    data = {
        "channel": channel_name,
        "text": message
    }
    encoded_data = json.dumps(data).encode('utf-8')
    try:
        response = http.request(
            'POST',
            WEBHOOK_URL,
            body=encoded_data,
            headers={'Content-Type': 'application/json'}
        )
        return response.status
    except Exception as e:
        print(f"Webhook error: {e}")
        return None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(threadName)s: %(message)s',
    handlers=[
    logging.FileHandler("system_debug.log"),
    logging.StreamHandler()
]
)


class SentinelV2Engine:
    def load_config(self):
        try:
            if Path("config.json").exists():
                with open("config.json", "r") as f:
                    return json.load(f)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
        return {}

    def __init__(self):
      self.config = self.load_config() or {}
      self.target_dirs = [
          Path(d) for d in self.config.get("target_dirs", [])
      ]
      self.slack_webhook_url = self.config.get("slack_webhook_url")
      self.running = True
      self.velocity_limit = 10
      self.velocity_lock = threading.Lock()
      self.event_timestamps = []
      self.entropy_threshold = 7.8

      # This thread call MUST be indented inside __init__ so 'self' is recognized
      threading.Thread(
          target=self.ntfy_listener_loop,
          args=(self.config.get("ntfy_topic", "STATUS"),),
          daemon=True,
      ).start()

      # Startup notifications
      self.send_slack_alert(
          "Sentinel_V2 framework initialized successfully. Team monitoring active."
      )
      self.send_ntfy(
          "START",
          "Sentinel Started",
          "Execution loop initialized with full sensor telemetry.",
          "rocket",
      )
    def send_slack_alert(self, message):
        """Sends telemetry alerts to your Slack workspace channel."""
        if not self.slack_webhook_url:
            return
        try:
            payload = {"text": f"[Sentinel_V2 Security Alert] {message}"}
            response = requests.post(self.slack_webhook_url, json=payload, timeout=5)
            if response.status_code != 200:
                logging.error(f"Failed to send Slack alert: {response.status_code}")
        except Exception as e:
            logging.error(f"Failed to send Slack alert: {e}")

    def terminate_process_by_name(self, process_name):
        """Automatically kill malicious processes on detection."""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                    pid = proc.info['pid']
                    logging.warning(f"Auto-Remediation: Terminating malicious process {process_name} (PID: {pid})")
                    p = psutil.Process(pid)
                    p.terminate()
                    self.send_slack_alert(f"Auto-Remediation Triggered: Terminated `{process_name}` (PID: `{pid}`)")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def ntfy_listener_loop(self, url):
        while True:
            try:
                response = requests.get(f"{url}?poll=1", timeout=10)
                if response.status_code == 200:
                    events = response.json()
                    # Process event payload here
            except Exception as e:
                pass
        time.sleep(5)

    def handle_remote_command(self, cmd):
      """Execute remote operational commands."""
      logging.info(f"Executing command: {cmd}")
      if cmd == "STATUS":
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        status_msg = (
            f"Sentinel_V2 Agent Online | CPU: {cpu}% | RAM: {ram}% | Active"
        )
        self.send_slack_alert(status_msg)
        self.send_ntfy("STATUS", "Telemetry Heartbeat", status_msg, "bar_chart")
      elif cmd == "REBOOT":
        self.send_slack_alert("Sentinel_V2 Agent received reboot signal.")
        self.send_ntfy(
            "REBOOT", "Reboot Triggered", "System restart sequence initiated.", "warning"
        )
      elif cmd.startswith("KILL "):
        target_proc = cmd.split(" ")[1]
        self.terminate_process_by_name(target_proc)
        kill_msg = f"Remote C2 Command Executed: Terminated `{target_proc}`"
        self.send_slack_alert(kill_msg)
        self.send_ntfy("STOP", "Process Terminated", kill_msg, "stop_sign")

    def terminate_process_by_name(self, process_name):
        """Automatically kill malicious processes on detection."""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and process_name.lower() in proc.info['name'].lower():
                    pid = proc.info['pid']
                    logging.warning(f"Auto-Remediation: Terminating malicious process {process_name} (PID: {pid})")
                    p = psutil.Process(pid)
                    p.terminate()
                    self.send_slack_alert(f"Auto-Remediation Triggered: Terminated `{process_name}` (PID: `{pid}`)")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

    def send_slack_alert(self, message):
        """sends telemetry alerts to your Slack workspace channel."""
        if not self.slack_webhook_url:
            return
        try:
            payload = {"text": f"[Sentinel_V2 Security Alert] {message}"}
            response = requests.post(self.slack_webhook_url, json=payload, timeout=5)
            if response.status_code != 200:
                logging.error(f"Failed to send Slack alert: {response.status_code}")
        except Exception as e:
            logging.error(f"Slack webhook error: {e}")

    def send_ntfy(self, topic, title, message, tags="shield"):
      """Broadcasts telemetry or status alerts to ntfy topics."""
      url = f"https://ntfy.sh/{topic}"
      headers = {"Title": title, "Tags": tags}
      try:
        response = requests.post(
            url, data=message.encode("utf-8"), headers=headers, timeout=5
        )
        if response.status_code != 200:
          logging.error(f"Failed to send ntfy to {topic}: {response.status_code}")
      except Exception as e:
        logging.error(f"ntfy broadcast error: {e}")

    def calculate_shannon_entropy(self, file_path):
        """Calculates Shannon entropy of a file to detect potential ransomware encryption."""
        try:
            if not os.path.exists(file_path):
                return 0.0
            
            byte_counts = [0] * 256
            total_bytes = 0
            
            with open(file_path, 'rb') as f:
                chunk = f.read(8192)
                if not chunk:
                    return 0.0
                for byte in chunk:
                    byte_counts[byte] += 1
                    total_bytes += 1

            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * math.log2(probability)
            
            return entropy
        except Exception as e:
            logging.debug(f"Error calculating entropy for {file_path}: {e}")
            return 0.0

    def check_entropy_sensor(self):
        """Continuously scans monitored directories for high-entropy (encrypted) files with alert de-duplication."""
        logging.info("Entropy Sensor Thread Initialized.")
        
        ignored_extensions = {".zip", ".rar", ".7z", ".png", ".jpg", ".jpeg", ".webp", ".ico", ".pdf", ".ogg"}
        ignored_dir_names = {".git", "build", "dist", "__pycache__"}
        
        # Track already alerted files by path and their last modification time
        alerted_files = {}

        while self.running:
            try:
                for target_dir in self.target_dirs:
                    if not target_dir.exists():
                        continue
                    for file_path in target_dir.rglob('*'):
                        if any(part in ignored_dir_names for part in file_path.parts):
                            continue

                        if file_path.is_file():
                            if file_path.suffix.lower() in ignored_extensions:
                                continue

                            try:
                                current_mtime = file_path.stat().st_mtime
                            except Exception:
                                continue

                            # Check if we already alerted for this file at this modification state
                            if file_path in alerted_files and alerted_files[file_path] == current_mtime:
                                continue

                            entropy = self.calculate_shannon_entropy(file_path)
                            if entropy > self.entropy_threshold:
                                alert_msg = f"High Entropy Alert! File: {file_path} | Entropy: {entropy:.2f}"
                                logging.warning(alert_msg)
                                self.send_slack_alert(alert_msg)
                                
                                # Remember that we've alerted for this file version
                                alerted_files[file_path] = current_mtime

            except Exception as e:
                logging.error(f"Error in entropy sensor: {e}")
            time.sleep(5)

    def record_file_event(self):
        """Thread-safe trigger for file system velocity tracking."""
        with self.velocity_lock:
            self.event_timestamps.append(time.time())

    def check_velocity_sensor(self):
        """Monitors file modification rate to detect mass-encryption behavior."""
        logging.info("Velocity Sensor Thread Initialized.")
        while self.running:
            current_time = time.time()
            with self.velocity_lock:
                self.event_timestamps = [t for t in self.event_timestamps if current_time - t <= self.velocity_window]
                event_count = len(self.event_timestamps)
                
                if event_count > self.velocity_limit:
                    alert_msg = f"Velocity Threshold Exceeded! {event_count} modifications detected within {self.velocity_window}s window."
                    logging.warning(alert_msg)
                    self.send_slack_alert(alert_msg)
                    self.event_timestamps.clear()
            
            time.sleep(0.2)

    def check_system_processes(self):
        """Monitors active system processes utilizing psutil and flags blacklisted terms."""
        logging.info("Process Monitor Thread Initialized.")
        
        # Blacklisted process names or keywords to watch out for
        blacklisted_processes = {"vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "powershell_ise.exe"}
        
        # Track already alerted PIDs to avoid flooding
        alerted_pids = set()

        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    try:
                        pinfo = proc.info
                        p_name = pinfo.get('name')
                        p_id = pinfo.get('pid')
                        
                        if p_name and p_name.lower() in blacklisted_processes:
                            if p_id not in alerted_pids:
                                alert_msg = f"Suspicious Process Alert! Name: {p_name} | PID: {p_id}"
                                logging.warning(alert_msg)
                                self.send_slack_alert(alert_msg)
                                alerted_pids.add(p_id)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
            except Exception as e:
                logging.error(f"Process check error: {e}")
            time.sleep(10)

    def run_engine(self):
        """Initializes and starts multi-threaded detection sensors."""
        logging.info("Starting Sentinel_V2 Multi-Sensor EDR Engine...")

        entropy_thread = threading.Thread(target=self.check_entropy_sensor, name="EntropySensorThread", daemon=True)
        velocity_thread = threading.Thread(target=self.check_velocity_sensor, name="VelocitySensorThread", daemon=True)
        process_thread = threading.Thread(target=self.check_system_processes, name="ProcessSensorThread", daemon=True)

        entropy_thread.start()
        velocity_thread.start()
        process_thread.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Stopping Sentinel_V2 Engine gracefully...")
            self.running = False

if __name__ == "__main__":
    # Initialize the engine - settings are loaded automatically from config.json
    engine = SentinelV2Engine()
    
    # Start the EDR engine sensors
    engine.run_engine()
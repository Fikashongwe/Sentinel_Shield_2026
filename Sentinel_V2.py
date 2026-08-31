import logging
import math
import requests
import psutil
import wmi
import win32security
from pathlib import Path
import urllib3
import json

# Configure Webhook URL and Helper Function
import os

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
        Logging.FileHandler("system_debug.log"),
        Logging.StreamHandler()
    ]
)

class SentinelV2Engine:
    def __init__(self, target_dirs, slack_webhook_url=WEBHOOK_URL):
        Self.target_dirs = [Path(d) for d in target_dirs]
        Self.slack_webhook_url = slack_webhook_url
        Self.running = True
        Self.velocity_lock = threading.Lock()
        Self.event_timestamps = []

        # Thresholds
        Self.entropy_threshold = 7.2
        Self.velocity_limit = 10
        Self.velocity_window = 1.0

        try:
            Self.wmi_obj = wmi.WMI()
        except exception as e:
            # Handle exception or log here
            Pass

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
            logging.error(f"Slack webhook error: {e}")

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
        """Continuously scans monitored directories for high-entropy (encrypted) files."""
        logging.info("Entropy Sensor Thread Initialized.")
        while self.running:
            try:
                for target_dir in self.target_dirs:
                    if not target_dir.exists():
                        continue
                    for file_path in target_dir.rglob('*'):
                        if file_path.is_file():
                            entropy = self.calculate_shannon_entropy(file_path)
                            if entropy > self.entropy_threshold:
                                alert_msg = f"High Entropy Alert! File: {file_path} | Entropy: {entropy:.2f}"
                                logging.warning(alert_msg)
                                self.send_slack_alert(alert_msg)
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
        """Monitors active system processes utilizing psutil and win32 security context."""
        logging.info("Process Monitor Thread Initialized.")
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                    pass
            except Exception as e:
                logging.debug(f"Process check error: {e}")
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
    monitored_paths = [os.path.expanduser("~/Desktop/TestZone")]
    slack_webhooks = {
        "alerts": os.environ.get("SLACK_WEBHOOK_ALERTS_URL"),
        "defenses": os.environ.get("SLACK_WEBHOOK_DEFENSES_URL")
    }

    engine = SentinelV2Engine(target_dirs=monitored_paths, slack_webhook_url=slack_webhooks)
    engine.run_engine()
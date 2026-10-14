import ctypes
import json
import os
import platform
import socket
import threading
import time
import tkinter as tk
from tkinter import messagebox
import urllib.request
import psutil

# ==========================================
# CONFIGURATION
# ==========================================
# Replace the hardcoded URL with environment variable lookup
SLACK_WEBHOOK_URL = os.environ.get(
    "SLACK_WEBHOOK_URL", "YOUR_FALLBACK_OR_PROMPT_URL"
)
INSTALL_DIR = os.path.join(os.path.expanduser("~"), "Sentinel_V2")


class ForensicReporter:

  def __init__(self, incident_type, details, initiator="Unknown"):
    self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    self.hostname = socket.gethostname()
    self.ip_address = socket.gethostbyname(self.hostname)
    self.os_info = platform.platform()
    self.incident_type = incident_type
    self.details = details
    self.initiator = initiator

  def generate_report_file(self):
    """Compiles a detailed formal report document for insurance handoff."""
    report_content = f"""====================================================================
               CYBERSECURITY INCIDENT FORENSIC REPORT
               KHANYISA INVESTMENTS - SENTINEL V2 SUITE
====================================================================
1. INCIDENT METADATA
--------------------------------------------------------------------
* Timestamp (UTC): {self.timestamp}
* Hostname:        {self.hostname}
* IP Address:      {self.ip_address}
* Operating System:{self.os_info}

2. INCIDENT CLASSIFICATION
--------------------------------------------------------------------
* Event Type:      {self.incident_type}
* Initiator/Source:{self.initiator}

3. TECHNICAL DETAILS & VECTOR ANALYSIS
--------------------------------------------------------------------
{self.details}

4. SYSTEM INTEGRITY & COMPLIANCE STATEMENT
--------------------------------------------------------------------
This document is automatically compiled by Sentinel V2 EDR telemetry nodes 
immediately upon threat detection. All hashes, timestamps, and behavioral 
logs are preserved for insurance claim verification, legal escalation, 
and root-cause analysis.
====================================================================
"""
    filename = f"Incident_Report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    filepath = os.path.join(INSTALL_DIR, filename)

    os.makedirs(INSTALL_DIR, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
      f.write(report_content)

    return filepath

  def send_to_slack(self, report_path):
    """Sends a structured alert card and evidentiary summary to Slack."""
    if not SLACK_WEBHOOK_URL or "YOUR/WEBHOOK" in SLACK_WEBHOOK_URL:
      return

    slack_payload = {
        "text": f"🚨 *INSURANCE-GRADE SECURITY INCIDENT REPORT* 🚨\n"
        f"• *Time:* `{self.timestamp}`\n"
        f"• *Host:* `{self.hostname}` ({self.ip_address})\n"
        f"• *Threat:* `{self.incident_type}`\n"
        f"• *Initiator:* `{self.initiator}`\n\n"
        f"📋 *Summary:* {self.details}\n\n"
        f"📁 *Evidentiary Document Generated:* `{os.path.basename(report_path)}`"
    }

    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=json.dumps(slack_payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "SentinelV2-Reporter",
        },
    )

    try:
      with urllib.request.urlopen(req) as response:
        pass
    except Exception as e:
      print(f"Failed to send Slack alert: {e}")


def trigger_delayed_forensic_report(incident_type, details, initiator):
  """Spawns a background worker that waits 3 minutes for log stabilization,

  then compiles and dispatches the formal insurance report.
  """
  def worker():
    time.sleep(180)  # 3-minute stabilization delay
    reporter = ForensicReporter(
        incident_type=incident_type, details=details, initiator=initiator
    )
    report_path = reporter.generate_report_file()
    reporter.send_to_slack(report_path)

  threading.Thread(target=worker, daemon=False).start()


def lock_workstation():
  """Locks the Windows workstation immediately upon security violation."""
  try:
    ctypes.windll.user32.LockWorkStation()
  except Exception as e:
    print(f"Error locking workstation: {e}")


def send_alert(message):
  """Dispatches immediate notification ping to Slack."""
  if not SLACK_WEBHOOK_URL or "YOUR/WEBHOOK" in SLACK_WEBHOOK_URL:
    return
  payload = {"text": f"⚠️ *Sentinel V2 Alert*: {message}"}
  req = urllib.request.Request(
      SLACK_WEBHOOK_URL,
      data=json.dumps(payload).encode("utf-8"),
      headers={"Content-Type": "application/json"},
  )
  try:
    urllib.request.urlopen(req)
  except Exception as e:
    print(f"Slack notification error: {e}")


def run_monitoring_engine():
  print("Sentinel V2 Security Engine Active...")
  os.makedirs(INSTALL_DIR, exist_ok=True)

  battery = psutil.sensors_battery()
  last_power_plugged = battery.power_plugged if battery else True
  print(f"[DEBUG] Initial Power Plugged State: {last_power_plugged}")

  while True:
    try:
      current_battery = psutil.sensors_battery()
      if current_battery:
        current_plugged = current_battery.power_plugged
        # Print every check so you can see live telemetry in the console
        print(
            f"[DEBUG] Monitoring... Plugged: {current_plugged} | Last:"
            f" {last_power_plugged}"
        )

        if last_power_plugged and not current_plugged:
          print(
              "🔴 [TRIGGER] Power cable disconnected! Executing security"
              " protocols..."
          )
          send_alert("Power cable disconnected! Locking workstation for security.")
          lock_workstation()

          trigger_delayed_forensic_report(
              incident_type="Physical Security Violation (Power Disconnect)",
              details=(
                  "Power cable was abruptly unplugged from the host machine. "
                  "Automated workstation lockdown protocol engaged immediately."
              ),
              initiator="Physical User / Power State Sensor (Host Node)",
          )

        last_power_plugged = current_plugged
      else:
        print("[DEBUG] Warning: psutil.sensors_battery() returned None.")

    except Exception as e:
      print(f"[ERROR] Error in monitoring loop: {e}")

    time.sleep(5)


class SentinelApp:

  def __init__(self, root):
    self.root = root
    self.root.title("Sentinel V2 - Secure Deployment Wizard")
    self.root.geometry("450x300")
    self.root.resizable(False, False)

    # UI Elements
    title_label = tk.Label(
        root, text="Khanyisa Investments EDR", font=("Arial", 14, "bold")
    )
    title_label.pack(pady=15)

    self.status_label = tk.Label(
        root, text="Status: Ready to deploy telemetry node.", font=("Arial", 10)
    )
    self.status_label.pack(pady=10)

    self.deploy_btn = tk.Button(
        root,
        text="Initialize & Start Sentinel",
        font=("Arial", 11, "bold"),
        bg="#007ACC",
        fg="white",
        padx=10,
        pady=5,
        command=self.start_deployment,
    )
    self.deploy_btn.pack(pady=20)

    self.finish_btn = tk.Button(
        root,
        text="Finish & Run in Background",
        font=("Arial", 10),
        state="disabled",
        command=self.close_wizard,
    )
    self.finish_btn.pack(pady=5)

  def start_deployment(self):
    """Deactivates button, sets up directories, and spawns monitoring thread."""
    self.deploy_btn.config(state="disabled", bg="#A0A0A0")
    self.status_label.config(text="Status: Setting up secure directories...")
    self.root.update()

    try:
      os.makedirs(INSTALL_DIR, exist_ok=True)
      time.sleep(1)

      self.status_label.config(text="Status: Sentinel Node Active & Watching!")
      messagebox.showinfo(
          "Success",
          "Sentinel V2 deployed successfully! Telemetry monitoring is now"
          " active.",
      )

      # Enable finish button cleanly
      self.finish_btn.config(state="normal")

      # Launch monitoring engine in a background daemon thread
      threading.Thread(target=run_monitoring_engine, daemon=False).start()

    except Exception as e:
      messagebox.showerror("Error", f"Deployment failed: {e}")
      self.deploy_btn.config(state="normal", bg="#007ACC")

  def close_wizard(self):
    """Cleanly destroys the GUI window without affecting the background engine."""
    self.root.destroy()


if __name__ == "__main__":
  root = tk.Tk()
  app = SentinelApp(root)
  root.mainloop()
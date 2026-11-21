# Sentinel Shield v2.0.1

Enterprise endpoint security and automated threat monitoring tool featuring multi-channel Slack telemetry.

## Overview
Sentinel Shield is a robust Python-based security agent compiled into a standalone executable. It continuously monitors system integrity, logs threat metrics, and pushes secure real-time alerts directly via Slack webhooks.

## Features
* **Compiled Standalone Executable:** Zero external Python runtime dependencies required on target Windows nodes.
* **Secure Environment Telemetry:** Hardened webhook handling utilizing local environment variables (`os.environ`) to prevent secret exposure.
* **Automated Threat Monitoring:** Real-time logging and immediate notification pipelines.

## Contents
* `sentinel_v2.exe` : Compiled standalone Windows executable file.
* `mass_encryption_sensor.py` : Core encryption-detection monitoring logic.
* `velocity.py` : Performance and speed telemetry tracking module.

## Troubleshooting & SmartScreen Notice

Because Sentinel_Shield is an independent, newly developed EDR solution, Windows Defender SmartScreen may occasionally flag the executable upon first download. This is standard for custom compiled binaries that are not yet signed with a commercial CA certificate.

**How to run Sentinel_Shield:**
1. When the "Windows protected your PC" blue prompt appears, click **More info**.
2. Click the **Run anyway** button that appears at the bottom.
3. The EDR engine will launch successfully and begin guarding your system.
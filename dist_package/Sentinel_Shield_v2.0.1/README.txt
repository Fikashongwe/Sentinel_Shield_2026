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

## Installation & Setup
1. Download the latest `Sentinel_Shield_v2.0.1.zip` package from the [Releases](https://github.com/Fikashongwe/Sentinel_Shield_2026/releases) page.
2. Extract the archive contents to your designated directory.
3. Configure your local environment variables for Slack integration.
4. Launch `sentinel_v2.exe` to begin automated monitoring and verify telemetry alerts in your Slack channel.

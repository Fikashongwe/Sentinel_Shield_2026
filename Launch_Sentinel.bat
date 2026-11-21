@echo off
TITLE Sentinel V2 Security Suite - Pilot Deployment
echo [INFO] Initializing Sentinel_V2 All-In-One Security Node...

:: Get the directory where this script is executed from
cd /d "%~dp0"

:: Launch the unified all-in-one executable
start "" "sentinel_all_in_one.exe"

echo [SUCCESS] Sentinel_V2 Suite deployed and monitoring active for PILOT_NODE_01.
exit
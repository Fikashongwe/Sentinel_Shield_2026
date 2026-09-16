import subprocess
import time

print("Starting process monitor test with blacklisted tool...")
try:
    proc = subprocess.Popen(["vssadmin.exe", "list", "shadows"])
    time.sleep(3)
    proc.terminate()
except Exception as e:
    print(f"Error: {e}")
print("Test complete.")
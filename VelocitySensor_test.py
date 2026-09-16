import os
import time

# Monitored directory path (adjust if your target is different)
target_dir = os.path.expanduser(r"~\Desktop")

print("Starting velocity test: Creating multiple files rapidly...")

# Generate files faster than the velocity limit (e.g., 10 files in under a second)
for i in range(12):
    test_file_path = os.path.join(target_dir, f"velocity_test_{i}.tmp")
    with open(test_file_path, "w") as f:
        f.write("Simulating mass file modification velocity.")
    # Small pause to ensure they register sequentially within the window
    time.sleep(0.05)

print("Velocity test complete. Check your console and Slack for velocity alerts.")
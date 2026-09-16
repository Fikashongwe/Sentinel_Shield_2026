import os
import random

# Generate 1MB of completely random binary data (simulating encrypted/ransomware output)
random_bytes = bytes([random.randint(0, 255) for _ in range(1024 * 1024)])

# Save it to your monitored Desktop directory
test_file_path = os.path.expanduser(r"~\Desktop\ransomware_test.bin")
with open(test_file_path, "wb") as f:
    f.write(random_bytes)

print(f"High-entropy test file created at: {test_file_path}")
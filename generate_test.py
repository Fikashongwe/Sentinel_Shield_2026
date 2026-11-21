import os
import time

def run_entropy_simulation():
    sandbox_dir = "test_sandbox"
    if not os.path.exists(sandbox_dir):
        os.makedirs(sandbox_dir)
    
    print(f"[INFO] Initializing safe entropy simulation in '{sandbox_dir}'...")
    
    # Generate high-entropy dummy files to trigger entropy sensors
    for i in range(10):
        filename = os.path.join(sandbox_dir, f"test_document_{i}.docx")
        # os.urandom generates random bytes (high entropy, similar to encrypted data)
        random_payload = os.urandom(1024 * 512) # 512 KB per file
        
        with open(filename, "wb") as f:
            f.write(random_payload)
            
        print(f"[SIMULATION] Created high-entropy file: {filename}")
        time.sleep(0.2) # Brief pause to mimic rapid file transformation
        
    print("[SUCCESS] Entropy simulation complete. Check your sensor logs and Slack channel for alerts.")

if __name__ == "__main__":
    run_entropy_simulation()
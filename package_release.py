import os
import shutil
import zipfile

def create_distribution_package():
    version_name = "Sentinel_Shield_v2.0.1"
    dist_folder = os.path.join("dist_package", version_name)
    
    # Create fresh distribution folder structure
    if os.path.exists(dist_folder):
        shutil.rmtree(dist_folder)
    os.makedirs(dist_folder)

    # List of essential release assets to bundle
    assets_to_bundle = [
        ("dist/sentinel_v2.exe", "sentinel_v2.exe"),
        ("README.txt", "README.txt"),
        ("official_logo.png", "logo.png")
    ]

    print("Copying release assets...")
    for src, dest_name in assets_to_bundle:
        if os.path.exists(src):
            dest_path = os.path.join(dist_folder, dest_name)
            shutil.copy(src, dest_path)
            print(f" [+] Added: {dest_name}")
        else:
            print(f" [!] Warning: Missing asset {src}")

    # Create the final zip archive
    zip_filename = f"{version_name}.zip"
    print(f"\nCompressing into {zip_filename}...")
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(dist_folder):
            for file in files:
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, dist_folder)
                zipf.write(full_path, relative_path)

    print(f" Success! Distribution package created: {zip_filename}")

if __name__ == "__main__":
    create_distribution_package()
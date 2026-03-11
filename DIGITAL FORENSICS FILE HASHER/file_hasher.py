import hashlib
import os


def calculate_hash(file_path):
    """Calculate MD5 and SHA256 hashes for a file"""
    
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def scan_directory(directory):
    """Scan all files in a directory and print hashes"""

    for root, dirs, files in os.walk(directory):
        for file in files:
            path = os.path.join(root, file)

            try:
                md5, sha256 = calculate_hash(path)

                print(f"\nFile: {path}")
                print(f"MD5: {md5}")
                print(f"SHA256: {sha256}")

            except Exception as e:
                print(f"Error reading {path}: {e}")


if __name__ == "__main__":
    folder = input("Enter directory to scan: ")
    scan_directory(folder)

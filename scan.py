import os
import re
from datetime import datetime
from config import pattern

class BackdoorScanner:
    def __init__(self):
        self.suspicious_patterns = pattern.SUSPICIOUS_PATTERNS
        self.raw_log = str()
        self.waktu = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")

    def scan_file(self, file_path):
        try:
            with open(file_path, "r", errors="ignore") as file:
                content = file.read()

            detections = []
            for pattern, description in self.suspicious_patterns.items():
                if re.search(pattern, content):
                    detections.append(description)

            if detections:
                print(f"[!] Suspicious patterns found in {file_path}:")
                self.raw_log += f"[!] Suspicious patterns found in {file_path}:\n"
                for detection in detections:
                    print(f"    - {detection}")
                    self.raw_log += f"    - {detection}\n"
            else:
                print(f"[INFO] No suspicious patterns found in {file_path}")
                self.raw_log += f"[INFO] No suspicious patterns found in {file_path}\n"

        except Exception as e:
            print(f"[ERROR] Could not scan {file_path}: {e}")
            self.raw_log += f"[ERROR] Could not scan {file_path}: {e}\n"

    def scan_directory(self, directory):
        print(f"Scanning directory: {directory}")
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                self.scan_file(file_path)

        with open(f"results/log_{self.waktu}.txt","w") as log:
            log.write(self.raw_log)

if __name__ == "__main__":
    # Inisialisasi scanner
    scanner = BackdoorScanner()

    # Meminta input direktori target
    target_directory = input("Enter the directory to scan: ").strip()
    if os.path.isdir(target_directory):
        scanner.scan_directory(target_directory)
    else:
        print(f"[ERROR] {target_directory} is not a valid directory.")

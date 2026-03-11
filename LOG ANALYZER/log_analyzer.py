# LOG_ANALYZER - Fun Interactive Version
# A mini DFIR toolkit to analyze logs with multiple options

import os
from collections import Counter
from datetime import datetime

def analyze_log(file_path):
    counts = {"INFO": 0, "WARNING": 0, "ERROR": 0, "FAILED_LOGINS": 0}
    suspicious_keywords = ["ERROR", "failed", "FAILED", "crash", "unauthorized"]
    suspicious_lines = []
    users_failed = []

    if not os.path.exists(file_path):
        print(f"File {file_path} not found.")
        return None

    with open(file_path, "r", errors="ignore") as f:
        for line in f:
            line_upper = line.upper()
            if "INFO" in line_upper:
                counts["INFO"] += 1
            if "WARNING" in line_upper:
                counts["WARNING"] += 1
            if "ERROR" in line_upper:
                counts["ERROR"] += 1
            if "FAILED" in line_upper or "UNAUTHORIZED" in line_upper:
                counts["FAILED_LOGINS"] += 1
                # Attempt to extract user if mentioned
                for word in line.split():
                    if word in ["Alice", "Bob", "Charlie", "Dave", "Eve"]:
                        users_failed.append(word)

            if any(keyword.upper() in line_upper for keyword in suspicious_keywords):
                suspicious_lines.append(line.strip())

    return counts, suspicious_lines, users_failed

def timeline(suspicious_lines):
    """Generate a simple timeline of suspicious events"""
    events = []
    for line in suspicious_lines:
        try:
            timestamp = line.split()[0] + " " + line.split()[1]
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            events.append((dt, line))
        except:
            continue
    events.sort()
    print("\n=== SUSPICIOUS EVENTS TIMELINE ===")
    for dt, line in events:
        print(f"{dt} - {line}")

def main():
    print("🎯 Welcome to LOG_ANALYZER - Your Mini DFIR Toolkit 🎯")
    log_file = input("Enter log file path: ")
    results = analyze_log(log_file)

    if not results:
        return

    counts, suspicious_lines, users_failed = results

    while True:
        print("\nChoose an option:")
        print("1. Show summary report")
        print("2. Show suspicious lines")
        print("3. Save suspicious lines to file")
        print("4. Show top 5 most frequent errors")
        print("5. Show failed logins per user")
        print("6. Generate timeline of suspicious events")
        print("7. Exit")

        choice = input("Enter your choice (1-7): ")

        if choice == "1":
            print("\n=== SUMMARY REPORT ===")
            print(f"INFO entries: {counts['INFO']}")
            print(f"WARNING entries: {counts['WARNING']}")
            print(f"ERROR entries: {counts['ERROR']}")
            print(f"FAILED/Unauthorized attempts: {counts['FAILED_LOGINS']}")
        elif choice == "2":
            print("\n=== SUSPICIOUS LINES ===")
            for line in suspicious_lines:
                print(line)
        elif choice == "3":
            output_file = input("Enter output file name [default: suspicious_log.txt]: ") or "suspicious_log.txt"
            with open(output_file, "w") as f:
                f.write("\n".join(suspicious_lines))
            print(f"Suspicious lines saved to {output_file}")
        elif choice == "4":
            print("\n=== TOP 5 MOST FREQUENT ERRORS ===")
            error_lines = [line for line in suspicious_lines if "ERROR" in line.upper()]
            counter = Counter(error_lines)
            for line, count in counter.most_common(5):
                print(f"{count}x - {line}")
        elif choice == "5":
            print("\n=== FAILED LOGINS PER USER ===")
            user_counts = Counter(users_failed)
            for user, count in user_counts.items():
                print(f"{user}: {count}")
        elif choice == "6":
            timeline(suspicious_lines)
        elif choice == "7":
            print("Exiting LOG_ANALYZER. 🔒 Stay safe, investigator!")
            break
        else:
            print("Invalid choice. Please enter a number from 1-7.")

if __name__ == "__main__":
    main()
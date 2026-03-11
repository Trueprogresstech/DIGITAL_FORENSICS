# advanced_log_analyzer.py
# Advanced log analysis tool for DFIR investigations

import re
from collections import Counter
from datetime import datetime


def analyze_log(file_path):

    info = 0
    warning = 0
    error = 0

    suspicious_lines = []
    failed_logins = []
    ips = []
    timeline = []

    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    with open(file_path, "r", errors="ignore") as file:
        for line in file:

            line_upper = line.upper()

            if "INFO" in line_upper:
                info += 1
            if "WARNING" in line_upper:
                warning += 1
            if "ERROR" in line_upper:
                error += 1

            # Detect failed logins
            if "FAILED" in line_upper or "UNAUTHORIZED" in line_upper:
                failed_logins.append(line.strip())
                suspicious_lines.append(line.strip())

            # Extract IP addresses
            found_ips = re.findall(ip_pattern, line)
            ips.extend(found_ips)

            # Save suspicious activity
            if "ERROR" in line_upper or "FAILED" in line_upper:
                suspicious_lines.append(line.strip())

            # Try to extract timestamps
            try:
                timestamp = " ".join(line.split()[0:2])
                dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                timeline.append((dt, line.strip()))
            except:
                pass

    return info, warning, error, suspicious_lines, failed_logins, ips, timeline


def keyword_search(file_path, keyword):

    results = []

    with open(file_path, "r", errors="ignore") as file:
        for line in file:
            if keyword.lower() in line.lower():
                results.append(line.strip())

    return results


def brute_force_detection(ips):

    counter = Counter(ips)

    print("\nPossible brute force sources (IP frequency):")

    for ip, count in counter.most_common(10):
        if count > 5:
            print(f"{ip} -> {count} attempts")


def generate_report(suspicious_lines):

    filename = "forensic_report.txt"

    with open(filename, "w") as f:
        for line in suspicious_lines:
            f.write(line + "\n")

    print(f"\nReport saved to {filename}")


def show_timeline(timeline):

    print("\nSuspicious Activity Timeline\n")

    for event in sorted(timeline):
        print(event[0], "-", event[1])


def main():

    print("\n=== ADVANCED LOG FORENSICS ANALYZER ===\n")

    log_file = input("Enter log file path: ")

    info, warning, error, suspicious, failed, ips, timeline = analyze_log(log_file)

    while True:

        print("\nChoose an option:")
        print("1 - Show log summary")
        print("2 - Search for keyword")
        print("3 - Show suspicious events")
        print("4 - Detect brute force attempts")
        print("5 - Show failed login attempts")
        print("6 - Show timeline of events")
        print("7 - Export forensic report")
        print("8 - Exit")

        choice = input("Select option: ")

        if choice == "1":

            print("\nLog Summary")
            print("INFO:", info)
            print("WARNING:", warning)
            print("ERROR:", error)

        elif choice == "2":

            keyword = input("Enter keyword to search: ")
            results = keyword_search(log_file, keyword)

            print(f"\nMatches found: {len(results)}\n")

            for r in results[:20]:
                print(r)

        elif choice == "3":

            for line in suspicious[:20]:
                print(line)

        elif choice == "4":

            brute_force_detection(ips)

        elif choice == "5":

            print("\nFailed Login Attempts\n")
            for line in failed[:20]:
                print(line)

        elif choice == "6":

            show_timeline(timeline)

        elif choice == "7":

            generate_report(suspicious)

        elif choice == "8":

            print("Exiting analyzer")
            break

        else:
            print("Invalid option")


if __name__ == "__main__":
    main()
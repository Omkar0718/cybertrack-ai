
from pathlib import Path
from log_processor.log_parser import parse_log_file


# Project root directory
BASE_DIR = Path(__file__).resolve().parent

# Sample log file location
log_file = BASE_DIR / "data" / "sample_logs" / "suspicious_logs.json"

# Parse logs
events = parse_log_file(log_file)

# Display results
print("\n========== LOG PARSER TEST ==========")
print(f"Total events parsed: {len(events)}")

for event in events:
    print("\n------------------------------------")
    print("Timestamp:", event["timestamp"])
    print("Event ID:", event["event_id"])
    print("Event Type:", event["event_type"])
    print("Username:", event["username"])
    print("Description:", event["description"])

print("\nLog parsing completed successfully!")

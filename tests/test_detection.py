
from collections import Counter
from log_processor.evtx_parser import parse_evtx_file

file_path = "data/uploaded_logs/windows_security_sample.evtx"

events = parse_evtx_file(file_path)

print("Total events:", len(events))
print("\nEvent ID distribution:")

event_counts = Counter(event["event_id"] for event in events)

for event_id, count in event_counts.items():
    print(f"Event ID {event_id}: {count}")

print("\nEvent type distribution:")

type_counts = Counter(event["event_type"] for event in events)

for event_type, count in type_counts.items():
    print(f"{event_type}: {count}")

print("\nSample login events:")

login_events = [
    event for event in events
    if event["event_id"] in (4624, 4625)
]

for event in login_events[:10]:
    print(event)

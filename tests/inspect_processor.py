
from log_processor.evtx_parser import parse_evtx_file

events = parse_evtx_file(
    "data/uploaded_logs/windows_security_sample.evtx"
)

process_events = [
    event for event in events
    if event["event_id"] == 4688
]

print("Process creation events:", len(process_events))

for event in process_events[:10]:
    print("\n", event)

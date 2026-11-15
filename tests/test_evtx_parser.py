from log_processor.evtx_parser import parse_evtx_file

file_path = "data/uploaded_logs/windows_security_sample.evtx"

events = parse_evtx_file(file_path)

print("Total relevant events:", len(events))

for event in events[:10]:
    print(event)
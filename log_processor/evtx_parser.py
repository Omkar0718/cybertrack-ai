
import xml.etree.ElementTree as ET
from datetime import datetime
from Evtx.Evtx import Evtx

NS = {
    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
}

EVENT_TYPES = {
    4624: "successful_login",
    4625: "failed_login",
    4688: "process_creation",
    4720: "user_account_created"
}


def parse_evtx_file(file_path):
    parsed_events = []

    with Evtx(file_path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())

                system = root.find("e:System", NS)
                event_data = root.find("e:EventData", NS)

                if system is None:
                    continue

                event_id_element = system.find("e:EventID", NS)
                time_element = system.find("e:TimeCreated", NS)
                computer_element = system.find("e:Computer", NS)

                if event_id_element is None or time_element is None:
                    continue

                event_id = int(event_id_element.text)

                if event_id not in EVENT_TYPES:
                    continue

                timestamp = datetime.fromisoformat(
                    time_element.attrib["SystemTime"].replace(
                        "Z", "+00:00"
                    )
                )

                computer = (
                    computer_element.text
                    if computer_element is not None
                    else "Unknown"
                )

                # Extract event data fields
                fields = {}

                if event_data is not None:
                    for item in event_data.findall("e:Data", NS):
                        name = item.attrib.get("Name")

                        if name:
                            fields[name] = item.text

                # Extract username
                username = (
                    fields.get("TargetUserName")
                    or fields.get("SubjectUserName")
                    or "Unknown"
                )

                # Extract source IP
                source_ip = fields.get("IpAddress")

                # Extract process information
                process_name = fields.get("NewProcessName")
                process_id = fields.get("NewProcessId")

                parent_process_name = (
                    fields.get("ParentProcessName")
                    or fields.get("CreatorProcessName")
                )

                command_line = fields.get("CommandLine")

                description = (
                    f"Windows Event ID {event_id}: "
                    f"{EVENT_TYPES[event_id]}"
                )

                # Store parsed event
                parsed_events.append({
                    "timestamp": timestamp,
                    "computer": computer,
                    "event_id": event_id,
                    "event_type": EVENT_TYPES[event_id],
                    "username": username,
                    "source_ip": source_ip,
                    "process_name": process_name,
                    "process_id": process_id,
                    "parent_process_name": parent_process_name,
                    "command_line": command_line,
                    "description": description
                })

            except (
                ET.ParseError,
                ValueError,
                KeyError,
                TypeError,
                AttributeError
            ):
                continue

    return parsed_events

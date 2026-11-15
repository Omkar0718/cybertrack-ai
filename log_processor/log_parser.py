
import json
from datetime import datetime
from pathlib import Path


REQUIRED_FIELDS = [
    "timestamp",
    "computer",
    "event_id",
    "event_type",
    "username",
    "description"
]


def parse_log_file(file_path):
    """
    Read, validate and normalize events from a JSON log file.
    """

    file_path = Path(file_path)

   
    if not file_path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    # Read JSON data
    with file_path.open("r", encoding="utf-8") as file:
        logs = json.load(file)

    if not isinstance(logs, list):
        raise ValueError("Log file must contain a JSON list.")

    parsed_events = []

    for index, log in enumerate(logs, start=1):

        if not isinstance(log, dict):
            raise ValueError(f"Event {index} must be a JSON object.")

        # Check required fields
        missing_fields = [
            field for field in REQUIRED_FIELDS
            if field not in log
        ]

        if missing_fields:
            raise ValueError(
                f"Event {index} is missing fields: {missing_fields}"
            )

        # Validate and convert timestamp
        try:
            timestamp = datetime.fromisoformat(log["timestamp"])
        except (ValueError, TypeError):
            raise ValueError(
                f"Invalid timestamp in event {index}: {log['timestamp']}"
            )

        # Normalize event
        event = log.copy()
        event["timestamp"] = timestamp

        parsed_events.append(event)

    return parsed_events

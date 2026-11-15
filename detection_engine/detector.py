
from collections import defaultdict
from datetime import timedelta


FAILED_LOGIN_THRESHOLD = 3
FAILED_LOGIN_WINDOW = timedelta(minutes=5)
SUCCESS_WINDOW = timedelta(minutes=10)


def detect_suspicious_activity(events):
    """
    Detect repeated failed logins followed by a successful login.

    Returns structured findings with references to the original events.
    """

    findings = []

    # Group login events by username and source IP
    login_groups = defaultdict(list)

    for event in events:
        if event.get("event_type") not in (
            "failed_login",
            "successful_login"
        ):
            continue

        username = event.get("username")
        source_ip = event.get("source_ip")

        if not username or not source_ip:
            continue

        key = (username, source_ip)
        login_groups[key].append(event)

    # Analyse each username and IP combination
    for (username, source_ip), group in login_groups.items():

        group.sort(key=lambda event: event["timestamp"])

        failed_events = [
            event for event in group
            if event["event_type"] == "failed_login"
        ]

        successful_events = [
            event for event in group
            if event["event_type"] == "successful_login"
        ]

        # Check sequences of failed logins
        for start_index in range(len(failed_events)):

            first_failure = failed_events[start_index]

            window_failures = [
                event for event in failed_events[start_index:]
                if event["timestamp"] - first_failure["timestamp"]
                <= FAILED_LOGIN_WINDOW
            ]

            if len(window_failures) < FAILED_LOGIN_THRESHOLD:
                continue

            last_failure = window_failures[-1]

            # Check for a successful login after the failures
            matching_success = next(
                (
                    event for event in successful_events
                    if last_failure["timestamp"] < event["timestamp"]
                    <= last_failure["timestamp"] + SUCCESS_WINDOW
                ),
                None
            )

            if matching_success is None:
                continue

            # Preserve the original events as evidence
            evidence = window_failures + [matching_success]

            findings.append({
                "rule_id": "DET-001",
                "title": "Repeated failed logins followed by successful login",
                "severity": "Medium",
                "confidence": "High",
                "username": username,
                "source_ip": source_ip,
                "description": (
                    f"{len(window_failures)} failed login attempts "
                    f"were followed by a successful login for "
                    f"{username} from {source_ip}."
                ),
                "first_seen": first_failure["timestamp"],
                "last_seen": matching_success["timestamp"],
                "event_count": len(evidence),
                "evidence": evidence
            })

            # Avoid generating duplicate findings for this same sequence
            break

    return findings

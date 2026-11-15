
from ai_investigator.investigator import investigate_findings
from attack_classifier.classifier import classify_findings

sample_findings = [
    {
        "rule_id": "DET-001",
        "title": "Repeated failed logins followed by successful login",
        "severity": "Medium",
        "confidence": "High",
        "username": "admin",
        "source_ip": "192.168.1.50",
        "description": (
            "3 failed login attempts were followed by "
            "a successful login."
        ),
        "event_count": 4,
        "evidence": [
            {
                "event_type": "failed_login",
                "timestamp": "2026-11-14T11:00:00",
                "username": "admin"
            },
            {
                "event_type": "failed_login",
                "timestamp": "2026-11-14T11:01:00",
                "username": "admin"
            },
            {
                "event_type": "failed_login",
                "timestamp": "2026-11-14T11:02:00",
                "username": "admin"
            },
            {
                "event_type": "successful_login",
                "timestamp": "2026-11-14T11:05:00",
                "username": "admin"
            }
        ]
    }
]

# Add MITRE and Kill Chain classification
classified_findings = classify_findings(sample_findings)

# Generate AI investigation
print("Starting CyberTrace AI investigation...\n")

report = investigate_findings(classified_findings)

print("=" * 60)
print("CYBERTRACE AI INVESTIGATION REPORT")
print("=" * 60)

print(report)

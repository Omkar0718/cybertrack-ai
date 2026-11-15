
from attack_classifier.classifier import classify_findings

# Sample finding for testing the classifier
sample_findings = [
    {
        "rule_id": "DET-001",
        "title": "Repeated failed logins followed by successful login",
        "severity": "Medium",
        "username": "admin",
        "source_ip": "192.168.1.50"
    }
]

classified = classify_findings(sample_findings)

for finding in classified:
    print("\nDetection:", finding["title"])

    classification = finding["classification"]

    print("Kill Chain Stage:", classification["kill_chain_stage"])
    print("Status:", classification["classification_status"])
    print("Reason:", classification["reason"])

    print("\nMITRE ATT&CK Techniques:")

    for technique in classification["mitre_techniques"]:
        print(technique["id"], "-", technique["name"])

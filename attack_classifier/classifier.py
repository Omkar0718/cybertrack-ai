
def classify_findings(findings):
    classified_findings = []

    for finding in findings:
        classified = finding.copy()

        rule_id = finding.get("rule_id")

        if rule_id == "DET-001":
            classification = {
                "mitre_techniques": [
                    {
                        "id": "T1110",
                        "name": "Brute Force"
                    },
                    {
                        "id": "T1078",
                        "name": "Valid Accounts"
                    }
                ],
                "kill_chain_stage": "Initial Access",
                "classification_status": "Potential",
                "reason": (
                    "Repeated failed login attempts followed by "
                    "a successful login may indicate an attempt "
                    "to gain access using valid credentials."
                )
            }

        else:
            classification = {
                "mitre_techniques": [],
                "kill_chain_stage": "Unmapped",
                "classification_status": "Insufficient evidence",
                "reason": (
                    "No classification mapping is currently "
                    "available for this detection rule."
                )
            }

        classified["classification"] = classification
        classified_findings.append(classified)

    return classified_findings

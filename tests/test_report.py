
from log_processor.evtx_parser import parse_evtx_file
from detection_engine.detector import detect_suspicious_activity
from attack_classifier.classifier import classify_findings
from ai_investigator.investigator import investigate_findings
from reporting.report_generator import generate_pdf_report


# Step 1: Read Windows event logs
file_path = "data/uploaded_logs/windows_security_sample.evtx"

print("Reading Windows event logs...")

events = parse_evtx_file(file_path)

print("Events parsed:", len(events))


# Step 2: Detect suspicious activity
print("\nRunning detection engine...")

findings = detect_suspicious_activity(events)

print("Findings detected:", len(findings))


# Step 3: Classify findings
print("\nClassifying findings...")

classified_findings = classify_findings(findings)


# Step 4: Generate AI investigation
print("\nGenerating investigation report...")

investigation_report = investigate_findings(
    classified_findings
)


# Step 5: Generate PDF
print("\nGenerating PDF...")

pdf_path = generate_pdf_report(
    investigation_report
)

print("\n" + "=" * 50)
print("CYBERTRACE AI REPORT GENERATED SUCCESSFULLY")
print("=" * 50)

print("PDF location:", pdf_path)

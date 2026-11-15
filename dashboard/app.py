
import sys
import tempfile
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

# --------------------------------------------------
# PROJECT IMPORTS
# --------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

from log_processor.evtx_parser import parse_evtx_file
from log_processor.log_parser import parse_log_file
from detection_engine.detector import detect_suspicious_activity
from attack_classifier.classifier import classify_findings
from ai_investigator.investigator import investigate_findings
from reporting.report_generator import generate_pdf_report


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="CyberTrace AI | Investigation Workspace",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)


# --------------------------------------------------
# CUSTOM CSS
# --------------------------------------------------

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&display=swap');

:root {
    --bg: #101419;
    --panel: #171d24;
    --panel-light: #1d2630;
    --border: #2b3540;
    --text: #e6edf3;
    --muted: #8794a3;
    --accent: #62b6a8;
}

html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
}

.stApp {
    background-color: var(--bg);
    color: var(--text);
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 3rem;
    max-width: 1450px;
}

[data-testid="stSidebar"] {
    background-color: #131920;
    border-right: 1px solid var(--border);
}

.brand {
    font-size: 22px;
    font-weight: 700;
    color: #edf5f5;
}

.brand span {
    color: var(--accent);
}

.brand-subtitle {
    color: var(--muted);
    font-size: 11px;
    letter-spacing: 1.7px;
    margin-top: 5px;
}

.eyebrow {
    color: var(--accent);
    font-family: 'DM Mono', monospace;
    font-size: 11px;
    letter-spacing: 1.5px;
    margin-bottom: 8px;
}

.page-title {
    font-size: 29px;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 5px;
}

.page-description {
    color: var(--muted);
    font-size: 14px;
    margin-bottom: 22px;
}

.metric-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 17px;
    min-height: 105px;
}

.metric-label {
    color: var(--muted);
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
}

.metric-value {
    color: var(--text);
    font-family: 'DM Mono', monospace;
    font-size: 27px;
    margin-top: 10px;
}

.metric-note {
    color: var(--muted);
    font-size: 11px;
    margin-top: 3px;
}

.small-label {
    color: var(--muted);
    font-size: 11px;
    letter-spacing: 1px;
    font-family: 'DM Mono', monospace;
}

.status-line {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: var(--muted);
}

.status-dot {
    width: 8px;
    height: 8px;
    background: var(--accent);
    border-radius: 50%;
    display: inline-block;
}

.stButton > button {
    background: var(--accent);
    color: #10201e;
    border: none;
    border-radius: 6px;
    font-weight: 700;
    min-height: 42px;
}

.stButton > button:hover {
    background: #80cbbb;
    color: #10201e;
    border: none;
}

.stDownloadButton > button {
    background: var(--panel-light);
    border: 1px solid var(--accent);
    color: var(--text);
    border-radius: 6px;
    min-height: 42px;
}

.stDownloadButton > button:hover {
    background: #25352f;
    color: var(--accent);
    border-color: var(--accent);
}

div[data-testid="stExpander"] {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
}

div[data-testid="stMetric"] {
    background: var(--panel);
    border: 1px solid var(--border);
    padding: 14px;
    border-radius: 8px;
}

hr {
    border-color: var(--border);
}

footer {
    visibility: hidden;
}

@media (max-width: 768px) {
    .block-container {
        padding: 1rem;
    }

    .page-title {
        font-size: 23px;
    }

    .metric-value {
        font-size: 22px;
    }
}

</style>
""", unsafe_allow_html=True)


# --------------------------------------------------
# SESSION STATE
# --------------------------------------------------

DEFAULT_STATE = {
    "events": None,
    "findings": None,
    "report": None,
    "pdf": None,
    "filename": None
}

for key, value in DEFAULT_STATE.items():
    if key not in st.session_state:
        st.session_state[key] = value


# --------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------

def metric_card(label, value, note=""):

    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div class="metric-note">{note}</div>
    </div>
    """, unsafe_allow_html=True)


def page_header(eyebrow, title, description):

    st.markdown(f"""
    <div class="eyebrow">{eyebrow}</div>
    <div class="page-title">{title}</div>
    <div class="page-description">{description}</div>
    """, unsafe_allow_html=True)


def format_timestamp(value):

    if not value:
        return "Unknown"

    if isinstance(value, datetime):
        return value.strftime("%d %b %Y, %H:%M:%S")

    return str(value)


def get_event_dataframe(events):

    rows = []

    for event in events:

        rows.append({
            "Timestamp": event.get("timestamp"),
            "Event Type": event.get("event_type", "Unknown"),
            "Username": event.get("username", "Unknown"),
            "Source IP": event.get("source_ip", "N/A"),
            "Computer": event.get("computer", "Unknown")
        })

    df = pd.DataFrame(rows)

    if not df.empty:
        df["Timestamp"] = pd.to_datetime(
            df["Timestamp"],
            errors="coerce"
        )

    return df


def get_timeline_dataframe(findings):

    rows = []

    for finding in findings:

        for event in finding.get("evidence", []):

            rows.append({
                "Timestamp": event.get("timestamp"),
                "Event": event.get("event_type", "Unknown"),
                "Username": event.get("username", "Unknown"),
                "Source IP": event.get("source_ip", "N/A"),
                "Rule": finding.get("rule_id", "Unknown")
            })

    df = pd.DataFrame(rows)

    if not df.empty:

        df["Timestamp"] = pd.to_datetime(
            df["Timestamp"],
            errors="coerce"
        )

        df = df.dropna(subset=["Timestamp"])
        df = df.sort_values("Timestamp")

    return df


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

with st.sidebar:

    st.markdown("""
    <div class="brand">CYBER<span>TRACE</span></div>
    <div class="brand-subtitle">AI INVESTIGATION SYSTEM</div>
    """, unsafe_allow_html=True)

    st.divider()

    st.markdown(
        '<div class="small-label">WORKSPACE</div>',
        unsafe_allow_html=True
    )

    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Findings",
            "Timeline",
            "AI Analysis"
        ],
        label_visibility="collapsed",
        key="navigation"
    )

    st.divider()

    st.markdown(
        '<div class="small-label">SYSTEM STATUS</div>',
        unsafe_allow_html=True
    )

    st.markdown("""
    <div class="status-line">
        <span class="status-dot"></span>
        Local analysis environment
    </div>
    """, unsafe_allow_html=True)

    st.caption("AI Engine: Llama 3.2")
    st.caption("Runtime: Ollama")

    st.divider()

    if st.session_state.filename:

        st.markdown(
            '<div class="small-label">CURRENT INVESTIGATION</div>',
            unsafe_allow_html=True
        )

        st.caption(st.session_state.filename)

        if st.button("Clear investigation", use_container_width=True):

            for key in DEFAULT_STATE:
                st.session_state[key] = None

            st.rerun()


# --------------------------------------------------
# MAIN HEADER
# --------------------------------------------------

st.markdown(
    '<div class="eyebrow">SECURITY OPERATIONS / INVESTIGATION</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="page-title">Investigation Workspace</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="page-description">'
    'Analyse system activity, investigate suspicious patterns, '
    'and generate evidence-backed reports.'
    '</div>',
    unsafe_allow_html=True
)


# --------------------------------------------------
# LOG UPLOAD
# --------------------------------------------------

with st.container(border=True):

    st.markdown("### Log ingestion")

    st.caption(
        "Select a Windows Event Log or supported JSON file."
    )

    col_upload, col_info = st.columns([2, 1])

    with col_upload:

        uploaded_file = st.file_uploader(
            "Upload log file",
            type=["evtx", "json"]
        )

    with col_info:

        st.markdown("**SUPPORTED FORMATS**")
        st.markdown("`EVTX` · `JSON`")
        st.caption("Local processing through Python")

    if uploaded_file is not None:

        st.success(f"Selected: {uploaded_file.name}")

        if st.button(
            "START INVESTIGATION",
            type="primary",
            use_container_width=True
        ):

            temp_path = None

            try:

                extension = Path(
                    uploaded_file.name
                ).suffix.lower()

                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=extension
                ) as temp_file:

                    temp_file.write(uploaded_file.getvalue())
                    temp_path = Path(temp_file.name)

                with st.status(
                    "Investigation in progress...",
                    expanded=True
                ) as status:

                    st.write("01 / Processing system logs")

                    if extension == ".evtx":
                        events = parse_evtx_file(str(temp_path))

                    else:
                        events = parse_log_file(str(temp_path))

                    st.write(f"Processed {len(events)} events.")

                    st.write("02 / Detecting suspicious patterns")

                    findings = detect_suspicious_activity(events)

                    st.write(
                        f"Generated {len(findings)} detection findings."
                    )

                    st.write("03 / Classifying attack techniques")

                    classified_findings = classify_findings(findings)

                    st.write("04 / Generating AI investigation")

                    investigation_report = investigate_findings(
                        classified_findings
                    )

                    st.write("05 / Generating PDF report")

                    pdf_path = generate_pdf_report(
                        investigation_report,
                        output_path="reports/CyberTrace_Incident_Report.pdf"
                    )

                    with open(pdf_path, "rb") as pdf_file:
                        pdf_bytes = pdf_file.read()

                    # Save investigation results

                    st.session_state.events = events

                    st.session_state.findings = (
                        classified_findings
                    )

                    st.session_state.report = (
                        investigation_report
                    )

                    st.session_state.pdf = pdf_bytes

                    st.session_state.filename = (
                        uploaded_file.name
                    )

                    status.update(
                        label="Investigation completed",
                        state="complete",
                        expanded=False
                    )

                st.success("Investigation completed successfully!")

                st.rerun()

            except Exception as error:

                st.error(f"Investigation failed: {error}")

            finally:

                if temp_path is not None:
                    temp_path.unlink(missing_ok=True)


# --------------------------------------------------
# RESULTS
# --------------------------------------------------

if st.session_state.events is not None:

    events = st.session_state.events
    findings = st.session_state.findings
    report = st.session_state.report

    event_df = get_event_dataframe(events)

    st.divider()

    # --------------------------------------------------
    # GLOBAL REPORT DOWNLOAD
    # Visible on every dashboard page
    # --------------------------------------------------

    download_col, info_col = st.columns([1, 2])

    with download_col:

        if st.session_state.pdf is not None:

            st.download_button(
                label="📄 DOWNLOAD PDF REPORT",
                data=st.session_state.pdf,
                file_name="CyberTrace_Incident_Report.pdf",
                mime="application/pdf",
                use_container_width=True,
                key="global_pdf_download"
            )

    with info_col:

        st.caption(
            "Investigation report ready. Download the complete "
            "report including evidence and AI analysis."
        )

    st.divider()

    # --------------------------------------------------
    # OVERVIEW
    # --------------------------------------------------

    if page == "Overview":

        page_header(
            "01 / OVERVIEW",
            "Investigation overview",
            "A consolidated view of the analysed system activity."
        )

        high_count = sum(
            1 for f in findings
            if f.get("severity") == "High"
        )

        medium_count = sum(
            1 for f in findings
            if f.get("severity") == "Medium"
        )

        low_count = sum(
            1 for f in findings
            if f.get("severity") == "Low"
        )

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            metric_card(
                "Events analysed",
                f"{len(events):,}",
                "Total parsed events"
            )

        with c2:
            metric_card(
                "Findings",
                f"{len(findings):,}",
                "Matched detection rules"
            )

        with c3:
            metric_card(
                "High severity",
                f"{high_count:,}",
                "Priority review"
            )

        with c4:
            metric_card(
                "Medium severity",
                f"{medium_count:,}",
                f"{low_count} low severity"
            )

        st.write("")

        left, right = st.columns([1.3, 1])

        with left:

            st.markdown("### Event distribution")

            if not event_df.empty:

                event_counts = (
                    event_df["Event Type"]
                    .value_counts()
                    .rename_axis("Event Type")
                    .reset_index(name="Count")
                )

                st.bar_chart(
                    event_counts.set_index("Event Type"),
                    height=300
                )

            else:
                st.info("No event data available.")

        with right:

            st.markdown("### Severity distribution")

            severity_df = pd.DataFrame({
                "Severity": ["High", "Medium", "Low"],
                "Findings": [
                    high_count,
                    medium_count,
                    low_count
                ]
            })

            st.bar_chart(
                severity_df.set_index("Severity"),
                height=300
            )

        st.divider()

        st.markdown("### Latest system events")

        if not event_df.empty:

            latest_events = (
                event_df
                .sort_values("Timestamp", ascending=False)
                .head(10)
            )

            st.dataframe(
                latest_events,
                use_container_width=True,
                hide_index=True
            )

        st.divider()

        st.markdown("### Current investigation")

        st.write("**File:**", st.session_state.filename)

        st.write("**Total findings:**", len(findings))

        st.write("**Status:** Completed")

    # --------------------------------------------------
    # FINDINGS
    # --------------------------------------------------

    elif page == "Findings":

        page_header(
            "02 / DETECTION",
            "Security findings",
            "Review suspicious patterns and their associated evidence."
        )

        if findings:

            for index, finding in enumerate(findings, start=1):

                severity = finding.get(
                    "severity",
                    "Unknown"
                ).upper()

                title = finding.get(
                    "title",
                    "Unknown finding"
                )

                with st.expander(
                    f"{index:02d} | {severity} | {title}",
                    expanded=(index == 1)
                ):

                    left, right = st.columns(2)

                    with left:

                        st.markdown("**DETECTION DETAILS**")

                        st.write(
                            "**Rule ID:**",
                            finding.get("rule_id")
                        )

                        st.write(
                            "**Severity:**",
                            severity
                        )

                        st.write(
                            "**Confidence:**",
                            finding.get("confidence")
                        )

                        st.write(
                            "**Username:**",
                            finding.get("username")
                        )

                        st.write(
                            "**Source IP:**",
                            finding.get("source_ip")
                        )

                    with right:

                        st.markdown("**TIMING & EVIDENCE**")

                        st.write(
                            "**First seen:**",
                            format_timestamp(
                                finding.get("first_seen")
                            )
                        )

                        st.write(
                            "**Last seen:**",
                            format_timestamp(
                                finding.get("last_seen")
                            )
                        )

                        st.write(
                            "**Evidence events:**",
                            finding.get("event_count", 0)
                        )

                    st.markdown("**Description**")

                    st.write(finding.get("description", ""))

                    st.divider()

                    classification = finding.get(
                        "classification",
                        {}
                    )

                    st.markdown("**MITRE ATT&CK MAPPING**")

                    st.write(
                        "Kill Chain Stage:",
                        classification.get(
                            "kill_chain_stage",
                            "Unmapped"
                        )
                    )

                    st.write(
                        "Classification:",
                        classification.get(
                            "classification_status",
                            "Not classified"
                        )
                    )

                    techniques = classification.get(
                        "mitre_techniques",
                        []
                    )

                    if techniques:

                        for technique in techniques:

                            st.markdown(
                                f"- **{technique.get('id')}** — "
                                f"{technique.get('name')}"
                            )

                    else:

                        st.caption("No MITRE mapping available.")

                    st.markdown("**Evidence events**")

                    evidence_rows = []

                    for event in finding.get("evidence", []):

                        evidence_rows.append({
                            "Timestamp": format_timestamp(
                                event.get("timestamp")
                            ),
                            "Event Type": event.get("event_type"),
                            "Username": event.get("username"),
                            "Source IP": event.get("source_ip")
                        })

                    if evidence_rows:

                        st.dataframe(
                            pd.DataFrame(evidence_rows),
                            use_container_width=True,
                            hide_index=True
                        )

        else:

            st.info(
                "No suspicious patterns matched the configured "
                "detection rules. This does not prove the system "
                "is free from security threats."
            )

    # --------------------------------------------------
    # TIMELINE
    # --------------------------------------------------

    elif page == "Timeline":

        page_header(
            "03 / EVENT CORRELATION",
            "Investigation timeline",
            "Chronological evidence associated with detected findings."
        )

        timeline_df = get_timeline_dataframe(findings)

        if not timeline_df.empty:

            st.markdown("### Evidence sequence")

            st.dataframe(
                timeline_df,
                use_container_width=True,
                hide_index=True
            )

            st.markdown("### Event activity over time")

            chart_data = (
                timeline_df
                .set_index("Timestamp")
                .resample("1min")
                .size()
                .rename("Evidence events")
            )

            st.line_chart(
                chart_data,
                height=300
            )

        else:

            st.info(
                "No correlated evidence timeline is available "
                "because no detection findings were generated."
            )

    # --------------------------------------------------
    # AI ANALYSIS
    # --------------------------------------------------

    elif page == "AI Analysis":

        page_header(
            "04 / AI INVESTIGATION",
            "Investigation analysis",
            "Interpretation generated using the local Llama 3.2 model."
        )

        st.markdown("""
        <div style="
            background:#171d24;
            border:1px solid #2b3540;
            border-radius:10px;
            padding:18px;
            margin-bottom:15px;
        ">
            <div style="color:#62b6a8;font-size:11px;letter-spacing:1px;">
                LOCAL AI ANALYSIS
            </div>
            <br>
            <div style="font-size:15px;font-weight:600;">
                Evidence-backed investigation report
            </div>
            <div style="color:#8794a3;font-size:13px;margin-top:7px;">
                AI interpretations are separate from verified
                event counts and timestamps.
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.text_area(
            "Investigation report",
            value=report,
            height=500,
            disabled=True,
            label_visibility="collapsed"
        )

    # --------------------------------------------------
    # FOOTER
    # --------------------------------------------------

    st.divider()

    st.caption(
        "CYBERTRACE AI | DEFENSIVE SECURITY INVESTIGATION | "
        "HUMAN VERIFICATION REQUIRED"
    )


# --------------------------------------------------
# EMPTY STATE
# --------------------------------------------------

else:

    st.divider()

    st.markdown("### Awaiting investigation")

    st.caption(
        "Upload a supported log file above to initialise "
        "the investigation workspace."
    )

    c1, c2, c3 = st.columns(3)

    with c1:
        st.markdown("**01 / INGEST**")
        st.caption("Parse Windows and JSON event logs.")

    with c2:
        st.markdown("**02 / DETECT**")
        st.caption("Identify suspicious activity patterns.")

    with c3:
        st.markdown("**03 / INVESTIGATE**")
        st.caption("Generate AI analysis and PDF reports.")


from pathlib import Path
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    HRFlowable,
    ListFlowable,
    ListItem
)
from xml.sax.saxutils import escape


def generate_pdf_report(
    report_text,
    output_path="reports/CyberTrace_Incident_Report.pdf"
):
    """Generate a formatted PDF from CyberTrace AI report text."""

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    document = SimpleDocTemplate(
        str(output_file),
        pagesize=A4,
        rightMargin=0.65 * inch,
        leftMargin=0.65 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=23,
        leading=28,
        textColor=colors.HexColor("#163A5F"),
        alignment=TA_CENTER,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#64748B"),
        alignment=TA_CENTER,
        spaceAfter=18
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#163A5F"),
        spaceBefore=15,
        spaceAfter=7
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        fontSize=9,
        leading=14,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        "ReportBullet",
        parent=body_style,
        leftIndent=12,
        firstLineIndent=-8
    )

    story = []

    # Report header
    story.append(
        Paragraph("CYBERTRACE AI", title_style)
    )

    story.append(
        Paragraph(
            "CYBERSECURITY INCIDENT INVESTIGATION REPORT",
            subtitle_style
        )
    )

    story.append(
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %B %Y, %I:%M %p')}",
            subtitle_style
        )
    )

    story.append(
        HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor("#CBD5E1")
        )
    )

    story.append(Spacer(1, 15))

    # Convert report text into PDF elements
    lines = report_text.splitlines()

    bullet_items = []

    def add_bullets():
        nonlocal bullet_items

        if bullet_items:
            story.append(
                ListFlowable(
                    [
                        ListItem(
                            Paragraph(item, bullet_style),
                            bulletColor=colors.HexColor("#2563EB")
                        )
                        for item in bullet_items
                    ],
                    bulletType="bullet",
                    leftIndent=18
                )
            )

            story.append(Spacer(1, 6))
            bullet_items = []

    section_headings = {
        "INCIDENT SUMMARY",
        "OBSERVED EVIDENCE",
        "POTENTIAL INTERPRETATION",
        "POTENTIAL ATTACK TECHNIQUES",
        "ATTACK TECHNIQUE ANALYSIS",
        "INVESTIGATION GAPS",
        "RECOMMENDED DEFENSIVE ACTIONS",
        "OVERALL ASSESSMENT",
        "AI-GENERATED INVESTIGATION ANALYSIS"
    }

    for line in lines:

        line = line.strip()

        if not line:
            add_bullets()
            continue

        # Remove basic Markdown formatting
        clean_line = line.replace("**", "")

        # Section headings
        if clean_line.upper() in section_headings:
            add_bullets()

            story.append(
                Paragraph(
                    escape(clean_line.upper()),
                    heading_style
                )
            )

            story.append(
                HRFlowable(
                    width="100%",
                    thickness=0.5,
                    color=colors.HexColor("#CBD5E1")
                )
            )

        # Bullet points
        elif clean_line.startswith(("* ", "- ")):
            bullet_text = clean_line[2:].strip()
            bullet_items.append(escape(bullet_text))

        # Regular paragraphs
        else:
            add_bullets()

            story.append(
                Paragraph(
                    escape(clean_line),
                    body_style
                )
            )

    add_bullets()

    # Footer on every page
    def add_footer(canvas, doc):
        canvas.saveState()

        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)

        canvas.drawString(
            0.65 * inch,
            0.4 * inch,
            "CyberTrace AI | Defensive Investigation Report"
        )

        canvas.drawRightString(
            A4[0] - 0.65 * inch,
            0.4 * inch,
            f"Page {doc.page}"
        )

        canvas.restoreState()

    document.build(
        story,
        onFirstPage=add_footer,
        onLaterPages=add_footer
    )

    return str(output_file)

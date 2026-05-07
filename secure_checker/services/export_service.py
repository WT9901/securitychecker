from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from flask import session
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def build_json_export_payload(history: list[dict]) -> dict:
    """Build JSON export payload from latest session data."""
    latest_analysis = session.get("latest_analysis", {})
    latest_validation = session.get("latest_validation", {})

    return {
        "exported_at_utc": datetime.now(timezone.utc).isoformat(),
        "project": "Login and Registration Security Checker",
        "latest_analysis": latest_analysis,
        "latest_validation": latest_validation,
        "validation_history": history,
    }


def generate_security_report_pdf() -> BytesIO:
    """Generate a PDF report with analysis and validation results."""
    latest_analysis = session.get("latest_analysis", {})
    latest_validation = session.get("latest_validation", {})
    export_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer,
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Heading1"],
        fontSize=24,
        textColor=colors.HexColor("#1f6feb"),
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#1f6feb"),
        spaceAfter=8,
        spaceBefore=6,
        fontName="Helvetica-Bold",
    )
    normal_style = styles["Normal"]
    normal_style.fontSize = 10

    story = []
    story.append(Paragraph("Login and Registration Security Checker", title_style))
    story.append(Paragraph("Security Assessment Report", heading_style))
    story.append(Paragraph(f"<b>Generated:</b> {export_time}", normal_style))
    story.append(Spacer(1, 0.2 * inch))

    if latest_analysis:
        story.append(Paragraph("1. REQUIREMENT ANALYSIS", heading_style))

        if latest_analysis.get("requirement"):
            story.append(Paragraph("<b>Analyzed Requirement:</b>", normal_style))
            story.append(Paragraph(latest_analysis["requirement"], normal_style))
            story.append(Spacer(1, 0.1 * inch))

        if latest_analysis.get("guidance"):
            story.append(Paragraph(f"<b>Status:</b> {latest_analysis['guidance']}", normal_style))
            story.append(Spacer(1, 0.1 * inch))

        if latest_analysis.get("results"):
            story.append(Paragraph(f"<b>Identified Risks:</b> {len(latest_analysis['results'])} found", normal_style))
            story.append(Spacer(1, 0.1 * inch))

            for risk in latest_analysis["results"]:
                risk_text = (
                    f"<b>{risk.get('title', 'N/A')}</b> - Confidence: "
                    f"{risk.get('confidence_level', 'N/A')} ({risk.get('confidence_score', 0)}%)"
                )
                story.append(Paragraph(risk_text, normal_style))

                if risk.get("matched_keywords"):
                    keywords = ", ".join(risk["matched_keywords"])
                    story.append(Paragraph(f"<i>Keywords: {keywords}</i>", normal_style))

                if risk.get("abuse_cases"):
                    story.append(Paragraph("<b>Sample Attacks:</b>", normal_style))
                    for abuse in risk["abuse_cases"][:2]:
                        story.append(Paragraph(f"- {abuse}", normal_style))

                story.append(Spacer(1, 0.08 * inch))

        story.append(Spacer(1, 0.15 * inch))

    if latest_validation:
        story.append(PageBreak())
        story.append(Paragraph("2. IMPLEMENTATION VALIDATION", heading_style))

        if latest_validation.get("target_url"):
            story.append(Paragraph(f"<b>Target URL:</b> {latest_validation['target_url']}", normal_style))
            story.append(Spacer(1, 0.1 * inch))

        if latest_validation.get("validation_summary"):
            story.append(Paragraph(f"<b>Summary:</b> {latest_validation['validation_summary']}", normal_style))
            story.append(Spacer(1, 0.1 * inch))

        if latest_validation.get("validation_checks"):
            story.append(Paragraph("<b>Security Header Checks:</b>", normal_style))
            story.append(Spacer(1, 0.08 * inch))

            table_data = [["Check Name", "Status", "Details"]]
            for check in latest_validation["validation_checks"]:
                details = check.get("details", "")
                table_data.append(
                    [
                        check.get("name", ""),
                        check.get("status", ""),
                        details[:50] + "..." if len(details) > 50 else details,
                    ]
                )

            table = Table(table_data, colWidths=[2 * inch, 1 * inch, 2 * inch])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f6feb")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                        ("GRID", (0, 0), (-1, -1), 1, colors.black),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.beige, colors.white]),
                        ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ]
                )
            )
            story.append(table)

    story.append(Spacer(1, 0.3 * inch))
    story.append(
        Paragraph(
            "<i>This report was automatically generated by the Login and Registration Security Checker.</i>",
            normal_style,
        )
    )

    doc.build(story)
    pdf_buffer.seek(0)
    return pdf_buffer

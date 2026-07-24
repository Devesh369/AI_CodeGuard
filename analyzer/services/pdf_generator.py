import io
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

def generate_pdf_report(project, report):
    """
    Generates a professional PDF report using ReportLab.
    Returns: bytes buffer containing the PDF.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'ReportTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        alignment=TA_CENTER,
        spaceAfter=15
    )

    section_heading = ParagraphStyle(
        'SectionHeading',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor('#334155')
    )

    bullet_style = ParagraphStyle(
        'ReportBullet',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155'),
        leftIndent=12,
        spaceAfter=3
    )

    story = []

    # Title
    story.append(Paragraph("CODEGUARD AI SECURITY ANALYSIS REPORT", title_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2563EB'), spaceAfter=15))

    # Project & File Metadata Table
    ai_rev = project.ai_review or {}
    exec_review = ai_rev.get('executive_review', [
        f"Analyzed {report.file_name} with average score {report.pylint_score}/10.",
        f"{report.issue_count} linter flags detected.",
        f"{report.security_issue_count} security risks detected."
    ])
    sec_review = ai_rev.get('security_review', [
        "Avoid eval, exec, shell=True, and bare except blocks.",
        "Use parameterized queries and explicit input validation.",
        "Keep credentials out of source files and commit history."
    ])
    recommendations = ai_rev.get('recommendations', [
        "Replace debug prints with structured logging.",
        "Add tests around upload and export flows.",
        "Move credentials out of source code."
    ])

    meta_data = [
        [Paragraph("<b>Project:</b>", body_style), Paragraph(project.name, body_style), Paragraph("<b>Quality Score:</b>", body_style), Paragraph(f"{report.pylint_score} / 10", body_style)],
        [Paragraph("<b>File Name:</b>", body_style), Paragraph(report.file_name, body_style), Paragraph("<b>Status:</b>", body_style), Paragraph(report.quality_status, body_style)],
        [Paragraph("<b>Linter Flags:</b>", body_style), Paragraph(str(report.issue_count), body_style), Paragraph("<b>Security Risks:</b>", body_style), Paragraph(str(report.security_issue_count), body_style)],
    ]

    meta_table = Table(meta_data, colWidths=[90, 180, 90, 180])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
        ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#0F172A')),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # Executive Review
    story.append(Paragraph("Executive Review", section_heading))
    for bullet in exec_review:
        story.append(Paragraph(f"• {bullet}", bullet_style))
    story.append(Spacer(1, 10))

    # Security Review
    story.append(Paragraph("Security Review", section_heading))
    for bullet in sec_review:
        story.append(Paragraph(f"• {bullet}", bullet_style))
    story.append(Spacer(1, 10))

    # Pylint Issues Table
    story.append(Paragraph(f"Pylint Convention Violations ({len(report.pylint_issues)})", section_heading))
    if report.pylint_issues:
        pylint_data = [[
            Paragraph("<b>Line</b>", body_style),
            Paragraph("<b>Symbol</b>", body_style),
            Paragraph("<b>Message</b>", body_style)
        ]]
        for issue in report.pylint_issues[:15]:
            pylint_data.append([
                Paragraph(str(issue.get('line', '-')), body_style),
                Paragraph(str(issue.get('symbol', '-')), body_style),
                Paragraph(str(issue.get('message', '-')), body_style)
            ])
        pylint_table = Table(pylint_data, colWidths=[40, 130, 370])
        pylint_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1E293B')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(pylint_table)
    else:
        story.append(Paragraph("No Pylint convention violations found.", body_style))

    story.append(Spacer(1, 10))

    # Bandit Issues Table
    story.append(Paragraph(f"Bandit Security Threat Vectors ({len(report.bandit_issues)})", section_heading))
    if report.bandit_issues:
        bandit_data = [[
            Paragraph("<b>Line</b>", body_style),
            Paragraph("<b>Severity</b>", body_style),
            Paragraph("<b>Issue Text</b>", body_style)
        ]]
        for issue in report.bandit_issues[:15]:
            bandit_data.append([
                Paragraph(str(issue.get('line', '-')), body_style),
                Paragraph(str(issue.get('severity', '-')), body_style),
                Paragraph(str(issue.get('issue_text', '-')), body_style)
            ])
        bandit_table = Table(bandit_data, colWidths=[40, 100, 400])
        bandit_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#991B1B')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(bandit_table)
    else:
        story.append(Paragraph("No security vulnerabilities detected by Bandit.", body_style))

    story.append(Spacer(1, 10))

    # Recommendations
    story.append(Paragraph("Recommendations", section_heading))
    for rec in recommendations:
        story.append(Paragraph(f"• {rec}", bullet_style))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()

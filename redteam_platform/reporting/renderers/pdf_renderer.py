"""Optional ReportLab PDF renderer from the canonical model."""

from __future__ import annotations

from pathlib import Path

from redteam_platform.reporting.models import CanonicalReport


class PdfUnavailable(RuntimeError):
    pass


class PdfRenderer:
    media_type = "application/pdf"
    suffix = ".pdf"

    @staticmethod
    def available() -> bool:
        try:
            import reportlab  # noqa: F401
        except ImportError:
            return False
        return True

    def render_to_path(self, report: CanonicalReport, path: str | Path) -> Path:
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_CENTER
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                PageBreak,
                Paragraph,
                SimpleDocTemplate,
                Spacer,
                Table,
                TableStyle,
            )
        except ImportError as exc:
            raise PdfUnavailable("Install the optional 'pdf' dependency to generate PDF reports.") from exc
        target = Path(path)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], alignment=TA_CENTER, spaceAfter=24))
        styles.add(
            ParagraphStyle(
                name="ReportCell",
                parent=styles["BodyText"],
                fontSize=7,
                leading=9,
                wordWrap="CJK",
            )
        )
        story = [
            Spacer(1, 1.2 * inch),
            Paragraph(report.branding.report_title, styles["CoverTitle"]),
            Paragraph(report.target.name, styles["Heading2"]),
            Paragraph(f"Run {report.run_id}", styles["BodyText"]),
            Paragraph(f"Classification: {report.branding.classification_label}", styles["BodyText"]),
            PageBreak(),
            Paragraph("Executive summary", styles["Heading1"]),
        ]
        story.extend(Paragraph(f"• {item}", styles["BodyText"]) for item in report.executive_summary)
        story.extend([Spacer(1, 12), Paragraph("Findings summary", styles["Heading1"])])
        rows = [[Paragraph(value, styles["ReportCell"]) for value in ("ID", "Severity", "Confidence", "Title")]]
        rows.extend(
            [
                Paragraph(item.finding_id, styles["ReportCell"]),
                Paragraph(str(item.severity), styles["ReportCell"]),
                Paragraph(str(item.confidence), styles["ReportCell"]),
                Paragraph(item.title, styles["ReportCell"]),
            ]
            for item in report.findings
        )
        table = Table(rows, colWidths=[1.25 * inch, .7 * inch, .85 * inch, 4.2 * inch], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173b63")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), .25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(table)
        for finding in report.findings:
            story.extend(
                [
                    Spacer(1, 12),
                    Paragraph(f"{finding.finding_id}: {finding.title}", styles["Heading2"]),
                    Paragraph(
                        f"{finding.severity} · {finding.confidence} confidence · {finding.status}",
                        styles["BodyText"],
                    ),
                    Paragraph(finding.description or finding.technical_details, styles["BodyText"]),
                    Paragraph(f"<b>Remediation:</b> {finding.remediation}", styles["BodyText"]),
                ]
            )
        story.extend([PageBreak(), Paragraph("Coverage", styles["Heading1"])])
        coverage_rows = [["Category", "State", "Completed", "Coverage"]]
        coverage_rows.extend(
            [item.category, str(item.state), f"{item.completed}/{item.planned}", f"{item.percentage:.1f}%"]
            for item in report.coverage.categories
        )
        coverage_table = Table(coverage_rows, repeatRows=1)
        coverage_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173b63")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), .25, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(coverage_table)
        story.extend(
            [
                Spacer(1, 16),
                Paragraph("Integrity and limitations", styles["Heading1"]),
                Paragraph(
                    (
                        f"Assessment manifest status: {report.integrity.status}; "
                        f"{report.integrity.hashes_verified}/{report.integrity.files_checked} "
                        "hashes verified."
                    ),
                    styles["BodyText"],
                ),
                Paragraph(
                    "This bounded report is security-assessment evidence, not compliance certification.",
                    styles["BodyText"],
                ),
            ]
        )
        document = SimpleDocTemplate(
            str(target),
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=42,
            bottomMargin=42,
            title=report.branding.report_title,
            author=report.branding.organization_name,
        )
        document.build(story)
        target.chmod(0o600)
        return target

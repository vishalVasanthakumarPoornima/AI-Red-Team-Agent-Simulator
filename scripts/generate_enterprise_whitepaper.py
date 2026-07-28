#!/usr/bin/env python3
"""Generate the enterprise white paper for the AI Agent Red Team Simulator."""

from __future__ import annotations

import os
from datetime import date
from pathlib import Path

from reportlab.graphics.shapes import Circle, Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "ai_agent_red_team_simulator_enterprise_white_paper.pdf"

PAGE_W, PAGE_H = A4
NAVY = HexColor("#071A2B")
NAVY_2 = HexColor("#0D2942")
BLUE = HexColor("#2D6CDF")
CYAN = HexColor("#22C6C8")
TEAL = HexColor("#0D8D8F")
ICE = HexColor("#EAF4FA")
PALE = HexColor("#F5F8FB")
INK = HexColor("#172534")
MUTED = HexColor("#5E6C7A")
LINE_COLOR = HexColor("#D5E0E8")
ORANGE = HexColor("#F09A43")
RED = HexColor("#D9514E")
GREEN = HexColor("#248A68")
WHITE = colors.white


def register_fonts() -> tuple[str, str, str]:
    """Use system fonts when available, with safe built-in fallbacks."""
    candidates = [
        (
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "/System/Library/Fonts/Supplemental/Arial Italic.ttf",
        ),
        (
            "/System/Library/Fonts/Supplemental/Helvetica.ttf",
            "/System/Library/Fonts/Supplemental/Helvetica Bold.ttf",
            "/System/Library/Fonts/Supplemental/Helvetica Oblique.ttf",
        ),
    ]
    for regular, bold, italic in candidates:
        if all(Path(path).exists() for path in (regular, bold, italic)):
            pdfmetrics.registerFont(TTFont("EnterpriseSans", regular))
            pdfmetrics.registerFont(TTFont("EnterpriseSans-Bold", bold))
            pdfmetrics.registerFont(TTFont("EnterpriseSans-Italic", italic))
            return "EnterpriseSans", "EnterpriseSans-Bold", "EnterpriseSans-Italic"
    return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique"


FONT, FONT_BOLD, FONT_ITALIC = register_fonts()


def styles():
    base = getSampleStyleSheet()
    return {
        "cover_kicker": ParagraphStyle(
            "CoverKicker", parent=base["Normal"], fontName=FONT_BOLD, fontSize=9,
            leading=12, textColor=CYAN, spaceAfter=5, tracking=1.2,
        ),
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=base["Title"], fontName=FONT_BOLD, fontSize=31,
            leading=34, textColor=WHITE, spaceAfter=12,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle", parent=base["Normal"], fontName=FONT, fontSize=13,
            leading=19, textColor=HexColor("#C9DCEA"), spaceAfter=15,
        ),
        "eyebrow": ParagraphStyle(
            "Eyebrow", parent=base["Normal"], fontName=FONT_BOLD, fontSize=8.2,
            leading=10, textColor=BLUE, tracking=1.1, spaceAfter=5,
        ),
        "section": ParagraphStyle(
            "SectionTitle", parent=base["Heading1"], fontName=FONT_BOLD, fontSize=23,
            leading=27, textColor=NAVY, spaceAfter=9, keepWithNext=True,
        ),
        "section_deck": ParagraphStyle(
            "SectionDeck", parent=base["Normal"], fontName=FONT, fontSize=11.2,
            leading=16, textColor=MUTED, spaceAfter=15,
        ),
        "h2": ParagraphStyle(
            "SubsectionTitle", parent=base["Heading2"], fontName=FONT_BOLD, fontSize=13,
            leading=16, textColor=NAVY_2, spaceBefore=10, spaceAfter=6, keepWithNext=True,
        ),
        "h3": ParagraphStyle(
            "MinorTitle", parent=base["Heading3"], fontName=FONT_BOLD, fontSize=10.3,
            leading=13, textColor=BLUE, spaceBefore=8, spaceAfter=4, keepWithNext=True,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName=FONT, fontSize=9.25,
            leading=13.7, textColor=INK, spaceAfter=7,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["BodyText"], fontName=FONT, fontSize=7.8,
            leading=10.4, textColor=MUTED, spaceAfter=4,
        ),
        "caption": ParagraphStyle(
            "Caption", parent=base["BodyText"], fontName=FONT_ITALIC, fontSize=7.4,
            leading=9.5, textColor=MUTED, spaceBefore=4, spaceAfter=7,
        ),
        "bullet": ParagraphStyle(
            "Bullet", parent=base["BodyText"], fontName=FONT, fontSize=8.8,
            leading=12.6, textColor=INK, leftIndent=12, firstLineIndent=-8,
            bulletIndent=2, spaceAfter=4,
        ),
        "card_title": ParagraphStyle(
            "CardTitle", parent=base["Normal"], fontName=FONT_BOLD, fontSize=9.2,
            leading=11.5, textColor=NAVY, spaceAfter=3,
        ),
        "card_body": ParagraphStyle(
            "CardBody", parent=base["Normal"], fontName=FONT, fontSize=7.8,
            leading=10.7, textColor=INK,
        ),
        "quote": ParagraphStyle(
            "Quote", parent=base["BodyText"], fontName=FONT_BOLD, fontSize=12.5,
            leading=17, textColor=NAVY, leftIndent=15, rightIndent=8, spaceAfter=7,
        ),
        "table_head": ParagraphStyle(
            "TableHead", parent=base["Normal"], fontName=FONT_BOLD, fontSize=7.4,
            leading=9, textColor=WHITE,
        ),
        "table": ParagraphStyle(
            "TableBody", parent=base["Normal"], fontName=FONT, fontSize=7.3,
            leading=9.4, textColor=INK,
        ),
        "table_bold": ParagraphStyle(
            "TableBodyBold", parent=base["Normal"], fontName=FONT_BOLD, fontSize=7.3,
            leading=9.4, textColor=NAVY,
        ),
        "toc_title": ParagraphStyle(
            "TOCTitle", parent=base["Title"], fontName=FONT_BOLD, fontSize=24,
            leading=28, textColor=NAVY, spaceAfter=12,
        ),
        "legal": ParagraphStyle(
            "Legal", parent=base["BodyText"], fontName=FONT, fontSize=8.4,
            leading=12.5, textColor=INK, spaceAfter=9,
        ),
    }


ST = styles()


class EnterpriseDocTemplate(BaseDocTemplate):
    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            style_name = flowable.style.name
            if style_name in {"SectionTitle", "SubsectionTitle"}:
                level = 0 if style_name == "SectionTitle" else 1
                text = flowable.getPlainText()
                key = f"heading-{level}-{self.seq.nextf('heading')}"
                self.canv.bookmarkPage(key)
                self.canv.addOutlineEntry(text, key, level=level, closed=False)
                self.notify("TOCEntry", (level, text, self.page - 1, key))


def cover_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setFillColor(NAVY_2)
    canvas.circle(PAGE_W * 0.88, PAGE_H * 0.84, 82 * mm, fill=1, stroke=0)
    canvas.setStrokeColor(HexColor("#183C59"))
    canvas.setLineWidth(0.5)
    for offset in range(-4, 8):
        y = 39 * mm + offset * 14 * mm
        canvas.line(0, y, PAGE_W, y + 38 * mm)
    canvas.setStrokeColor(CYAN)
    canvas.setLineWidth(1.1)
    canvas.line(18 * mm, 24 * mm, 70 * mm, 24 * mm)
    canvas.setFillColor(CYAN)
    canvas.circle(70 * mm, 24 * mm, 1.5 * mm, fill=1, stroke=0)
    canvas.restoreState()


def content_page(canvas, doc):
    canvas.saveState()
    canvas.setFillColor(WHITE)
    canvas.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
    canvas.setStrokeColor(LINE_COLOR)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, PAGE_H - 14 * mm, PAGE_W - 18 * mm, PAGE_H - 14 * mm)
    canvas.setFont(FONT_BOLD, 6.8)
    canvas.setFillColor(NAVY)
    canvas.drawString(18 * mm, PAGE_H - 10.5 * mm, "AI AGENT RED TEAM SIMULATOR")
    canvas.setFont(FONT, 6.8)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(PAGE_W - 18 * mm, PAGE_H - 10.5 * mm, "ENTERPRISE WHITE PAPER | JULY 2026")
    canvas.line(18 * mm, 14 * mm, PAGE_W - 18 * mm, 14 * mm)
    canvas.setFont(FONT, 6.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(18 * mm, 9.5 * mm, "Engineering white paper - authorized testing environments only")
    canvas.setFont(FONT_BOLD, 7)
    canvas.setFillColor(NAVY)
    canvas.drawRightString(PAGE_W - 18 * mm, 9.5 * mm, str(max(1, doc.page - 1)))
    canvas.restoreState()


def p(text, style="body"):
    return Paragraph(text, ST[style])


def bullet(text):
    return Paragraph(f"- {text}", ST["bullet"])


def section(number, title, deck):
    return [
        p(f"SECTION {number}", "eyebrow"),
        p(title, "section"),
        p(deck, "section_deck"),
        rule(),
        Spacer(1, 5 * mm),
    ]


def rule(color=CYAN, width=36 * mm):
    drawing = Drawing(170 * mm, 2 * mm)
    drawing.add(Rect(0, 0.55 * mm, width, 0.8 * mm, fillColor=color, strokeColor=None))
    drawing.add(Rect(width, 0.55 * mm, 170 * mm - width, 0.8 * mm, fillColor=LINE_COLOR, strokeColor=None))
    return drawing


def callout(title, body, accent=BLUE, width=174 * mm):
    inner = Table(
        [[p(title, "card_title")], [p(body, "card_body")]],
        colWidths=[width - 13 * mm],
        style=TableStyle([
            ("LEFTPADDING", (0, 0), (-1, -1), 6 * mm),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
            ("TOPPADDING", (0, 0), (-1, 0), 4 * mm),
            ("BOTTOMPADDING", (0, -1), (-1, -1), 4 * mm),
            ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ]),
    )
    outer = Table([["", inner]], colWidths=[3 * mm, width - 3 * mm])
    outer.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), accent),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, LINE_COLOR),
    ]))
    return outer


def card_grid(cards, columns=3, widths=None):
    if widths is None:
        widths = [174 * mm / columns] * columns
    rows = []
    for index in range(0, len(cards), columns):
        row = []
        for title, body, accent in cards[index:index + columns]:
            cell = Table(
                [[""], [p(title, "card_title")], [p(body, "card_body")]],
                colWidths=[widths[len(row)] - 8 * mm],
                rowHeights=[2.2 * mm, None, None],
            )
            cell.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), accent),
                ("BACKGROUND", (0, 1), (0, -1), WHITE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
                ("TOPPADDING", (0, 1), (-1, 1), 4 * mm),
                ("BOTTOMPADDING", (0, -1), (-1, -1), 4 * mm),
                ("BOX", (0, 0), (-1, -1), 0.6, LINE_COLOR),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            row.append(cell)
        while len(row) < columns:
            row.append("")
        rows.append(row)
    table = Table(rows, colWidths=widths, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 2.2 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2.2 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 2.2 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2 * mm),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def data_table(headers, rows, widths, font_size=7.3):
    head = [Paragraph(str(value), ST["table_head"]) for value in headers]
    body = []
    for row in rows:
        body.append([
            Paragraph(str(value), ST["table_bold"] if column == 0 else ST["table"])
            for column, value in enumerate(row)
        ])
    table = Table([head] + body, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY_2),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PALE]),
        ("GRID", (0, 0), (-1, -1), 0.45, LINE_COLOR),
        ("LEFTPADDING", (0, 0), (-1, -1), 2.5 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2.5 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 2.3 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.3 * mm),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def metric_strip(metrics):
    cells = []
    widths = [174 * mm / len(metrics)] * len(metrics)
    for value, label, color in metrics:
        cells.append([
            [p(f'<font color="{color.hexval()}"><b>{value}</b></font>', "quote")],
            [p(label, "small")],
        ])
    table = Table([[Table(cell, colWidths=[widths[i] - 6 * mm]) for i, cell in enumerate(cells)]], colWidths=widths)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PALE),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE_COLOR),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, LINE_COLOR),
        ("LEFTPADDING", (0, 0), (-1, -1), 3 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 3 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def architecture_diagram():
    d = Drawing(174 * mm, 94 * mm)
    w = 174 * mm
    box_w = 43 * mm
    box_h = 19 * mm
    xs = [2 * mm, 65.5 * mm, 129 * mm]
    ys = [64 * mm, 34 * mm, 4 * mm]

    def box(x, y, title, subtitle, fill, title_color=WHITE):
        d.add(Rect(x, y, box_w, box_h, rx=3 * mm, ry=3 * mm, fillColor=fill, strokeColor=None))
        d.add(String(x + 4 * mm, y + 12.2 * mm, title, fontName=FONT_BOLD, fontSize=8.2, fillColor=title_color))
        d.add(String(x + 4 * mm, y + 6.2 * mm, subtitle, fontName=FONT, fontSize=6.5, fillColor=title_color))

    box(xs[0], ys[0], "Operators", "CLI + natural language", NAVY_2)
    box(xs[1], ys[0], "Orchestration", "intent, scope, monitoring", BLUE)
    box(xs[2], ys[0], "Reporting", "JSON, Markdown, timeline", TEAL)
    box(xs[0], ys[1], "Attack Engines", "static + adaptive probes", BLUE)
    box(xs[1], ys[1], "Evaluation", "detectors + severity", NAVY_2)
    box(xs[2], ys[1], "Kali Lab", "recon + bounded web tests", ORANGE, NAVY)
    box(xs[0], ys[2], "Python Targets", "explicit REDTEAM_TARGET", TEAL)
    box(xs[1], ys[2], "HTTP Agents", "health, metadata, invoke", BLUE)
    box(xs[2], ys[2], "Hosted / Web Apps", "authorized endpoints", NAVY_2)

    arrows = [
        (xs[0] + box_w, ys[0] + box_h / 2, xs[1], ys[0] + box_h / 2),
        (xs[1] + box_w, ys[0] + box_h / 2, xs[2], ys[0] + box_h / 2),
        (xs[1] + box_w / 2, ys[0], xs[1] + box_w / 2, ys[1] + box_h),
        (xs[0] + box_w / 2, ys[1], xs[0] + box_w / 2, ys[2] + box_h),
        (xs[1] + box_w / 2, ys[1], xs[1] + box_w / 2, ys[2] + box_h),
        (xs[2] + box_w / 2, ys[1], xs[2] + box_w / 2, ys[2] + box_h),
        (xs[0] + box_w, ys[1] + box_h / 2, xs[1], ys[1] + box_h / 2),
        (xs[1] + box_w, ys[1] + box_h / 2, xs[2], ys[1] + box_h / 2),
    ]
    for x1, y1, x2, y2 in arrows:
        d.add(Line(x1, y1, x2, y2, strokeColor=HexColor("#8BA5B8"), strokeWidth=1))
        angle = 2.2 * mm
        if abs(x2 - x1) > abs(y2 - y1):
            d.add(Polygon([x2, y2, x2 - angle, y2 + angle / 2, x2 - angle, y2 - angle / 2], fillColor=HexColor("#8BA5B8"), strokeColor=None))
        else:
            d.add(Polygon([x2, y2, x2 - angle / 2, y2 + angle, x2 + angle / 2, y2 + angle], fillColor=HexColor("#8BA5B8"), strokeColor=None))
    return d


def lifecycle_diagram():
    d = Drawing(174 * mm, 46 * mm)
    steps = [
        ("1", "Scope", "authorized targets"),
        ("2", "Discover", "services + metadata"),
        ("3", "Recon", "capabilities + routes"),
        ("4", "Probe", "static + adaptive"),
        ("5", "Evaluate", "detectors + severity"),
        ("6", "Report", "evidence + actions"),
    ]
    gap = 28.5 * mm
    for idx, (number, title, subtitle) in enumerate(steps):
        x = 8 * mm + idx * gap
        d.add(Circle(x + 5 * mm, 27 * mm, 5 * mm, fillColor=BLUE if idx < 5 else TEAL, strokeColor=None))
        d.add(String(x + 5 * mm, 25.4 * mm, number, textAnchor="middle", fontName=FONT_BOLD, fontSize=7, fillColor=WHITE))
        d.add(String(x + 5 * mm, 16 * mm, title, textAnchor="middle", fontName=FONT_BOLD, fontSize=7.3, fillColor=NAVY))
        d.add(String(x + 5 * mm, 10.4 * mm, subtitle, textAnchor="middle", fontName=FONT, fontSize=5.9, fillColor=MUTED))
        if idx < len(steps) - 1:
            d.add(Line(x + 10.5 * mm, 27 * mm, x + gap - 0.5 * mm, 27 * mm, strokeColor=CYAN, strokeWidth=1.5))
    return d


def topology_diagram():
    d = Drawing(174 * mm, 77 * mm)
    d.add(Rect(2 * mm, 7 * mm, 76 * mm, 61 * mm, rx=3 * mm, fillColor=PALE, strokeColor=LINE_COLOR))
    d.add(Rect(96 * mm, 7 * mm, 76 * mm, 61 * mm, rx=3 * mm, fillColor=PALE, strokeColor=LINE_COLOR))
    d.add(String(8 * mm, 59 * mm, "Developer / CI environment", fontName=FONT_BOLD, fontSize=9, fillColor=NAVY))
    d.add(String(102 * mm, 59 * mm, "Kali assessment host", fontName=FONT_BOLD, fontSize=9, fillColor=NAVY))
    d.add(Rect(9 * mm, 35 * mm, 58 * mm, 15 * mm, rx=2 * mm, fillColor=BLUE, strokeColor=None))
    d.add(String(38 * mm, 43 * mm, "Loopback-only agent service", textAnchor="middle", fontName=FONT_BOLD, fontSize=7, fillColor=WHITE))
    d.add(String(38 * mm, 38.3 * mm, "127.0.0.1:18080 / 181xx", textAnchor="middle", fontName=FONT, fontSize=6.2, fillColor=WHITE))
    d.add(Rect(9 * mm, 15 * mm, 58 * mm, 13 * mm, rx=2 * mm, fillColor=NAVY_2, strokeColor=None))
    d.add(String(38 * mm, 21.2 * mm, "CLI, monitor, evaluator", textAnchor="middle", fontName=FONT_BOLD, fontSize=7, fillColor=WHITE))
    d.add(Rect(104 * mm, 35 * mm, 58 * mm, 15 * mm, rx=2 * mm, fillColor=ORANGE, strokeColor=None))
    d.add(String(133 * mm, 43 * mm, "Bounded security tooling", textAnchor="middle", fontName=FONT_BOLD, fontSize=7, fillColor=NAVY))
    d.add(String(133 * mm, 38.3 * mm, "nmap / whatweb / nikto / sqlmap", textAnchor="middle", fontName=FONT, fontSize=6.2, fillColor=NAVY))
    d.add(Rect(104 * mm, 15 * mm, 58 * mm, 13 * mm, rx=2 * mm, fillColor=NAVY_2, strokeColor=None))
    d.add(String(133 * mm, 21.2 * mm, "Prompt and HTTP probes", textAnchor="middle", fontName=FONT_BOLD, fontSize=7, fillColor=WHITE))
    d.add(Line(67 * mm, 42.5 * mm, 104 * mm, 42.5 * mm, strokeColor=CYAN, strokeWidth=2))
    d.add(Polygon([104 * mm, 42.5 * mm, 100.5 * mm, 44.5 * mm, 100.5 * mm, 40.5 * mm], fillColor=CYAN, strokeColor=None))
    d.add(String(85.5 * mm, 48.5 * mm, "reverse SSH tunnel", textAnchor="middle", fontName=FONT_BOLD, fontSize=6.3, fillColor=TEAL))
    d.add(String(85.5 * mm, 35 * mm, "no LAN exposure", textAnchor="middle", fontName=FONT, fontSize=6.1, fillColor=MUTED))
    return d


def build_story():
    story = []

    # Cover
    story.extend([
        Spacer(1, 44 * mm),
        p("ENTERPRISE SECURITY WHITE PAPER", "cover_kicker"),
        p("AI Agent Red Team<br/>Simulator", "cover_title"),
        p("A practical architecture for authorized, evidence-driven security testing of AI agents across local Python targets, HTTP services, hosted endpoints, and isolated Kali lab workflows.", "cover_subtitle"),
        Spacer(1, 8 * mm),
        Table(
            [[p("Architecture", "card_title"), p("Methodology", "card_title"), p("Adoption Blueprint", "card_title")],
             [p("Composable target discovery, attack engines, evaluation, monitoring, and reporting.", "card_body"), p("Static, adaptive, HTTP, and Kali-backed tests with fail-closed semantics.", "card_body"), p("A phased path from engineering lab to governed enterprise program.", "card_body")]],
            colWidths=[52 * mm, 52 * mm, 52 * mm],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), HexColor("#102F49")),
                ("BOX", (0, 0), (-1, -1), 0.5, HexColor("#31546C")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, HexColor("#31546C")),
                ("TEXTCOLOR", (0, 0), (-1, -1), WHITE),
                ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4 * mm),
                ("TOPPADDING", (0, 0), (-1, -1), 4 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4 * mm),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]),
        ),
        Spacer(1, 32 * mm),
        p("VERSION 1.0  |  13 JULY 2026", "cover_kicker"),
        p("Prepared from the current project repository and a dated local validation snapshot.", "cover_subtitle"),
        NextPageTemplate("content"),
        PageBreak(),
    ])

    # Document control
    story.extend(section("00", "Document purpose and control", "A precise statement of audience, scope, evidence, and responsible-use boundaries."))
    story.extend([
        p("Purpose", "h2"),
        p("This white paper explains the business value, technical architecture, security methodology, operating model, and enterprise adoption path for the AI Agent Red Team Simulator. It is written for security leaders, application security teams, AI platform owners, engineering leaders, auditors, and technical buyers evaluating an internal AI assurance capability."),
        data_table(
            ["Field", "Value"],
            [
                ["Document status", "Engineering white paper - Version 1.0"],
                ["Repository snapshot", "Branch codex/kali-agent-cli; HEAD 86a8081; current working tree reviewed on 13 July 2026"],
                ["Validation snapshot", "47 unit tests passed; six explicit targets discovered; deterministic smoke scan 6 PASS / 0 FAIL / 0 ERROR; compilation succeeded"],
                ["Primary audience", "CISO, AppSec, AI platform engineering, security architecture, governance, risk, and compliance"],
                ["Classification", "Project documentation; authorized testing environments only"],
            ],
            [42 * mm, 132 * mm],
        ),
        Spacer(1, 4 * mm),
        callout("Responsible-use boundary", "The project is designed for isolated labs, systems owned by the operator, or environments covered by explicit authorization. It uses simulated payloads and fake lab secrets. It is not a license to probe public or third-party systems, harvest real credentials, or execute destructive actions.", ORANGE),
        p("Evidence basis", "h2"),
        p("Claims are derived from repository code, configuration, tests, generated report formats, and a local validation run. Historical Kali connectivity and hosted-service checks are treated as environment-dependent capabilities, not as current availability guarantees. External framework alignment is directional rather than a certification claim."),
        p("How to read this paper", "h2"),
        p("Sections 1-3 provide the executive and architecture view. Sections 4-8 cover threat coverage, methodology, controls, deployment, and reporting. Sections 9-12 address validation evidence, adoption, limitations, and roadmap. The appendix maps capabilities to project artifacts."),
        PageBreak(),
    ])

    # TOC
    story.extend([p("DOCUMENT GUIDE", "eyebrow"), p("Contents", "toc_title"), p("The table of contents is generated from the final paginated document.", "section_deck")])
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle(name="TOC0", fontName=FONT_BOLD, fontSize=9.5, leading=15, leftIndent=0, firstLineIndent=0, textColor=NAVY, spaceBefore=3),
        ParagraphStyle(name="TOC1", fontName=FONT, fontSize=8, leading=12, leftIndent=9 * mm, firstLineIndent=0, textColor=MUTED),
    ]
    toc.dotsMinLevel = 0
    story.extend([toc, PageBreak()])

    # 1 Executive summary
    story.extend(section("01", "Executive summary", "AI agents expand the application attack surface from text generation into tools, data, memory, services, and automated actions. The simulator makes that risk testable."))
    story.extend([
        p("The proposition", "h2"),
        p("The AI Agent Red Team Simulator is an extensible, local-first assessment platform for testing agent behavior and the surrounding application surface. It combines deterministic attack suites, locally generated adaptive prompts, HTTP service discovery, bounded Kali tooling, explicit evidence capture, and enterprise-style reporting. The result is a repeatable security feedback loop that can be used during development, before deployment, and after material changes."),
        metric_strip([
            ("6", "explicitly enrolled target agents", BLUE),
            ("5", "default attack categories", TEAL),
            ("47", "unit tests passed in current snapshot", GREEN),
            ("4", "primary execution modes", ORANGE),
        ]),
        Spacer(1, 5 * mm),
        p("Why it matters", "h2"),
        card_grid([
            ("Close the AI assurance gap", "Traditional scanners do not reliably evaluate prompt disclosure, model refusal quality, secret leakage, or tool misuse. This project adds behavior-aware tests around the agent boundary.", BLUE),
            ("Keep sensitive testing local", "The adaptive harness can use local Ollama models. Loopback services and reverse SSH tunnels reduce unnecessary network exposure during lab assessments.", TEAL),
            ("Produce defensible evidence", "Structured JSON, Markdown reports, timelines, event streams, detector evidence, status counts, and remediation text create an auditable record of what was tested.", ORANGE),
        ]),
        p("Strategic position", "h2"),
        p("The current implementation is best understood as an engineering-grade AI security validation platform and enterprise program accelerator. It is not yet a turnkey multi-tenant commercial control plane. Its strength is a clear separation of scope, attack generation, transport, evaluation, and reporting - a foundation that can be hardened and integrated into CI/CD and governance workflows."),
        callout("Executive takeaway", "Adopt the simulator first as a governed internal testing capability for AI application teams. Use it to standardize pre-release evidence, establish regression baselines, and surface control gaps before investing in broader automation or centralized orchestration.", BLUE),
        PageBreak(),
    ])

    # 2 landscape and value
    story.extend(section("02", "Risk landscape and business value", "Agentic applications combine probabilistic behavior with conventional software, making isolated model testing insufficient."))
    story.extend([
        p("The compound attack surface", "h2"),
        p("An AI agent is not only a model. It is a system of prompts, orchestration logic, tools, credentials, APIs, memory, data providers, deployment infrastructure, and user interfaces. A prompt injection may become materially harmful only when the application grants broad tools, returns sensitive context, trusts model output, or exposes an insecure service path."),
        data_table(
            ["Risk domain", "Enterprise consequence", "Simulator response"],
            [
                ["Prompt and instruction control", "Guardrail bypass, policy drift, hidden instruction disclosure", "Prompt injection and prompt-disclosure suites with evidence-aware detectors"],
                ["Sensitive information", "Credential leakage, policy exposure, data loss", "Secret patterns, configured-secret redaction, fake lab secrets, response guards"],
                ["Tools and agency", "Unauthorized action, destructive operations, privilege abuse", "Tool-abuse payloads, capability probes, dry-run and scope recommendations"],
                ["Application surface", "Unsafe output handling, exposed endpoints, error leakage", "HTTP discovery plus optional Kali recon and bounded web probes"],
                ["Operational reliability", "Coverage gaps hidden as false success", "PASS / FAIL / ERROR / UNPARSED semantics and fail-on-findings modes"],
            ],
            [38 * mm, 62 * mm, 74 * mm],
        ),
        p("Alignment to recognized guidance", "h2"),
        p("The testing themes align with several areas in the OWASP Top 10 for LLM Applications 2025, including prompt injection, sensitive information disclosure, improper output handling, excessive agency, and system prompt leakage. The operating model also supports the NIST AI RMF functions of Govern, Map, Measure, and Manage by creating scoped tests, measurable outcomes, remediation evidence, and repeatable oversight. These are alignment claims only; the project does not confer compliance or certification."),
        card_grid([
            ("Reduce late-stage surprises", "Move behavior and integration tests left, before production deployment or major agent changes.", BLUE),
            ("Standardize evidence", "Replace ad hoc screenshots with consistent findings, timestamps, evidence excerpts, and machine-readable artifacts.", CYAN),
            ("Create a regression loop", "Convert discovered weaknesses into guardrails and tests that can be rerun after model, prompt, tool, or code changes.", TEAL),
        ]),
        PageBreak(),
    ])

    # 3 solution overview
    story.extend(section("03", "Platform overview", "A modular assessment fabric spans local Python targets, live agent services, hosted endpoints, and isolated Kali workflows."))
    story.extend([
        architecture_diagram(),
        p("Figure 1. Logical platform architecture. Solid paths represent orchestrated flows; every assessment converges on normalized evidence and reporting.", "caption"),
        p("Core architectural principles", "h2"),
        card_grid([
            ("Explicit enrollment", "Only Python modules declaring REDTEAM_TARGET = True are discovered. Scratch modules and placeholders are excluded by default.", BLUE),
            ("Transport independence", "The evaluator can test imported Python functions, local HTTP services, reverse-tunneled agents, or authorized hosted URLs.", CYAN),
            ("Fail-closed interpretation", "Transport failures and empty or unparsed remote output are not treated as security passes.", ORANGE),
            ("Evidence first", "Every result includes target, attack, prompt, response excerpt, status, severity, reason, detectors, evidence, and timestamp where available.", TEAL),
            ("Local-first operation", "Adaptive prompt generation can remain on the operator's machine using Ollama, limiting unnecessary external data flow.", GREEN),
            ("Composable reporting", "Per-test JSON, combined Markdown, enterprise reports, timeline Markdown, and JSONL event streams serve humans and automation.", NAVY_2),
        ], columns=3),
        PageBreak(),
    ])

    # 4 components
    story.extend(section("04", "Component architecture", "Clear module boundaries make the simulator understandable, testable, and extensible."))
    story.extend([
        data_table(
            ["Layer", "Key components", "Responsibility"],
            [
                ["Operator layer", "ai_red_team_cli.py; scripts/redteam_chat.sh", "Deterministic commands and natural-language requests"],
                ["Orchestration", "red_team_assistant.py; assessment_monitor.py", "Intent parsing, action routing, lifecycle events, artifact finalization"],
                ["Attack engines", "scanner/attack_runner.py; local_red_team; http_agent_attack.py; kali_*_attack.py", "Payload loading, adaptive generation, HTTP probing, Kali-backed assessment"],
                ["Target and service layer", "scanner/target_loader.py; agent_service.py; agent_registry.py; agent_lab_server.py", "Explicit discovery, standard service contract, health, metadata, invoke, lab exposure"],
                ["Evaluation", "scanner/detectors.py; targets/_guardrails.py", "Pattern-based findings, severity, safe-refusal recognition, output protection"],
                ["Reporting", "enterprise_report.py; scanner/report_generator.py", "Normalized findings, summaries, remediation, evidence and executive artifacts"],
                ["Deployment", "render.yaml; scripts/bootstrap_dev.sh; scripts/validate.sh", "Repeatable runtime, hosted blueprints, validation gates"],
            ],
            [34 * mm, 68 * mm, 72 * mm],
        ),
        p("Standard target contract", "h2"),
        p("A local target is intentionally lightweight: it declares the explicit enrollment marker and exposes run_agent(prompt). The attack runner imports the module, invokes it, normalizes non-string responses, detects transport-like error text, evaluates behavior, redacts configured secrets, and records a timestamped result. This contract lowers the cost of adding internal test doubles or real application adapters."),
        callout("Service contract", "HTTP agent services expose GET /health, GET /metadata, and POST /invoke. Requests are JSON objects, capped at 32,000 bytes, and responses include no-store, nosniff, and frame-denial headers. This is a lab-friendly service adapter, not a complete production authentication layer.", CYAN),
        p("Functional target portfolio", "h2"),
        data_table(
            ["Target", "Purpose", "Runtime style"],
            [
                ["ollama_agent", "General local LLM target", "Ollama HTTP API"],
                ["tool_agent", "Tool-use and fake-secret test target", "Deterministic Python"],
                ["travel_agent", "Lightweight travel assistant", "Local Ollama with output guard"],
                ["tutor_agent", "Lightweight tutor assistant", "Local Ollama with output guard"],
                ["weather_insight_agent", "Weather guidance with live data tools", "LangGraph + Ollama + weather providers"],
                ["travel_planner_agent", "Trip planning with weather context", "LangGraph + Ollama + weather providers"],
            ],
            [45 * mm, 73 * mm, 56 * mm],
        ),
        PageBreak(),
    ])

    # 5 Threat model
    story.extend(section("05", "Threat model and coverage", "The simulator tests both model behavior and the application controls that turn model outputs into business impact."))
    story.extend([
        p("Protected assets", "h2"),
        card_grid([
            ("Instructions and policy", "System prompts, developer guidance, role boundaries, internal operating rules.", BLUE),
            ("Secrets and sensitive data", "API keys, tokens, connection data, private context, fake lab credentials.", RED),
            ("Tools and privileges", "File, shell, network, business transaction, and data-access capabilities.", ORANGE),
            ("Service integrity", "Agent endpoints, parsers, error paths, request limits, output handling.", TEAL),
            ("Availability and cost", "Model latency, timeouts, unbounded requests, coverage degradation.", NAVY_2),
            ("Assurance evidence", "Reports, event traces, detector results, timestamps, and remediation records.", GREEN),
        ]),
        p("Attack categories", "h2"),
        data_table(
            ["Category", "Representative objective", "Primary signal"],
            [
                ["Prompt disclosure", "Reveal hidden instructions or policy text", "Disclosure markers and protected-content evidence"],
                ["System prompt disclosure", "Elicit system or developer message content", "Instruction blocks, role labels, internal-rule patterns"],
                ["Prompt injection", "Override or redirect intended agent behavior", "Unsafe compliance, policy bypass, sensitive or manipulated output"],
                ["Tool abuse", "Induce destructive or unauthorized actions", "Capability claims, command execution language, dangerous command text"],
                ["Secret extraction", "Expose keys, tokens, credentials, or private values", "Known fake values, configured-secret matches, token patterns"],
                ["Web-app probes", "Find SQL errors, reflection, traversal, error leakage, agent endpoints", "HTTP status, response evidence, Kali tool output"],
            ],
            [42 * mm, 72 * mm, 60 * mm],
        ),
        p("Out-of-scope by design", "h2"),
        p("The default safety boundary excludes destructive exploitation, credential harvesting, public target scanning without authorization, persistence, denial-of-service testing, covert exfiltration, and claims of complete model safety. Multimodal attacks, RAG poisoning, supply-chain scanning, model theft, and quantitative bias evaluation are not comprehensively implemented in the current baseline."),
        PageBreak(),
    ])

    # 6 methodology
    story.extend(section("06", "Assessment methodology", "A six-stage workflow turns authorized scope into reproducible evidence and actionable remediation."))
    story.extend([
        lifecycle_diagram(),
        p("Figure 2. Assessment lifecycle. Monitoring records observable actions and outcomes at each stage without exposing hidden model reasoning.", "caption"),
        data_table(
            ["Stage", "Key actions", "Control objective"],
            [
                ["1. Scope", "Select targets, attack classes, limits, transport, and fail conditions", "Prevent unauthorized or unbounded execution"],
                ["2. Discover", "Enumerate explicit modules, registry entries, local services, or supplied URLs", "Establish a testable inventory"],
                ["3. Recon", "Read metadata, probe capabilities, inspect endpoints, optionally run bounded web recon", "Adapt tests to the real application surface"],
                ["4. Probe", "Run curated payloads, locally generated adaptive prompts, HTTP probes, or Kali tools", "Exercise model and application controls"],
                ["5. Evaluate", "Normalize responses; detect disclosure, secrets, unsafe tools, refusals, errors, and unparsed output", "Make status and evidence consistent"],
                ["6. Report", "Write structured artifacts, risk summaries, remediation, timeline, and event stream", "Support triage, governance, and regression"],
            ],
            [31 * mm, 86 * mm, 57 * mm],
        ),
        p("Execution modes", "h2"),
        card_grid([
            ("Deterministic scanner", "Curated payload files are applied to explicit Python targets. Best for fast, repeatable regression checks.", BLUE),
            ("Adaptive local red team", "A local Ollama planner generates target-specific prompts, then the evaluator tests locally hosted target agents.", TEAL),
            ("Live HTTP assessment", "Compatible services are discovered through health and metadata contracts; recon informs dynamic probes against invoke endpoints.", CYAN),
            ("Kali-backed assessment", "A separate Kali host runs bounded recon and prompt or web probes against tunneled local services or authorized URLs.", ORANGE),
        ], columns=2, widths=[87 * mm, 87 * mm]),
        PageBreak(),
    ])

    # 7 security controls
    story.extend(section("07", "Security and safety controls", "The project contains practical controls for target enrollment, data handling, network exposure, execution bounds, and truthful reporting."))
    story.extend([
        data_table(
            ["Control", "Implementation", "Residual consideration"],
            [
                ["Explicit target enrollment", "AST-based discovery requires REDTEAM_TARGET = True", "Marker review remains a code-governance responsibility"],
                ["Local-first model use", "Ollama endpoints and local adaptive planning are supported", "Model weights, prompts, and local host still require protection"],
                ["Secret hygiene", "Environment-only keys, output redaction, fake lab secrets, guard_response filters", "Redaction is pattern based and should be backed by secret scanning and least privilege"],
                ["Loopback isolation", "Agent lab services bind to 127.0.0.1 by default", "Hosted deployment requires production network and identity controls"],
                ["Reverse tunnel", "Kali reaches local services without LAN exposure", "SSH keys, host trust, ports, and teardown require operational governance"],
                ["Request bounds", "Single-agent service caps JSON bodies at 32,000 bytes", "Rate limiting, authentication, and quotas are future hardening areas"],
                ["Safe web posture", "Bounded, non-destructive probes and explicit authorization language", "Operator policy and target allowlists should be enforced centrally"],
                ["Fail-closed reporting", "Remote errors, empty output, and unparsed results cannot silently become PASS", "Coverage still depends on detector quality and complete transport telemetry"],
                ["Observable audit trail", "Timeline and JSONL events record scope, tools, HTTP calls, return codes, and status", "Integrity protection and centralized retention are not yet built in"],
            ],
            [39 * mm, 75 * mm, 60 * mm],
        ),
        p("Secure-by-default recommendations for enterprise use", "h2"),
        bullet("Run assessments in isolated developer, CI, or dedicated security environments with egress controls."),
        bullet("Require a signed scope manifest or centrally managed allowlist before any URL or Kali workflow can execute."),
        bullet("Use short-lived service identities and vault-managed secrets; never place credentials in system prompts."),
        bullet("Make tool execution dry-run by default and require explicit human approval for any state-changing test."),
        bullet("Send artifacts to tamper-evident storage and attach build, model, prompt, tool, and dataset versions."),
        bullet("Treat detector updates as security code: review, test, version, and calibrate false-positive and false-negative rates."),
        callout("Control philosophy", "The simulator should sit inside a broader AI secure-development lifecycle. It measures selected behaviors and surfaces evidence; authorization, identity, data governance, model governance, conventional AppSec, and incident response remain essential surrounding controls.", BLUE),
        PageBreak(),
    ])

    # 8 deployment
    story.extend(section("08", "Deployment and integration patterns", "The architecture supports a low-friction local lab today and a clear path toward CI and centralized enterprise operation."))
    story.extend([
        topology_diagram(),
        p("Figure 3. Recommended isolated Kali topology for testing local services. The reverse tunnel makes the target reachable from Kali while preserving loopback-only binding on the development host.", "caption"),
        p("Supported patterns", "h2"),
        data_table(
            ["Pattern", "Best use", "Key dependencies"],
            [
                ["Developer workstation", "Fast target development and deterministic regression", "Python 3.13, .venv, optional local Ollama"],
                ["Local service lab", "HTTP contract and end-to-end agent behavior", "Agent services, registry, ports 18101 / 18102 or configured alternatives"],
                ["Kali paired lab", "Independent recon plus prompt and web tests", "Key-based SSH, tunnel ports, Kali tools, reachable host"],
                ["Hosted demo services", "External service evaluation in an owned environment", "Render blueprint, OLLAMA_URL, environment-injected keys"],
                ["CI validation", "Unit tests, compilation, discovery, deterministic smoke and policy gates", "Pinned Python runtime, non-zero fail conditions, artifact retention"],
            ],
            [42 * mm, 72 * mm, 60 * mm],
        ),
        p("Runtime baseline", "h2"),
        p("The repository pins Python 3.13 and includes scripts/bootstrap_dev.sh to create .venv and install requirements. LangGraph is the only declared Python package in requirements.txt; other core paths use the standard library. Local model defaults use llama3.2:1b where supported, while lightweight travel and tutor targets can use separate smaller Ollama models."),
        p("Hosted-service caveat", "h2"),
        p("The Render blueprint starts Python web services for the weather and travel-planner targets, but it does not run Ollama inside the same process. A deployment therefore needs an authorized Ollama-compatible endpoint configured through OLLAMA_URL. OPENWEATHER_API_KEY is optional because Open-Meteo provides a fallback data path."),
        PageBreak(),
    ])

    # 9 reporting
    story.extend(section("09", "Evidence, reporting, and observability", "The project treats assessment output as an auditable product, not a terminal transcript."))
    story.extend([
        p("Artifact model", "h2"),
        data_table(
            ["Artifact", "Format", "Primary consumer"],
            [
                ["Per-target attack results", "JSON", "Developers, automated analysis, regression comparison"],
                ["Combined scan report", "Markdown", "Engineering review and rapid triage"],
                ["Enterprise report", "Markdown + JSON", "Security leadership, risk owners, evidence systems"],
                ["Assessment timeline", "Markdown", "Human-readable phase and activity review"],
                ["Assessment events", "JSONL", "Replay, ingestion, SIEM or data-pipeline integration"],
                ["Kali and HTTP reports", "JSON", "Technical evidence and tool-level troubleshooting"],
            ],
            [47 * mm, 33 * mm, 94 * mm],
        ),
        p("Finding anatomy", "h2"),
        card_grid([
            ("Identity", "Stable finding ID, run, target, attack, and timestamp support traceability.", BLUE),
            ("Decision", "Status, severity, confidence, detector names, and reason explain classification.", TEAL),
            ("Evidence", "Prompt, redacted response excerpt, matched indicators, HTTP or tool output support triage.", ORANGE),
            ("Action", "Risk-oriented remediation translates technical behavior into a control improvement.", GREEN),
        ], columns=2, widths=[87 * mm, 87 * mm]),
        p("Observable behavior, not hidden reasoning", "h2"),
        p("The assessment monitor records interpreted intent, discovered services, generated probes, HTTP calls, Kali commands, return codes, phase status, and result summaries. It deliberately does not expose hidden model chain-of-thought. This is the correct enterprise boundary: record decisions, inputs, tools, outputs, and outcomes that can be audited without inventing or disclosing internal reasoning traces."),
        p("Result semantics", "h2"),
        p("PASS means no configured issue was detected in that execution context; it does not prove the absence of vulnerability. FAIL indicates a security finding. ERROR indicates an execution, availability, parser, or service failure. Kali paths also use UNPARSED when remote output cannot be safely interpreted. Fail-on-findings options convert adverse outcomes into non-zero exit behavior for automation."),
        PageBreak(),
    ])

    # 10 validation evidence
    story.extend(section("10", "Current validation snapshot", "A dated evidence snapshot demonstrates local correctness while preserving clear boundaries around environment-dependent testing."))
    story.extend([
        metric_strip([
            ("47 / 47", "unit tests passed", GREEN),
            ("6", "explicit targets discovered", BLUE),
            ("6 / 6", "smoke probes passed", TEAL),
            ("0", "smoke failures or errors", GREEN),
        ]),
        Spacer(1, 5 * mm),
        p("Validation executed on 13 July 2026", "h2"),
        data_table(
            ["Check", "Observed result", "Meaning"],
            [
                ["Unit test suite", ".venv/bin/python -m unittest discover -s tests -> Ran 47 tests; OK", "Current deterministic tests pass, including scanner, reporting, assistant, HTTP, service, monitoring, and Kali error paths"],
                ["Target discovery", "Six targets listed", "Explicit enrollment boundary is operating as intended"],
                ["Deterministic smoke", "tool_agent x prompt_disclosure -> 6 PASS, 0 FAIL, 0 ERROR", "The core loader, runner, detector, redaction, and report path executed successfully"],
                ["Compilation", "Core modules compiled without syntax errors", "The reviewed Python module set is syntactically valid"],
            ],
            [38 * mm, 70 * mm, 66 * mm],
        ),
        p("Test portfolio represented in the repository", "h2"),
        p("The test suite covers agent registry behavior, assessment monitoring, attack execution, detectors, enterprise reporting, HTTP agent assessment, Kali remote helpers, Kali URL behavior, Ollama target behavior, natural-language assistant routing, service resolution, and target discovery. This breadth is valuable, but coverage percentage and mutation quality are not currently reported."),
        p("Evidence limitations", "h2"),
        bullet("The smoke result is one target and one attack category; it is a pipeline check, not a full security assessment."),
        bullet("Local model and weather-provider behavior can vary with model availability, configuration, latency, and network access."),
        bullet("Kali reachability and hosted URL validation were not re-executed for this white paper."),
        bullet("PASS / FAIL classifications are detector-dependent and should be reviewed for high-impact releases."),
        callout("Truthful validation statement", "The current repository demonstrates a working local assessment and reporting foundation. External integrations remain conditional on their runtime environment and should be validated as part of each deployment or demonstration.", ORANGE),
        PageBreak(),
    ])

    # 11 operating model
    story.extend(section("11", "Enterprise operating model", "A successful program combines platform ownership, security policy, product-team accountability, and evidence-based release gates."))
    story.extend([
        p("Recommended roles", "h2"),
        data_table(
            ["Role", "Accountability"],
            [
                ["AI Security / AppSec", "Own attack taxonomy, detector calibration, high-risk review, methodology, and exception policy"],
                ["AI Platform Engineering", "Provide target adapters, model and prompt provenance, test environments, service identity, and CI integration"],
                ["Product Engineering", "Remediate findings, add regression tests, maintain least-privilege tools, and approve release evidence"],
                ["Governance / Risk", "Define risk thresholds, evidence retention, reporting cadence, and alignment with organizational AI policy"],
                ["Infrastructure / SRE", "Operate isolated runners, secrets, logs, availability controls, artifact storage, and hosted assessment boundaries"],
                ["Business Owner", "Accept residual risk and validate that agent capabilities match business intent"],
            ],
            [52 * mm, 122 * mm],
        ),
        p("Suggested release gate", "h2"),
        card_grid([
            ("1. Inventory", "Target owner, business purpose, model, prompt, tools, data, endpoints, and deployment version recorded.", NAVY_2),
            ("2. Baseline", "Unit tests, compilation, discovery, deterministic suites, and service checks complete.", BLUE),
            ("3. Risk test", "Adaptive and integration tests run for high-impact agents; findings triaged by severity.", TEAL),
            ("4. Decision", "Blocking issues fixed or explicitly accepted by accountable risk owner with an expiry.", ORANGE),
            ("5. Evidence", "Reports, timeline, code revision, runtime versions, and exceptions attached to release record.", GREEN),
            ("6. Monitor", "Retest after prompt, model, tool, data, or authorization changes; trend outcomes over time.", CYAN),
        ]),
        p("Illustrative policy thresholds", "h2"),
        p("Block release on Critical secret exposure, destructive tool compliance, authentication bypass, or unparsed failures in required coverage. Require security approval for High findings and repeated ERROR results. Permit lower-severity issues only with an owner, due date, compensating controls, and regression test. Thresholds must be tailored to business impact and agent agency."),
        PageBreak(),
    ])

    # 12 adoption roadmap
    story.extend(section("12", "Adoption roadmap", "A phased approach creates value quickly while building the controls required for enterprise scale."))
    story.extend([
        data_table(
            ["Phase", "0-30 days", "31-90 days", "90-180 days"],
            [
                ["Objective", "Establish a governed pilot", "Integrate into delivery", "Scale and measure"],
                ["Scope", "Two to three owned agents; deterministic and HTTP paths", "Critical agents; adaptive tests; CI artifacts; selected Kali workflows", "Portfolio inventory; centralized runners; recurring and event-driven assessment"],
                ["Controls", "Authorization checklist, target allowlist, fake data, isolated runners", "Service identity, vault secrets, signed scope, release thresholds, artifact retention", "RBAC, tenant isolation, policy-as-code, provenance, centralized audit and exception workflow"],
                ["Metrics", "Run success, findings by severity, remediation owner", "Escaped findings, retest closure, false-positive review, time to evidence", "Coverage by risk tier, recurrence, control effectiveness, mean time to remediate"],
                ["Exit criteria", "Repeatable test and report on pilot targets", "Required release gate operating for critical changes", "Risk-tiered coverage with executive trend reporting"],
            ],
            [27 * mm, 49 * mm, 49 * mm, 49 * mm],
        ),
        p("Priority engineering backlog", "h2"),
        card_grid([
            ("Policy and authorization", "Central allowlists, signed scope manifests, target ownership, risk-tier profiles, non-interactive approval boundaries.", RED),
            ("Identity and secrets", "Authentication for services, short-lived identities, vault integration, secret scanning, key rotation, encrypted artifacts.", ORANGE),
            ("Reproducibility", "Containerized runners, pinned tool versions, model and prompt hashes, deterministic fixtures, seeded evaluations.", BLUE),
            ("Detection quality", "Semantic evaluators, human review sampling, adversarial detector tests, calibration data, false-negative analysis.", TEAL),
            ("Enterprise integration", "SARIF or equivalent output, ticketing, SIEM, CI templates, signed reports, release metadata, dashboards.", CYAN),
            ("Scale and resilience", "Job queue, concurrency controls, quotas, rate limits, retries, time budgets, cancellation, multi-tenant separation.", NAVY_2),
        ]),
        p("Recommended pilot success criteria", "h2"),
        bullet("At least two representative agents onboarded without custom changes to the core evaluator."),
        bullet("A security finding can be reproduced, remediated, and locked into a regression test."),
        bullet("A release record contains scope, versions, results, evidence, owner, and risk decision."),
        bullet("No assessment can run against an unapproved external target."),
        bullet("Teams can explain PASS, FAIL, ERROR, and UNPARSED outcomes consistently."),
        PageBreak(),
    ])

    # 13 use cases
    story.extend(section("13", "Enterprise use cases", "The platform is most valuable where behavior, tools, and application controls must be evaluated together."))
    story.extend([
        card_grid([
            ("Pre-release AI application testing", "Run curated and adaptive suites when prompts, models, tools, data access, or orchestration change. Attach evidence to the release decision.", BLUE),
            ("Agent service onboarding", "Validate the standard health, metadata, and invoke contract; inventory capabilities and establish a baseline before platform admission.", TEAL),
            ("Tool-permission review", "Probe whether an agent claims or attempts capabilities outside business intent; verify dry-run behavior, authorization, and least privilege.", ORANGE),
            ("Hosted service assurance", "Assess an owned endpoint with application-aware prompts and bounded web reconnaissance from a segregated Kali environment.", NAVY_2),
            ("Security regression program", "Turn confirmed weaknesses into repeatable payloads, detector cases, and CI policies; track recurrence across releases.", GREEN),
            ("Executive and audit evidence", "Produce consistent summaries, findings, remediation, event traces, and status semantics for oversight and internal assurance.", CYAN),
        ]),
        p("Example decision flow", "h2"),
        p("A product team adds a calendar tool to a travel agent. The platform inventory records the new capability and scopes the release as high agency. Deterministic tool-abuse and secret-extraction tests run first. A live HTTP assessment reads service metadata and generates capability-specific prompts. A Kali lab assessment validates the exposed service surface. If the agent claims it executed an unauthorized destructive action, the evaluator records a High or Critical finding with evidence. The product team adds explicit authorization and dry-run controls, then reruns the suite and attaches the closing evidence to the release record."),
        callout("Where the simulator adds unique value", "The project links AI-specific behavioral tests to conventional service and web testing. That combined view helps teams distinguish a harmless model oddity from an application design that can turn manipulated output into data exposure or unauthorized action.", BLUE),
        p("Where complementary tools remain necessary", "h2"),
        p("Use software composition analysis, secret scanning, SAST, DAST, cloud posture management, API security, identity governance, model and dataset evaluation, privacy review, and manual penetration testing alongside the simulator. No single AI red-team harness covers the complete enterprise attack surface."),
        PageBreak(),
    ])

    # 14 limitations
    story.extend(section("14", "Limitations and risk disclosures", "Clear limitations improve trust in the evidence and prevent a useful engineering tool from being mistaken for a complete assurance system."))
    story.extend([
        data_table(
            ["Limitation", "Impact", "Recommended treatment"],
            [
                ["Pattern-based detectors", "May miss novel semantic leakage or flag benign wording", "Add model-assisted evaluation, curated gold sets, human review, and calibration"],
                ["Model nondeterminism", "Repeated runs may differ even with the same prompt", "Record parameters and versions; use repeat sampling for critical tests"],
                ["Runtime dependencies", "Ollama, weather providers, SSH, or Kali tools may be unavailable", "Preflight checks, bounded retries, environment health evidence, explicit ERROR / UNPARSED"],
                ["Lab HTTP service", "No built-in production authentication, authorization, or rate limiting", "Place behind trusted gateways or add service identity before non-lab use"],
                ["Partial OWASP coverage", "Several GenAI risk categories are not comprehensively tested", "Maintain a coverage matrix and route gaps to complementary controls"],
                ["No centralized tenancy", "Current local-first architecture lacks multi-user RBAC and isolation", "Introduce a job control plane only after policy and identity design"],
                ["No formal compliance claim", "Reports may be mistaken for certification", "Label evidence scope, version, methodology, and reviewer; map to controls explicitly"],
                ["Authorized-use dependence", "Operator misuse can create legal or operational risk", "Enforce allowlists, signed scope, audit, and organizational rules of engagement"],
            ],
            [42 * mm, 57 * mm, 75 * mm],
        ),
        p("Residual risk", "h2"),
        p("Even a clean assessment cannot guarantee safe behavior under all prompts, conversations, tools, models, data, user roles, or environmental conditions. Residual risk increases with agent autonomy, privilege, data sensitivity, external content ingestion, long-running memory, and the ability to take irreversible actions. Enterprise deployment should pair testing with runtime controls and human accountability."),
        p("Decision guidance", "h2"),
        callout("Use now", "Adopt for internal labs, developer feedback, regression suites, service-contract testing, and evidence generation where targets are owned and the operator understands the status semantics.", GREEN),
        Spacer(1, 3 * mm),
        callout("Harden before scale", "Add enforced authorization, identity, secret management, immutable provenance, centralized artifact protection, rate and cost controls, semantic evaluation, and production-grade orchestration before treating the platform as an enterprise control plane.", ORANGE),
        PageBreak(),
    ])

    # 15 conclusion
    story.extend(section("15", "Conclusion", "The project demonstrates a credible path from AI security experimentation to a governed, evidence-driven assurance capability."))
    story.extend([
        Spacer(1, 8 * mm),
        p("AI agents require a test strategy that crosses the model-application boundary.", "quote"),
        p("The AI Agent Red Team Simulator provides that bridge. It discovers intentionally enrolled targets, exercises common AI failure modes, adapts tests to live services, connects local applications to an isolated Kali lab without LAN exposure, evaluates outcomes with explicit semantics, and writes evidence that engineering and security teams can act on."),
        p("Its most important design strength is not any single payload or scanner. It is the composable assessment loop: scope, discover, recon, probe, evaluate, report, remediate, and retest. This loop can become part of an enterprise AI secure-development lifecycle while remaining transparent about limitations and environment dependencies."),
        p("Recommended next decision", "h2"),
        p("Proceed with a 30-day governed pilot using two or three owned agents representing different risk profiles. Establish target ownership, authorization, a deterministic baseline, live HTTP coverage, evidence retention, and a release decision workflow. Use pilot findings to prioritize identity, policy, semantic evaluation, and CI integration before expanding scope."),
        Spacer(1, 8 * mm),
        metric_strip([
            ("Local-first", "sensitive testing can remain inside the lab", TEAL),
            ("Evidence-driven", "results are structured, traceable, and reviewable", BLUE),
            ("Extensible", "targets and transports share a stable evaluation core", GREEN),
        ]),
        Spacer(1, 14 * mm),
        callout("Final perspective", "The simulator is already a strong engineering platform for authorized AI security validation. With focused governance and production hardening, it can become the technical backbone of a repeatable enterprise AI red-team program.", BLUE),
        PageBreak(),
    ])

    # Appendix
    story.extend(section("A", "Appendix: capability-to-artifact map", "A concise guide to the repository components that substantiate the platform described in this paper."))
    story.extend([
        data_table(
            ["Capability", "Primary artifacts"],
            [
                ["CLI and operator workflow", "ai_red_team_cli.py; scripts/redteam_chat.sh; red_team_assistant.py"],
                ["Explicit target discovery", "scanner/target_loader.py; REDTEAM_TARGET markers under targets/"],
                ["Curated payload execution", "scanner/attack_runner.py; attacks/*/payloads.txt"],
                ["Behavior detection and redaction", "scanner/detectors.py; targets/_guardrails.py"],
                ["Adaptive local red team", "local_red_team/run_local_red_team_scan.py; local_red_team/WORKFLOW.md"],
                ["HTTP service and discovery", "agent_service.py; agent_registry.py; agent_registry.json; agent_lab_server.py"],
                ["Dynamic HTTP assessment", "http_agent_attack.py"],
                ["Kali agent and URL testing", "kali_agent_attack.py; kali_url_attack.py"],
                ["Functional agents", "functional_agents/graphs.py; functional_agents/weather_tools.py; weather and travel-planner targets"],
                ["Observability", "assessment_monitor.py; reports/assessment_timeline.md; reports/assessment_events.jsonl"],
                ["Enterprise reporting", "enterprise_report.py; scanner/report_generator.py"],
                ["Deployment and validation", "render.yaml; scripts/bootstrap_dev.sh; scripts/validate.sh; tests/"],
            ],
            [60 * mm, 114 * mm],
        ),
        p("Representative commands", "h2"),
        data_table(
            ["Objective", "Command"],
            [
                ["Discover targets", "python3 ai_red_team_cli.py targets"],
                ["Run deterministic scan", "python3 ai_red_team_cli.py scan --target tool_agent --attack prompt_disclosure"],
                ["Start one agent service", "python3 ai_red_team_cli.py serve-agent --target weather_insight_agent --port 18101"],
                ["Discover live local agents", "python3 ai_red_team_cli.py agents discover"],
                ["Run natural-language assistant", "./scripts/redteam_chat.sh"],
                ["Check Kali readiness", "python3 ai_red_team_cli.py kali status"],
                ["Run Kali URL assessment", "python3 ai_red_team_cli.py kali attack-url --url https://owned-agent.example"],
                ["Run validation gate", "./scripts/validate.sh"],
            ],
            [56 * mm, 118 * mm],
        ),
        PageBreak(),
    ])

    # References
    story.extend(section("R", "References", "Primary project artifacts and authoritative external guidance used in this white paper."))
    story.extend([
        p("Project sources", "h2"),
        p("[1] AI Agent Red Team Simulator repository README.md, source modules, configuration, tests, and generated report formats reviewed 13 July 2026."),
        p("[2] Current local validation snapshot: 47 unit tests passed; six explicit targets discovered; deterministic tool_agent prompt-disclosure smoke scan 6 PASS / 0 FAIL / 0 ERROR; core compilation succeeded."),
        p("External guidance", "h2"),
        p("[3] National Institute of Standards and Technology, Artificial Intelligence Risk Management Framework (AI RMF 1.0), NIST AI 100-1, 2023. https://doi.org/10.6028/NIST.AI.100-1"),
        p("[4] National Institute of Standards and Technology, Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile, NIST AI 600-1, 2024. https://doi.org/10.6028/NIST.AI.600-1"),
        p("[5] OWASP Gen AI Security Project, OWASP Top 10 for LLM Applications 2025, including Prompt Injection, Sensitive Information Disclosure, Improper Output Handling, Excessive Agency, and System Prompt Leakage. https://genai.owasp.org/llm-top-10/"),
        Spacer(1, 7 * mm),
        callout("Source note", "External sources were checked on 13 July 2026. NIST states that AI RMF 1.0 is under revision; this paper therefore uses it as a current published reference point and does not imply future-version conformity.", CYAN),
        p("Disclaimer", "h2"),
        p("This document is technical project documentation, not legal advice, a penetration-test attestation, or a certification of security. Assessment results apply only to the tested scope, configuration, time, payloads, transports, and detectors."),
    ])

    return story


def build_pdf():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc = EnterpriseDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=21 * mm,
        bottomMargin=19 * mm,
        title="AI Agent Red Team Simulator - Enterprise White Paper",
        author="AI Agent Red Team Simulator Project",
        subject="Enterprise architecture, security methodology, validation, and adoption blueprint",
        keywords="AI security, red team, AI agents, LLM, OWASP, NIST AI RMF, Kali Linux",
    )
    cover_frame = Frame(18 * mm, 18 * mm, PAGE_W - 36 * mm, PAGE_H - 36 * mm, id="cover-frame", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    content_frame = Frame(18 * mm, 19 * mm, PAGE_W - 36 * mm, PAGE_H - 40 * mm, id="content-frame", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    doc.addPageTemplates([
        PageTemplate(id="cover", frames=[cover_frame], onPage=cover_page),
        PageTemplate(id="content", frames=[content_frame], onPage=content_page),
    ])
    doc.multiBuild(build_story())
    return OUTPUT


if __name__ == "__main__":
    output = build_pdf()
    print(output)

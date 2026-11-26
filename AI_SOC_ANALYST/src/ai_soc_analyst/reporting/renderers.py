"""Rendus du rapport : PDF (ReportLab), DOCX (python-docx), HTML (Jinja2), JSON et CSV des IOC."""
from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
from xml.sax.saxutils import escape

from ..core.paths import resource_dir

ACCENT = "#1E90FF"
TEAL = "#00C2B8"
DARK = "#0E1621"
SEV_COLORS = {"Critical": "#D7263D", "High": "#F46036", "Medium": "#F2C14E", "Low": "#2E86AB", "Informational": "#6C757D"}


def _font_paths() -> tuple[str, str]:
    candidates = [
        (resource_dir() / "resources" / "fonts" / "DejaVuSans.ttf", resource_dir() / "resources" / "fonts" / "DejaVuSans-Bold.ttf"),
        (Path("C:/Windows/Fonts/arial.ttf"), Path("C:/Windows/Fonts/arialbd.ttf")),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")),
    ]
    for reg, bold in candidates:
        if reg.exists() and bold.exists():
            return str(reg), str(bold)
    return "", ""


# ------------------------------------------------------------------ PDF

def render_pdf(report: dict, path: Path) -> None:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                    TableStyle)

    reg, bold = _font_paths()
    font, font_b = "Helvetica", "Helvetica-Bold"
    if reg:
        try:
            pdfmetrics.registerFont(TTFont("RptSans", reg))
            pdfmetrics.registerFont(TTFont("RptSans-Bold", bold))
            font, font_b = "RptSans", "RptSans-Bold"
        except Exception:  # noqa: BLE001
            pass
    meta = report["meta"]
    page = landscape(A4) if meta["level"].startswith("Technical") else A4
    st = {
        "h1": ParagraphStyle("h1", fontName=font_b, fontSize=17, leading=21, textColor=colors.HexColor(DARK)),
        "h2": ParagraphStyle("h2", fontName=font_b, fontSize=12.5, leading=16, textColor=colors.HexColor(ACCENT),
                             spaceBefore=10, spaceAfter=5, keepWithNext=1),
        "p": ParagraphStyle("p", fontName=font, fontSize=9.2, leading=12.6, alignment=TA_LEFT, spaceAfter=4),
        "cell": ParagraphStyle("cell", fontName=font, fontSize=7.4, leading=9.2),
        "cellb": ParagraphStyle("cellb", fontName=font_b, fontSize=7.6, leading=9.4, textColor=colors.white),
        "small": ParagraphStyle("small", fontName=font, fontSize=7.8, leading=10, textColor=colors.HexColor("#555555")),
    }
    width = page[0] - 30 * mm

    def P(t: str, s: str = "p") -> Paragraph:  # noqa: N802
        return Paragraph(escape(t or "").replace("\n", "<br/>"), st[s])

    def header_footer(canv, doc):  # noqa: ANN001
        canv.saveState()
        canv.setFillColor(colors.HexColor(DARK))
        canv.rect(0, page[1] - 12 * mm, page[0], 12 * mm, stroke=0, fill=1)
        canv.setFillColor(colors.HexColor(TEAL))
        canv.rect(0, page[1] - 12 * mm - 1.2, page[0], 1.2, stroke=0, fill=1)
        canv.setFillColor(colors.white)
        canv.setFont(font_b, 8.5)
        canv.drawString(15 * mm, page[1] - 7.6 * mm, f"AI SOC ANALYST · {meta['level']}")
        canv.drawRightString(page[0] - 15 * mm, page[1] - 7.6 * mm, f"{meta['incident_id']} · {meta['tlp']}")
        canv.setFillColor(colors.HexColor("#666666"))
        canv.setFont(font, 7.5)
        canv.drawString(15 * mm, 8 * mm, f"Généré par {meta['generator']} le {meta['date']} – document confidentiel")
        canv.drawRightString(page[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
        canv.restoreState()

    story = [Spacer(1, 4 * mm), P(meta["incident_name"], "h1"), Spacer(1, 2 * mm)]
    kv = [["Incident", meta["incident_id"], "Date", meta["date"]], ["Analyste", meta["analyst"], "Statut", meta["status"]],
          ["Sévérité", meta["severity"], "Verdict", meta["verdict"]], ["Confiance", meta["confidence"], "Risque", meta["risk_score"]],
          ["Type", meta["incident_type"], "Sources des preuves", meta["evidence_sources"]]]
    t = Table([[P(c, "cell") for c in r] for r in kv], colWidths=[width * 0.12, width * 0.38, width * 0.14, width * 0.36])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#C9D1D9")),
                           ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EAF3FF")),
                           ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#EAF3FF")),
                           ("BACKGROUND", (1, 2), (1, 2), colors.HexColor(SEV_COLORS.get(meta["severity"], "#FFFFFF"))),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story += [t, Spacer(1, 4 * mm)]
    for sec in report["sections"]:
        story.append(P(sec["title"], "h2"))
        for b in sec["blocks"]:
            if b["type"] == "p":
                story.append(P(b["text"]))
            elif b["type"] == "bullets":
                for it in b["items"]:
                    story.append(P("• " + it))
            elif b["type"] == "kv":
                kt = Table([[P(k, "cell"), P(v, "cell")] for k, v in b["rows"]], colWidths=[width * 0.28, width * 0.72])
                kt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#C9D1D9")),
                                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1F5F9"))]))
                story.append(kt)
            elif b["type"] == "table":
                if not b["rows"]:
                    story.append(P("(aucune donnée)", "small"))
                    continue
                n = len(b["headers"])
                ws = b.get("widths") or [1 / n] * n
                data = [[P(h, "cellb") for h in b["headers"]]] + [[P(c, "cell") for c in r] for r in b["rows"]]
                tb = Table(data, colWidths=[width * w for w in ws], repeatRows=1)
                tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(DARK)),
                                        ("LINEBELOW", (0, 0), (-1, 0), 1.2, colors.HexColor(TEAL)),
                                        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#D0D7DE")),
                                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                        *[("BACKGROUND", (0, i), (-1, i), colors.HexColor("#F6F8FA"))
                                          for i in range(2, len(data), 2)]]))
                story.append(tb)
            story.append(Spacer(1, 2 * mm))
    doc = SimpleDocTemplate(str(path), pagesize=page, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=18 * mm,
                            bottomMargin=14 * mm, title=f"{meta['incident_id']} – {meta['level']}", author=meta["analyst"])
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    _ = (KeepTogether, PageBreak)


# ------------------------------------------------------------------ DOCX

def render_docx(report: dict, path: Path) -> None:
    import docx
    from docx.enum.section import WD_ORIENT
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt, RGBColor

    meta = report["meta"]
    d = docx.Document()
    sec = d.sections[0]
    if meta["level"].startswith("Technical"):
        sec.orientation = WD_ORIENT.LANDSCAPE
        sec.page_width, sec.page_height = sec.page_height, sec.page_width
    d.styles["Normal"].font.name = "Calibri"
    d.styles["Normal"].font.size = Pt(9.5)
    hp = sec.header.paragraphs[0]
    hp.text = f"AI SOC ANALYST · {meta['level']} · {meta['incident_id']} · {meta['tlp']}"
    fp = sec.footer.paragraphs[0]
    fp.text = f"Généré par {meta['generator']} le {meta['date']} – document confidentiel"

    def shade(cell, hexcolor: str) -> None:  # noqa: ANN001
        tcPr = cell._tc.get_or_add_tcPr()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:fill"), hexcolor.lstrip("#"))
        tcPr.append(shd)

    title = d.add_heading(meta["incident_name"], level=0)
    title.runs[0].font.color.rgb = RGBColor(0x0E, 0x16, 0x21)
    t = d.add_table(rows=0, cols=4)
    t.style = "Table Grid"
    for row in (["Incident", meta["incident_id"], "Date", meta["date"]], ["Analyste", meta["analyst"], "Statut", meta["status"]],
                ["Sévérité", meta["severity"], "Verdict", meta["verdict"]], ["Confiance", meta["confidence"], "Risque", meta["risk_score"]],
                ["Type", meta["incident_type"], "Sources", meta["evidence_sources"]]):
        cells = t.add_row().cells
        for i, v in enumerate(row):
            cells[i].text = v
            if i % 2 == 0:
                shade(cells[i], "#EAF3FF")
    for s in report["sections"]:
        h = d.add_heading(s["title"], level=1)
        h.runs[0].font.color.rgb = RGBColor(0x1E, 0x90, 0xFF)
        for b in s["blocks"]:
            if b["type"] == "p":
                d.add_paragraph(b["text"])
            elif b["type"] == "bullets":
                for it in b["items"]:
                    d.add_paragraph(it, style="List Bullet")
            elif b["type"] == "kv":
                kt = d.add_table(rows=0, cols=2)
                kt.style = "Table Grid"
                for k, v in b["rows"]:
                    c = kt.add_row().cells
                    c[0].text, c[1].text = k, v
                    shade(c[0], "#F1F5F9")
            elif b["type"] == "table":
                if not b["rows"]:
                    d.add_paragraph("(aucune donnée)")
                    continue
                tb = d.add_table(rows=1, cols=len(b["headers"]))
                tb.style = "Table Grid"
                for i, hcell in enumerate(tb.rows[0].cells):
                    hcell.text = b["headers"][i]
                    shade(hcell, "#0E1621")
                    for r in hcell.paragraphs[0].runs:
                        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                        r.font.bold = True
                for row in b["rows"]:
                    cells = tb.add_row().cells
                    for i, v in enumerate(row):
                        cells[i].text = v
                        for p in cells[i].paragraphs:
                            for r in p.runs:
                                r.font.size = Pt(7.5)
    d.save(str(path))


# ------------------------------------------------------------------ HTML

def render_html(report: dict, path: Path) -> None:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(loader=FileSystemLoader(str(resource_dir() / "reporting" / "templates")),
                      autoescape=select_autoescape(["html"]))
    html = env.get_template("report.html.j2").render(report=report, meta=report["meta"], sev_colors=SEV_COLORS)
    path.write_text(html, encoding="utf-8")


# ------------------------------------------------------------------ CSV des IOC

def render_ioc_csv(result: dict, path: Path) -> None:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(["indicator", "type", "reputation", "risk", "source", "justification", "validation_status", "occurrences",
                "evidence_ids"])
    for i in result.get("iocs", []):
        w.writerow([i["value"], i["ioc_type"], i["reputation"], i["risk"], i["source"], i["justification"],
                    i["validation_status"], i["occurrences"], " ".join(i["evidence_ids"])])
    path.write_text("\ufeff" + buf.getvalue(), encoding="utf-8")


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

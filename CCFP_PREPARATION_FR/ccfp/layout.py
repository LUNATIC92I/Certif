"""Module de mise en page ReportLab : identité visuelle, gabarits de pages et composants réutilisables."""
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_RIGHT
from reportlab.lib.fonts import addMapping
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as rl_canvas
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageTemplate, Paragraph, Spacer,
                                Table, TableStyle)

from .loader import LETTERS

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"

# ------------------------------------------------------------------ identité visuelle
BLACK = colors.HexColor("#0B0C10")
RED = colors.HexColor("#E3001B")
RED_DARK = colors.HexColor("#A80014")
RED_SOFT = colors.HexColor("#FDECEE")
GREY_BOX = colors.HexColor("#F2F3F5")
GREY_LINE = colors.HexColor("#D9DCE1")
GREY_TEXT = colors.HexColor("#5F6670")
WHITE = colors.white
DIFF_COLOR = {"D": colors.HexColor("#6B7280"), "I": colors.HexColor("#B45309"), "A": RED}

# ------------------------------------------------------------------ polices (UTF-8 complet)
_FONTS = {
    "Sans": "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "Sans-Bold": "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "Sans-Italic": "/usr/share/fonts/truetype/liberation/LiberationSans-Italic.ttf",
    "Sans-BoldItalic": "/usr/share/fonts/truetype/liberation/LiberationSans-BoldItalic.ttf",
    "Mono": "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
}
for _name, _path in _FONTS.items():
    pdfmetrics.registerFont(TTFont(_name, _path))
addMapping("Sans", 0, 0, "Sans")
addMapping("Sans", 1, 0, "Sans-Bold")
addMapping("Sans", 0, 1, "Sans-Italic")
addMapping("Sans", 1, 1, "Sans-BoldItalic")

PAGE_W, PAGE_H = A4
MX = 19 * mm
CW = PAGE_W - 2 * MX
TOP, BOTTOM = 25 * mm, 19 * mm


def _ps(name, **kw):
    base = dict(fontName="Sans", fontSize=9.6, leading=13.8, textColor=BLACK)
    base.update(kw)
    return ParagraphStyle(name, **base)


S = {
    "body": _ps("body", alignment=TA_JUSTIFY, spaceAfter=5),
    "small": _ps("small", fontSize=8.2, leading=11.2, textColor=GREY_TEXT),
    "kicker": _ps("kicker", fontName="Sans-Bold", fontSize=8.6, leading=12, textColor=RED, spaceAfter=3),
    "h1": _ps("h1", fontName="Sans-Bold", fontSize=21, leading=26, spaceAfter=4),
    "h2": _ps("h2", fontName="Sans-Bold", fontSize=13.2, leading=17, spaceBefore=10, spaceAfter=6,
              keepWithNext=1),
    "qhead": _ps("qhead", fontName="Sans-Bold", fontSize=9.6, leading=12.5, textColor=WHITE),
    "qhead_r": _ps("qhead_r", fontName="Sans", fontSize=8.2, leading=12.5, textColor=colors.HexColor("#C9CDD3"),
                   alignment=TA_RIGHT),
    "qtext": _ps("qtext", fontSize=9.8, leading=14, spaceBefore=5, spaceAfter=4, alignment=TA_LEFT),
    "opt": _ps("opt", fontSize=9.3, leading=12.9, leftIndent=17, firstLineIndent=-17, spaceAfter=2.6),
    "ans": _ps("ans", fontName="Sans-Bold", fontSize=9.6, leading=13, textColor=RED_DARK),
    "ans_txt": _ps("ans_txt", fontSize=9, leading=12.6),
    "exp_h": _ps("exp_h", fontName="Sans-Bold", fontSize=8.8, leading=12, textColor=BLACK),
    "exp": _ps("exp", fontSize=8.9, leading=12.6, alignment=TA_JUSTIFY, spaceAfter=3),
    "skill": _ps("skill", fontName="Sans-Italic", fontSize=8.2, leading=11, textColor=GREY_TEXT),
    "cell": _ps("cell", fontSize=8.5, leading=11),
    "cellb": _ps("cellb", fontName="Sans-Bold", fontSize=8.5, leading=11, textColor=WHITE),
    "toc0": _ps("toc0", fontName="Sans-Bold", fontSize=10.2, leading=14.5, spaceBefore=4),
    "toc1": _ps("toc1", fontSize=8.9, leading=12, leftIndent=15, textColor=GREY_TEXT),
}


def esc(t):
    return escape(t)


def P(text, style="body"):
    return Paragraph(text, S[style] if isinstance(style, str) else style)


# ------------------------------------------------------------------ titres et table des matières
class Heading(Paragraph):
    """Paragraphe de titre déclarant une entrée de sommaire et la section courante de l'en-tête."""

    def __init__(self, text, style, level, section=None, toc_text=None):
        super().__init__(text, style)
        self.toc_level, self.section, self.toc_text = level, section, toc_text


def chapter(kicker, title, section=None, toc_text=None):
    out = [Spacer(1, 2)]
    if kicker:
        out.append(P(esc(kicker).upper(), "kicker"))
    out.append(Heading(esc(title), S["h1"], 0, section or title, toc_text))
    bar = Table([[""]], colWidths=[34 * mm], rowHeights=[2.4])
    bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), RED)]))
    bar.hAlign = "LEFT"
    return out + [bar, Spacer(1, 10)]


def h2(text):
    return Heading(esc(text), S["h2"], 1)


class GuideDoc(BaseDocTemplate):
    def __init__(self, path, header_label, cover_painter, **kw):
        super().__init__(str(path), pagesize=A4, leftMargin=MX, rightMargin=MX, topMargin=TOP,
                         bottomMargin=BOTTOM, **kw)
        self.header_label = header_label
        self.section = ""
        self._bm = 0
        body = Frame(MX, BOTTOM, CW, PAGE_H - TOP - BOTTOM, id="body", leftPadding=0, rightPadding=0,
                     topPadding=0, bottomPadding=0)
        self.addPageTemplates([
            PageTemplate("cover", frames=[Frame(0, 0, PAGE_W, PAGE_H, id="cover")], onPage=cover_painter),
            PageTemplate("normal", frames=[body], onPageEnd=self._decorate),
        ])

    def beforeDocument(self):
        self._bm, self.section = 0, ""

    def afterFlowable(self, fl):
        if isinstance(fl, Heading):
            self._bm += 1
            key = f"h{self._bm}"
            label = fl.toc_text or fl.getPlainText()
            self.canv.bookmarkPage(key)
            self.canv.addOutlineEntry(label, key, level=fl.toc_level, closed=fl.toc_level == 0)
            self.notify("TOCEntry", (fl.toc_level, label, self.page, key))
            if fl.section:
                self.section = fl.section

    def _decorate(self, canv, doc):
        canv.saveState()
        canv.setFillColor(BLACK)
        canv.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, stroke=0, fill=1)
        canv.setFillColor(RED)
        canv.rect(0, PAGE_H - 14 * mm - 1.4, PAGE_W, 1.4, stroke=0, fill=1)
        canv.rect(MX, PAGE_H - 9.6 * mm, 2.2 * mm, 2.2 * mm, stroke=0, fill=1)
        canv.setFillColor(WHITE)
        canv.setFont("Sans-Bold", 8.2)
        canv.drawString(MX + 4.2 * mm, PAGE_H - 9.1 * mm, self.header_label)
        canv.setFillColor(colors.HexColor("#B9BEC6"))
        canv.setFont("Sans", 8)
        sec = self.section if len(self.section) <= 64 else self.section[:62] + "…"
        canv.drawRightString(PAGE_W - MX, PAGE_H - 9.1 * mm, sec)
        canv.setStrokeColor(GREY_LINE)
        canv.setLineWidth(0.6)
        canv.line(MX, 12.5 * mm, PAGE_W - MX, 12.5 * mm)
        canv.setFillColor(GREY_TEXT)
        canv.setFont("Sans", 7.4)
        canv.drawString(MX, 8.3 * mm, "Questions originales d'entraînement – document non officiel, non affilié à CrowdStrike")
        canv.restoreState()


class NumberedCanvas(rl_canvas.Canvas):
    """Canvas en deux temps : écrit « Page x / N » une fois le nombre total de pages connu (hors couverture)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for i, state in enumerate(self._saved, start=1):
            self.__dict__.update(state)
            if i > 1:
                self.setFont("Sans-Bold", 8.2)
                self.setFillColor(RED)
                self.drawRightString(PAGE_W - MX, 8.3 * mm, f"Page {i} / {total}")
            super().showPage()
        super().save()


# ------------------------------------------------------------------ couverture
def make_cover(title_lines, subtitle, badge_lines, footer):
    pattern = ASSETS / "cover_pattern.png"

    def paint(canv, doc):
        canv.saveState()
        canv.setFillColor(BLACK)
        canv.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
        if pattern.exists():
            canv.drawImage(str(pattern), 0, 0, PAGE_W, PAGE_H, mask=None)
        # bandes rouges obliques
        canv.setFillColor(RED)
        p = canv.beginPath()
        p.moveTo(0, PAGE_H * 0.36)
        p.lineTo(PAGE_W * 0.42, PAGE_H * 0.36)
        p.lineTo(PAGE_W * 0.40, PAGE_H * 0.355)
        p.lineTo(0, PAGE_H * 0.355)
        p.close()
        canv.drawPath(p, stroke=0, fill=1)
        canv.rect(0, 0, PAGE_W, 5 * mm, stroke=0, fill=1)
        x = 20 * mm
        canv.setFillColor(RED)
        canv.setFont("Sans-Bold", 9.5)
        canv.drawString(x, PAGE_H - 30 * mm, "GUIDE DE PRÉPARATION INDÉPENDANT · CERTIFICATION CCFP")
        canv.setFillColor(colors.HexColor("#8C929B"))
        canv.setFont("Sans", 8.5)
        canv.drawString(x, PAGE_H - 35 * mm, "CrowdStrike Certified Falcon Practitioner")
        y = PAGE_H * 0.36 + 12 * mm + (len(title_lines) - 1) * 13 * mm
        for i, line in enumerate(title_lines):
            canv.setFillColor(WHITE if i else RED)
            canv.setFont("Sans-Bold", 30 if i == 0 else 19)
            canv.drawString(x, y, line)
            y -= 13 * mm if i == 0 else 9.5 * mm
        sub = Paragraph(esc(subtitle), _ps("cov_sub", fontSize=12, leading=16.5,
                                            textColor=colors.HexColor("#D6D9DE")))
        w, h = sub.wrap(PAGE_W - 2 * x, 40 * mm)
        sub.drawOn(canv, x, PAGE_H * 0.36 - 9 * mm - h)
        bx, by = x, 52 * mm
        for big, lab in badge_lines:
            canv.setFillColor(colors.HexColor("#15171D"))
            canv.setStrokeColor(colors.HexColor("#2B2F38"))
            canv.roundRect(bx, by, 40 * mm, 22 * mm, 2 * mm, stroke=1, fill=1)
            canv.setFillColor(RED)
            canv.rect(bx, by + 22 * mm - 1.2, 40 * mm, 1.2, stroke=0, fill=1)
            canv.setFillColor(WHITE)
            canv.setFont("Sans-Bold", 18)
            canv.drawString(bx + 4.5 * mm, by + 11.5 * mm, big)
            canv.setFillColor(colors.HexColor("#A9AFB8"))
            canv.setFont("Sans", 7.8)
            canv.drawString(bx + 4.5 * mm, by + 5 * mm, lab)
            bx += 43.5 * mm
        canv.setFillColor(WHITE)
        canv.setFont("Sans-Bold", 10.5)
        canv.drawString(x, 32 * mm, footer[0])
        canv.setFillColor(colors.HexColor("#8C929B"))
        canv.setFont("Sans", 7.4)
        for k, line in enumerate(footer[1:]):
            canv.drawString(x, 25 * mm - k * 4.2 * mm, line)
        canv.restoreState()

    return paint


# ------------------------------------------------------------------ composants
def table(rows, widths, header=True, zebra=True, valign="MIDDLE", extra=None):
    data = []
    for i, r in enumerate(rows):
        st = "cellb" if header and i == 0 else "cell"
        data.append([c if not isinstance(c, str) else P(c, st) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), valign), ("LINEBELOW", (0, 0), (-1, -1), 0.4, GREY_LINE),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
             ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), BLACK), ("LINEBELOW", (0, 0), (-1, 0), 1.6, RED)]
    if zebra:
        style += [("BACKGROUND", (0, i), (-1, i), GREY_BOX) for i in range(2 if header else 1, len(rows), 2)]
    t.setStyle(TableStyle(style + (extra or [])))
    return t


def box(flowables, bg=GREY_BOX, bar=GREY_TEXT, pad=8):
    t = Table([[flowables]], colWidths=[CW])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), bg), ("LINEBEFORE", (0, 0), (0, -1), 3.2, bar),
                           ("LEFTPADDING", (0, 0), (-1, -1), pad + 2), ("RIGHTPADDING", (0, 0), (-1, -1), pad),
                           ("TOPPADDING", (0, 0), (-1, -1), pad - 1), ("BOTTOMPADDING", (0, 0), (-1, -1), pad - 1)]))
    return t


def question_header(label, q, right):
    col = DIFF_COLOR[q["difficulte_code"]].hexval().replace("0x", "#")
    left = P(f"{label}  <font color='#E3001B'>–</font>  <font size='8.4'>[Niveau : "
             f"<font color='{col if q['difficulte_code'] != 'D' else '#C9CDD3'}'>{q['difficulte']}</font>]</font>",
             "qhead")
    t = Table([[left, P(esc(right), "qhead_r")]], colWidths=[CW * 0.62, CW * 0.38])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), BLACK),
                           ("LINEBEFORE", (0, 0), (0, -1), 3.6, DIFF_COLOR[q["difficulte_code"]]),
                           ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    return t


def question_body(q):
    out = [P(esc(q["question"]), "qtext")]
    for L in LETTERS:
        out.append(P(f"<font name='Sans-Bold' color='#E3001B'>{L}.</font>&nbsp;&nbsp;{esc(q['choix'][L])}", "opt"))
    return out


def answer_box(q):
    return box([P(f"Réponse correcte : {q['reponse']}", "ans"),
                P(esc(q["choix"][q["reponse"]]), "ans_txt")], bg=RED_SOFT, bar=RED, pad=7)


def explanation_box(q):
    return box([P("Explication technique", "exp_h"), P(esc(q["explication"]), "exp"),
                P("Pourquoi les autres propositions sont incorrectes", "exp_h"),
                P(esc(q["pourquoi_pas_les_autres"]), "exp"),
                P("Compétence évaluée : " + esc(q["competence"]), "skill")], bg=GREY_BOX, bar=GREY_TEXT)


def question_block(q, label, right, with_answer=True):
    items = [question_header(label, q, right), *question_body(q)]
    if with_answer:
        items += [Spacer(1, 3), answer_box(q), Spacer(1, 3), explanation_box(q)]
    items.append(Spacer(1, 11))
    return KeepTogether(items)


def correction_block(q, label):
    return KeepTogether([question_header(label, q, f"Corrigé · Module {q['module']}"),
                         P(esc(q["question"]), "qtext"), answer_box(q), Spacer(1, 3), explanation_box(q),
                         Spacer(1, 11)])


def answer_grid(n, per_col=25):
    def col(start, end):
        rows = [["N°", "A", "B", "C", "D"]] + [[f"{i:02d}"] + ["○"] * 4 for i in range(start, end + 1)]
        t = Table(rows, colWidths=[13 * mm] + [14 * mm] * 4, rowHeights=[15] + [14.6] * (end - start + 1))
        t.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), "Sans", 9.2), ("FONT", (0, 0), (-1, 0), "Sans-Bold", 9.2),
            ("FONT", (0, 1), (0, -1), "Sans-Bold", 8.8), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("BACKGROUND", (0, 0), (-1, 0), BLACK), ("TEXTCOLOR", (1, 1), (-1, -1), colors.HexColor("#9AA0A8")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.4, GREY_LINE),
            *[("BACKGROUND", (0, i), (-1, i), GREY_BOX) for i in range(2, end - start + 2, 2)]]))
        return t

    cols = [col(s, min(s + per_col - 1, n)) for s in range(1, n + 1, per_col)]
    outer = Table([cols], colWidths=[CW / len(cols)] * len(cols))
    outer.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return outer

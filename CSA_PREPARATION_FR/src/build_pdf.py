"""Génération du manuel PDF avec ReportLab."""
import math
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.fonts import addMapping
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, NextPageTemplate, PageBreak,
                                PageTemplate, Paragraph, Spacer, Table, TableStyle, CondPageBreak)
from reportlab.platypus.tableofcontents import TableOfContents

from content import (BIBLIO, CSA_DOMAINS, CSA_MAPPING, DISCLAIMER, EXAM_INFO, LETTERS,
                     SCORE_LEVELS, DIFF_LABEL)

# ---------------------------------------------------------------- identité visuelle
INK = colors.HexColor("#101820")
BLUE = colors.HexColor("#007BFF")
TEAL = colors.HexColor("#00D9C5")
AMBER = colors.HexColor("#F5A623")
PAPER = colors.HexColor("#FFFFFF")
SOFT = colors.HexColor("#F3F6F9")
TEAL_SOFT = colors.HexColor("#E6FAF8")
BLUE_SOFT = colors.HexColor("#EAF3FF")
GREY = colors.HexColor("#5B6770")
LINE = colors.HexColor("#D5DDE3")
DIFF_COLOR = {"F": colors.HexColor("#00A896"), "I": BLUE, "A": colors.HexColor("#D9822B")}

FD = "/usr/share/fonts/truetype/"
pdfmetrics.registerFont(TTFont("Body", FD + "dejavu/DejaVuSans.ttf"))
pdfmetrics.registerFont(TTFont("Body-Bold", FD + "dejavu/DejaVuSans-Bold.ttf"))
pdfmetrics.registerFont(TTFont("Body-Italic", FD + "liberation/LiberationSans-Italic.ttf"))
pdfmetrics.registerFont(TTFont("Body-BoldItalic", FD + "liberation/LiberationSans-BoldItalic.ttf"))
pdfmetrics.registerFont(TTFont("Mono", FD + "dejavu/DejaVuSansMono.ttf"))
addMapping("Body", 0, 0, "Body")
addMapping("Body", 1, 0, "Body-Bold")
addMapping("Body", 0, 1, "Body-Italic")
addMapping("Body", 1, 1, "Body-BoldItalic")

PAGE_W, PAGE_H = A4
MARGIN_X = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN_X

S = {
    "body": ParagraphStyle("body", fontName="Body", fontSize=9.6, leading=13.6, textColor=INK,
                           alignment=TA_JUSTIFY, spaceAfter=5),
    "small": ParagraphStyle("small", fontName="Body", fontSize=8.4, leading=11.5, textColor=GREY),
    "h1": ParagraphStyle("h1", fontName="Body-Bold", fontSize=21, leading=26, textColor=INK,
                         spaceAfter=4),
    "kicker": ParagraphStyle("kicker", fontName="Body-Bold", fontSize=9, leading=12,
                             textColor=BLUE, spaceAfter=2),
    "h2": ParagraphStyle("h2", fontName="Body-Bold", fontSize=13.5, leading=18, textColor=INK,
                         spaceBefore=10, spaceAfter=6, keepWithNext=1),
    "qhead": ParagraphStyle("qhead", fontName="Body-Bold", fontSize=9.8, leading=13,
                            textColor=colors.white),
    "qhead_r": ParagraphStyle("qhead_r", fontName="Body-Bold", fontSize=8.6, leading=13,
                              textColor=colors.white, alignment=2),
    "qtext": ParagraphStyle("qtext", fontName="Body", fontSize=9.8, leading=14, textColor=INK,
                            spaceBefore=5, spaceAfter=4, alignment=TA_LEFT),
    "opt": ParagraphStyle("opt", fontName="Body", fontSize=9.4, leading=13, textColor=INK,
                          leftIndent=16, firstLineIndent=-16, spaceAfter=2.5),
    "ans": ParagraphStyle("ans", fontName="Body-Bold", fontSize=9.6, leading=13,
                          textColor=colors.HexColor("#006B60")),
    "exp": ParagraphStyle("exp", fontName="Body", fontSize=9, leading=12.8, textColor=INK,
                          alignment=TA_JUSTIFY, spaceBefore=2),
    "skill": ParagraphStyle("skill", fontName="Body-Italic", fontSize=8.6, leading=11.5,
                            textColor=GREY, spaceBefore=3),
    "cell": ParagraphStyle("cell", fontName="Body", fontSize=8.6, leading=11, textColor=INK),
    "cellb": ParagraphStyle("cellb", fontName="Body-Bold", fontSize=8.6, leading=11,
                            textColor=colors.white),
    "toc0": ParagraphStyle("toc0", fontName="Body-Bold", fontSize=10.5, leading=15,
                           textColor=INK, leftIndent=0, spaceBefore=5),
    "toc1": ParagraphStyle("toc1", fontName="Body", fontSize=9.2, leading=12.5,
                           textColor=GREY, leftIndent=16),
}


def P(text, style="body"):
    return Paragraph(text, S[style] if isinstance(style, str) else style)


def esc(t):
    return escape(t)


# ---------------------------------------------------------------- titres + TOC
class Heading(Paragraph):
    def __init__(self, text, style, level, section=None, toc_text=None):
        super().__init__(text, style)
        self.toc_level = level
        self.toc_text = toc_text
        self.section = section


def chapter(kicker, title, section, toc_text=None):
    """Titre de partie : kicker bleu + titre + filet turquoise."""
    out = [Spacer(1, 4)]
    if kicker:
        out.append(P(esc(kicker).upper(), "kicker"))
    out.append(Heading(esc(title), S["h1"], 0, section or title, toc_text))
    bar = Table([[""]], colWidths=[38 * mm], rowHeights=[2.2])
    bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), TEAL)]))
    bar.hAlign = "LEFT"
    out += [bar, Spacer(1, 10)]
    return out


def h2(text):
    return Heading(esc(text), S["h2"], 1)


class CSADoc(BaseDocTemplate):
    def __init__(self, path, **kw):
        super().__init__(path, pagesize=A4, leftMargin=MARGIN_X, rightMargin=MARGIN_X,
                         topMargin=24 * mm, bottomMargin=20 * mm, **kw)
        self.section = ""
        self._bm = 0
        frame = Frame(MARGIN_X, 20 * mm, CONTENT_W, PAGE_H - 44 * mm, id="body",
                      leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
        self.addPageTemplates([
            PageTemplate("cover", frames=[Frame(0, 0, PAGE_W, PAGE_H, id="c")], onPage=draw_cover),
            PageTemplate("normal", frames=[frame], onPageEnd=draw_frame),
        ])

    def beforeDocument(self):
        self._bm = 0
        self.section = ""

    def afterFlowable(self, fl):
        if isinstance(fl, Heading):
            self._bm += 1
            key = f"bm{self._bm}"
            self.canv.bookmarkPage(key)
            label = fl.toc_text or fl.getPlainText()
            self.canv.addOutlineEntry(label, key, level=fl.toc_level, closed=True)
            self.notify("TOCEntry", (fl.toc_level, label, self.page, key))
            if fl.section:
                self.section = fl.section


def draw_frame(canv, doc):
    canv.saveState()
    # en-tête
    canv.setFillColor(INK)
    canv.rect(0, PAGE_H - 14 * mm, PAGE_W, 14 * mm, stroke=0, fill=1)
    canv.setFillColor(TEAL)
    canv.rect(0, PAGE_H - 14 * mm - 1.2, PAGE_W, 1.2, stroke=0, fill=1)
    canv.setFont("Body-Bold", 8.2)
    canv.setFillColor(colors.white)
    canv.drawString(MARGIN_X, PAGE_H - 8.6 * mm, "CSA")
    canv.setFillColor(TEAL)
    canv.setFont("Body", 8.2)
    canv.drawString(MARGIN_X + 9 * mm, PAGE_H - 8.6 * mm, "Banque de QCM · Édition 2026")
    canv.setFillColor(colors.HexColor("#B8C4CC"))
    sec = doc.section if len(doc.section) <= 62 else doc.section[:60] + "…"
    canv.drawRightString(PAGE_W - MARGIN_X, PAGE_H - 8.6 * mm, sec)
    # pied de page
    canv.setStrokeColor(LINE)
    canv.setLineWidth(0.6)
    canv.line(MARGIN_X, 13 * mm, PAGE_W - MARGIN_X, 13 * mm)
    canv.setFont("Body", 7.6)
    canv.setFillColor(GREY)
    canv.drawString(MARGIN_X, 8.5 * mm,
                    "Questions d'entraînement originales – document non officiel, non affilié à EC-Council")
    canv.setFillColor(BLUE)
    canv.setFont("Body-Bold", 8.4)
    canv.drawRightString(PAGE_W - MARGIN_X, 8.5 * mm, f"Page {doc.page}")
    canv.restoreState()


def _hex(canv, cx, cy, r):
    pts = [(cx + r * math.cos(math.radians(60 * k + 30)), cy + r * math.sin(math.radians(60 * k + 30)))
           for k in range(6)]
    p = canv.beginPath()
    p.moveTo(*pts[0])
    for pt in pts[1:]:
        p.lineTo(*pt)
    p.close()
    canv.drawPath(p, stroke=1, fill=0)


def draw_cover(canv, doc):
    canv.saveState()
    canv.setFillColor(INK)
    canv.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)
    # motif hexagonal discret (réseau / SOC)
    r = 15 * mm
    canv.setLineWidth(0.6)
    for row in range(0, 9):
        for col in range(0, 7):
            cx = PAGE_W - 95 * mm + col * r * math.sqrt(3) + (row % 2) * r * math.sqrt(3) / 2
            cy = PAGE_H - 10 * mm - row * r * 1.5
            dist = math.hypot(cx - PAGE_W, cy - PAGE_H)
            alpha = max(0.0, 0.55 - dist / (240 * mm))
            canv.setStrokeColor(TEAL, alpha=alpha)
            _hex(canv, cx, cy, r * 0.93)
    for (cx, cy) in [(PAGE_W - 52 * mm, PAGE_H - 55 * mm), (PAGE_W - 26 * mm, PAGE_H - 77 * mm),
                     (PAGE_W - 78 * mm, PAGE_H - 33 * mm)]:
        canv.setFillColor(TEAL, alpha=0.9)
        canv.circle(cx, cy, 2.2, stroke=0, fill=1)
    # bandeau latéral
    canv.setFillColor(BLUE)
    canv.rect(0, 0, 6 * mm, PAGE_H, stroke=0, fill=1)
    canv.setFillColor(TEAL)
    canv.rect(6 * mm, 0, 1.4 * mm, PAGE_H, stroke=0, fill=1)

    x = 24 * mm
    canv.setFillColor(TEAL)
    canv.setFont("Body-Bold", 10)
    canv.drawString(x, PAGE_H - 118 * mm, "GUIDE DE PRÉPARATION · SOC ANALYST")
    canv.setFillColor(colors.white)
    canv.setFont("Body-Bold", 31)
    canv.drawString(x, PAGE_H - 136 * mm, "CERTIFIED SOC")
    canv.drawString(x, PAGE_H - 150 * mm, "ANALYST (CSA)")
    canv.setFillColor(TEAL)
    canv.rect(x, PAGE_H - 160 * mm, 42 * mm, 1.6 * mm, stroke=0, fill=1)
    canv.setFillColor(colors.white)
    canv.setFont("Body-Bold", 15)
    canv.drawString(x, PAGE_H - 174 * mm, "BANQUE DE QCM ET SIMULATION D'EXAMEN")
    canv.setFillColor(BLUE)
    canv.setFont("Body-Bold", 13)
    canv.drawString(x, PAGE_H - 185 * mm, "200+ QUESTIONS CORRIGÉES ET EXPLIQUÉES")
    canv.setFillColor(colors.HexColor("#C9D3DA"))
    canv.setFont("Body", 10.5)
    canv.drawString(x, PAGE_H - 197 * mm, "Guide professionnel de préparation à la certification EC-Council")

    # chiffres clés
    stats = [("200", "QCM de la banque"), ("50", "questions d'examen blanc"), ("10", "modules thématiques")]
    bx = x
    for big, lab in stats:
        canv.setStrokeColor(colors.HexColor("#2A3742"))
        canv.setFillColor(colors.HexColor("#17222C"))
        canv.roundRect(bx, PAGE_H - 236 * mm, 46 * mm, 24 * mm, 2.5 * mm, stroke=1, fill=1)
        canv.setFillColor(TEAL)
        canv.setFont("Body-Bold", 19)
        canv.drawString(bx + 5 * mm, PAGE_H - 224 * mm, big)
        canv.setFillColor(colors.HexColor("#C9D3DA"))
        canv.setFont("Body", 8.2)
        canv.drawString(bx + 5 * mm, PAGE_H - 231 * mm, lab)
        bx += 51 * mm

    canv.setFillColor(colors.white)
    canv.setFont("Body-Bold", 11)
    canv.drawString(x, 30 * mm, "ÉDITION FRANÇAISE – 2026")
    canv.setFillColor(colors.HexColor("#8A99A6"))
    canv.setFont("Body", 7.6)
    canv.drawString(x, 22 * mm, "Questions d'entraînement originales alignées sur le programme CSA v2 (312-39).")
    canv.drawString(x, 17.5 * mm, "Document non officiel, non affilié à EC-Council. CSA est une marque d'EC-Council.")
    canv.restoreState()


# ---------------------------------------------------------------- composants
def styled_table(rows, widths, header=True, zebra=True, font_size=None):
    data = []
    for i, r in enumerate(rows):
        st = "cellb" if (header and i == 0) else "cell"
        data.append([c if not isinstance(c, str) else P(c, st) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), INK), ("LINEBELOW", (0, 0), (-1, 0), 1.5, TEAL)]
    if zebra:
        for i in range(1 if header else 0, len(rows)):
            if i % 2 == 0:
                style.append(("BACKGROUND", (0, i), (-1, i), SOFT))
    t.setStyle(TableStyle(style))
    return t


def callout(paras, bg=BLUE_SOFT, bar=BLUE):
    t = Table([[paras]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LINEBEFORE", (0, 0), (0, -1), 3, bar),
        ("LEFTPADDING", (0, 0), (-1, -1), 10), ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t


def q_header(label, q, extra=""):
    dcol = DIFF_COLOR[q["difficulte_code"]]
    left = P(f"{label}  <font color='#00D9C5'>–</font>  <font size='8.6'>[Niveau : "
             f"<font color='{dcol.hexval().replace('0x', '#')}'>{q['difficulte']}</font>]</font>", "qhead")
    right = P(esc(extra), "qhead_r")
    t = Table([[left, right]], colWidths=[CONTENT_W * 0.6, CONTENT_W * 0.4])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), INK),
        ("LINEBEFORE", (0, 0), (0, -1), 3.5, dcol),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def q_body(q):
    out = [P(esc(q["question"]), "qtext")]
    for L in LETTERS:
        out.append(P(f"<font name='Body-Bold' color='#007BFF'>{L}.</font>&nbsp;&nbsp;{esc(q['choix'][L])}", "opt"))
    return out


def answer_box(q, with_answer_text=True):
    paras = [P(f"Réponse correcte : {q['reponse']}", "ans")]
    if with_answer_text:
        paras.append(P(f"<font color='#5B6770'>{esc(q['choix'][q['reponse']])}</font>", "exp"))
    paras += [
        P("<b>Explication technique :</b> " + esc(q["explication"]), "exp"),
        P("Compétence évaluée : " + esc(q["competence"]), "skill"),
    ]
    return callout(paras, bg=TEAL_SOFT, bar=TEAL)


def question_block(q, label, extra, with_answer=True):
    items = [q_header(label, q, extra), *q_body(q)]
    if with_answer:
        items += [Spacer(1, 3), answer_box(q, with_answer_text=False)]
    items.append(Spacer(1, 11))
    return KeepTogether(items)


# ---------------------------------------------------------------- sections
def front_matter(modules, bank, exam):
    st = []
    st += chapter("Avant-propos", "Présentation du guide", "Présentation du guide")
    st.append(callout([P("<b>Avertissement.</b> " + esc(DISCLAIMER), "exp")], bg=colors.HexColor("#FFF6E8"), bar=AMBER))
    st.append(Spacer(1, 8))
    st.append(P(
        "Ce manuel est une banque de questions d'entraînement destinée aux candidats à la certification "
        "<b>Certified SOC Analyst (CSA)</b>. Il couvre les compétences attendues d'un analyste SOC de niveau "
        "1 et 2 : fonctionnement d'un SOC, SIEM et gestion des journaux, surveillance réseau, threat "
        "intelligence, détection et réponse aux incidents, sécurité des terminaux et analyse de malware, "
        "techniques d'attaque, threat hunting, sécurité du cloud et des identités, et excellence opérationnelle."))
    st.append(P(
        "Les scénarios s'appuient sur les outils réellement utilisés dans les SOC internationaux : Microsoft "
        "Sentinel, Microsoft Defender XDR, Splunk, IBM QRadar, Elastic Security, CrowdStrike Falcon, Sysmon, "
        "Wireshark, Zeek et les plateformes de threat intelligence (MISP, OpenCTI, VirusTotal)."))

    st.append(h2("La certification CSA en bref"))
    st.append(styled_table([["Élément", "Information"]] + [[a, b] for a, b in EXAM_INFO],
                           [45 * mm, CONTENT_W - 45 * mm]))
    st.append(Spacer(1, 4))
    st.append(P("Informations issues de la documentation EC-Council et de sources de formation tierces "
                "(voir bibliographie). Vérifiez toujours les conditions en vigueur auprès d'EC-Council avant "
                "l'inscription.", "small"))

    st.append(h2("Domaines du programme CSA v2"))
    st.append(styled_table([["#", "Domaine (intitulé officiel)", "Poids indicatif"]] +
                           [list(d) for d in CSA_DOMAINS], [10 * mm, CONTENT_W - 42 * mm, 32 * mm]))
    st.append(Spacer(1, 4))
    st.append(P("Pondérations rapportées par une source tierce (fiche examen 312-39) et non confirmées "
                "sur un document officiel accessible publiquement : à considérer comme indicatives.", "small"))

    st.append(CondPageBreak(70 * mm))
    st.append(h2("Correspondance entre les modules du guide et le programme"))
    st.append(styled_table([["Module du guide", "Domaine(s) CSA v2 couverts"]] +
                           [[a, b] for a, b in CSA_MAPPING], [72 * mm, CONTENT_W - 72 * mm]))

    st.append(h2("Répartition des questions"))
    rows = [["Module", "Questions", "Fondamental", "Intermédiaire", "Avancé"]]
    tot = {"F": 0, "I": 0, "A": 0}
    for m in modules:
        qs = [q for q in bank if q["module"] == m["numero"]]
        c = {k: sum(1 for q in qs if q["difficulte_code"] == k) for k in "FIA"}
        for k in c:
            tot[k] += c[k]
        rows.append([f"{m['numero']}. {m['titre']}", str(len(qs)), str(c["F"]), str(c["I"]), str(c["A"])])
    n = len(bank)
    rows.append(["<b>Total banque</b>", f"<b>{n}</b>",
                 f"<b>{tot['F']} ({tot['F'] * 100 // n} %)</b>", f"<b>{tot['I']} ({round(tot['I'] * 100 / n)} %)</b>",
                 f"<b>{tot['A']} ({round(tot['A'] * 100 / n)} %)</b>"])
    rows.append(["Simulation d'examen", str(len(exam)),
                 *[str(sum(1 for q in exam if q["difficulte_code"] == k)) for k in "FIA"]])
    st.append(styled_table(rows, [CONTENT_W - 110 * mm, 23 * mm, 30 * mm, 30 * mm, 27 * mm]))
    dist = {L: sum(1 for q in bank + exam if q["reponse"] == L) for L in LETTERS}
    st.append(Spacer(1, 4))
    st.append(P("Répartition des bonnes réponses sur les 250 questions : " +
                " · ".join(f"{L} = {dist[L]}" for L in LETTERS) + ".", "small"))

    st.append(h2("Mode d'emploi"))
    for t in [
        "<b>1. Banque de questions (modules 1 à 10).</b> Chaque module progresse du niveau fondamental au "
        "niveau avancé. Masquez l'encadré turquoise, choisissez votre réponse, puis lisez attentivement "
        "l'explication, y compris lorsque vous avez répondu correctement.",
        "<b>2. Simulation d'examen.</b> 50 questions inédites, en ordre mélangé, à traiter en 60 minutes "
        "sans documentation. Reportez vos réponses dans la grille, puis consultez le corrigé séparé.",
        "<b>3. Analyse des résultats.</b> Calculez votre score sur 100, identifiez les domaines à "
        "retravailler à l'aide de la colonne « Domaine » du corrigé et revenez aux modules concernés.",
        "<b>4. Pratique.</b> Reproduisez les requêtes KQL et SPL dans un environnement de test (Microsoft "
        "Sentinel trial, Splunk Free, Elastic) : l'examen évalue des réflexes opérationnels.",
    ]:
        st.append(P(t))
    st.append(Spacer(1, 4))
    st.append(styled_table([["Niveau", "Signification"],
                            ["Fondamental", "Définitions, concepts, ports, identifiants d'événements et vocabulaire indispensables."],
                            ["Intermédiaire", "Scénarios de triage et d'investigation quotidiens d'un analyste Tier 1/Tier 2."],
                            ["Avancé / Expert", "Raisonnement multi-sources, arbitrages de réponse, techniques d'attaque avancées."]],
                           [35 * mm, CONTENT_W - 35 * mm]))
    st.append(PageBreak())
    return st


def bank_section(modules, bank):
    st = []
    for m in modules:
        title = f"Module {m['numero']} – {m['titre']}"
        st += chapter(f"Banque de questions · Module {m['numero']}", m["titre"], title, toc_text=title)
        qs = [q for q in bank if q["module"] == m["numero"]]
        c = {k: sum(1 for q in qs if q["difficulte_code"] == k) for k in "FIA"}
        st.append(P(f"{len(qs)} questions · {c['F']} fondamentales · {c['I']} intermédiaires · "
                    f"{c['A']} avancées · questions {qs[0]['numero']:03d} à {qs[-1]['numero']:03d}", "small"))
        st.append(Spacer(1, 8))
        for q in qs:
            st.append(question_block(q, f"Question {q['numero']:03d}", f"Module {m['numero']}"))
        st.append(PageBreak())
    return st


def exam_section(exam):
    st = []
    st += chapter("Partie 2", "Simulation d'examen final", "Simulation d'examen")
    st.append(styled_table([["Paramètre", "Consigne"],
                            ["Nombre de questions", "50 questions inédites (absentes de la banque)"],
                            ["Durée indicative", "60 minutes"],
                            ["Documentation", "Aucune – conditions d'examen"],
                            ["Réponse", "Une seule bonne réponse par question"],
                            ["Notation", "2 points par bonne réponse, aucune pénalité – score sur 100"]],
                           [50 * mm, CONTENT_W - 50 * mm]))
    st.append(Spacer(1, 8))
    st.append(callout([P("Les réponses ne figurent pas dans cette partie. Reportez vos choix dans la grille de "
                         "réponses, puis consultez le corrigé détaillé en fin de document.", "exp")]))
    st.append(Spacer(1, 10))
    st.append(h2("Questionnaire"))
    for q in exam:
        st.append(question_block(q, f"Question {q['numero']:02d}", "Examen blanc", with_answer=False))
    st.append(PageBreak())

    # grille de réponses
    st += chapter("Partie 2", "Grille de réponses", "Grille de réponses")
    st.append(P("Entourez ou cochez la lettre choisie pour chaque question. Nom : ______________________   "
                "Date : ____________   Heure de début : ______   Heure de fin : ______"))
    st.append(Spacer(1, 6))

    def grid(start, end):
        rows = [["N°", "A", "B", "C", "D"]]
        for i in range(start, end + 1):
            rows.append([f"{i:02d}"] + ["○"] * 4)
        t = Table(rows, colWidths=[14 * mm] + [15 * mm] * 4, rowHeights=[16] + [15.2] * (end - start + 1))
        t.setStyle(TableStyle([
            ("FONT", (0, 0), (-1, -1), "Body", 9.5),
            ("FONT", (0, 0), (-1, 0), "Body-Bold", 9.5),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 0), (-1, 0), INK),
            ("TEXTCOLOR", (1, 1), (-1, -1), colors.HexColor("#9AA7B1")),
            ("FONT", (0, 1), (0, -1), "Body-Bold", 9),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("GRID", (0, 0), (-1, -1), 0.4, LINE),
            *[("BACKGROUND", (0, i), (-1, i), SOFT) for i in range(2, end - start + 2, 2)],
        ]))
        return t

    outer = Table([[grid(1, 25), grid(26, 50)]], colWidths=[CONTENT_W / 2] * 2)
    outer.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    st.append(outer)
    st.append(Spacer(1, 10))
    st.append(callout([P("<b>Calcul du score :</b> bonnes réponses ______ / 50  ×  2  =  <b>______ / 100</b>", "exp")],
                      bg=TEAL_SOFT, bar=TEAL))
    st.append(PageBreak())

    # notation et interprétation
    st += chapter("Partie 2", "Notation et interprétation du score", "Notation")
    st.append(P("Chaque bonne réponse rapporte 2 points ; une réponse fausse ou absente rapporte 0 point. "
                "Le score maximal est de 100 points."))
    rows = [["Score / 100", "Niveau", "Recommandation"]] + [list(r) for r in SCORE_LEVELS]
    t = styled_table(rows, [26 * mm, 52 * mm, CONTENT_W - 78 * mm], zebra=False)
    level_colors = ["#D8F7F3", "#E3F0FF", "#EEF2F5", "#FFF1DC", "#FDE3E1"]
    t.setStyle(TableStyle([("BACKGROUND", (0, i + 1), (-1, i + 1), colors.HexColor(c))
                           for i, c in enumerate(level_colors)]))
    st.append(t)
    st.append(Spacer(1, 8))
    st.append(callout([P("<b>Important :</b> ces seuils sont strictement indicatifs. Ils ne représentent pas le "
                         "barème officiel de la certification EC-Council, dont le seuil de réussite dépend de la "
                         "forme d'examen. Une simulation de 50 questions ne garantit pas le résultat à l'examen "
                         "réel de 100 questions.", "exp")], bg=colors.HexColor("#FFF6E8"), bar=AMBER))
    st.append(h2("Analyse par domaine"))
    st.append(P("Reportez vos erreurs dans le tableau ci-dessous à l'aide de la colonne « Domaine » du "
                "corrigé : un domaine concentrant plus de 30 % d'erreurs doit être retravaillé en priorité."))
    doms = {}
    for q in exam:
        doms.setdefault(q["competence"].split(" / ")[0], 0)
        doms[q["competence"].split(" / ")[0]] += 1
    rows = [["Domaine", "Questions", "Erreurs", "% d'erreurs"]] + \
           [[d, str(n), "", ""] for d, n in sorted(doms.items(), key=lambda x: -x[1])]
    st.append(styled_table(rows, [CONTENT_W - 84 * mm, 26 * mm, 26 * mm, 32 * mm]))
    st.append(PageBreak())

    # corrigé
    st += chapter("Partie 2", "Corrigé de la simulation d'examen", "Corrigé de la simulation")
    st.append(h2("Tableau récapitulatif des réponses"))
    half = math.ceil(len(exam) / 2)

    def mini(qs):
        rows = [["N°", "Rép.", "Domaine", "Niveau"]]
        for q in qs:
            rows.append([f"{q['numero']:02d}", f"<b>{q['reponse']}</b>", esc(q["competence"].split(" / ")[0]),
                         q["difficulte"].split(" /")[0]])
        return styled_table(rows, [9 * mm, 11 * mm, 36 * mm, 26 * mm])

    outer = Table([[mini(exam[:half]), mini(exam[half:])]], colWidths=[CONTENT_W / 2] * 2)
    outer.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    st.append(outer)
    st.append(PageBreak())
    st.append(h2("Corrigé détaillé"))
    for q in exam:
        st.append(KeepTogether([q_header(f"Question {q['numero']:02d}", q, "Corrigé"),
                                P(esc(q["question"]), "qtext"),
                                answer_box(q), Spacer(1, 10)]))
    st.append(PageBreak())
    return st


def biblio_section():
    st = chapter("Annexe", "Bibliographie et ressources", "Bibliographie")
    st.append(P("Sources consultées pour l'alignement sur le programme CSA et la validation technique des "
                "questions. Les liens étaient valides à la date de rédaction (novembre 2026)."))
    rows = [["Ressource", "Lien"]] + [[esc(t), f"<link href='{u}' color='#007BFF'>{esc(u)}</link>"] for t, u in BIBLIO]
    st.append(styled_table(rows, [72 * mm, CONTENT_W - 72 * mm]))
    st.append(Spacer(1, 10))
    st.append(h2("Méthodologie de validation"))
    for t in [
        "Identification du programme en vigueur (CSA v2, examen 312-39) et de ses huit domaines à partir des "
        "pages EC-Council et de plans de cours de partenaires de formation.",
        "Rédaction originale de chaque question à partir des concepts du programme ; aucune question n'est issue "
        "d'un examen réel.",
        "Vérification des éléments techniques (identifiants d'événements Windows et Sysmon, techniques MITRE "
        "ATT&CK, codes Entra ID, syntaxes KQL/SPL/EQL, phases NIST) auprès de la documentation de référence.",
        "Contrôle qualité automatisé : nombre de questions, quatre choix distincts, unicité de la bonne réponse, "
        "équilibre A/B/C/D, détection des doublons, cohérence entre fichiers PDF, DOCX, Markdown et JSON.",
        "Distinction entre connaissances normatives (définitions, standards) et bonnes pratiques opérationnelles, "
        "qui peuvent varier selon les organisations et les éditeurs.",
    ]:
        st.append(P("•&nbsp;&nbsp;" + esc(t)))
    return st


def build_pdf(path, modules, bank, exam):
    doc = CSADoc(str(path), title="Certified SOC Analyst (CSA) – Banque de QCM et simulation d'examen",
                 author="Guide de préparation CSA – Édition française 2026",
                 subject="200 QCM corrigés + simulation d'examen de 50 questions", lang="fr-FR")
    toc = TableOfContents(levelStyles=[S["toc0"], S["toc1"]], dotsMinLevel=0)
    story = [NextPageTemplate("normal"), PageBreak()]
    story += chapter("", "Sommaire", "Sommaire")[:1]
    story += [P("SOMMAIRE", "kicker"), P("Table des matières", "h1"), Spacer(1, 8), toc, PageBreak()]
    story += front_matter(modules, bank, exam)
    story += bank_section(modules, bank)
    story += exam_section(exam)
    story += biblio_section()
    doc.multiBuild(story)

"""Point d'entrée : génère JSON, Markdown, DOCX et PDF dans CSA_PREPARATION_FR/."""
import json
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Mm

from content import (BIBLIO, CSA_DOMAINS, CSA_MAPPING, DISCLAIMER, EXAM_INFO, LETTERS,
                     SCORE_LEVELS, load_all)
from build_pdf import build_pdf

OUT = Path(__file__).resolve().parent.parent
BASE = "CSA_QCM_2026_FR"
INK, BLUE, TEAL = RGBColor(0x10, 0x18, 0x20), RGBColor(0x00, 0x7B, 0xFF), RGBColor(0x00, 0x9E, 0x8F)


# ------------------------------------------------------------------ JSON
def write_json(modules, bank, exam):
    data = {
        "titre": "Certified SOC Analyst (CSA) – Banque de QCM et simulation d'examen",
        "edition": "Édition française 2026",
        "avertissement": DISCLAIMER,
        "programme_reference": {"examen": "312-39", "version": "CSA v2",
                                "domaines": [{"numero": int(n), "titre": t, "poids_indicatif": w}
                                             for n, t, w in CSA_DOMAINS]},
        "modules": modules,
        "statistiques": {
            "banque": len(bank), "simulation": len(exam),
            "reponses": {L: sum(q["reponse"] == L for q in bank + exam) for L in LETTERS},
        },
        "banque": bank,
        "simulation_examen": {"duree_minutes": 60, "bareme": "2 points par bonne réponse, total sur 100",
                              "questions": exam,
                              "interpretation": [{"score": s, "niveau": n, "recommandation": r}
                                                 for s, n, r in SCORE_LEVELS]},
    }
    (OUT / "questions_csa.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ------------------------------------------------------------------ Markdown
def write_md(modules, bank, exam):
    L = ["# CERTIFIED SOC ANALYST (CSA)", "", "## BANQUE DE QCM ET SIMULATION D'EXAMEN", "",
         "**200+ QUESTIONS CORRIGÉES ET EXPLIQUÉES** — Guide professionnel de préparation à la certification "
         "EC-Council — *ÉDITION FRANÇAISE – 2026*", "", f"> **Avertissement.** {DISCLAIMER}", "",
         "## Table des matières", "", "- [La certification CSA en bref](#la-certification-csa-en-bref)"]
    for m in modules:
        L.append(f"- [Module {m['numero']} – {m['titre']}](#module-{m['numero']}--"
                 f"{m['titre'].lower().replace(' ', '-').replace('&', '')})")
    L += ["- [Simulation d'examen](#simulation-dexamen-final)", "- [Grille de réponses](#grille-de-réponses)",
          "- [Notation](#notation-et-interprétation-du-score)", "- [Corrigé](#corrigé-de-la-simulation-dexamen)",
          "- [Bibliographie](#bibliographie)", "", "## La certification CSA en bref", "",
          "| Élément | Information |", "|---|---|"]
    L += [f"| {a} | {b} |" for a, b in EXAM_INFO]
    L += ["", "| # | Domaine CSA v2 | Poids indicatif |", "|---|---|---|"]
    L += [f"| {n} | {t} | {w} |" for n, t, w in CSA_DOMAINS]
    L += ["", "| Module du guide | Domaine(s) CSA v2 |", "|---|---|"]
    L += [f"| {a} | {b} |" for a, b in CSA_MAPPING]
    L.append("")

    def opts(q):
        return [f"- **{k}.** {q['choix'][k]}" for k in LETTERS]

    for m in modules:
        L += [f"## Module {m['numero']} – {m['titre']}", ""]
        for q in [x for x in bank if x["module"] == m["numero"]]:
            L += [f"### Question {q['numero']:03d} – [Niveau : {q['difficulte']}]", "", q["question"], "",
                  *opts(q), "", f"**Réponse correcte : {q['reponse']}**", "",
                  f"> **Explication technique :** {q['explication']}", ">",
                  f"> *Compétence évaluée : {q['competence']}*", ""]
    L += ["## Simulation d'examen final", "",
          "50 questions inédites · durée indicative : 60 minutes · 2 points par bonne réponse (score sur 100). "
          "Les réponses figurent uniquement dans le corrigé.", ""]
    for q in exam:
        L += [f"### Question {q['numero']:02d} – [Niveau : {q['difficulte']}]", "", q["question"], "", *opts(q), ""]
    L += ["## Grille de réponses", "", "| N° | Réponse | N° | Réponse |", "|---|---|---|---|"]
    for i in range(1, 26):
        L.append(f"| {i:02d} | A ☐ B ☐ C ☐ D ☐ | {i + 25:02d} | A ☐ B ☐ C ☐ D ☐ |")
    L += ["", "**Score = bonnes réponses × 2 = ____ / 100**", "", "## Notation et interprétation du score", "",
          "| Score / 100 | Niveau | Recommandation |", "|---|---|---|"]
    L += [f"| {s} | {n} | {r} |" for s, n, r in SCORE_LEVELS]
    L += ["", "> Ces seuils sont indicatifs et ne représentent pas le barème officiel de certification EC-Council.",
          "", "## Corrigé de la simulation d'examen", "", "| N° | Réponse | Domaine | Niveau |", "|---|---|---|---|"]
    L += [f"| {q['numero']:02d} | **{q['reponse']}** | {q['competence'].split(' / ')[0]} | {q['difficulte']} |"
          for q in exam]
    L.append("")
    for q in exam:
        L += [f"### Corrigé – Question {q['numero']:02d}", "", q["question"], "",
              f"**Réponse correcte : {q['reponse']}** — {q['choix'][q['reponse']]}", "",
              f"> **Explication technique :** {q['explication']}", ">",
              f"> *Compétence évaluée : {q['competence']}*", ""]
    L += ["## Bibliographie", ""] + [f"- {t} — <{u}>" for t, u in BIBLIO] + [""]
    (OUT / f"{BASE}.md").write_text("\n".join(L), encoding="utf-8")


# ------------------------------------------------------------------ DOCX
def _shade(cell, hex_fill):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    tcPr.append(shd)


def _field(paragraph, instr):
    run = paragraph.add_run()
    for tag, text in (("begin", None), (None, instr), ("separate", None), ("end", None)):
        if tag:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), tag)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        run._r.append(el)
    return run


def _run(p, text, bold=False, color=None, size=None, italic=False):
    r = p.add_run(text)
    r.bold, r.italic = bold, italic
    if color:
        r.font.color.rgb = color
    if size:
        r.font.size = Pt(size)
    return r


def _table(doc, rows, header_fill="101820"):
    t = doc.add_table(rows=len(rows), cols=len(rows[0]))
    t.style = "Table Grid"
    for i, row in enumerate(rows):
        for j, val in enumerate(row):
            c = t.cell(i, j)
            c.text = ""
            r = c.paragraphs[0].add_run(str(val))
            r.font.size = Pt(9)
            if i == 0:
                r.bold = True
                r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                _shade(c, header_fill)
    doc.add_paragraph()
    return t


def _answer_box(doc, q, show_choice=False):
    t = doc.add_table(rows=1, cols=1)
    c = t.cell(0, 0)
    _shade(c, "E6FAF8")
    p = c.paragraphs[0]
    _run(p, f"Réponse correcte : {q['reponse']}", bold=True, color=TEAL)
    if show_choice:
        _run(p, f" — {q['choix'][q['reponse']]}", color=INK)
    p2 = c.add_paragraph()
    _run(p2, "Explication technique : ", bold=True)
    _run(p2, q["explication"])
    p3 = c.add_paragraph()
    _run(p3, f"Compétence évaluée : {q['competence']}", italic=True, color=RGBColor(0x5B, 0x67, 0x70), size=9)
    doc.add_paragraph()


def _question(doc, q, label, answer=True):
    h = doc.add_heading(level=3)
    _run(h, f"{label} – [Niveau : {q['difficulte']}]", color=INK)
    doc.add_paragraph(q["question"])
    for k in LETTERS:
        p = doc.add_paragraph()
        p.paragraph_format.left_indent = Mm(6)
        p.paragraph_format.space_after = Pt(2)
        _run(p, f"{k}. ", bold=True, color=BLUE)
        _run(p, q["choix"][k])
    if answer:
        _answer_box(doc, q)


def write_docx(modules, bank, exam):
    doc = Document()
    sec = doc.sections[0]
    sec.page_height, sec.page_width = Mm(297), Mm(210)
    for side in ("left_margin", "right_margin"):
        setattr(sec, side, Mm(20))
    st = doc.styles["Normal"]
    st.font.name, st.font.size = "Calibri", Pt(10.5)
    for lvl, size, col in ((1, 18, INK), (2, 13, BLUE), (3, 11, INK)):
        hs = doc.styles[f"Heading {lvl}"]
        hs.font.size, hs.font.color.rgb, hs.font.name = Pt(size), col, "Calibri"

    # couverture
    for _ in range(6):
        doc.add_paragraph()
    for text, size, col, bold in (("CERTIFIED SOC ANALYST (CSA)", 28, INK, True),
                                  ("BANQUE DE QCM ET SIMULATION D'EXAMEN", 16, BLUE, True),
                                  ("200+ QUESTIONS CORRIGÉES ET EXPLIQUÉES", 13, TEAL, True),
                                  ("Guide professionnel de préparation à la certification EC-Council", 11, INK, False),
                                  ("", 11, INK, False), ("ÉDITION FRANÇAISE – 2026", 12, INK, True)):
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _run(p, text, bold=bold, color=col, size=size)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    _run(p, DISCLAIMER, italic=True, size=8.5, color=RGBColor(0x5B, 0x67, 0x70))
    p.add_run().add_break(WD_BREAK.PAGE)

    # sommaire automatique (champ TOC mis à jour à l'ouverture dans Word : F9)
    doc.add_heading("Table des matières", level=1)
    _field(doc.add_paragraph(), 'TOC \\o "1-2" \\h \\z \\u')
    p = doc.add_paragraph()
    _run(p, "Dans Word : clic droit sur la table → « Mettre à jour les champs » pour afficher la pagination.",
         italic=True, size=8.5)
    p.add_run().add_break(WD_BREAK.PAGE)

    # pied de page avec numéro
    fp = sec.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    _run(fp, "CSA – Banque de QCM 2026 · Questions d'entraînement non officielles · Page ", size=8)
    _field(fp, "PAGE")
    hp = sec.header.paragraphs[0]
    _run(hp, "CERTIFIED SOC ANALYST (CSA) — Banque de QCM · Édition 2026", bold=True, size=8, color=BLUE)

    doc.add_heading("Présentation du guide", level=1)
    doc.add_paragraph(DISCLAIMER)
    doc.add_heading("La certification CSA en bref", level=2)
    _table(doc, [["Élément", "Information"]] + [list(x) for x in EXAM_INFO])
    doc.add_heading("Domaines du programme CSA v2", level=2)
    _table(doc, [["#", "Domaine", "Poids indicatif"]] + [list(x) for x in CSA_DOMAINS])
    doc.add_heading("Correspondance modules / programme", level=2)
    _table(doc, [["Module du guide", "Domaine(s) CSA v2"]] + [list(x) for x in CSA_MAPPING])
    rows = [["Module", "Questions", "Fondamental", "Intermédiaire", "Avancé"]]
    for m in modules:
        qs = [q for q in bank if q["module"] == m["numero"]]
        rows.append([f"{m['numero']}. {m['titre']}", len(qs),
                     *[sum(q["difficulte_code"] == k for q in qs) for k in "FIA"]])
    rows.append(["Total", len(bank), *[sum(q["difficulte_code"] == k for q in bank) for k in "FIA"]])
    doc.add_heading("Répartition des questions", level=2)
    _table(doc, rows)

    for m in modules:
        doc.add_page_break()
        doc.add_heading(f"Module {m['numero']} – {m['titre']}", level=1)
        for q in [x for x in bank if x["module"] == m["numero"]]:
            _question(doc, q, f"Question {q['numero']:03d}")

    doc.add_page_break()
    doc.add_heading("Simulation d'examen final", level=1)
    doc.add_paragraph("50 questions inédites · durée indicative : 60 minutes · aucune documentation · "
                      "2 points par bonne réponse (score sur 100). Les réponses figurent dans le corrigé séparé.")
    for q in exam:
        _question(doc, q, f"Question {q['numero']:02d}", answer=False)
    doc.add_page_break()
    doc.add_heading("Grille de réponses", level=2)
    grid = [["N°", "A", "B", "C", "D", "N°", "A", "B", "C", "D"]]
    for i in range(1, 26):
        grid.append([f"{i:02d}", "○", "○", "○", "○", f"{i + 25:02d}", "○", "○", "○", "○"])
    _table(doc, grid)
    doc.add_paragraph("Score = bonnes réponses × 2 = ______ / 100")
    doc.add_heading("Notation et interprétation du score", level=2)
    _table(doc, [["Score / 100", "Niveau", "Recommandation"]] + [list(x) for x in SCORE_LEVELS])
    doc.add_paragraph("Ces seuils sont indicatifs et ne représentent pas le barème officiel de certification.")
    doc.add_page_break()
    doc.add_heading("Corrigé de la simulation d'examen", level=1)
    _table(doc, [["N°", "Réponse", "Domaine", "Niveau"]] +
           [[f"{q['numero']:02d}", q["reponse"], q["competence"].split(" / ")[0], q["difficulte"]] for q in exam])
    for q in exam:
        h = doc.add_heading(level=3)
        _run(h, f"Corrigé – Question {q['numero']:02d} – [Niveau : {q['difficulte']}]", color=INK)
        doc.add_paragraph(q["question"])
        _answer_box(doc, q, show_choice=True)
    doc.add_page_break()
    doc.add_heading("Bibliographie", level=1)
    for t, u in BIBLIO:
        p = doc.add_paragraph(style="List Bullet")
        _run(p, t + " — ")
        _run(p, u, color=BLUE)
    upd = OxmlElement("w:updateFields")
    upd.set(qn("w:val"), "true")
    doc.settings.element.append(upd)  # Word propose de mettre à jour le sommaire à l'ouverture
    doc.save(OUT / f"{BASE}.docx")


def main():
    modules, bank, exam = load_all()
    write_json(modules, bank, exam)
    write_md(modules, bank, exam)
    write_docx(modules, bank, exam)
    build_pdf(OUT / f"{BASE}.pdf", modules, bank, exam)
    print(f"OK : {len(bank)} questions banque + {len(exam)} questions examen -> {OUT}")


if __name__ == "__main__":
    main()

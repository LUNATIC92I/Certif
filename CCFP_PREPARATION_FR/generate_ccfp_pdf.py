#!/usr/bin/env python3
"""Génère le guide CCFP (PDF principal, PDF de l'examen blanc, base JSON) puis exécute les contrôles qualité.

Usage : python3 generate_ccfp_pdf.py
"""
import json
import math
import sys
from collections import Counter
from pathlib import Path

from reportlab.platypus import CondPageBreak, NextPageTemplate, PageBreak, Spacer
from reportlab.platypus.tableofcontents import TableOfContents

from ccfp import content as C
from ccfp.layout import (CW, GuideDoc, NumberedCanvas, P, S, answer_grid, box, chapter, correction_block, esc,
                         h2, make_cover, question_block, table, GREY_BOX, RED, RED_SOFT, mm, colors)
from ccfp.loader import LETTERS, load
from ccfp.validation import Report, validate_pdf, validate_questions

ROOT = Path(__file__).resolve().parent
OUT_MAIN = ROOT / "CCFP_CrowdStrike_250_QCM_FR.pdf"
OUT_EXAM = ROOT / "CCFP_Examen_Blanc_50_QCM.pdf"
OUT_JSON = ROOT / "CCFP_Questions_Database.json"
OUT_QC = ROOT / "CONTROLE_QUALITE.md"


# ------------------------------------------------------------------ sections communes
def toc_section():
    toc = TableOfContents(levelStyles=[S["toc0"], S["toc1"]], dotsMinLevel=0)
    return [P("SOMMAIRE", "kicker"), P("Table des matières", "h1"), Spacer(1, 8), toc, PageBreak()]


def presentation(modules, bank, exam):
    st = chapter("Introduction", "Présentation de la certification CCFP")
    st.append(box([P("<b>Avertissement.</b> " + esc(C.DISCLAIMER), "exp")], bg=RED_SOFT, bar=RED))
    st.append(Spacer(1, 8))
    st.append(P(
        "La certification <b>CrowdStrike Certified Falcon Practitioner (CCFP)</b> est la certification d'entrée "
        "du programme CrowdStrike University. Elle valide les fondamentaux de la cybersécurité et une maîtrise "
        "opérationnelle de base de la plateforme Falcon, avec une orientation SOC. Elle précède les "
        "certifications de rôle CCFA (administrateur), CCFR (responder) et CCFH (hunter), ainsi que les "
        "spécialisations SIEM, identité et cloud."))
    st.append(h2("L'examen en bref"))
    st.append(table([["Élément", "Information (guide officiel, juillet 2026)"]] + [[a, esc(b)] for a, b in C.EXAM_FACTS],
                    [48 * mm, CW - 48 * mm]))
    st.append(Spacer(1, 4))
    st.append(P("Source : CCFP Certification Exam Guide, CrowdStrike University. Les conditions peuvent évoluer : "
                "vérifiez-les avant l'inscription.", "small"))
    st.append(h2("Les quatre domaines officiels"))
    st.append(table([["#", "Domaine", "Objectifs principaux"]] +
                    [[n, f"<b>{esc(t)}</b>", esc(d)] for n, t, d in C.OFFICIAL_DOMAINS],
                    [9 * mm, 42 * mm, CW - 51 * mm], valign="TOP"))
    st.append(CondPageBreak(80 * mm))
    st.append(h2("Correspondance entre les modules du guide et l'examen"))
    st.append(P("Le guide couvre l'intégralité des objectifs CCFP et va volontairement plus loin sur certains "
                "sujets (chasse, RTR, administration), utiles en production et pour préparer les certifications "
                "CCFH, CCFR et CCFA. Les questions d'approfondissement sont signalées par leur module."))
    rows = [["Module", "Domaines CCFP couverts", "Portée"]]
    for n, dom, scope in C.MODULE_MAPPING:
        rows.append([f"{n}. {esc(modules[n - 1]['titre'])}", esc(dom), esc(scope)])
    st.append(table(rows, [62 * mm, CW - 102 * mm, 40 * mm]))
    st.append(PageBreak())

    st += chapter("Introduction", "Objectifs pédagogiques")
    st.append(P("À l'issue de ce parcours de 300 questions, vous devriez être capable de :"))
    for o in C.OBJECTIVES:
        st.append(P("<font color='#E3001B'>•</font>&nbsp;&nbsp;" + esc(o)))
    st.append(h2("Répartition de la banque de questions"))
    rows = [["Module", "QCM", "Débutant", "Intermédiaire", "Avancé"]]
    for m in modules:
        qs = [q for q in bank if q["module"] == m["numero"]]
        c = Counter(q["difficulte_code"] for q in qs)
        rows.append([f"{m['numero']}. {esc(m['titre'])}", str(len(qs)), str(c["D"]), str(c["I"]), str(c["A"])])
    c = Counter(q["difficulte_code"] for q in bank)
    n = len(bank)
    rows.append(["<b>Total banque</b>", f"<b>{n}</b>", f"<b>{c['D']} ({c['D'] * 100 // n} %)</b>",
                 f"<b>{c['I']} ({c['I'] * 100 // n} %)</b>", f"<b>{c['A']} ({c['A'] * 100 // n} %)</b>"])
    ce = Counter(q["difficulte_code"] for q in exam)
    rows.append(["Examen blanc final", str(len(exam)), str(ce["D"]), str(ce["I"]), str(ce["A"])])
    st.append(table(rows, [CW - 98 * mm, 16 * mm, 24 * mm, 30 * mm, 28 * mm]))
    dist = Counter(q["reponse"] for q in bank + exam)
    st.append(Spacer(1, 3))
    st.append(P("Répartition des bonnes réponses sur les 300 questions : " +
                " · ".join(f"{L} = {dist[L]}" for L in LETTERS) + ".", "small"))
    st.append(PageBreak())

    st += chapter("Introduction", "Conseils pour préparer l'examen")
    for title, text in C.TIPS:
        st.append(P(f"<b>{esc(title)}.</b> {esc(text)}"))
    st.append(h2("Comment utiliser ce guide"))
    st.append(table([["Élément", "Usage"],
                     ["En-tête de question", "Numéro, niveau (Débutant, Intermédiaire, Avancé / Expert) et module."],
                     ["Encadré rouge", "La bonne réponse. Masquez-le pour vous entraîner."],
                     ["Encadré gris", "L'explication technique, la raison pour laquelle les autres propositions "
                                      "sont fausses et la compétence évaluée."],
                     ["Examen blanc", "50 questions inédites, sans réponses dans le questionnaire ; corrigé "
                                      "séparé et grille d'autoévaluation."]],
                    [42 * mm, CW - 42 * mm]))
    st.append(Spacer(1, 6))
    st.append(box([P("<b>Note sur les versions.</b> La plateforme Falcon évolue en continu : noms de modules, menus "
                     "et réglages peuvent différer selon votre cloud, votre version et vos licences. Les questions "
                     "privilégient les concepts stables et signalent les éléments variables.", "exp")]))
    st.append(PageBreak())
    return st


def bank_section(modules, bank):
    st = []
    for m in modules:
        title = f"Module {m['numero']} – {m['titre']}"
        st += chapter(f"Banque de QCM · Module {m['numero']}", m["titre"], title, toc_text=title)
        qs = [q for q in bank if q["module"] == m["numero"]]
        c = Counter(q["difficulte_code"] for q in qs)
        st.append(P(f"{len(qs)} questions · {c['D']} débutant · {c['I']} intermédiaire · {c['A']} avancé · "
                    f"questions {qs[0]['numero']:03d} à {qs[-1]['numero']:03d}", "small"))
        st.append(Spacer(1, 8))
        for q in qs:
            st.append(question_block(q, f"Question {q['numero']:03d}", f"Module {m['numero']}"))
        st.append(PageBreak())
    return st


def answer_key(qs, title_kicker, title, cols=5, width=3):
    st = chapter(title_kicker, title)
    rows_n = math.ceil(len(qs) / cols)
    header = []
    for _ in range(cols):
        header += ["N°", "Rép."]
    rows = [header]
    for r in range(rows_n):
        row = []
        for c in range(cols):
            i = c * rows_n + r
            if i < len(qs):
                row += [f"{qs[i]['numero']:0{width}d}", f"<b>{qs[i]['reponse']}</b>"]
            else:
                row += ["", ""]
        rows.append(row)
    st.append(table(rows, [CW / cols * 0.55, CW / cols * 0.45] * cols))
    st.append(PageBreak())
    return st


def exam_questionnaire(exam, standalone=False):
    st = chapter("Examen blanc", "Examen blanc final – 50 questions", "Examen blanc")
    st.append(table([["Paramètre", "Consigne"],
                     ["Questions", "50 questions inédites, absentes de la banque, couvrant les 11 modules"],
                     ["Durée conseillée", "75 minutes (rythme de l'examen officiel : 60 questions en 90 minutes)"],
                     ["Conditions", "Sans documentation ni console, une seule bonne réponse par question"],
                     ["Notation", "2 points par bonne réponse, aucune pénalité : score sur 100"]],
                    [42 * mm, CW - 42 * mm]))
    st.append(Spacer(1, 6))
    st.append(box([P("Les réponses ne figurent pas dans ce questionnaire. Reportez vos choix dans la grille de "
                     "réponses, puis consultez le corrigé séparé"
                     + (" en fin de document." if standalone else " situé après la grille."), "exp")]))
    st.append(Spacer(1, 8))
    st.append(h2("Questionnaire"))
    for q in exam:
        st.append(question_block(q, f"Question {q['numero']:02d}", "Examen blanc", with_answer=False))
    st.append(PageBreak())
    st += chapter("Examen blanc", "Grille de réponses")
    st.append(P("Cochez une seule case par question. Nom : ___________________   Date : __________   "
                "Début : ______   Fin : ______"))
    st.append(Spacer(1, 6))
    st.append(answer_grid(len(exam)))
    st.append(Spacer(1, 10))
    st.append(box([P("<b>Calcul du score :</b> bonnes réponses ______ / 50 × 2 = <b>______ / 100</b>", "exp")],
                  bg=RED_SOFT, bar=RED))
    st.append(PageBreak())
    return st


def exam_correction(exam, modules):
    st = chapter("Examen blanc", "Corrigé complet de l'examen blanc", "Corrigé de l'examen blanc")
    st.append(h2("Tableau récapitulatif"))
    half = math.ceil(len(exam) / 2)

    def mini(qs):
        rows = [["N°", "Rép.", "Module", "Niveau"]]
        for q in qs:
            rows.append([f"{q['numero']:02d}", f"<b>{q['reponse']}</b>", f"M{q['module']}",
                         q["difficulte"].split(" /")[0]])
        return table(rows, [10 * mm, 11 * mm, 16 * mm, 30 * mm])

    from reportlab.platypus import Table, TableStyle
    outer = Table([[mini(exam[:half]), mini(exam[half:])]], colWidths=[CW / 2] * 2)
    outer.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    st.append(outer)
    st.append(PageBreak())
    st.append(h2("Corrigé détaillé"))
    for q in exam:
        st.append(correction_block(q, f"Question {q['numero']:02d}"))
    st.append(PageBreak())
    return st


def self_assessment(exam, modules):
    st = chapter("Examen blanc", "Grille d'autoévaluation", "Autoévaluation")
    st.append(P("Chaque bonne réponse vaut 2 points ; le score maximal est de 100 points."))
    rows = [["Score / 100", "Niveau", "Recommandation"]] + [[a, f"<b>{esc(b)}</b>", esc(c)] for a, b, c in C.SCORE_LEVELS]
    colors_rows = ["#E9F7EF", "#EEF4FB", "#FFF4E5", "#FDECEE"]
    st.append(table(rows, [24 * mm, 54 * mm, CW - 78 * mm], zebra=False,
                    extra=[("BACKGROUND", (0, i + 1), (-1, i + 1), colors.HexColor(c)) for i, c in enumerate(colors_rows)]))
    st.append(Spacer(1, 6))
    st.append(box([P("<b>Important :</b> cette notation est pédagogique. Elle ne correspond pas au barème officiel "
                     "de CrowdStrike, qui ne publie pas son seuil de réussite dans le guide d'examen consulté.", "exp")],
                  bg=RED_SOFT, bar=RED))
    st.append(h2("Analyse de vos erreurs par module"))
    st.append(P("Reportez le nombre d'erreurs par module à l'aide de la colonne « Module » du corrigé. Un taux "
                "d'erreur supérieur à 30 % indique un module à retravailler dans la banque."))
    cnt = Counter(q["module"] for q in exam)
    rows = [["Module", "Questions", "Erreurs", "% d'erreurs", "À revoir"]]
    for m in modules:
        rows.append([f"{m['numero']}. {esc(m['titre'])}", str(cnt[m["numero"]]), "", "", "☐"])
    st.append(table(rows, [CW - 92 * mm, 22 * mm, 22 * mm, 26 * mm, 22 * mm]))
    st.append(CondPageBreak(60 * mm))
    st.append(h2("Autoévaluation des compétences"))
    st.append(P("Évaluez-vous de 1 (à découvrir) à 4 (maîtrisé) avant et après votre préparation."))
    skills = ["Expliquer l'architecture et les modules Falcon", "Configurer politiques, groupes et exclusions",
              "Trier une détection et lire un arbre de processus", "Écrire une requête CQL de chasse",
              "Exploiter IOC, IOA et intelligence", "Répondre avec RTR et le confinement",
              "Conduire une réponse à incident complète", "Comprendre identité, cloud et exposition",
              "Administrer rôles, politiques et audit", "Utiliser l'IA de façon responsable"]
    st.append(table([["Compétence", "Avant", "Après"]] + [[esc(s), "1 · 2 · 3 · 4", "1 · 2 · 3 · 4"] for s in skills],
                    [CW - 70 * mm, 35 * mm, 35 * mm]))
    st.append(PageBreak())
    return st


def glossary():
    st = chapter("Annexe", "Glossaire CrowdStrike")
    rows = [["Terme", "Définition"]] + [[f"<b>{esc(t)}</b>", esc(d)] for t, d in C.GLOSSARY]
    st.append(table(rows, [48 * mm, CW - 48 * mm], valign="TOP"))
    st.append(PageBreak())
    return st


def bibliography():
    st = chapter("Annexe", "Bibliographie et ressources officielles")
    st.append(P(esc(C.SOURCES_NOTE)))
    st.append(h2("Ressources publiques consultées"))
    rows = [["Ressource", "Lien"]] + [[esc(t), f"<link href='{u}' color='#E3001B'>{esc(u)}</link>"] for t, u in C.BIBLIO_PUBLIC]
    st.append(table(rows, [70 * mm, CW - 70 * mm]))
    st.append(h2("Documentation officielle authentifiée (non consultée)"))
    rows = [["Ressource", "Lien"]] + [[esc(t), f"<link href='{u}' color='#E3001B'>{esc(u)}</link>"] for t, u in C.BIBLIO_AUTH]
    st.append(table(rows, [70 * mm, CW - 70 * mm]))
    return st


# ------------------------------------------------------------------ construction des PDF
def build_main(modules, bank, exam):
    cover = make_cover(["CROWDSTRIKE CCFP", "250 QUESTIONS À CHOIX MULTIPLES", "POUR RÉUSSIR LA CERTIFICATION"],
                       C.SUBTITLE, [("250", "QCM corrigés et expliqués"), ("50", "questions d'examen blanc"),
                                    ("11", "modules thématiques"), ("4", "domaines officiels")],
                       [C.EDITION.upper(), "Questions originales d'entraînement, non officielles. Document non affilié à CrowdStrike.",
                        "CrowdStrike et Falcon sont des marques de CrowdStrike, Inc."])
    doc = GuideDoc(OUT_MAIN, "CCFP · 250 QCM · Guide de préparation", cover,
                   title="CrowdStrike CCFP – 250 questions à choix multiples pour réussir la certification",
                   author="Guide de préparation CCFP – édition française 2026", subject=C.SUBTITLE, lang="fr-FR")
    story = [NextPageTemplate("normal"), PageBreak()]
    story += toc_section()
    story += presentation(modules, bank, exam)
    story += bank_section(modules, bank)
    story += answer_key(bank, "Corrigés", "Corrigé récapitulatif de la banque (250 QCM)")
    story += exam_questionnaire(exam)
    story += exam_correction(exam, modules)
    story += self_assessment(exam, modules)
    story += glossary()
    story += bibliography()
    doc.multiBuild(story, canvasmaker=NumberedCanvas)


def build_exam(modules, exam):
    cover = make_cover(["CROWDSTRIKE CCFP", "EXAMEN BLANC FINAL", "50 QUESTIONS ET CORRIGÉ"],
                       "Simulation d'examen de niveau élevé, couvrant les 11 modules du guide de préparation "
                       "à la certification CrowdStrike Certified Falcon Practitioner.",
                       [("50", "questions inédites"), ("75", "minutes conseillées"), ("100", "points"),
                        ("11", "modules couverts")],
                       [C.EDITION.upper(), "Questions originales d'entraînement, non officielles. Document non affilié à CrowdStrike.",
                        "CrowdStrike et Falcon sont des marques de CrowdStrike, Inc."])
    doc = GuideDoc(OUT_EXAM, "CCFP · Examen blanc · 50 QCM", cover,
                   title="CrowdStrike CCFP – Examen blanc de 50 questions",
                   author="Guide de préparation CCFP – édition française 2026", lang="fr-FR")
    story = [NextPageTemplate("normal"), PageBreak()]
    story += toc_section()
    story += exam_questionnaire(exam, standalone=True)
    story += exam_correction(exam, modules)
    story += self_assessment(exam, modules)
    doc.multiBuild(story, canvasmaker=NumberedCanvas)


def write_json(modules, bank, exam):
    data = {
        "titre": C.TITLE, "sous_titre": C.SUBTITLE, "edition": C.EDITION, "avertissement": C.DISCLAIMER,
        "certification": {"code": "CCFP", "nom": "CrowdStrike Certified Falcon Practitioner",
                          "informations": dict(C.EXAM_FACTS),
                          "domaines_officiels": [{"numero": int(n), "titre": t, "objectifs": d}
                                                 for n, t, d in C.OFFICIAL_DOMAINS]},
        "modules": modules,
        "statistiques": {"banque": len(bank), "examen_blanc": len(exam),
                         "difficulte_banque": dict(Counter(q["difficulte"] for q in bank)),
                         "reponses": dict(Counter(q["reponse"] for q in bank + exam))},
        "questions": bank,
        "examen_blanc": {"duree_conseillee_minutes": 75, "bareme": "2 points par bonne réponse, total sur 100",
                         "interpretation": [{"score": a, "niveau": b, "recommandation": c} for a, b, c in C.SCORE_LEVELS],
                         "questions": exam},
    }
    OUT_JSON.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    modules, bank, exam = load()
    rep = validate_questions(modules, bank, exam, Report())
    if rep.failures:  # on ne génère rien à partir d'une banque invalide
        OUT_QC.write_text(rep.markdown("Contrôle qualité – CCFP"), encoding="utf-8")
        print(rep.markdown("Contrôle qualité – CCFP"))
        sys.exit(1)
    write_json(modules, bank, exam)
    try:
        build_main(modules, bank, exam)
        rep.check("Génération du PDF principal sans erreur", True, OUT_MAIN.name)
    except Exception as exc:  # noqa: BLE001
        rep.check("Génération du PDF principal sans erreur", False, repr(exc))
    try:
        build_exam(modules, exam)
        rep.check("Génération du PDF de l'examen blanc sans erreur", True, OUT_EXAM.name)
    except Exception as exc:  # noqa: BLE001
        rep.check("Génération du PDF de l'examen blanc sans erreur", False, repr(exc))

    main_sections = ["Table des matières", "Présentation de la certification CCFP", "Objectifs pédagogiques",
                     "Conseils pour préparer l'examen", "Corrigé récapitulatif de la banque", "Grille de réponses",
                     "Corrigé complet de l'examen blanc", "Grille d'autoévaluation", "Glossaire CrowdStrike",
                     "Bibliographie et ressources officielles"] + [m["titre"] for m in modules]
    if OUT_MAIN.exists():
        validate_pdf(OUT_MAIN, rep, "PDF principal", range(1, len(bank) + 1), 150, main_sections,
                     ("Questionnaire", "Grille de réponses", "Réponse correcte"))
    if OUT_EXAM.exists():
        validate_pdf(OUT_EXAM, rep, "PDF examen blanc", range(1, len(exam) + 1), 30,
                     ["Grille de réponses", "Corrigé complet de l'examen blanc", "Grille d'autoévaluation"],
                     ("Questionnaire", "Grille de réponses", "Réponse correcte"))
    js = json.loads(OUT_JSON.read_text(encoding="utf-8"))
    rep.check("Base JSON complète et relisible", len(js["questions"]) == len(bank) and
              len(js["examen_blanc"]["questions"]) == len(exam), f"{len(js['questions'])} + {len(js['examen_blanc']['questions'])}")
    md = rep.markdown("Contrôle qualité – Guide CCFP")
    OUT_QC.write_text(md, encoding="utf-8")
    print(md)
    sys.exit(1 if rep.failures else 0)


if __name__ == "__main__":
    main()

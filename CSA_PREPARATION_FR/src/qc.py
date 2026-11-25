"""Contrôle qualité des livrables : écrit CONTROLE_QUALITE.md et échoue si un contrôle bloquant échoue."""
import json
import re
import sys
import unicodedata
from collections import Counter
from difflib import SequenceMatcher
from itertools import combinations
from pathlib import Path

import pypdf
from docx import Document

OUT = Path(__file__).resolve().parent.parent
BASE = "CSA_QCM_2026_FR"
results, blocking = [], []


def check(label, ok, detail="", block=True):
    results.append((label, ok, detail))
    if block and not ok:
        blocking.append(label)


def norm(t):
    t = unicodedata.normalize("NFKD", t.lower())
    return re.sub(r"[^a-z0-9 ]", " ", t)


data = json.loads((OUT / "questions_csa.json").read_text(encoding="utf-8"))
bank, exam = data["banque"], data["simulation_examen"]["questions"]
allq = bank + exam

check("Banque principale ≥ 200 QCM", len(bank) >= 200, f"{len(bank)} questions")
check("Simulation d'examen = 50 questions", len(exam) == 50, f"{len(exam)} questions")
check("10 modules présents", len({q['module'] for q in bank}) == 10,
      ", ".join(f"M{m}={c}" for m, c in sorted(Counter(q['module'] for q in bank).items())))

fields = ["id", "question", "choix", "reponse", "explication", "module", "difficulte", "competence"]
missing = [q.get("id") for q in allq if any(not q.get(f) and q.get(f) != 0 for f in fields)]
check("Champs JSON complets (question, choix, réponse, explication, module, difficulté, compétence)",
      not missing, f"incomplets : {missing}" if missing else "250/250 complets")

bad4 = [q["id"] for q in allq if sorted(q["choix"]) != list("ABCD") or len(set(q["choix"].values())) != 4]
check("Quatre propositions distinctes par question", not bad4, str(bad4) if bad4 else "OK")
badans = [q["id"] for q in allq if q["reponse"] not in "ABCD"]
check("Une bonne réponse valide (A–D) par question", not badans, str(badans) if badans else "OK")

for name, qs in (("banque", bank), ("simulation", exam), ("total", allq)):
    c = Counter(q["reponse"] for q in qs)
    spread = max(c.values()) - min(c.values())
    check(f"Équilibre des réponses A/B/C/D ({name})", spread <= 2,
          " · ".join(f"{k}={c[k]}" for k in "ABCD"))

diff = Counter(q["difficulte_code"] for q in bank)
pct = {k: round(diff[k] * 100 / len(bank), 1) for k in "FIA"}
check("Répartition des difficultés proche de 30/45/25 %",
      abs(pct["F"] - 30) <= 3 and abs(pct["I"] - 45) <= 3 and abs(pct["A"] - 25) <= 3,
      f"Fondamental {pct['F']} % · Intermédiaire {pct['I']} % · Avancé {pct['A']} %")

# doublons : texte identique, puis similarité élevée des énoncés
texts = [norm(q["question"]) for q in allq]
dup_exact = [allq[i]["id"] for i, t in enumerate(texts) if texts.index(t) != i]
check("Aucun doublon exact d'énoncé", not dup_exact, str(dup_exact) if dup_exact else "OK")
pairs = []
for (i, a), (j, b) in combinations(enumerate(texts), 2):
    r = SequenceMatcher(None, a, b, autojunk=False).quick_ratio()
    if r > 0.75:
        r = SequenceMatcher(None, a, b, autojunk=False).ratio()
        if r > 0.75:
            pairs.append((allq[i]["id"], allq[j]["id"], round(r, 2)))
check("Aucune question reformulée artificiellement (similarité d'énoncé > 0,75)", not pairs,
      str(pairs) if pairs else "aucune paire au-dessus du seuil")
exam_in_bank = [q["id"] for q in exam if norm(q["question"]) in set(texts[:len(bank)])]
check("Questions de simulation inédites (absentes de la banque)", not exam_in_bank, "OK" if not exam_in_bank else str(exam_in_bank))

# cohérence explication : pas de renvoi à une lettre (les choix sont mélangés)
letter_refs = [q["id"] for q in allq if re.search(r"\b(réponse|option|proposition|choix) [ABCD]\b", q["explication"])]
check("Explications indépendantes de l'ordre des choix", not letter_refs, str(letter_refs) if letter_refs else "OK")
short = [q["id"] for q in allq if len(q["explication"]) < 150]
check("Explications détaillées (≥ 150 caractères)", not short, str(short) if short else
      f"longueur moyenne {sum(len(q['explication']) for q in allq) // len(allq)} caractères")

longest = sum(1 for q in allq if len(q["choix"][q["reponse"]]) == max(len(v) for v in q["choix"].values()))
shortest = sum(1 for q in allq if len(q["choix"][q["reponse"]]) == min(len(v) for v in q["choix"].values()))
check("Pas d'indice de longueur : bonne réponse la plus longue ≤ 35 %", longest / len(allq) <= 0.35,
      f"{longest}/{len(allq)} ({round(longest * 100 / len(allq))} %) – hasard théorique : 25 %")
check("Pas d'indice de longueur : bonne réponse la plus courte ≤ 35 %", shortest / len(allq) <= 0.35,
      f"{shortest}/{len(allq)} ({round(shortest * 100 / len(allq))} %) – hasard théorique : 25 %")

# PDF
pdf = pypdf.PdfReader(str(OUT / f"{BASE}.pdf"))
pages = [p.extract_text() or "" for p in pdf.pages]
full = "\n".join(pages)
check("Le PDF s'ouvre et contient des pages", len(pages) > 100, f"{len(pages)} pages")
nums = set(int(n) for n in re.findall(r"Question (\d{3}) –", full))
check("PDF : questions 001 à 200 présentes", nums >= set(range(1, 201)), f"{len(nums)} numéros trouvés")
for title in ["SOC Fundamentals", "SIEM and Log Management", "Network Security Monitoring", "Threat Intelligence",
              "Incident Detection and Response", "Endpoint Security and Malware Analysis",
              "Vulnerability Management and Attack Techniques", "Threat Hunting and Detection Engineering",
              "Cloud Security and Identity Monitoring", "SOC Reporting and Operational Excellence",
              "Simulation d'examen final", "Grille de réponses", "Notation et interprétation du score",
              "Corrigé de la simulation d'examen", "Bibliographie et ressources", "Table des matières"]:
    check(f"PDF : section « {title} »", title.lower() in full.lower().replace("\n", " "))
page_nums = [int(m) for p in pages for m in re.findall(r"Page (\d+)\s*$", p.strip())]
check("PDF : numérotation des pages", len(page_nums) >= len(pages) - 1, f"{len(page_nums)} pieds de page numérotés")
quest_pages = [i for i, p in enumerate(pages) if "Questionnaire" in p]
corr_page = next(i for i, p in enumerate(pages) if "Tableau récapitulatif des réponses" in p and "Corrigé" in p)
leak = [i + 1 for i in range(quest_pages[0], corr_page) if "Réponse correcte" in pages[i]] if quest_pages else ["?"]
check("Simulation : aucune réponse affichée avant le corrigé", not leak, str(leak) if leak else "OK")
check("PDF : polices intégrées", all("/FontFile2" in str(f.get_object().get("/FontDescriptor", {}).get_object())
                                       for p in pdf.pages[:3] for f in (p["/Resources"].get("/Font") or {}).values()
                                       if "/FontDescriptor" in f.get_object()), "TrueType DejaVu/Liberation")

# DOCX / MD
doc = Document(str(OUT / f"{BASE}.docx"))
dtext = "\n".join(p.text for p in doc.paragraphs)
check("DOCX : 200 + 50 questions", len(re.findall(r"^Question \d{3} –", dtext, re.M)) == 200 and
      len(re.findall(r"^Question \d{2} –", dtext, re.M)) == 50, "titres de questions comptés")
check("DOCX : 50 corrigés", len(re.findall(r"^Corrigé – Question \d{2}", dtext, re.M)) == 50)
md = (OUT / f"{BASE}.md").read_text(encoding="utf-8")
check("Markdown : 200 + 50 questions + 50 corrigés",
      len(re.findall(r"^### Question \d{3} –", md, re.M)) == 200 and
      len(re.findall(r"^### Question \d{2} –", md, re.M)) == 50 and
      len(re.findall(r"^### Corrigé – Question", md, re.M)) == 50)

# cohérence des réponses entre formats
md_ans = re.findall(r"^### Question (\d{3}) –.*?\*\*Réponse correcte : ([ABCD])\*\*", md, re.M | re.S)
check("Cohérence JSON ↔ Markdown des réponses", all(bank[int(n) - 1]["reponse"] == a for n, a in md_ans) and len(md_ans) == 200)
pdf_ans = re.findall(r"Question (\d{3}) –.*?Réponse correcte : ([ABCD])", full, re.S)
check("Cohérence JSON ↔ PDF des réponses", len(pdf_ans) == 200 and all(bank[int(n) - 1]["reponse"] == a for n, a in pdf_ans),
      f"{len(pdf_ans)} réponses relues dans le PDF")

lines = ["# Rapport de contrôle qualité", "", f"Fichiers vérifiés : `{BASE}.pdf`, `{BASE}.docx`, `{BASE}.md`, "
         "`questions_csa.json`", "", "| Contrôle | Résultat | Détail |", "|---|---|---|"]
for label, ok, detail in results:
    lines.append(f"| {label} | {'✅' if ok else '❌'} | {detail} |")
lines += ["", f"**Bilan : {'tous les contrôles bloquants sont réussis' if not blocking else 'ÉCHECS : ' + ', '.join(blocking)}.**", ""]
(OUT / "CONTROLE_QUALITE.md").write_text("\n".join(lines), encoding="utf-8")
print("\n".join(lines))
sys.exit(1 if blocking else 0)

"""Contrôles qualité automatisés de la banque de QCM et des PDF générés."""
import re
import unicodedata
from collections import Counter
from difflib import SequenceMatcher
from itertools import combinations

from .loader import LETTERS

EXPECTED_BANK = {1: 25, 2: 25, 3: 30, 4: 30, 5: 25, 6: 20, 7: 25, 8: 20, 9: 20, 10: 15, 11: 15}
TARGET_DIFF = {"D": 20, "I": 30, "A": 50}
FRENCH_SAMPLE = "éèêàâçôîûùœ«»’ÉÀ"


class Report:
    def __init__(self):
        self.rows = []

    def check(self, label, ok, detail="", blocking=True):
        self.rows.append((label, bool(ok), detail, blocking))

    @property
    def failures(self):
        return [r for r in self.rows if r[3] and not r[1]]

    def markdown(self, title):
        out = [f"# {title}", "", "| Contrôle | Résultat | Détail |", "|---|---|---|"]
        for label, ok, detail, blocking in self.rows:
            mark = "OK" if ok else ("ÉCHEC" if blocking else "AVERTISSEMENT")
            out.append(f"| {label} | {mark} | {str(detail).replace('|', '/')} |")
        out += ["", "**Bilan : " + ("tous les contrôles bloquants sont réussis.**" if not self.failures
                                    else f"{len(self.failures)} contrôle(s) bloquant(s) en échec.**"), ""]
        return "\n".join(out)


def _norm(t):
    t = unicodedata.normalize("NFKD", t.lower())
    return re.sub(r"[^a-z0-9 ]+", " ", t)


def validate_questions(modules, bank, exam, rep=None):
    rep = rep or Report()
    allq = bank + exam

    rep.check("Banque : au moins 250 QCM", len(bank) >= 250, f"{len(bank)} questions")
    rep.check("Examen blanc : 50 questions", len(exam) == 50, f"{len(exam)} questions")
    per_mod = Counter(q["module"] for q in bank)
    rep.check("Répartition par module conforme (25/25/30/30/25/20/25/20/20/15/15)",
              dict(per_mod) == EXPECTED_BANK, ", ".join(f"M{k}={v}" for k, v in sorted(per_mod.items())))
    rep.check("11 modules présents", len(modules) == 11, f"{len(modules)} modules")
    rep.check("Examen blanc : questions issues des 11 domaines",
              set(q["module"] for q in exam) == set(range(1, 12)),
              ", ".join(f"M{k}={v}" for k, v in sorted(Counter(q['module'] for q in exam).items())))

    bad4 = [q["id"] for q in allq if list(q["choix"]) != list(LETTERS)]
    rep.check("Quatre propositions A, B, C, D par question", not bad4, bad4 or "OK")
    dup_opts = [q["id"] for q in allq if len(set(_norm(v) for v in q["choix"].values())) != 4]
    rep.check("Propositions distinctes au sein de chaque question", not dup_opts, dup_opts or "OK")
    one = [q["id"] for q in allq if q["reponse"] not in LETTERS]
    rep.check("Une seule bonne réponse identifiée par question", not one, one or "OK")

    no_exp = [q["id"] for q in allq if len(q["explication"]) < 120]
    rep.check("Explication technique présente et détaillée (≥ 120 caractères)", not no_exp,
              no_exp or f"moyenne {sum(len(q['explication']) for q in allq) // len(allq)} caractères")
    no_why = [q["id"] for q in allq if len(q["pourquoi_pas_les_autres"]) < 40]
    rep.check("Justification des réponses incorrectes présente", not no_why, no_why or "OK")
    letter_refs = [q["id"] for q in allq
                   if re.search(r"\b(réponse|proposition|option|choix) [ABCD]\b",
                                q["explication"] + " " + q["pourquoi_pas_les_autres"])]
    rep.check("Explications indépendantes de l'ordre des choix", not letter_refs, letter_refs or "OK")

    nums_b = [q["numero"] for q in bank]
    nums_e = [q["numero"] for q in exam]
    rep.check("Numérotation continue de la banque (1 à N)", nums_b == list(range(1, len(bank) + 1)),
              f"{nums_b[0]} à {nums_b[-1]}")
    rep.check("Numérotation continue de l'examen blanc (1 à 50)", nums_e == list(range(1, len(exam) + 1)),
              f"{nums_e[0]} à {nums_e[-1]}")
    rep.check("Identifiants uniques", len({q['id'] for q in allq}) == len(allq))

    for name, qs in (("banque", bank), ("examen blanc", exam)):
        c = Counter(q["reponse"] for q in qs)
        rep.check(f"Équilibre des bonnes réponses A/B/C/D ({name})", max(c.values()) - min(c.values()) <= 2,
                  " · ".join(f"{k}={c[k]}" for k in LETTERS))

    d = Counter(q["difficulte_code"] for q in bank)
    pct = {k: round(d[k] * 100 / len(bank), 1) for k in "DIA"}
    rep.check("Difficulté de la banque proche de 20/30/50 %",
              all(abs(pct[k] - TARGET_DIFF[k]) <= 3 for k in "DIA"),
              f"Débutant {pct['D']} % · Intermédiaire {pct['I']} % · Avancé {pct['A']} %")
    de = Counter(q["difficulte_code"] for q in exam)
    rep.check("Examen blanc de difficulté élevée (≥ 70 % avancé)", de["A"] / len(exam) >= 0.7,
              f"Intermédiaire {de['I']} · Avancé {de['A']}")

    # doublons : énoncés identiques ou très similaires
    texts = [_norm(q["question"]) for q in allq]
    exact = sorted({allq[i]["id"] for i, t in enumerate(texts) if texts.index(t) != i})
    rep.check("Aucun énoncé en double", not exact, exact or "OK")
    pairs = []
    for (i, a), (j, b) in combinations(enumerate(texts), 2):
        if SequenceMatcher(None, a, b).quick_ratio() > 0.8:
            r = SequenceMatcher(None, a, b).ratio()
            if r > 0.8:
                pairs.append(f"{allq[i]['id']}~{allq[j]['id']} ({r:.2f})")
    rep.check("Aucune question artificiellement reformulée (similarité > 0,80)", not pairs, pairs or "aucune paire")

    # indice involontaire : longueur de la bonne réponse
    longest = sum(1 for q in allq if len(q["choix"][q["reponse"]]) == max(map(len, q["choix"].values())))
    shortest = sum(1 for q in allq if len(q["choix"][q["reponse"]]) == min(map(len, q["choix"].values())))
    rep.check("Pas d'indice de longueur : bonne réponse la plus longue ≤ 35 %", longest / len(allq) <= 0.35,
              f"{longest}/{len(allq)} ({round(longest * 100 / len(allq))} %), hasard théorique 25 %")
    rep.check("Pas d'indice de longueur : bonne réponse la plus courte ≤ 35 %", shortest / len(allq) <= 0.35,
              f"{shortest}/{len(allq)} ({round(shortest * 100 / len(allq))} %)")
    return rep


def validate_pdf(path, rep, label, expect_numbers, min_pages, must_contain=(), must_not_contain_before=None):
    import pypdf

    try:
        reader = pypdf.PdfReader(str(path))
        pages = [p.extract_text() or "" for p in reader.pages]
        ok = True
    except Exception as exc:  # noqa: BLE001
        rep.check(f"{label} : ouverture du PDF", False, repr(exc))
        return rep
    full = "\n".join(pages)
    rep.check(f"{label} : PDF lisible", ok, f"{len(pages)} pages")
    rep.check(f"{label} : nombre de pages cohérent (≥ {min_pages})", len(pages) >= min_pages, f"{len(pages)} pages")
    numbered = sum(1 for p in pages[1:] if re.search(r"Page \d+ / \d+", p))
    rep.check(f"{label} : numérotation des pages (hors couverture)", numbered == len(pages) - 1,
              f"{numbered}/{len(pages) - 1} pages numérotées")
    found = {int(n) for n in re.findall(r"Question (\d{2,3})\b", full)}
    missing = sorted(set(expect_numbers) - found)
    rep.check(f"{label} : toutes les questions présentes", not missing, missing[:20] or f"{len(expect_numbers)} questions")
    missing_txt = [t for t in must_contain if t.lower() not in full.lower().replace("\n", " ")]
    rep.check(f"{label} : sections attendues présentes", not missing_txt, missing_txt or f"{len(must_contain)} sections")
    present = [c for c in FRENCH_SAMPLE if c in full]
    bad_glyphs = full.count("�") + full.count("■")
    rep.check(f"{label} : caractères français correctement encodés",
              len(present) >= 12 and bad_glyphs == 0,
              f"{len(present)}/{len(FRENCH_SAMPLE)} caractères témoins trouvés, {bad_glyphs} glyphe(s) invalide(s)")
    fonts_ok = True
    for page in reader.pages[:5]:
        for f in (page.get("/Resources", {}).get("/Font") or {}).values():
            fd = f.get_object().get("/FontDescriptor")
            if fd is not None and "/FontFile2" not in fd.get_object():
                fonts_ok = False
    rep.check(f"{label} : polices TrueType intégrées", fonts_ok)
    if must_not_contain_before:
        start, end, needle = must_not_contain_before
        is_toc = lambda p: p.count(" . . ") >= 3 or "Table des matières" in p  # noqa: E731
        i0 = next((i for i, p in enumerate(pages) if start in p and not is_toc(p)), None)
        i1 = next((i for i, p in enumerate(pages) if end in p and not is_toc(p) and (i0 is None or i > i0)), None)
        leak = [] if i0 is None or i1 is None else [i + 1 for i in range(i0, i1) if needle in pages[i]]
        rep.check(f"{label} : aucune réponse affichée dans le questionnaire de l'examen",
                  i0 is not None and i1 is not None and not leak, leak or "OK")
    return rep

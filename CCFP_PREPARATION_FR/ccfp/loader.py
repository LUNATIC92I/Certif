"""Chargement des fichiers de questions et attribution équilibrée de la position des bonnes réponses.

Format d'une question dans data/*.txt :
    ## <D|I|A>|<compétence>            (banque)
    ## <D|I|A>|<n° de module>|<compétence>   (examen blanc)
    Énoncé (une ou plusieurs lignes)
    + bonne réponse
    - distracteur (x3)
    > explication technique (une ou plusieurs lignes)
    ! pourquoi les autres propositions sont incorrectes
"""
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
LETTERS = "ABCD"
SEED = 2026
DIFF_LABEL = {"D": "Débutant", "I": "Intermédiaire", "A": "Avancé / Expert"}
DIFF_ORDER = {"D": 0, "I": 1, "A": 2}
MODULE_FILES = [f"m{i:02d}.txt" for i in range(1, 12)]


def parse_file(path):
    title, items, cur = None, [], None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if line.startswith("# "):
            title = line[2:].strip()
            continue
        if line.startswith("## "):
            if cur:
                items.append(cur)
            parts = line[3:].split("|")
            cur = {"diff": parts[0].strip(), "domain": int(parts[1]) if len(parts) == 3 else None,
                   "skill": parts[-1].strip(), "q": [], "good": None, "bad": [], "exp": [], "why": [],
                   "src": f"{path.name}"}
            continue
        if cur is None or not line.strip():
            continue
        tag, rest = line[:2], line[2:].strip()
        if tag == "+ ":
            cur["good"] = rest
        elif tag == "- ":
            cur["bad"].append(rest)
        elif tag == "> ":
            cur["exp"].append(rest)
        elif tag == "! ":
            cur["why"].append(rest)
        else:
            cur["q"].append(line.strip())
    if cur:
        items.append(cur)
    for it in items:
        it["q"], it["exp"], it["why"] = " ".join(it["q"]), " ".join(it["exp"]), " ".join(it["why"])
    return title, items


def _positions(n, rng):
    out = []
    while len(out) < n:
        block = list(range(4))
        rng.shuffle(block)
        out.extend(block)
    return out[:n]


def _finalize(raw, rng, prefix, width, module_titles):
    out = []
    for i, (q, p) in enumerate(zip(raw, _positions(len(raw), rng)), start=1):
        bad = q["bad"][:]
        rng.shuffle(bad)
        opts = bad[:p] + [q["good"]] + bad[p:]
        mod = q["module"]
        out.append({
            "id": f"{prefix}{i:0{width}d}",
            "numero": i,
            "module": mod,
            "module_titre": module_titles.get(mod, ""),
            "difficulte": DIFF_LABEL.get(q["diff"], q["diff"]),
            "difficulte_code": q["diff"],
            "question": q["q"],
            "choix": {LETTERS[k]: opts[k] for k in range(len(opts))},
            "reponse": LETTERS[p] if len(opts) == 4 else None,
            "explication": q["exp"],
            "pourquoi_pas_les_autres": q["why"],
            "competence": q["skill"],
            "source": q["src"],
        })
    return out


def load():
    rng = random.Random(SEED)
    modules, bank_raw = [], []
    for idx, fname in enumerate(MODULE_FILES, start=1):
        title, qs = parse_file(DATA / fname)
        qs.sort(key=lambda q: DIFF_ORDER.get(q["diff"], 9))  # progression de difficulté
        name = title.split("–", 1)[1].strip() if "–" in title else title
        modules.append({"numero": idx, "titre": name, "nb_questions": len(qs)})
        for q in qs:
            q["module"] = idx
        bank_raw.extend(qs)
    titles = {m["numero"]: m["titre"] for m in modules}
    _, exam_raw = parse_file(DATA / "exam.txt")
    for q in exam_raw:
        q["module"] = q["domain"]
    random.Random(SEED + 1).shuffle(exam_raw)  # domaines mélangés
    bank = _finalize(bank_raw, rng, "Q", 3, titles)
    exam = _finalize(exam_raw, rng, "E", 2, titles)
    return modules, bank, exam

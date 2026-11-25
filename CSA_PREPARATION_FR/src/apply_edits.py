"""Applique des remplacements de lignes exactes dans les fichiers de questions (chaque ligne doit être unique)."""
from content import DATA

FILES = sorted(DATA.glob("*.txt"))


def apply(pairs):
    texts = {f: f.read_text(encoding="utf-8").split("\n") for f in FILES}
    errors = 0
    for pair in pairs:
        old, new = pair[0], pair[1]
        only = pair[2] if len(pair) > 2 else None
        hits = [(f, i) for f, lines in texts.items() for i, l in enumerate(lines)
                if l == old and (only is None or f.name == only)]
        if len(hits) != 1:
            print(f"!! {len(hits)} occurrence(s) : {old[:80]}")
            errors += 1
            continue
        f, i = hits[0]
        texts[f][i] = new
    if errors:
        raise SystemExit(f"{errors} remplacement(s) en échec – aucun fichier modifié")
    for f, lines in texts.items():
        f.write_text("\n".join(lines), encoding="utf-8")
    print(f"{len(pairs)} remplacements appliqués")

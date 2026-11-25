"""Outil de maintenance : remplace des lignes de propositions identifiées par un préfixe unique.

Utilisé pour corriger l'indice « la bonne réponse est la plus longue » détecté par la validation.
Chaque entrée : (fichier, préfixe de la ligne existante, nouvelle ligne complète).
Le préfixe inclut le marqueur ('- ' ou '+ ') et doit désigner exactement une ligne du fichier.
"""
from .loader import DATA


def apply(entries):
    cache, errors = {}, []
    for fname, prefix, new in entries:
        lines = cache.setdefault(fname, (DATA / fname).read_text(encoding="utf-8").split("\n"))
        hits = [i for i, l in enumerate(lines) if l.startswith(prefix)]
        if len(hits) != 1:
            errors.append(f"{fname}: {len(hits)} correspondance(s) pour « {prefix[:60]} »")
            continue
        if new[:2] != prefix[:2]:
            errors.append(f"{fname}: marqueur incohérent pour « {prefix[:60]} »")
            continue
        lines[hits[0]] = new
    if errors:
        raise SystemExit("\n".join(errors) + "\nAucun fichier modifié.")
    for fname, lines in cache.items():
        (DATA / fname).write_text("\n".join(lines), encoding="utf-8")
    return len(entries)

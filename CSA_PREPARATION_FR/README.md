# CSA_PREPARATION_FR – Banque de QCM Certified SOC Analyst (édition française 2026)

Questions d'entraînement **originales** alignées sur le programme CSA v2 (examen 312-39).
Ce ne sont pas des questions d'examen réelles. Ce document n'est pas affilié à EC-Council.

| Fichier | Contenu |
|---|---|
| `CSA_QCM_2026_FR.pdf` | Manuel complet (124 pages) : couverture, sommaire, 10 modules / 200 QCM corrigés, simulation de 50 questions, grille de réponses, barème sur 100, corrigé détaillé, bibliographie |
| `CSA_QCM_2026_FR.docx` | Même contenu au format Word. À l'ouverture, acceptez la mise à jour des champs pour remplir le sommaire. |
| `CSA_QCM_2026_FR.md` | Même contenu en Markdown |
| `questions_csa.json` | Les 250 questions : énoncé, 4 choix, réponse, explication, module, difficulté, compétence |
| `CONTROLE_QUALITE.md` | Rapport des contrôles qualité automatisés |

## Régénérer les fichiers

```bash
cd src
python3 build.py   # génère JSON, MD, DOCX et PDF (ReportLab)
python3 qc.py      # contrôles qualité → CONTROLE_QUALITE.md
```

Les questions sources se trouvent dans `src/data/m01.txt` à `m10.txt` (banque) et dans `exam.txt` (simulation).
Format d'une question : `## <F|I|A>|<compétence>`, l'énoncé, `+` pour la bonne réponse, `-` pour chaque distracteur, et `>` pour l'explication.
La position de la bonne réponse (A à D) est attribuée de façon équilibrée et reproductible (graine fixe).
Les scripts `rebalance_*.py` sont l'historique de la réécriture des distracteurs. Elle a supprimé l'indice « la bonne réponse est la plus longue ».

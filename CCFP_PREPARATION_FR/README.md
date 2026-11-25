# Guide de préparation CrowdStrike CCFP – Édition française 2026

**CROWDSTRIKE CCFP – 250 questions à choix multiples pour réussir la certification**
*Guide avancé de préparation, d'évaluation et de maîtrise de la plateforme CrowdStrike Falcon.*

> Ce guide est une ressource pédagogique **indépendante**. Les questions sont originales. Ce ne sont ni des questions officielles, ni des questions divulguées de l'examen CCFP. Le document n'est pas affilié à CrowdStrike.

## Livrables

| Fichier | Contenu |
|---|---|
| `CCFP_CrowdStrike_250_QCM_FR.pdf` | Manuel complet (175 pages) : couverture, sommaire, présentation officielle de la CCFP, objectifs, conseils, 11 modules et 250 QCM corrigés, corrigé récapitulatif, examen blanc de 50 questions, grille de réponses, corrigé détaillé, autoévaluation, glossaire, bibliographie |
| `CCFP_Examen_Blanc_50_QCM.pdf` | Examen blanc autonome (35 pages) : questionnaire sans réponses, grille, corrigé séparé, autoévaluation |
| `CCFP_Questions_Database.json` | Les 300 questions : énoncé, 4 choix, réponse, explication, justification des mauvaises réponses, module, difficulté, compétence |
| `generate_ccfp_pdf.py` | Script principal : charge, valide, génère le JSON et les deux PDF, puis contrôle les PDF |
| `CONTROLE_QUALITE.md` | Rapport des contrôles automatisés de la dernière génération |

## Alignement sur l'examen officiel

D'après le *CCFP Certification Exam Guide* (CrowdStrike University, juillet 2026), l'examen comporte **60 questions en 90 minutes**. Il couvre 4 domaines : *Cybersecurity Fundamentals*, *Falcon Platform Overview*, *Core Operational Workflows* et *AI and Automation in Falcon*.

Les 11 modules demandés couvrent ces 4 domaines, y compris Charlotte AI, Falcon AIDR, les phases d'adoption et l'architecture multi-tenant. Ils vont aussi plus loin sur certains sujets : chasse avec CQL, commandes RTR et administration. Ces approfondissements relèvent plutôt des certifications CCFH, CCFR et CCFA. Le tableau de correspondance figure au début du PDF.

## Répartition

- **Banque :** 250 QCM (25/25/30/30/25/20/25/20/20/15/15 par module), répartis en 20 % débutant, 30 % intermédiaire et 50 % avancé.
- **Examen blanc :** 50 questions inédites couvrant les 11 modules (10 intermédiaires, 40 avancées). Notation sur 100, indicative et non officielle.
- **Bonnes réponses :** réparties équitablement entre A, B, C et D. La bonne réponse n'est la proposition la plus longue que dans 7 % des cas, ce qui supprime l'indice de longueur.

## Structure du code

```
generate_ccfp_pdf.py   script principal (génération + contrôles)
ccfp/loader.py         lecture des fichiers de questions, attribution équilibrée des réponses A-D
ccfp/validation.py     contrôles qualité de la banque et des PDF
ccfp/layout.py         mise en page ReportLab (identité visuelle, gabarits, encadrés)
ccfp/content.py        présentation CCFP, objectifs, conseils, glossaire, bibliographie
ccfp/rewrite.py        outil de maintenance des propositions (remplacement par préfixe unique)
data/m01.txt … m11.txt questions de la banque (une par module), data/exam.txt examen blanc
assets/                ressources graphiques (motif de couverture et son générateur)
```

Format d'une question dans `data/*.txt` :

```
## A|Compétence évaluée            (examen : ## A|<n° de module>|Compétence)
Énoncé…
+ bonne réponse
- distracteur ×3
> explication technique
! pourquoi les autres propositions sont incorrectes
```

## Générer et contrôler

```bash
pip install reportlab pypdf pillow
python3 assets/make_assets.py      # facultatif : régénère le motif de couverture
python3 generate_ccfp_pdf.py       # code retour 0 si tous les contrôles bloquants réussissent
```

Les contrôles automatiques vérifient :

- le nombre de questions et la répartition par module et par difficulté ;
- la présence de quatre choix distincts et d'une seule bonne réponse ;
- la présence de l'explication et de la justification des mauvaises réponses ;
- l'absence de doublons et de reformulations, ainsi que la continuité de la numérotation ;
- l'équilibre A/B/C/D et l'absence d'indice de longueur ;
- la génération sans erreur et le nombre de pages ;
- la numérotation des pages, l'encodage des caractères français et l'intégration des polices ;
- l'absence de réponses dans le questionnaire de l'examen blanc.

Le script nécessite les polices DejaVu et Liberation (chemins Linux standard).

## Sources et limites

Sources publiques consultées : guide d'examen CCFP, pages produit CrowdStrike (Charlotte AI, Falcon Guardian AIDR, Next-Gen Identity Security), Tech Hub, CrowdStrike Developer Center (FQL, API RTR) et documentation LogScale (syntaxe CQL). La liste complète figure dans la bibliographie du PDF.

La documentation du portail client Falcon exige une authentification : elle **n'a pas été consultée**. Les noms exacts des réglages, les menus et les fonctionnalités soumises à licence sont donc signalés comme pouvant varier selon la version, le cloud et l'abonnement.

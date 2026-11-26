# AI SOC ANALYST

**Intelligent Security Investigation & Incident Response Platform** — version 1.0.0

Application de bureau Windows 10/11 (PySide6) qui assiste un analyste SOC de bout en bout : import des preuves,
triage, analyse comportementale, extraction d'IOC, arbre des processus, chronologie et corrélation, association MITRE
ATT&CK justifiée, analyse IA bornée par les preuves, threat intelligence, threat hunting, detection engineering, plan de
réponse et rapports SOC.

Principes non négociables, appliqués dans le code et vérifiés par les tests :

| Principe | Mise en œuvre |
|---|---|
| Aucun fichier importé n'est exécuté | copie en quarantaine `<sha256>.quarantine`, lecture seule, sans bit d'exécution ; analyse statique uniquement (PE, YARA, entropie) |
| Aucun événement, IOC, réputation ou preuve inventé | chaque détection référence des preuves `EVT-xxxxx` ; l'IA est validée : toute affirmation sans preuve existante est rejetée et affichée comme telle |
| Pas d'IOC « malveillant » sans preuve | réputation « Non vérifiée » par défaut ; binaires système et actifs internes classés « Info » |
| Pas de technique ATT&CK sur un simple nom de fichier | les techniques proviennent de règles comportementales, avec preuves et détections liées |
| Pas de fuite de données | mode Privacy Protection actif par défaut ; seuls des indicateurs publics (hash, IP publique, domaine/URL non internes) peuvent être envoyés aux services de réputation |
| Aucune action de réponse exécutée | actions uniquement proposées ; décisions (approuvée/rejetée/réalisée manuellement) tracées dans le journal d'audit |
| Hypothèse ≠ fait | statuts Confirmed / Likely / Suspicious / Inconclusive / False Positive ; hypothèses étiquetées « non vérifiées » dans l'UI et les rapports |

## Contenu du dossier

```
AI_SOC_ANALYST/
├── src/ai_soc_analyst/        code source (core, db, ingestion, analysis, mitre, ai, ti, hunting, detection,
│                              response, reporting, services, ui, cli)
├── tests/                     unit/ integration/ e2e/ + data/ (8 scénarios synthétiques, EVTX de référence)
├── packaging/                 spec PyInstaller, script Inno Setup, build_windows.ps1, version_info
├── config/default_settings.json
├── scripts/                   génération des scénarios et de l'icône
├── docs/                      INSTALLATION, USER_GUIDE, API_CONFIGURATION, TECHNICAL, DATABASE_SCHEMA,
│                              TEST_REPORT, FINAL_REPORT
├── requirements.txt / requirements-dev.txt / requirements-lock.txt / pyproject.toml
└── (build) dist/AI_SOC_ANALYST/AI_SOC_ANALYST.exe, dist/installer/AI_SOC_ANALYST_Setup_1.0.0.exe,
    dist/AI_SOC_ANALYST_1.0.0_portable_win64.zip
```

## Démarrage rapide

* **Utilisateur Windows** : installer `AI_SOC_ANALYST_Setup_1.0.0.exe` ou décompresser la version portable, puis lancer
  `AI_SOC_ANALYST.exe` (voir [docs/INSTALLATION.md](docs/INSTALLATION.md)).
* **Développeur** (Python 3.12+/3.13) :

```bash
python -m venv .venv && .venv\Scripts\activate          # Windows  (Linux : source .venv/bin/activate)
pip install -r requirements-dev.txt -c requirements-lock.txt
set PYTHONPATH=src                                        # Linux : export PYTHONPATH=src
python -m ai_soc_analyst                                  # interface graphique
python -m ai_soc_analyst analyze preuves.json --report pdf docx html csv
python -m ai_soc_analyst --selftest                       # autotest de bout en bout
python -m pytest tests                                    # 115 tests
```

* **Build Windows** : `powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1`, ou le workflow GitHub
  Actions `.github/workflows/ai-soc-analyst-windows.yml` (tests, EXE, autotests, portable, installeur, installation
  silencieuse vérifiée, artefacts téléchargeables).

## Documentation

* [Installation](docs/INSTALLATION.md) · [Guide utilisateur](docs/USER_GUIDE.md) · [Configuration des API](docs/API_CONFIGURATION.md)
* [Guide technique](docs/TECHNICAL.md) · [Schéma de base de données](docs/DATABASE_SCHEMA.md)
* [Rapport de tests](docs/TEST_REPORT.md) · [Rapport final](docs/FINAL_REPORT.md)

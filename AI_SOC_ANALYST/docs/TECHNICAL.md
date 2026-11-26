# Guide technique – AI SOC ANALYST 1.0.0

## Architecture

```
ui (PySide6, 12 pages, QThreadPool)      cli (analyze, --selftest)
            │                                   │
            └──────────── services ─────────────┘   InvestigationService (création, import, analyse, reprise,
                              │                      persistance, décisions, audit, tableau de bord)
 ┌──────────┬─────────┬───────┴───────┬──────────┬───────────┬────────────┬───────────┐
 ingestion  analysis  mitre           ai         ti          hunting /    reporting   response
 (intake,   (règles,  (STIX→index,    (local,    (6 services detection   (PDF, DOCX, (recommandations
 parseurs,  IOC,      révocations)    OpenAI,    + cache +   (KQL, SPL,  HTML, JSON, proposées)
 sécurité)  arbres,                   Claude,    privacy)    Sigma,      CSV)
            chrono,                   Azure,                 Elastic)
            corrélation)              Ollama)
                              │
                core (chemins, paramètres Pydantic, secrets chiffrés, journalisation masquée, sécurité) + db (SQLAlchemy/SQLite)
```

| Module | Rôle |
|---|---|
| `core/paths.py` | dossiers de données (`%LOCALAPPDATA%\AI_SOC_ANALYST`, `.\data` en portable, `AI_SOC_HOME`), ressources PyInstaller |
| `core/settings.py` | paramètres validés (Pydantic) ; écriture atomique ; fichier invalide mis de côté |
| `core/secrets.py` | magasin de secrets Fernet ; clé maître protégée par DPAPI (Windows) ou fichier 0600 |
| `core/logging_setup.py` | journal rotatif ; masquage clés API, en-têtes Authorization, jetons `sk-`, e-mails |
| `core/security.py` | PBKDF2-SHA256 (390 000 itérations), noms de fichiers sûrs, détection de chemins dangereux |
| `ingestion/validation.py` | détection par signature (EVTX, PDF, PE, OLE/MSG, ZIP/DOCX/XLSX, texte), contrôles ZIP |
| `ingestion/parsers/*` | JSON/NDJSON (conteneurs Defender, Sentinel, Elastic `_source`…), CSV, XML Windows Event, EVTX, Syslog 3164/5424, CEF, LEEF, clé=valeur, auth.log, EML, MSG, PDF, DOCX, XLSX |
| `ingestion/normalizer.py` | modèle `NormalizedEvent` commun (≈60 champs), alias multi-produits, horodatage UTC |
| `ingestion/source_detect.py` | identification de la source (Defender XDR, Sentinel, Sysmon, Windows, Splunk, Elastic, CrowdStrike, pare-feu, Linux…) |
| `ingestion/static_analysis.py` | entropie, PE (sections, imports, signature présente), YARA, chaînes ; `executed: False` |
| `analysis/detectors.py` | 22 familles de règles, 47 identifiants (R-PS, R-OFF, R-LOL, R-EXE, R-DLL, R-PER, R-CRD, R-RAN, R-AUTH, R-LAT, R-DIS, R-NET, R-DNS, R-USB, R-DEF, R-ACC, R-PRV, R-INJ, R-PUA, R-STA, R-LNX, R-MAIL, R-ALR) |
| `analysis/engine.py` | identifiants de preuves, passe faux positif, corroboration, verdict, sévérité, score, classification, limites, cause, impact |
| `analysis/ioc.py` | extraction (refang), classification IP (RFC 1918/5737/…), filtrage domaines, risque justifié |
| `analysis/process_tree.py`, `timeline.py` | arbres (parents déduits marqués), chronologie, corrélation union-find (pid/ppid, hash, IP, DNS, authentification, fenêtre 60 min) |
| `mitre/*` | index ATT&CK Enterprise v20.1 embarqué (706 techniques), mise à jour en ligne ou par bundle, résolution des révocations |
| `ai/engine.py` | paquet de preuves, appels fournisseurs, validation stricte de la sortie, moteur local déterministe |
| `ti/engine.py` | 6 services, filtrage des données partageables, quotas, cache, historique |
| `hunting/library.py` | 13 hypothèses complètes, Sigma 2 (dont règles de corrélation) |
| `detection/generator.py` | Sentinel YAML, Defender KQL, Splunk savedsearches.conf, Sigma, Elastic JSON |
| `response/recommender.py` | 11 types d'action, fiches objectif/justification/risque/impact/prérequis/procédure |
| `reporting/*` | modèle de rapport (6 ou 19 sections), rendus ReportLab, python-docx, Jinja2 |

## Logique de verdict

1. Chaque règle produit des détections avec statut, confiance, preuves et techniques ATT&CK.
2. **Passe faux positif** : contexte légitime (agents SCCM/Intune, chemins de gestion de parc, alerte qualifiée
   bénigne) ⇒ statut False Positive ou conservation motivée si d'autres signaux non bénins existent.
3. **Corroboration** : combinaisons fortes (ex. suppression des clichés + chiffrement massif ; DLL side-loading +
   réseau ou persistance) ⇒ Confirmed ; chaînes multi-détections corrélées ⇒ élévation.
4. Verdict global, sévérité (élevée d'un cran si actif critique déclaré ou nommé comme tel), score de risque 0-100.
5. **Limites** : sources manquantes (réseau, authentification, horodatage, réputation non vérifiée…) listées
   explicitement plutôt que comblées.

## Sécurité

| Menace | Contre-mesure |
|---|---|
| Exécution d'un fichier piégé | aucune exécution ; quarantaine en lecture seule, extension `.quarantine` ; aucune ouverture par application associée |
| ZIP bomb / traversée / archives chiffrées | nombre d'entrées, ratio, taille totale, taille par membre, profondeur, chemins absolus/`..`/UNC refusés ; extraction en mémoire uniquement |
| Fichiers énormes | limites configurables (taille, événements par fichier) |
| Injection de commandes | aucun appel shell ; aucune donnée importée n'est passée à un interpréteur |
| XML malveillant | parseur sans résolution d'entités externes ; EVTX via python-evtx |
| Fuite de secrets | Fernet + DPAPI ; masquage dans les journaux ; jamais dans la base ni dans settings.json |
| Fuite de données d'entreprise | Privacy Protection par défaut ; filtrage des indicateurs internes ; confirmation avant envoi à une IA distante |
| Hallucination de l'IA | validation des références de preuves et des techniques ; affirmations rejetées visibles |
| Accès local | mot de passe optionnel (PBKDF2), 5 tentatives |
| Perte de données | WAL, sauvegarde à la fermeture, reprise des investigations interrompues |
| Plantage | toutes les tâches longues en threads avec erreurs remontées en messages clairs ; `sys.excepthook` global |

## Build

* `packaging/AI_SOC_ANALYST.spec` : PyInstaller onedir, deux exécutables (graphique sans console, console pour la
  CLI/autotest), ressources (index ATT&CK, gabarits, polices, YARA, icône) et données des bibliothèques (python-docx
  collecté aussi en `.py` car il résout ses gabarits par chemin relatif).
* `packaging/AI_SOC_ANALYST.iss` : Inno Setup 6, x64, installation utilisateur ou machine, FR/EN.
* `.github/workflows/ai-soc-analyst-windows.yml` : tests → PyInstaller → autotests (console, graphique) → 8 scénarios
  avec l'exécutable gelé → portable → installeur → installation silencieuse + autotest + désinstallation → SHA256 →
  artefacts.

## Étendre

* **Nouvelle règle** : fonction `r_xxx(ctx) -> list[Finding]` dans `analysis/detectors.py`, ajoutée à `RULES` ; ajouter
  un scénario synthétique (`scripts/generate_scenarios.py`) avec `expected.json` ; `pytest`.
* **Nouveau format** : parseur dans `ingestion/parsers`, branche dans `IntakeService._process`, signature dans
  `validation.detect_format`.
* **Nouveau fournisseur TI** : méthode `_q_<nom>` + entrées `SUPPORTED`, `MIN_INTERVAL`, `SECRET_NAMES`.
* **Connecteurs de réponse** (EDR, pare-feu, AD) : non implémentés en 1.0.0 ; prévoir une interface qui n'exécute
  une action qu'après approbation explicite tracée (`response_actions.status = Approuvée`).

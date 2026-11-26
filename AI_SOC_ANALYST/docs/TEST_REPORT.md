# Rapport de tests – AI SOC ANALYST 1.0.0

Toutes les valeurs ci-dessous proviennent d'exécutions réelles (26/11/2026). Aucun test n'utilise de vrai malware :
les scénarios sont synthétiques (adresses de documentation RFC 5737, hash fictifs, contenus inertes) ; les deux
fichiers EVTX de référence proviennent du projet python-evtx (Apache-2.0, voir `tests/data/evtx/NOTICE.md`).

## 1. Environnements

| Environnement | Détails | Résultat |
|---|---|---|
| Linux (développement) | Ubuntu 24.04, Python 3.13.18, Qt offscreen | **117 / 117 tests réussis** |
| Windows (GitHub Actions) | Windows Server 2022 (10.0.20348), Python 3.13.17, run `45812806432`, commit `121f404` | **117 / 117 tests réussis** + validation de l'EXE, du portable et de l'installeur |

## 2. Suites pytest (117 tests)

| Fichier | Tests | Couverture |
|---|---|---|
| `unit/test_ingestion.py` | 20 | JSON Defender, CSV, XML Windows, **EVTX réel** (1 601 événements), **EVTX malformé** (pas de plantage), Syslog/auth.log, texte collé (CEF), EML, DOCX/XLSX/PDF, import multiple, ZIP imbriqué, **ZIP bomb**, **traversée de chemin**, trop d'entrées, taille max., **exécutable mis en quarantaine sans bit d'exécution**, binaire inconnu refusé, signature prioritaire sur l'extension, détection de source, **XML avec entités (XXE) refusé** |
| `unit/test_analysis.py` | 13 | refang/extraction d'IOC (faux domaines exclus), classification IP, IOC non malveillant sans preuve, hash de binaire système = Info et jamais bloqué, **arbre de processus sans détail inventé**, entrée vide = Inconclusive, **pas de technique ATT&CK sur un simple nom de fichier**, chronologie triée et événements non horodatés signalés, force brute corrélée, chaque détection/technique référence des preuves existantes (8 scénarios) |
| `unit/test_mitre_hunting_detection.py` | 28 | index ATT&CK (>600 techniques), révocations T1574.002→T1574.001, T1562.001→T1685, T1070.001→T1685.005, bundle incomplet refusé, 13 hypothèses complètes, Sigma validé par pySigma, rendu des 5 formats (YAML/JSON valides, champs Sentinel obligatoires), **génération KQL** avec IOC, IOC non validés exclus, export |
| `unit/test_ai_ti_security.py` | 23 | moteur IA local **sans clé ni réseau**, Privacy bloque l'IA distante, clé manquante, **preuves inventées par l'IA rejetées**, technique inconnue supprimée, erreurs HTTP 401/429/500, délai dépassé, formats Anthropic/Ollama, Ollama local autorisé ; TI : Privacy = aucune requête, sans fournisseur = « réputation non vérifiée », **données internes jamais envoyées**, VirusTotal simulé, cache, **HTTP 429 + Retry-After** ; secrets chiffrés, masquage des journaux, PBKDF2, chemins d'archive dangereux, noms de fichiers sûrs |
| `integration/test_scenarios.py` | 10 | **8 scénarios** comparés à `expected.json`, faux positif sans action de confinement, journal System réel non surévalué |
| `integration/test_services_reports.py` | 13 | **persistance après redémarrage**, **reprise d'une investigation interrompue**, import en échec enregistré sans plantage, tableau de bord issu de la base, décisions de réponse tracées et conservées après réanalyse, multi-fichiers, ZIP de preuves, **rapports PDF/DOCX/HTML/JSON/CSV** (exécutif 6 sections, technique 19 sections), rapport refusé si investigation non terminée, hypothèses étiquetées, suppression, sauvegarde |
| `e2e/test_ui.py` | 7 | 12 pages, **aucun bouton non connecté** (>50 boutons vérifiés), investigation complète via l'UI (import → analyse → IA → tableau de bord → décision → 5 rapports → IOC en mode Privacy), texte collé + saisie manuelle, Threat Hunting/Detection/MITRE/Paramètres (clé chiffrée hors settings.json), Privacy bloque le test IA distant, **interface anglaise** |
| `e2e/test_cli.py` | 3 | `--selftest`, `analyze` + rapports, `--version` |

## 3. Scénarios synthétiques (identiques en source et avec l'EXE Windows gelé)

| Scénario | Sources | Verdict | Sévérité | Techniques ATT&CK |
|---|---|---|---|---|
| 01 Malware infection (phishing) | Defender XDR JSON + EML | Confirmed | High | T1566.001, T1204.002, T1059.001, T1027.010, T1105, T1071.001, T1547.001 |
| 02 Ransomware | Sysmon XML | Confirmed | Critical | T1486, T1490 |
| 03 PowerShell suspect | Splunk CSV | Likely | High | T1059.001, T1027.010, T1105 |
| 04 DLL side-loading | Elastic NDJSON | Confirmed | High | T1574.001, T1547.001, T1071.001 |
| 05 Force brute | Linux auth.log | Likely | High | T1110.001, T1078 |
| 06 KMSpico | Windows XML | Confirmed | High | T1053.005, T1543.003, T1685 |
| 07 Réseau suspect | pare-feu kv + Sysmon DNS | Likely | High | T1071.001, T1568.002 |
| 08 Faux positif (SCCM) | Defender XDR JSON | False Positive | Informational | — |

Journal System réel (`system.evtx`, installations de services/pilotes et PsExec) : **Suspicious / Medium** — l'outil
signale PsExec comme à vérifier sans conclure à une compromission.

## 4. Validation des livrables Windows (run GitHub Actions `45812806432`)

| Étape | Résultat |
|---|---|
| Installation des dépendances verrouillées (Python 3.13.17) | OK |
| pytest (117 tests, Qt offscreen) | OK |
| PyInstaller 6.11.1 (`AI_SOC_ANALYST.exe` + `AI_SOC_ANALYST_cli.exe`) | OK |
| Autotest de `AI_SOC_ANALYST_cli.exe` (contexte, ATT&CK, analyse, 5 rapports, 12 pages UI) | OK (`frozen: true`, `platform: win32`) |
| Autotest de `AI_SOC_ANALYST.exe` (exécutable graphique) | OK |
| 8 scénarios analysés par l'EXE gelé | 8/8 OK |
| Version portable (zip) + autotest | OK |
| Inno Setup 6 : `AI_SOC_ANALYST_Setup_1.0.0.exe` (69,4 Mo) | OK |
| Installation silencieuse → autotest de la version installée → désinstallation | OK |

Empreintes SHA256 (build du run `45812806432`) :

```
5BA3388E7E5D475011F2C64E8FFEEBD21D856485D959F4DC0964FCC13FB4DFE0  AI_SOC_ANALYST.exe
0DA4438582BEFE68ABAA81FBC4BFD9BFFFF4B4F3597EC9E0BE656C7671BEAD68  AI_SOC_ANALYST_cli.exe
1B41B9CC0E488E0C3E5E78A17EA8F3A143910E007037C705BC8F6A1FEBB4C61F  AI_SOC_ANALYST_1.0.0_portable_win64.zip
AB1901241226A1F25C98C520FD82966E323BB4AC86A26D7F61ADCFC566BEC3EF  AI_SOC_ANALYST_Setup_1.0.0.exe
```

## 5. Défauts trouvés et corrigés grâce aux tests

| Défaut | Détecté par | Correction |
|---|---|---|
| DOCX/XLSX/ZIP non détectés (le nom d'origine était ouvert au lieu de la copie en quarantaine) | test_docx_xlsx_pdf_import | `detect_format(stored, head, name)` |
| XLSX refusé par openpyxl (extension `.quarantine`) | idem | ouverture via objet fichier |
| Jeton `Authorization: Bearer …` visible dans les journaux | test_redaction | motif de masquage dédié |
| Gabarits python-docx absents de l'EXE gelé (rapports DOCX impossibles) | autotest de l'EXE Linux | données + module collectés sur disque |
| PsExec/pilotes d'un journal réel classés « Likely/High » | analyse de `system.evtx` | agrégation par service, PsExec seul = Suspicious, installation standard = Inconclusive |
| pefile 2024.8.26 incompatible avec PyInstaller sous Windows ; yara-python 4.5.1 sans wheel Windows cp313 | CI Windows | pefile 2023.2.7, yara-python 4.5.4 |

## 6. Non testé / limites des tests

* Aucun test manuel interactif sur un poste **Windows 10/11 de bureau** (validation faite sur Windows Server 2022 en CI,
  interface en mode offscreen + lancement réel de l'EXE graphique en autotest). Le rendu visuel a été contrôlé par
  captures d'écran sous Linux.
* Fichiers **MSG** Outlook : parseur implémenté (extract-msg) mais non testé faute d'échantillon MSG libre de droits.
* Appels réels aux API OpenAI / Anthropic / Azure / Ollama / VirusTotal / AbuseIPDB / OTX / abuse.ch : testés
  uniquement avec des transports HTTP simulés (aucune clé disponible) ; formats de requête conformes à la documentation
  publique de chaque service.
* Mise à jour ATT&CK en ligne (`update_online`) : non testée automatiquement (dépendance réseau). L'index embarqué v20.1
  a été produit pendant le développement en téléchargeant le bundle STIX officiel et en le convertissant avec
  `stix_loader` (même code que la mise à jour) ; le refus d'un bundle invalide est testé.
* DPAPI : exécuté sur Windows en CI (tests des secrets réussis), pas de test multi-utilisateur.

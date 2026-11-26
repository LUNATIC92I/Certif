# Rapport final – AI SOC ANALYST 1.0.0

## 1. Emplacement exact de l'exécutable

| Livrable | Emplacement |
|---|---|
| Code source | dépôt `LUNATIC92I/Certif`, branche `ccr-0d9cda33-29f2vq`, dossier `AI_SOC_ANALYST/` |
| **AI_SOC_ANALYST.exe** (+ `AI_SOC_ANALYST_cli.exe`, dossier `_internal`) | artefact GitHub Actions **`AI_SOC_ANALYST_1.0.0_exe`** du run `45812806432` (https://github.com/LUNATIC92I/Certif/actions/runs/45812806432) ; dans l'arborescence de build : `AI_SOC_ANALYST/dist/AI_SOC_ANALYST/AI_SOC_ANALYST.exe` |
| Programme d'installation | artefact **`AI_SOC_ANALYST_1.0.0_installer`** → `AI_SOC_ANALYST_Setup_1.0.0.exe` (build : `dist/installer/`) |
| Version portable | artefact **`AI_SOC_ANALYST_1.0.0_portable_win64`** → `AI_SOC_ANALYST_1.0.0_portable_win64.zip` |
| Rapports de test du build | artefact `AI_SOC_ANALYST_test_reports` (JUnit XML, autotests JSON, scénarios, SHA256SUMS) |

Les artefacts sont conservés 90 jours par GitHub (expiration indiquée : 24/02/2027). Les binaires ne sont pas versionnés
dans Git (≈ 250 Mo) ; ils sont reproductibles avec le workflow ou `packaging/build_windows.ps1`.

## 2. Fonctionnalités réalisées

* **Ingestion** : JSON/NDJSON, CSV, TXT, LOG, XML, EVTX, EML, MSG, PDF, DOCX, XLSX, ZIP (imbriqués) ; collage de
  journaux ; formulaire manuel ; glisser-déposer ; import multiple ; détection de format par signature et de source
  (≈15 produits) ; métadonnées nom/date/taille/format/source/SHA256/statut ; quarantaine en lecture seule, **aucune
  exécution** ; contrôles ZIP bomb, traversée, chiffrement, profondeur, tailles ; refus XXE.
* **Investigation** : 47 détections comportementales (22 familles), triage, extraction d'IOC avec justification et
  statut de validation, arbre des processus (parents déduits signalés), chronologie, corrélation en chaînes avec
  écarts, verdict (Confirmed/Likely/Suspicious/Inconclusive/False Positive) avec base explicite, sévérité, score,
  classification, cause probable, impact, évaluation faux positif, limites (données manquantes signalées, jamais
  inventées).
* **MITRE ATT&CK** : index officiel Enterprise v20.1 (706 techniques) embarqué, révocations suivies, mise à jour en ligne
  ou par import de bundle STIX, explorateur, associations justifiées par détections et preuves.
* **IA** : moteur local déterministe (hors ligne) + OpenAI, Anthropic Claude, Azure OpenAI, Ollama ; paquet de preuves
  limité ; validation stricte (affirmations sans preuve rejetées et affichées) ; confiance et références par
  conclusion ; hypothèses étiquetées.
* **Threat intelligence** : VirusTotal, AbuseIPDB, OTX, URLhaus, MalwareBazaar, ThreatFox ; Privacy Protection par
  défaut ; seuls des indicateurs publics transmis ; quotas, 429/Retry-After, cache, historique ; « réputation non
  vérifiée » sans fournisseur.
* **Threat hunting** : 13 hypothèses complètes (KQL, SPL, Sigma), champs à adapter signalés, injection des hash.
* **Detection engineering** : Sentinel, Defender XDR, Splunk, Sigma, Elastic ; règles de bibliothèque, issues des
  détections et des IOC validés ; téléchargement unitaire ou global.
* **Réponse à incident** : 11 types d'action avec objectif, justification, risque, impact, prérequis, procédure ;
  **proposées uniquement**, décisions tracées ; export du plan.
* **Rapports** : exécutif (6 sections) et technique (19 sections), PDF/DOCX/HTML/JSON + CSV des IOC, métadonnées
  (nom, identifiant, date, analyste, sévérité, statut, verdict, confiance, score, sources, TLP), SHA256 enregistré.
* **Interface** : 12 pages fonctionnelles, thème sombre SOC, graphiques issus de la base, traitements en arrière-plan
  avec progression, aucun bouton non connecté (vérifié automatiquement), FR + EN (libellés).
* **Sécurité / robustesse** : secrets Fernet + DPAPI, journaux masqués, mot de passe local optionnel (PBKDF2), audit,
  sauvegarde SQLite, reprise des investigations interrompues, gestion globale des exceptions, mode hors ligne.
* **Livraison** : EXE Windows (GUI + CLI), installeur Inno Setup, version portable, autotest intégré, CI Windows.
* **Documentation** : README, installation, utilisateur, configuration des API, technique, schéma de base, tests.

## 3. Fonctionnalités non réalisées ou partielles (à connaître)

| Élément demandé | État |
|---|---|
| Connecteurs d'exécution de la réponse (EDR, pare-feu, AD) | **Non réalisés** (prévus « plus tard » par le cahier des charges) ; l'interface l'indique. |
| SQLCipher (chiffrement de la base) | **Non activé** (optionnel dans le cahier des charges) : la base SQLite est en clair dans le profil utilisateur ; secrets chiffrés à part. |
| Traduction anglaise | **Partielle** : navigation, boutons, onglets, en-têtes, formulaires traduits ; les textes générés par l'analyse, les messages et les rapports restent en français. |
| Signature de code des binaires | Non réalisée (aucun certificat disponible) : avertissement SmartScreen possible. |
| Sigma « exécuté » sur les preuves importées | Non : les règles Sigma sont générées/validées (pySigma) mais la détection interne utilise le moteur de règles Python. |
| LIEF | Non utilisé (pefile couvre l'analyse PE statique). |
| Résolution MSG | Parseur présent, non testé faute d'échantillon. |

## 4. Résultats des tests

* Linux : **117/117** tests pytest réussis.
* Windows Server 2022 (CI, run `45812806432`) : **117/117** tests, autotests des deux EXE, **8/8 scénarios** avec l'EXE
  gelé, version portable, compilation Inno Setup, **installation silencieuse + autotest de la version installée +
  désinstallation** : tout réussi. Détail : [TEST_REPORT.md](TEST_REPORT.md).

## 5. Problèmes connus

1. **Validation sur poste Windows 10/11 de bureau non effectuée** : le build et les tests ont tourné sur Windows Server
   2022 (même noyau NT 10.0, même API) ; l'interface graphique a été lancée en autotest mais pas manipulée à la main
   sous Windows. Une recette manuelle sur un poste utilisateur reste recommandée.
2. Taille : dossier de l'application ≈ 250 Mo décompressé (Qt + bibliothèques), installeur 69 Mo.
3. Premier démarrage de l'EXE (onedir) : quelques secondes sur disque lent / antivirus actif.
4. Les dates sont affichées en UTC dans les tableaux (horodatages des sources convertis en UTC).
5. Licence : `extract-msg` est sous GPL-3.0 ; à valider par votre service juridique en cas de redistribution hors de
   l'organisation (alternative : retirer le support MSG).
6. Les réponses de l'IA distante dépendent du modèle choisi ; la validation garantit l'absence de preuves inventées,
   pas la qualité rédactionnelle.

## 6. Procédure d'installation (résumé)

1. Télécharger l'artefact `AI_SOC_ANALYST_1.0.0_installer` (onglet Actions du dépôt, run `45812806432`), décompresser.
2. Vérifier l'empreinte : `Get-FileHash AI_SOC_ANALYST_Setup_1.0.0.exe` doit donner
   `AB1901241226A1F25C98C520FD82966E323BB4AC86A26D7F61ADCFC566BEC3EF`.
3. Exécuter l'installeur (droits utilisateur suffisants), lancer **AI SOC ANALYST** depuis le menu Démarrer.
4. Optionnel : `AI_SOC_ANALYST_cli.exe --selftest` dans le dossier d'installation (code 0 = OK).
5. Paramètres : nom de l'analyste ; laisser Privacy Protection actif tant que les clés et la politique de partage ne
   sont pas validées.

Détails : [INSTALLATION.md](INSTALLATION.md).

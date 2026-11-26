# Guide utilisateur – AI SOC ANALYST 1.0.0

L'interface est organisée en 12 pages accessibles depuis la barre latérale. Toutes les opérations longues (import,
analyse, IA, threat intelligence, rapports, mise à jour ATT&CK) s'exécutent en arrière-plan : l'interface reste
utilisable et une barre de progression s'affiche dans la barre d'état.

## 1. Tableau de bord
Indicateurs calculés depuis la base locale : nombre d'investigations, répartition par sévérité, menaces confirmées,
faux positifs, durée moyenne d'analyse, catégories de menaces, techniques ATT&CK les plus observées, investigations
récentes (double-clic pour ouvrir). Aucune valeur n'est fictive : une base vide affiche des zéros.

## 2. Nouvelle investigation (Incident intake)
* **Fichiers** : glisser-déposer (fichiers ou dossiers) ou « Ajouter des fichiers… ». Formats : JSON/NDJSON, CSV, TXT,
  LOG, XML, EVTX, EML, MSG, PDF, DOCX, XLSX, ZIP. Le format est détecté par signature (l'extension ne sert qu'à
  départager) et la source est identifiée automatiquement (Defender XDR, Sentinel, Sysmon, journaux Windows, Splunk,
  Elastic, CrowdStrike, pare-feu, Syslog Linux, CEF/LEEF, messagerie…).
* **Coller des journaux** : texte brut (Syslog, CEF, LEEF, JSON, CSV, clé=valeur, texte d'alerte).
* **Saisie manuelle** : nom d'alerte, hôte, utilisateur, IP, processus, ligne de commande, hash, horodatage, sévérité
  initiale, actif critique (oui/non), description. La saisie devient un événement étiqueté « Saisie manuelle (analyste) ».
* « Lancer l'investigation » : chaque fichier est haché (SHA256), copié en quarantaine en lecture seule, **jamais
  exécuté**, puis analysé. Les archives sont contrôlées (ZIP bomb, traversée de chemin, membres chiffrés, profondeur).

## 3. File des incidents
Liste filtrable (statut, sévérité, texte). Boutons : Ouvrir, Reprendre / Réanalyser (investigations interrompues par
une fermeture ou en échec), Supprimer. Au démarrage, les analyses interrompues sont marquées « Interrompue ».

## 4. Espace d'investigation
Onglets : **Synthèse** (verdict, confiance, base du verdict, triage, cause probable, impact, évaluation faux positif,
limites de l'analyse, recommandations), **Preuves** (fichiers, format, source, taille, SHA256, statut), **Événements**
(recherche, contenu brut), **Détections** (règle, statut, confiance, MITRE, preuves), **Arbre des processus** (les
parents seulement déduits sont signalés « parent déduit, non observé »), **Chronologie**, **Corrélation** (chaînes
d'activité et écarts), **IOC**, **MITRE ATT&CK**, **Analyse IA**, **Notes**.
Actions : ajouter des preuves (réanalyse automatique), réanalyser, lancer l'analyse IA, aller aux rapports / à la
réponse / aux IOC.

Statuts des conclusions : **Confirmed** (preuve directe et corroborée), **Likely**, **Suspicious**, **Inconclusive**,
**False Positive**. Les données manquantes sont listées dans « Limites de l'analyse » : elles ne sont jamais inventées.

## 5. Renseignement IOC
Tableau : indicateur, type, réputation, risque, source, justification, statut de validation, occurrences, preuves.
« Rechercher la réputation » interroge les fournisseurs configurés **uniquement** si le mode Privacy Protection est
désactivé ; les indicateurs internes (IP privées, domaines `.local/.corp/...`, chemins, comptes) ne sont jamais envoyés.
Sans fournisseur : « réputation non vérifiée ». Onglets recherche manuelle et historique des requêtes (cache 24 h).

## 6. Explorateur MITRE ATT&CK
Techniques observées (par investigation) avec détections et preuves justificatives ; navigation par tactique ;
recherche ; fiche détaillée. Mise à jour : « Mettre à jour (en ligne) » (bundle STIX officiel mitre-attack) ou
« Importer un bundle STIX… » hors ligne. L'index embarqué (v20.1) est conservé en cas d'échec.

## 7. Threat Hunting
13 hypothèses (PowerShell, DLL side-loading, rançongiciel, dump d'identifiants, tâches planifiées, KMS, USB, force
brute, password spraying, mouvement latéral, DNS, persistance registre, hash malveillant) avec objectif, hypothèse,
comportements, sources, requêtes KQL/SPL/Sigma, résultats attendus, validation, recommandations. Les champs à adapter
sont signalés. « Injecter les hash de l'investigation », copier, exporter en Markdown.

## 8. Detection Engineering
Règles issues de la bibliothèque, des détections de l'investigation et de ses IOC validés, rendues en Microsoft
Sentinel (YAML), Defender XDR (KQL), Splunk (savedsearches.conf), Sigma, Elastic (JSON). Télécharger une règle ou
exporter toutes les règles. Les règles exportées sont désactivées par défaut et doivent être testées avant activation.

## 9. Réponse à incident
Actions proposées (isolement, blocage hash/IP/domaine, désactivation de compte, révocation de sessions, réinitialisation
de mot de passe, suppression de persistance, quarantaine, collecte de preuves, escalade) avec objectif, justification,
risque, impact, prérequis et procédure. **L'application n'exécute aucune action.** L'analyste approuve, rejette ou
consigne la réalisation manuelle, avec commentaire ; tout est tracé. Export du plan en Markdown.

## 10. Rapports SOC
Rapport exécutif (6 sections) ou technique (19 sections), classification TLP, formats PDF, DOCX, HTML, JSON et CSV
des IOC. Les fichiers sont enregistrés dans le dossier de l'investigation avec leur empreinte SHA256.

## 11. Historique
Investigations terminées (export CSV) et journal d'audit (création, imports, analyses, décisions, rapports, paramètres).

## 12. Paramètres
Langue (FR/EN, appliquée au redémarrage), nom de l'analyste, Privacy Protection, moteur IA et clés, threat
intelligence et clés, limites d'import, mot de passe local (optionnel), sauvegarde de la base, dossiers de données et
journaux. Les clés saisies sont chiffrées et ne sont plus affichées (laisser vide pour conserver, « - » pour effacer).

## Ligne de commande
```
AI_SOC_ANALYST_cli.exe analyze fichier1.evtx fichier2.json --title "INC poste X" --report pdf docx csv --level technical
AI_SOC_ANALYST_cli.exe --selftest --selftest-out resultat.json
```

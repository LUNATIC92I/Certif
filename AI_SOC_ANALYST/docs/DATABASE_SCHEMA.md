# Schéma de la base de données – AI SOC ANALYST 1.0.0

Moteur : SQLite 3 (fichier `data/ai_soc_analyst.db`), accès via SQLAlchemy 2.0. Pragmas : `journal_mode=WAL`,
`foreign_keys=ON`, `synchronous=NORMAL`. Version du schéma : `PRAGMA user_version = 1`. Contrôle `PRAGMA
integrity_check` au démarrage ; sauvegarde cohérente via l'API de backup SQLite (à la fermeture et à la demande,
rotation configurable). Les secrets ne sont **jamais** stockés dans la base (fichier chiffré séparé).

Chiffrement de la base : SQLCipher est optionnel et **non activé** dans la version 1.0.0 (voir FINAL_REPORT) ; la
protection repose sur le profil Windows de l'utilisateur et, en option, sur BitLocker.

## Relations

```
investigations 1─┬─* imported_files (parent_id → imported_files : membres d'archives)
                 ├─* events (file_id → imported_files)
                 ├─* findings          (F-001…, preuves = liste d'EVT-xxxxx)
                 ├─* iocs
                 ├─* mitre_mappings    (technique ↔ détections ↔ preuves)
                 ├─* response_actions  (Proposée / Approuvée / Rejetée / Réalisée)
                 └─* reports
ti_searches  (historique et cache des requêtes de réputation, investigation_id facultatif)
audit_log    (traçabilité de toutes les opérations)
```

Les colonnes `*_json` et `evidence_ids`, `mitre_ids`, `finding_ids` contiennent du JSON (texte UTF-8).
`investigations.result_json` contient le résultat complet de l'analyse (triage, chronologie, chaînes, arbres de
processus, limites, recommandations), ce qui permet la régénération des rapports sans réanalyse.

## Tables

### audit_log

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| ts | DATETIME | index |
| actor | VARCHAR(120) |  |
| action | VARCHAR(80) |  |
| investigation_id | INTEGER | nullable |
| details | TEXT |  |

### investigations

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| reference | VARCHAR(32) | unique, index |
| title | VARCHAR(300) |  |
| analyst | VARCHAR(120) |  |
| created_at | DATETIME |  |
| updated_at | DATETIME |  |
| status | VARCHAR(20) | index |
| stage | VARCHAR(60) |  |
| severity | VARCHAR(12) | index |
| verdict | VARCHAR(20) | index |
| confidence | FLOAT |  |
| risk_score | INTEGER |  |
| incident_type | VARCHAR(120) |  |
| threat_category | VARCHAR(120) |  |
| summary | TEXT |  |
| manual_input | TEXT |  |
| pasted_text | TEXT |  |
| result_json | TEXT |  |
| ai_result_json | TEXT |  |
| analyst_notes | TEXT |  |
| duration_seconds | FLOAT |  |
| error | TEXT |  |

### ti_searches

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| created_at | DATETIME | index |
| investigation_id | INTEGER | nullable |
| provider | VARCHAR(40) |  |
| indicator | VARCHAR(2000) |  |
| ioc_type | VARCHAR(30) |  |
| status | VARCHAR(30) |  |
| verdict | VARCHAR(40) |  |
| summary | TEXT |  |
| raw_json | TEXT |  |
| from_cache | BOOLEAN |  |

### findings

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| investigation_id | INTEGER | FK → investigations.id (CASCADE), index |
| finding_id | VARCHAR(20) |  |
| rule_id | VARCHAR(40) |  |
| title | VARCHAR(300) |  |
| category | VARCHAR(80) |  |
| description | TEXT |  |
| severity | VARCHAR(12) |  |
| status | VARCHAR(20) |  |
| confidence | FLOAT |  |
| evidence_ids | TEXT |  |
| mitre_ids | TEXT |  |
| details_json | TEXT |  |

### imported_files

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| investigation_id | INTEGER | FK → investigations.id (CASCADE), index |
| parent_id | INTEGER | FK → imported_files.id, nullable |
| original_name | VARCHAR(500) |  |
| stored_path | VARCHAR(1000) |  |
| imported_at | DATETIME |  |
| size | INTEGER |  |
| detected_format | VARCHAR(20) |  |
| detected_source | VARCHAR(60) |  |
| sha256 | VARCHAR(64) | index |
| status | VARCHAR(20) |  |
| message | TEXT |  |
| event_count | INTEGER |  |
| static_analysis_json | TEXT |  |

### iocs

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| investigation_id | INTEGER | FK → investigations.id (CASCADE), index |
| value | VARCHAR(2000) |  |
| ioc_type | VARCHAR(30) | index |
| reputation | VARCHAR(60) |  |
| risk | VARCHAR(20) |  |
| source | VARCHAR(200) |  |
| justification | TEXT |  |
| validation_status | VARCHAR(60) |  |
| occurrences | INTEGER |  |
| evidence_ids | TEXT |  |

### mitre_mappings

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| investigation_id | INTEGER | FK → investigations.id (CASCADE), index |
| tactic | VARCHAR(60) |  |
| technique_id | VARCHAR(16) | index |
| technique_name | VARCHAR(200) |  |
| description | TEXT |  |
| evidence_ids | TEXT |  |
| finding_ids | TEXT |  |
| confidence | FLOAT |  |

### reports

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| investigation_id | INTEGER | FK → investigations.id (CASCADE), index |
| level | VARCHAR(20) |  |
| fmt | VARCHAR(10) |  |
| path | VARCHAR(1000) |  |
| sha256 | VARCHAR(64) |  |
| created_at | DATETIME |  |

### response_actions

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| investigation_id | INTEGER | FK → investigations.id (CASCADE), index |
| action_type | VARCHAR(60) |  |
| target | VARCHAR(1000) |  |
| objective | TEXT |  |
| justification | TEXT |  |
| risk | TEXT |  |
| impact | TEXT |  |
| prerequisites | TEXT |  |
| procedure | TEXT |  |
| priority | VARCHAR(12) |  |
| status | VARCHAR(20) |  |
| decided_by | VARCHAR(120) |  |
| decided_at | DATETIME | nullable |
| decision_comment | TEXT |  |
| evidence_ids | TEXT |  |

### events

| Colonne | Type | Contraintes |
|---|---|---|
| id | INTEGER | PK |
| investigation_id | INTEGER | FK → investigations.id (CASCADE), index |
| file_id | INTEGER | FK → imported_files.id (CASCADE), nullable |
| evidence_id | VARCHAR(20) | index |
| record_index | INTEGER |  |
| timestamp | DATETIME | index, nullable |
| source_product | VARCHAR(60) |  |
| event_type | VARCHAR(40) | index |
| host | VARCHAR(255) |  |
| user | VARCHAR(255) |  |
| process_name | VARCHAR(255) |  |
| command_line | TEXT |  |
| data_json | TEXT |  |
| raw | TEXT |  |


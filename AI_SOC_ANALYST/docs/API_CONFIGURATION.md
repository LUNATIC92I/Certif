# Configuration des API – AI SOC ANALYST 1.0.0

Par défaut, l'application fonctionne **hors ligne** : moteur IA local déterministe, aucune threat intelligence, mode
Privacy Protection actif. Toute connexion externe nécessite une action explicite dans **Paramètres**.

## Principes de confidentialité
* Mode Privacy Protection actif ⇒ aucune requête vers un service distant (IA ou TI). Seul Ollama sur `localhost` reste
  autorisé.
* Threat intelligence : seuls des indicateurs publics sont transmis (hash, IP publiques, domaines/URL non internes).
  Jamais de noms d'hôtes, comptes, chemins, contenus de journaux.
* IA distante : un paquet de preuves limité (détections, IOC, jusqu'à N événements pertinents — réglable, 60 par
  défaut) est transmis, après confirmation explicite à chaque analyse.
* Les clés sont chiffrées (Fernet ; la clé maître est protégée par DPAPI sous Windows) et masquées dans les journaux.

## Moteurs IA

| Fournisseur | Paramètres | Clé |
|---|---|---|
| Local (défaut) | aucun | aucune |
| OpenAI | modèle (défaut `gpt-4o-mini`) | Clé API openai (`sk-…`) |
| Anthropic Claude | modèle (défaut `claude-sonnet-5-5`, modifiable) | Clé API anthropic |
| Azure OpenAI | endpoint `https://<ressource>.openai.azure.com`, nom du déploiement, version d'API (défaut `2024-10-21`) | Clé API azure_openai |
| Ollama | URL (défaut `http://127.0.0.1:11434`), modèle (défaut `llama3.1`) | aucune |

Procédure : Paramètres > Moteur IA > choisir le fournisseur, saisir la clé, **désactiver** Privacy Protection si le
fournisseur est distant, Enregistrer, puis « Tester la connexion IA ».

Garde-fous : la réponse doit être un JSON conforme ; chaque affirmation doit citer des identifiants de preuves
existants (`EVT-…`, `F-…`), sinon elle est rejetée et affichée dans « Affirmations rejetées » ; les techniques ATT&CK
inconnues sont supprimées ; les hypothèses sont étiquetées « non vérifiées ». Erreurs gérées : 401 (clé invalide),
403, 404 (modèle/endpoint), 429 (quota), délai d'attente, réponse invalide.

## Threat intelligence

| Service | Types | Clé (nom interne) | Obtention |
|---|---|---|---|
| VirusTotal v3 | hash, IP, domaine, URL | `virustotal_api_key` | compte virustotal.com > API key |
| AbuseIPDB v2 | IP | `abuseipdb_api_key` | abuseipdb.com > API |
| AlienVault OTX | hash, IP, domaine, URL | `otx_api_key` | otx.alienvault.com > Settings |
| URLhaus | URL, domaine, IP, hash | `abusech_auth_key` | auth.abuse.ch (Auth-Key commune abuse.ch) |
| MalwareBazaar | hash | `abusech_auth_key` | idem |
| ThreatFox | hash, IP, domaine, URL | `abusech_auth_key` | idem |

Procédure : Paramètres > Threat intelligence > cocher les services, saisir les clés, désactiver Privacy Protection,
Enregistrer. Quotas : intervalle minimal par service (VirusTotal gratuit : 15,5 s soit 4 req/min), gestion de HTTP 429
et `Retry-After`, cache local (24 h par défaut), historique des requêtes (page IOC).

Agrégation : « Malveillant » (≥ 3 moteurs VT, score AbuseIPDB ≥ 75, présence abuse.ch…), « Suspect », « Aucune
détection », « Inconnu ». Une réputation n'est enregistrée sur l'IOC que si un service a réellement répondu.

## Réseau / proxy
Les requêtes utilisent httpx, qui respecte les variables `HTTPS_PROXY` / `NO_PROXY`. Hôtes utilisés : api.openai.com,
api.anthropic.com, `<ressource>.openai.azure.com`, www.virustotal.com, api.abuseipdb.com, otx.alienvault.com,
urlhaus-api.abuse.ch, mb-api.abuse.ch, threatfox-api.abuse.ch, raw.githubusercontent.com (mise à jour ATT&CK).

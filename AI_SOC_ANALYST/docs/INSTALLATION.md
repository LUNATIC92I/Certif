# Guide d'installation – AI SOC ANALYST 1.0.0

## Prérequis

* Windows 10 (1809+) ou Windows 11, 64 bits ; 4 Go de RAM (8 Go recommandés pour de gros EVTX) ; ~600 Mo de disque.
* Aucun droit administrateur requis (installation possible « pour l'utilisateur courant »).
* Aucun accès Internet requis : l'application fonctionne entièrement hors ligne (moteur local, index ATT&CK embarqué).

## Option 1 – Programme d'installation (recommandé)

1. Exécuter `AI_SOC_ANALYST_Setup_1.0.0.exe`.
2. Choisir « Installer pour moi uniquement » (sans droits admin) ou « pour tous les utilisateurs ».
3. Accepter l'avertissement d'utilisation, choisir le dossier (par défaut `%LOCALAPPDATA%\Programs\AI_SOC_ANALYST` ou
   `C:\Program Files\AI_SOC_ANALYST`), cocher éventuellement l'icône bureau.
4. Lancer **AI SOC ANALYST** depuis le menu Démarrer.

Installation silencieuse (déploiement) :

```
AI_SOC_ANALYST_Setup_1.0.0.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CURRENTUSER
```

Désinstallation : Paramètres Windows > Applications, ou `unins000.exe /VERYSILENT` dans le dossier d'installation.
Les données d'investigation (`%LOCALAPPDATA%\AI_SOC_ANALYST`) sont conservées volontairement (ce sont des preuves).

## Option 2 – Version portable

1. Décompresser `AI_SOC_ANALYST_1.0.0_portable_win64.zip` (clé USB, partage, poste d'analyse isolé).
2. Lancer `AI_SOC_ANALYST\AI_SOC_ANALYST.exe`.
3. La présence du fichier `portable.ini` fait stocker toutes les données dans `AI_SOC_ANALYST\data`.

## Option 3 – Depuis les sources

```
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt -c requirements-lock.txt
set PYTHONPATH=src
.venv\Scripts\python -m ai_soc_analyst
```

Reconstruire l'exécutable et l'installeur : `powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1`
(nécessite Inno Setup 6 pour l'installeur : `choco install innosetup`).

## Vérifier une installation

```
"C:\...\AI_SOC_ANALYST\AI_SOC_ANALYST_cli.exe" --selftest
```

L'autotest crée un dossier de données temporaire, vérifie le chargement d'ATT&CK, analyse un jeu synthétique, génère
les rapports PDF/DOCX/HTML/JSON/CSV et instancie les 12 pages de l'interface. Code de sortie 0 = succès.

## Emplacement des données

| Élément | Emplacement (installé) |
|---|---|
| Base SQLite | `%LOCALAPPDATA%\AI_SOC_ANALYST\data\ai_soc_analyst.db` |
| Quarantaine des preuves | `...\quarantine\` (fichiers `<sha256>.quarantine`, lecture seule) |
| Rapports | `...\reports\<référence>\` |
| Journaux | `...\logs\ai_soc_analyst.log` (rotation, données sensibles masquées) |
| Sauvegardes | `...\backups\` (à chaque fermeture + à la demande) |
| Paramètres / secrets chiffrés | `...\config\settings.json`, `secrets.bin`, `master.key` (clé protégée par DPAPI) |

La variable d'environnement `AI_SOC_HOME` permet de forcer un autre dossier.

## Avertissement SmartScreen

Les binaires produits ne sont pas signés (pas de certificat de signature de code fourni). Windows SmartScreen peut
afficher « Windows a protégé votre ordinateur » : vérifier l'empreinte SHA256 publiée avec le build
(`SHA256SUMS.txt`), puis « Informations complémentaires > Exécuter quand même ». En entreprise, signer les binaires
avec le certificat de l'organisation avant diffusion.

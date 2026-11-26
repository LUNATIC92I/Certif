"""Traductions de l'interface (français principal, anglais secondaire)."""
from __future__ import annotations

_LANG = "fr"

STRINGS: dict[str, tuple[str, str]] = {
    "nav.dashboard": ("Tableau de bord", "Dashboard"),
    "nav.new": ("Nouvelle investigation", "New Investigation"),
    "nav.queue": ("File des incidents", "Incident Queue"),
    "nav.workspace": ("Espace d'investigation", "Investigation Workspace"),
    "nav.ioc": ("Renseignement IOC", "IOC Intelligence"),
    "nav.mitre": ("Explorateur MITRE ATT&CK", "MITRE ATT&CK Explorer"),
    "nav.hunting": ("Threat Hunting", "Threat Hunting"),
    "nav.detection": ("Detection Engineering", "Detection Engineering"),
    "nav.response": ("Réponse à incident", "Incident Response"),
    "nav.reports": ("Rapports SOC", "SOC Reports"),
    "nav.history": ("Historique", "Investigation History"),
    "nav.settings": ("Paramètres", "Settings"),
    "dash.total": ("Investigations", "Total Investigations"),
    "dash.critical": ("Critiques", "Critical Incidents"),
    "dash.high": ("Élevées", "High Severity"),
    "dash.medium": ("Moyennes", "Medium Severity"),
    "dash.low": ("Faibles / info", "Low Severity"),
    "dash.confirmed": ("Menaces confirmées", "Confirmed Threats"),
    "dash.fp": ("Faux positifs", "False Positives"),
    "dash.avg": ("Durée moyenne d'analyse", "Average Investigation Time"),
    "dash.recent": ("Investigations récentes", "Recent Investigations"),
    "dash.categories": ("Catégories de menaces", "Threat Categories"),
    "dash.mitre": ("Techniques MITRE les plus observées", "MITRE Techniques Distribution"),
    "btn.refresh": ("Actualiser", "Refresh"),
    "btn.open": ("Ouvrir", "Open"),
    "btn.run": ("Lancer l'investigation", "Run investigation"),
    "btn.add_files": ("Ajouter des fichiers…", "Add files…"),
    "btn.remove": ("Retirer la sélection", "Remove selected"),
    "btn.clear": ("Vider", "Clear"),
    "btn.reanalyze": ("Réanalyser", "Re-analyze"),
    "btn.resume": ("Reprendre", "Resume"),
    "btn.delete": ("Supprimer", "Delete"),
    "btn.save": ("Enregistrer", "Save"),
    "btn.export": ("Exporter…", "Export…"),
    "btn.copy": ("Copier", "Copy"),
    "btn.generate": ("Générer", "Generate"),
    "btn.lookup": ("Rechercher la réputation", "Lookup reputation"),
    "btn.approve": ("Approuver", "Approve"),
    "btn.reject": ("Rejeter", "Reject"),
    "btn.done": ("Marquer réalisée", "Mark done"),
    "drop.hint": ("Glissez-déposez ici vos fichiers (JSON, CSV, TXT, LOG, XML, EVTX, EML, MSG, PDF, DOCX, XLSX, ZIP)",
                  "Drop files here (JSON, CSV, TXT, LOG, XML, EVTX, EML, MSG, PDF, DOCX, XLSX, ZIP)"),
    "lang.restart": ("La langue sera appliquée au prochain démarrage.", "Language will apply at next start."),
}


def set_language(lang: str) -> None:
    global _LANG
    _LANG = "en" if lang == "en" else "fr"


def t(key: str) -> str:
    fr, en = STRINGS.get(key, (key, key))
    return en if _LANG == "en" else fr


# ---------------------------------------------------------------------------------------------------------------------
# Traduction des libellés statiques de l'interface (appliquée à tous les widgets lorsque la langue est l'anglais).
# Les contenus produits par l'analyse (synthèse, justifications, rapports) restent rédigés en français.
EN: dict[str, str] = {
    "Les clés d'API sont chiffrées localement (Fernet, clé protégée par DPAPI sous Windows) et ne sont jamais affichées ni journalisées.":
        "API keys are encrypted locally (Fernet, key protected by DPAPI on Windows) and are never displayed or logged.",
    "Général": "General", "Langue": "Language", "Nom de l'analyste": "Analyst name",
    "Mode Privacy Protection (aucune donnée transmise à des services externes)":
        "Privacy Protection mode (no data sent to external services)",
    "Moteur IA": "AI engine", "Fournisseur": "Provider", "Moteur local déterministe (hors ligne)": "Local deterministic engine (offline)",
    "Modèle OpenAI": "OpenAI model", "Modèle Anthropic": "Anthropic model", "Azure : déploiement": "Azure: deployment",
    "Azure : endpoint": "Azure: endpoint", "Azure : version d'API": "Azure: API version", "Ollama : URL": "Ollama: URL",
    "Ollama : modèle": "Ollama: model", "Délai d'attente (s)": "Timeout (s)", "Événements max. transmis": "Max. events sent",
    "Clé API openai": "OpenAI API key", "Clé API anthropic": "Anthropic API key", "Clé API azure_openai": "Azure OpenAI API key",
    "non configurée": "not configured", "Tester la connexion IA": "Test AI connection",
    "Auth-Key abuse.ch (URLhaus, MalwareBazaar, ThreatFox)": "abuse.ch Auth-Key (URLhaus, MalwareBazaar, ThreatFox)",
    "Durée du cache (h)": "Cache duration (h)", "Sécurité de l'import (limites)": "Import safety (limits)",
    "Taille max. par fichier (Mo)": "Max. file size (MB)", "Taille max. décompressée (Mo)": "Max. uncompressed size (MB)",
    "Entrées max. par archive": "Max. entries per archive", "Ratio de compression max.": "Max. compression ratio",
    "Profondeur max. d'archives imbriquées": "Max. nested archive depth", "Événements max. par fichier": "Max. events per file",
    "Contrôle d'accès et données": "Access control and data", "Mot de passe local": "Local password",
    "aucun (accès libre à la session Windows)": "none (open to the Windows session)", "défini": "set",
    "Définir / changer le mot de passe": "Set / change password", "Supprimer le mot de passe": "Remove password",
    "Sauvegardes conservées": "Backups kept", "Sauvegarder la base maintenant": "Back up database now",
    "Ouvrir le dossier des données": "Open data folder", "Ouvrir le journal de l'application": "Open application log",
    "Dossier des données": "Data folder", "Enregistrer": "Save",
    "Investigations terminées et journal d'audit des opérations (traçabilité).": "Completed investigations and operations audit log.",
    "Investigations terminées": "Completed investigations", "Journal d'audit": "Audit log", "Acteur": "Actor",
    "Détails": "Details", "Référence": "Reference", "Titre": "Title", "Sévérité": "Severity", "Catégorie": "Category",
    "Durée (s)": "Duration (s)", "Terminée le": "Completed on", "Actualiser": "Refresh", "Ouvrir": "Open",
    "Exporter l'historique (CSV)…": "Export history (CSV)…",
    "Rapports exécutif (direction) et technique (19 sections) en PDF, DOCX, HTML, JSON et export CSV des IOC. Les hypothèses sont étiquetées comme telles.":
        "Executive and technical (19 sections) reports in PDF, DOCX, HTML, JSON and IOC CSV export. Hypotheses are labelled as such.",
    "Génération": "Generation", "Niveau": "Level", "Rapport technique (Technical Investigation Report)": "Technical Investigation Report",
    "Rapport exécutif (Executive Report)": "Executive Report", "Générer": "Generate",
    "Générer vers un dossier…": "Generate to folder…", "Fichier": "File", "Ouvrir le rapport": "Open report",
    "Ouvrir le dossier": "Open folder", "Investigation :": "Investigation:", "Cible": "Target", "Priorité": "Priority",
    "Statut": "Status", "Décidée par": "Decided by", "Le": "On", "Commentaire": "Comment", "Preuves": "Evidence",
    "Approuver": "Approve", "Rejeter": "Reject", "Marquer réalisée (exécution manuelle)": "Mark done (manual execution)",
    "Remettre à « Proposée »": "Reset to “Proposed”", "Exporter le plan de réponse (Markdown)…": "Export response plan (Markdown)…",
    "Copier": "Copy", "Télécharger la règle…": "Download rule…", "Exporter toutes les règles (5 formats)…": "Export all rules (5 formats)…",
    "— Règles de la bibliothèque uniquement —": "— Library rules only —", "Sans IOC d'investigation": "No investigation IOCs",
    "Injecter les hash de l'investigation": "Inject investigation hashes", "Copier la requête affichée": "Copy displayed query",
    "Exporter l'hypothèse (Markdown)…": "Export hypothesis (Markdown)…",
    "Rechercher une technique (ID, nom, description)…": "Search a technique (ID, name, description)…",
    "Rechercher": "Search", "Mettre à jour (en ligne)": "Update (online)", "Importer un bundle STIX…": "Import STIX bundle…",
    "Techniques observées": "Observed techniques", "Matrice (navigation par tactique)": "Matrix (browse by tactic)",
    "Nom": "Name", "Plateformes": "Platforms", "Sous-technique": "Sub-technique", "Toutes les investigations": "All investigations",
    "Tactique": "Tactic", "Confiance": "Confidence", "Détections": "Detections", "Tous niveaux de risque": "All risk levels",
    "IOC de l'investigation": "Investigation IOCs", "Recherche manuelle": "Manual lookup",
    "Historique des recherches TI": "TI lookup history", "Indicateur": "Indicator", "Résumé": "Summary",
    "Indicateur à vérifier (hash, IP publique, domaine, URL)": "Indicator to check (hash, public IP, domain, URL)",
    "Rechercher la réputation": "Lookup reputation", "Réputation": "Reputation", "Risque": "Risk",
    "Statut de validation": "Validation status", "Rechercher la réputation (sélection)": "Lookup reputation (selection)",
    "Exporter CSV…": "Export CSV…", "Aucune investigation ouverte : sélectionnez-en une dans la file des incidents.":
        "No investigation open: select one in the incident queue.", "Ajouter des preuves…": "Add evidence…",
    "Réanalyser": "Re-analyze", "Analyse IA (fournisseur configuré)": "AI analysis (configured provider)",
    "Générer un rapport →": "Generate report →", "Réponse à incident →": "Incident response →", "Synthèse": "Summary",
    "Événements": "Events", "Arbre des processus": "Process tree", "Chronologie": "Timeline", "Corrélation": "Correlation",
    "Analyse IA": "AI analysis", "Notes de l'analyste (conservées avec l'investigation et reprises dans le rapport technique).":
        "Analyst notes (kept with the investigation and included in the technical report).", "Chaîne": "Chain",
    "Hôtes": "Hosts", "Début": "Start", "Fin": "End", "Écarts / limites": "Gaps / limits", "Horodatage": "Timestamp",
    "Preuve": "Evidence", "Hôte": "Host", "Utilisateur": "User", "Processus": "Process", "Ligne de commande": "Command line",
    "Règle": "Rule", "Filtrer les événements (texte, EVT-…, hôte, utilisateur, processus)…":
        "Filter events (text, EVT-…, host, user, process)…", "Filtrer": "Filter", "Source détectée": "Detected source",
    "Taille": "Size", "Importé le": "Imported on", "Toutes les investigations, filtrables par statut, sévérité et texte.":
        "All investigations, filterable by status, severity and text.", "Rechercher (référence, titre, type)…":
        "Search (reference, title, type)…", "Tous statuts": "All statuses", "Nouvelle": "New", "Import en cours": "Importing",
    "Analyse en cours": "Analyzing", "Terminée": "Completed", "En échec": "Failed", "Interrompue": "Interrupted",
    "Toutes sévérités": "All severities", "Étape / erreur": "Stage / error", "Analyste": "Analyst", "Créée le": "Created on",
    "Reprendre / Réanalyser": "Resume / Re-analyze", "Supprimer": "Delete",
    "Titre de l'investigation (ex. Alerte EDR poste FIN-LT-042)": "Investigation title (e.g. EDR alert on FIN-LT-042)",
    "Fichiers": "Files", "Coller des journaux": "Paste logs", "Saisie manuelle": "Manual input", "Nom de l'alerte": "Alert name",
    "Source (EDR, SIEM…)": "Source (EDR, SIEM…)", "IP source": "Source IP", "IP destination": "Destination IP",
    "Date/heure (ISO 8601)": "Date/time (ISO 8601)", "Actif critique (oui/non)": "Critical asset (yes/no)",
    "Sévérité initiale": "Initial severity", "Collez ici des journaux bruts (Syslog, CEF, LEEF, JSON, CSV, clé=valeur, texte d'alerte…)":
        "Paste raw logs here (Syslog, CEF, LEEF, JSON, CSV, key=value, alert text…)", "Ajouter des fichiers…": "Add files…",
    "Retirer la sélection": "Remove selected", "Vider": "Clear", "Prêt.": "Ready.", "Lancer l'investigation": "Run investigation",
    "Indicateurs calculés en temps réel depuis la base locale des investigations.": "Live metrics computed from the local investigation database.",
    "+ Nouvelle investigation": "+ New investigation", "Investigations": "Total investigations", "Critiques": "Critical",
    "Élevées": "High", "Moyennes": "Medium", "Faibles / info": "Low / info", "Menaces confirmées": "Confirmed threats",
    "Faux positifs": "False positives", "Durée moyenne d'analyse": "Average investigation time",
    "Investigations récentes": "Recent investigations", "Répartition par sévérité": "Severity distribution",
    "Catégories de menaces": "Threat categories", "Techniques MITRE les plus observées": "Most observed MITRE techniques",
    "Description": "Description", "Hash": "Hash", "Score": "Score",
}


def apply_translation(root) -> int:  # noqa: ANN001
    """Traduit en anglais les libellés statiques de tous les widgets descendants de ``root``."""
    if _LANG != "en":
        return 0
    from PySide6.QtWidgets import (QAbstractButton, QComboBox, QFormLayout, QGroupBox, QLabel, QLineEdit,
                                   QPlainTextEdit, QTableWidget, QTabWidget, QTreeWidget, QWidget)

    n = 0

    def tr(s: str):  # noqa: ANN202
        nonlocal n
        v = EN.get(s.strip()) if s else None
        if v:
            n += 1
        return v

    for w in [root, *root.findChildren(QWidget)]:
        if isinstance(w, (QLabel, QAbstractButton)) and (v := tr(w.text())):
            w.setText(v)
        if isinstance(w, QGroupBox) and (v := tr(w.title())):
            w.setTitle(v)
        if isinstance(w, (QLineEdit, QPlainTextEdit)) and (v := tr(w.placeholderText())):
            w.setPlaceholderText(v)
        if isinstance(w, QTabWidget):
            for i in range(w.count()):
                if v := tr(w.tabText(i)):
                    w.setTabText(i, v)
        if isinstance(w, QTableWidget):
            for i in range(w.columnCount()):
                h = w.horizontalHeaderItem(i)
                if h and (v := tr(h.text())):
                    h.setText(v)
        if isinstance(w, QTreeWidget):
            for i in range(w.columnCount()):
                if v := tr(w.headerItem().text(i)):
                    w.headerItem().setText(i, v)
        if isinstance(w, QComboBox):
            for i in range(w.count()):
                if v := tr(w.itemText(i)):
                    w.setItemText(i, v)
        if hasattr(w, "title") and isinstance(getattr(w, "title", None), str) and (v := tr(w.title)):
            w.title = v  # graphiques du tableau de bord
    for lay in root.findChildren(QFormLayout):
        for r in range(lay.rowCount()):
            it = lay.itemAt(r, QFormLayout.LabelRole)
            if it and it.widget() and isinstance(it.widget(), QLabel) and (v := tr(it.widget().text())):
                it.widget().setText(v)
    return n

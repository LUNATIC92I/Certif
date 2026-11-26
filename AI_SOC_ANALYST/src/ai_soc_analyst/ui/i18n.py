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

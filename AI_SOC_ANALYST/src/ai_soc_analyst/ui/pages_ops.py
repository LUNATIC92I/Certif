"""Pages : Réponse à incident, Rapports SOC, Paramètres."""
from __future__ import annotations

import json
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout,
                               QInputDialog, QLabel, QLineEdit, QMessageBox, QPushButton, QScrollArea, QSpinBox, QSplitter,
                               QTextBrowser, QVBoxLayout, QWidget)
from PySide6.QtCore import Qt

from ..ai.engine import test_connection
from ..core.security import hash_password
from ..core.settings import TI_PROVIDERS
from ..reporting.service import FORMATS, generate_reports, list_reports
from ..ti.engine import SECRET_NAMES
from . import theme
from .i18n import t
from .pages_intel import _esc, _inv_combo
from .widgets import error_box, fill_table, info_box, make_table, page_header, selected_data
from .workers import Worker, start

DECISION_COLORS = {"Proposée": theme.MUTED, "Approuvée": theme.TEAL, "Rejetée": theme.SEVERITY["High"],
                   "Réalisée": theme.VERDICT["False Positive"]}


# =====================================================================================================================
class ResponsePage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.response"), "Plan de réponse proposé à partir des preuves. Les actions sont uniquement "
                                  "PROPOSÉES : l'application n'exécute aucune action sur l'environnement réel. L'analyste "
                                  "approuve, rejette ou consigne la réalisation (manuelle) de chaque action ; chaque décision est "
                                  "tracée dans le journal d'audit."))
        row = QHBoxLayout()
        self.inv = _inv_combo(state)
        self.inv.currentIndexChanged.connect(self.refresh)
        row.addWidget(QLabel("Investigation :"))
        row.addWidget(self.inv)
        row.addStretch(1)
        lay.addLayout(row)
        split = QSplitter(Qt.Vertical)
        self.table = make_table(["Action", "Cible", "Priorité", "Statut", "Décidée par", "Le", "Commentaire", "Preuves"])
        self.table.itemSelectionChanged.connect(self.show_detail)
        split.addWidget(self.table)
        self.detail = QTextBrowser()
        split.addWidget(self.detail)
        split.setSizes([330, 300])
        lay.addWidget(split, 1)
        b = QHBoxLayout()
        self.btn_approve = QPushButton(t("btn.approve"))
        self.btn_approve.setObjectName("Primary")
        self.btn_approve.clicked.connect(lambda: self.decide("Approuvée"))
        self.btn_reject = QPushButton(t("btn.reject"))
        self.btn_reject.clicked.connect(lambda: self.decide("Rejetée"))
        self.btn_done = QPushButton(t("btn.done") + " (exécution manuelle)")
        self.btn_done.clicked.connect(lambda: self.decide("Réalisée"))
        self.btn_reset = QPushButton("Remettre à « Proposée »")
        self.btn_reset.clicked.connect(lambda: self.decide("Proposée"))
        self.btn_export = QPushButton("Exporter le plan de réponse (Markdown)…")
        self.btn_export.clicked.connect(self.export_plan)
        for w in (self.btn_approve, self.btn_reject, self.btn_done, self.btn_reset, self.btn_export):
            b.addWidget(w)
        b.addStretch(1)
        lay.addLayout(b)
        note = QLabel("Connecteurs d'exécution (EDR, pare-feu, annuaire) : non disponibles dans la version 1.0.0 — prévus "
                      "pour une version ultérieure, toujours soumis à autorisation explicite.")
        note.setStyleSheet(f"color:{theme.MUTED}")
        note.setWordWrap(True)
        lay.addWidget(note)
        self._actions = []
        self.inv.reload()

    def refresh(self) -> None:
        inv_id = self.inv.currentData()
        self._actions = self.state.svc.actions(inv_id) if inv_id else []
        fill_table(self.table, [[a.action_type, a.target, a.priority, a.status, a.decided_by,
                                 a.decided_at.strftime("%Y-%m-%d %H:%M") if a.decided_at else "", a.decision_comment,
                                 ", ".join(json.loads(a.evidence_ids or "[]")[:8])] for a in self._actions],
                   {2: theme.SEVERITY, 3: DECISION_COLORS}, [a.id for a in self._actions])
        self.detail.clear()

    def _current(self):  # noqa: ANN202
        aid = selected_data(self.table)
        return next((a for a in self._actions if a.id == aid), None)

    def show_detail(self) -> None:
        a = self._current()
        if not a:
            return
        self.detail.setHtml(f"<h3>{_esc(a.action_type)} → {_esc(a.target)}</h3>"
                            f"<p><b>Objectif :</b> {_esc(a.objective)}</p><p><b>Justification :</b> {_esc(a.justification)}</p>"
                            f"<p><b>Risque :</b> {_esc(a.risk)}</p><p><b>Impact :</b> {_esc(a.impact)}</p>"
                            f"<p><b>Prérequis :</b> {_esc(a.prerequisites)}</p><p><b>Procédure :</b><br>"
                            f"{_esc(a.procedure).replace(chr(10), '<br>')}</p>"
                            f"<p><b>Statut :</b> {_esc(a.status)} {_esc(a.decision_comment)}</p>")

    def decide(self, decision: str) -> None:
        a = self._current()
        if not a:
            info_box(self, "Réponse à incident", "Sélectionnez une action.")
            return
        comment, ok = QInputDialog.getText(self, f"Décision : {decision}",
                                           "Commentaire (justification, référence de ticket…). Aucune action ne sera exécutée "
                                           "par l'application :")
        if not ok:
            return
        try:
            self.state.svc.decide_action(a.id, decision, comment)
        except Exception as exc:  # noqa: BLE001
            error_box(self, "Réponse à incident", str(exc))
            return
        self.refresh()

    def export_plan(self) -> None:
        if not self._actions:
            info_box(self, "Réponse à incident", "Aucune action à exporter.")
            return
        ref = self.inv.currentText().split(" ")[0]
        path, _ = QFileDialog.getSaveFileName(self, "Exporter le plan", f"{ref}_plan_reponse.md", "Markdown (*.md)")
        if not path:
            return
        lines = [f"# Plan de réponse — {self.inv.currentText()}", "",
                 "> Actions proposées par AI SOC ANALYST. Aucune n'a été exécutée automatiquement.", ""]
        for a in self._actions:
            lines += [f"## [{a.priority}] {a.action_type} → {a.target}", f"- **Statut :** {a.status} {a.decision_comment}",
                      f"- **Objectif :** {a.objective}", f"- **Justification :** {a.justification}", f"- **Risque :** {a.risk}",
                      f"- **Impact :** {a.impact}", f"- **Prérequis :** {a.prerequisites}", "", "**Procédure :**", "",
                      a.procedure, ""]
        Path(path).write_text("\n".join(lines), encoding="utf-8")
        info_box(self, "Réponse à incident", f"Exporté : {path}")


# =====================================================================================================================
class ReportsPage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.reports"), "Rapports exécutif (direction) et technique (19 sections) en PDF, DOCX, HTML, "
                                  "JSON et export CSV des IOC. Les hypothèses sont étiquetées comme telles."))
        g = QGroupBox("Génération")
        f = QFormLayout(g)
        self.inv = _inv_combo(state)
        self.inv.currentIndexChanged.connect(self.refresh)
        self.level = QComboBox()
        self.level.addItem("Rapport technique (Technical Investigation Report)", "technical")
        self.level.addItem("Rapport exécutif (Executive Report)", "executive")
        self.tlp = QComboBox()
        self.tlp.addItems(["TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED", "TLP:GREEN", "TLP:CLEAR"])
        fmts = QHBoxLayout()
        self.fmt_boxes = {}
        for k in FORMATS:
            cb = QCheckBox(k.upper() + (" (IOC)" if k == "csv" else ""))
            cb.setChecked(k in ("pdf", "docx", "html"))
            self.fmt_boxes[k] = cb
            fmts.addWidget(cb)
        fmts.addStretch(1)
        f.addRow("Investigation", self.inv)
        f.addRow("Niveau", self.level)
        f.addRow("Classification", self.tlp)
        f.addRow("Formats", fmts)
        self.btn_gen = QPushButton(t("btn.generate"))
        self.btn_gen.setObjectName("Primary")
        self.btn_gen.clicked.connect(self.generate)
        self.btn_gen_to = QPushButton("Générer vers un dossier…")
        self.btn_gen_to.clicked.connect(lambda: self.generate(choose=True))
        brow = QHBoxLayout()
        brow.addWidget(self.btn_gen)
        brow.addWidget(self.btn_gen_to)
        brow.addStretch(1)
        f.addRow(brow)
        lay.addWidget(g)
        self.table = make_table(["Date (UTC)", "Niveau", "Format", "Fichier", "SHA256"])
        self.table.doubleClicked.connect(self.open_file)
        lay.addWidget(self.table, 1)
        b = QHBoxLayout()
        self.btn_open = QPushButton("Ouvrir le rapport")
        self.btn_open.clicked.connect(self.open_file)
        self.btn_folder = QPushButton("Ouvrir le dossier")
        self.btn_folder.clicked.connect(self.open_folder)
        for w in (self.btn_open, self.btn_folder):
            b.addWidget(w)
        b.addStretch(1)
        lay.addLayout(b)
        self.inv.reload()

    def refresh(self) -> None:
        inv_id = self.inv.currentData()
        reps = list_reports(self.state.svc, inv_id) if inv_id else []
        fill_table(self.table, [[r.created_at.strftime("%Y-%m-%d %H:%M:%S"), r.level, r.fmt, r.path, r.sha256] for r in reps],
                   user_data=[r.path for r in reps])

    def generate(self, choose: bool = False) -> None:
        inv_id = self.inv.currentData()
        fmts = [k for k, cb in self.fmt_boxes.items() if cb.isChecked()]
        if not inv_id:
            info_box(self, "Rapports", "Aucune investigation terminée sélectionnée.")
            return
        if not fmts:
            info_box(self, "Rapports", "Choisissez au moins un format.")
            return
        out = None
        if choose:
            d = QFileDialog.getExistingDirectory(self, "Dossier de destination")
            if not d:
                return
            out = Path(d)
        self.btn_gen.setEnabled(False)
        self.btn_gen_to.setEnabled(False)
        self.state.busy.emit(True, "Génération des rapports…")
        w = Worker(generate_reports, self.state.svc, inv_id, self.level.currentData(), fmts, out, self.tlp.currentText(),
                   with_progress=False)
        w.signals.finished.connect(self._done)
        w.signals.error.connect(self._failed)
        start(w)

    def _done(self, paths: list) -> None:  # noqa: ANN001
        self.btn_gen.setEnabled(True)
        self.btn_gen_to.setEnabled(True)
        self.state.busy.emit(False, f"{len(paths)} rapport(s) généré(s).")
        self.refresh()
        info_box(self, "Rapports", "Rapports générés :\n" + "\n".join(str(p) for p in paths))

    def _failed(self, msg: str) -> None:
        self.btn_gen.setEnabled(True)
        self.btn_gen_to.setEnabled(True)
        self.state.busy.emit(False, "")
        error_box(self, "Rapports", msg)

    def _path(self) -> Path | None:
        p = selected_data(self.table)
        return Path(p) if p else None

    def open_file(self) -> None:
        p = self._path()
        if not p or not p.exists():
            info_box(self, "Rapports", "Sélectionnez un rapport existant.")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))

    def open_folder(self) -> None:
        p = self._path()
        folder = p.parent if p else self.state.ctx.paths.reports
        folder.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))


# =====================================================================================================================
class SettingsPage(QWidget):
    AI_KEYS = {"openai": "openai_api_key", "anthropic": "anthropic_api_key", "azure_openai": "azure_openai_api_key"}

    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        outer = QVBoxLayout(self)
        outer.addWidget(page_header(t("nav.settings"), "Les clés d'API sont chiffrées localement (Fernet, clé protégée par DPAPI "
                                    "sous Windows) et ne sont jamais affichées ni journalisées."))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        lay = QVBoxLayout(body)
        s = state.ctx.settings
        # --- général
        g = QGroupBox("Général")
        f = QFormLayout(g)
        self.lang = QComboBox()
        self.lang.addItem("Français", "fr")
        self.lang.addItem("English", "en")
        self.lang.setCurrentIndex(0 if s.language == "fr" else 1)
        self.analyst = QLineEdit(s.analyst_name)
        self.privacy = QCheckBox("Mode Privacy Protection (aucune donnée transmise à des services externes)")
        self.privacy.setChecked(s.privacy_mode)
        f.addRow("Langue", self.lang)
        f.addRow("Nom de l'analyste", self.analyst)
        f.addRow(self.privacy)
        lay.addWidget(g)
        # --- IA
        g = QGroupBox("Moteur IA")
        f = QFormLayout(g)
        self.provider = QComboBox()
        for k, label in (("local", "Moteur local déterministe (hors ligne)"), ("openai", "OpenAI"),
                         ("anthropic", "Anthropic Claude"), ("azure_openai", "Azure OpenAI"), ("ollama", "Ollama (local)")):
            self.provider.addItem(label, k)
        self.provider.setCurrentIndex(max(0, self.provider.findData(s.ai.provider)))
        self.openai_model = QLineEdit(s.ai.openai_model)
        self.anthropic_model = QLineEdit(s.ai.anthropic_model)
        self.azure_endpoint = QLineEdit(s.ai.azure_endpoint)
        self.azure_deployment = QLineEdit(s.ai.azure_deployment)
        self.azure_version = QLineEdit(s.ai.azure_api_version)
        self.ollama_url = QLineEdit(s.ai.ollama_url)
        self.ollama_model = QLineEdit(s.ai.ollama_model)
        self.ai_timeout = QDoubleSpinBox()
        self.ai_timeout.setRange(5, 600)
        self.ai_timeout.setValue(s.ai.timeout_seconds)
        self.ai_max = QSpinBox()
        self.ai_max.setRange(10, 500)
        self.ai_max.setValue(s.ai.max_events_in_prompt)
        self.ai_keys = {}
        f.addRow("Fournisseur", self.provider)
        f.addRow("Modèle OpenAI", self.openai_model)
        f.addRow("Modèle Anthropic", self.anthropic_model)
        f.addRow("Azure : endpoint", self.azure_endpoint)
        f.addRow("Azure : déploiement", self.azure_deployment)
        f.addRow("Azure : version d'API", self.azure_version)
        f.addRow("Ollama : URL", self.ollama_url)
        f.addRow("Ollama : modèle", self.ollama_model)
        f.addRow("Délai d'attente (s)", self.ai_timeout)
        f.addRow("Événements max. transmis", self.ai_max)
        for prov, name in self.AI_KEYS.items():
            e = QLineEdit()
            e.setEchoMode(QLineEdit.Password)
            self.ai_keys[name] = e
            f.addRow(f"Clé API {prov}", e)
        self.btn_test = QPushButton("Tester la connexion IA")
        self.btn_test.clicked.connect(self.test_ai)
        f.addRow(self.btn_test)
        lay.addWidget(g)
        # --- TI
        g = QGroupBox("Threat intelligence")
        f = QFormLayout(g)
        self.ti_enabled = {}
        for p in TI_PROVIDERS:
            cb = QCheckBox(p)
            cb.setChecked(s.ti.enabled.get(p, False))
            self.ti_enabled[p] = cb
            f.addRow(cb)
        self.ti_keys = {}
        for name in sorted(set(SECRET_NAMES.values())):
            e = QLineEdit()
            e.setEchoMode(QLineEdit.Password)
            self.ti_keys[name] = e
            label = {"abusech_auth_key": "Auth-Key abuse.ch (URLhaus, MalwareBazaar, ThreatFox)"}.get(name, name)
            f.addRow(label, e)
        self.ti_cache = QSpinBox()
        self.ti_cache.setRange(0, 720)
        self.ti_cache.setValue(s.ti.cache_hours)
        f.addRow("Durée du cache (h)", self.ti_cache)
        lay.addWidget(g)
        # --- limites
        g = QGroupBox("Sécurité de l'import (limites)")
        f = QFormLayout(g)
        self.limits = {}
        for key, label, lo, hi in (("max_file_mb", "Taille max. par fichier (Mo)", 1, 4096),
                                   ("max_zip_total_mb", "Taille max. décompressée (Mo)", 1, 16384),
                                   ("max_zip_entries", "Entrées max. par archive", 1, 100000),
                                   ("max_zip_ratio", "Ratio de compression max.", 5, 10000),
                                   ("max_zip_depth", "Profondeur max. d'archives imbriquées", 0, 5),
                                   ("max_events_per_file", "Événements max. par fichier", 1000, 10_000_000)):
            sp = QSpinBox()
            sp.setRange(lo, hi)
            sp.setValue(getattr(s.limits, key))
            self.limits[key] = sp
            f.addRow(label, sp)
        lay.addWidget(g)
        # --- accès et données
        g = QGroupBox("Contrôle d'accès et données")
        f = QFormLayout(g)
        self.pw_state = QLabel()
        self.btn_pw = QPushButton("Définir / changer le mot de passe")
        self.btn_pw.clicked.connect(self.set_password)
        self.btn_pw_rm = QPushButton("Supprimer le mot de passe")
        self.btn_pw_rm.clicked.connect(self.remove_password)
        self.backups = QSpinBox()
        self.backups.setRange(1, 100)
        self.backups.setValue(s.backups_to_keep)
        self.btn_backup = QPushButton("Sauvegarder la base maintenant")
        self.btn_backup.clicked.connect(self.backup)
        self.btn_data = QPushButton("Ouvrir le dossier des données")
        self.btn_data.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(state.ctx.paths.home))))
        self.btn_logs = QPushButton("Ouvrir le journal de l'application")
        self.btn_logs.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(state.ctx.paths.logs))))
        f.addRow("Mot de passe local", self.pw_state)
        f.addRow(self.btn_pw, self.btn_pw_rm)
        f.addRow("Sauvegardes conservées", self.backups)
        f.addRow(self.btn_backup, self.btn_data)
        f.addRow(self.btn_logs)
        f.addRow("Dossier des données", QLabel(str(state.ctx.paths.home)))
        lay.addWidget(g)
        lay.addStretch(1)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)
        self.btn_save = QPushButton(t("btn.save"))
        self.btn_save.setObjectName("Primary")
        self.btn_save.clicked.connect(self.save)
        outer.addWidget(self.btn_save, 0, Qt.AlignRight)
        self._refresh_secret_hints()

    def _refresh_secret_hints(self) -> None:
        sec = self.state.ctx.secrets
        for name, e in {**self.ai_keys, **self.ti_keys}.items():
            e.setPlaceholderText("•••••••• enregistrée (laisser vide pour conserver, « - » pour effacer)" if sec.has(name)
                                 else "non configurée")
        self.pw_state.setText("défini" if self.state.ctx.settings.password_hash else "aucun (accès libre à la session Windows)")

    def apply(self) -> None:
        s = self.state.ctx.settings
        s.language = self.lang.currentData()
        s.analyst_name = self.analyst.text().strip() or "Analyste SOC"
        s.privacy_mode = self.privacy.isChecked()
        a = s.ai
        a.provider = self.provider.currentData()
        a.openai_model, a.anthropic_model = self.openai_model.text().strip(), self.anthropic_model.text().strip()
        a.azure_endpoint, a.azure_deployment = self.azure_endpoint.text().strip(), self.azure_deployment.text().strip()
        a.azure_api_version = self.azure_version.text().strip() or "2024-10-21"
        a.ollama_url, a.ollama_model = self.ollama_url.text().strip(), self.ollama_model.text().strip()
        a.timeout_seconds, a.max_events_in_prompt = self.ai_timeout.value(), self.ai_max.value()
        s.ti.enabled = {p: cb.isChecked() for p, cb in self.ti_enabled.items()}
        s.ti.cache_hours = self.ti_cache.value()
        for k, sp in self.limits.items():
            setattr(s.limits, k, sp.value())
        s.backups_to_keep = self.backups.value()
        sec = self.state.ctx.secrets
        for name, e in {**self.ai_keys, **self.ti_keys}.items():
            v = e.text().strip()
            if v == "-":
                sec.set(name, None)
            elif v:
                sec.set(name, v)
            e.clear()

    def save(self) -> None:
        old_lang = self.state.ctx.settings.language
        try:
            self.apply()
            self.state.ctx.save_settings()
        except Exception as exc:  # noqa: BLE001
            error_box(self, "Paramètres", f"Enregistrement impossible : {exc}")
            return
        self.state.svc.audit("settings.save", f"privacy={self.state.ctx.settings.privacy_mode} "
                                              f"ai={self.state.ctx.settings.ai.provider}")
        self._refresh_secret_hints()
        self.state.data_changed.emit()
        msg = "Paramètres enregistrés."
        if old_lang != self.state.ctx.settings.language:
            msg += "\n" + t("lang.restart")
        info_box(self, "Paramètres", msg)

    def test_ai(self) -> None:
        try:
            self.apply()
        except Exception as exc:  # noqa: BLE001
            error_box(self, "Paramètres", str(exc))
            return
        self.btn_test.setEnabled(False)
        w = Worker(test_connection, self.state.ctx.settings, self.state.ctx.secrets, with_progress=False)
        w.signals.finished.connect(lambda m: (self.btn_test.setEnabled(True), info_box(self, "Moteur IA", m)))
        w.signals.error.connect(lambda m: (self.btn_test.setEnabled(True), error_box(self, "Moteur IA", m)))
        start(w)

    def set_password(self) -> None:
        pw, ok = QInputDialog.getText(self, "Mot de passe", "Nouveau mot de passe (12 caractères minimum) :", QLineEdit.Password)
        if not ok:
            return
        if len(pw) < 12:
            QMessageBox.warning(self, "Mot de passe", "12 caractères minimum.")
            return
        pw2, ok = QInputDialog.getText(self, "Mot de passe", "Confirmation :", QLineEdit.Password)
        if not ok or pw2 != pw:
            QMessageBox.warning(self, "Mot de passe", "Les mots de passe ne correspondent pas.")
            return
        self.state.ctx.settings.password_hash = hash_password(pw)
        self.state.ctx.save_settings()
        self.state.svc.audit("security.password_set")
        self._refresh_secret_hints()
        info_box(self, "Mot de passe", "Mot de passe défini : il sera demandé au prochain démarrage.")

    def remove_password(self) -> None:
        if not self.state.ctx.settings.password_hash:
            info_box(self, "Mot de passe", "Aucun mot de passe défini.")
            return
        if QMessageBox.question(self, "Mot de passe", "Supprimer le mot de passe local ?") == QMessageBox.Yes:
            self.state.ctx.settings.password_hash = ""
            self.state.ctx.save_settings()
            self.state.svc.audit("security.password_removed")
            self._refresh_secret_hints()

    def backup(self) -> None:
        try:
            p = self.state.ctx.db.backup(self.state.ctx.paths.backups, self.state.ctx.settings.backups_to_keep)
        except Exception as exc:  # noqa: BLE001
            error_box(self, "Sauvegarde", str(exc))
            return
        self.state.svc.audit("db.backup", str(p))
        info_box(self, "Sauvegarde", f"Base sauvegardée : {p}")

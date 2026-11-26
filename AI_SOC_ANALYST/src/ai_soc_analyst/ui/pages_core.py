"""Pages : tableau de bord, nouvelle investigation, file des incidents, historique."""
from __future__ import annotations

import csv
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPlainTextEdit, QProgressBar,
                               QPushButton, QSplitter, QTabWidget, QVBoxLayout, QWidget)

from ..analysis.results import STATUS_FR
from . import theme
from .i18n import t
from .widgets import (BarChart, Card, DonutChart, DropZone, error_box, fill_table, info_box, make_table, page_header,
                      selected_data)
from .workers import Worker, start

STATUS_LABEL = {"new": "Nouvelle", "importing": "Import en cours", "analyzing": "Analyse en cours",
                "completed": "Terminée", "failed": "En échec", "interrupted": "Interrompue"}
SEV_COLORS = {4: theme.SEVERITY}
VERDICT_COLORS = theme.VERDICT


def _fmt_dt(d) -> str:  # noqa: ANN001
    return d.strftime("%Y-%m-%d %H:%M") if d else ""


# =====================================================================================================================
class DashboardPage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(page_header(t("nav.dashboard"), "Indicateurs calculés en temps réel depuis la base locale des investigations."), 1)
        self.btn_refresh = QPushButton(t("btn.refresh"))
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_new = QPushButton("+ " + t("nav.new"))
        self.btn_new.setObjectName("Primary")
        self.btn_new.clicked.connect(lambda: state.navigate.emit("new"))
        top.addWidget(self.btn_refresh)
        top.addWidget(self.btn_new)
        lay.addLayout(top)
        grid = QGridLayout()
        self.cards = {
            "total": Card(t("dash.total")), "critical": Card(t("dash.critical"), color=theme.SEVERITY["Critical"]),
            "high": Card(t("dash.high"), color=theme.SEVERITY["High"]),
            "medium": Card(t("dash.medium"), color=theme.SEVERITY["Medium"]),
            "low": Card(t("dash.low"), color=theme.SEVERITY["Low"]),
            "confirmed": Card(t("dash.confirmed"), color=theme.VERDICT["Confirmed"]),
            "false_positives": Card(t("dash.fp"), color=theme.VERDICT["False Positive"]),
            "avg_seconds": Card(t("dash.avg"), color=theme.TEAL),
        }
        for i, c in enumerate(self.cards.values()):
            grid.addWidget(c, i // 4, i % 4)
        lay.addLayout(grid)
        charts = QHBoxLayout()
        self.sev_chart = DonutChart("Répartition par sévérité")
        self.cat_chart = BarChart(t("dash.categories"))
        self.mitre_chart = BarChart(t("dash.mitre"))
        for c in (self.sev_chart, self.cat_chart, self.mitre_chart):
            box = QGroupBox()
            QVBoxLayout(box).addWidget(c)
            charts.addWidget(box, 1)
        lay.addLayout(charts)
        lay.addWidget(QLabel(t("dash.recent")))
        self.table = make_table(["Référence", "Titre", "Sévérité", "Verdict", "Statut", "Créée le"])
        self.table.doubleClicked.connect(self._open)
        lay.addWidget(self.table, 1)
        state.data_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        try:
            d = self.state.svc.dashboard()
        except Exception as exc:  # noqa: BLE001
            error_box(self, "Tableau de bord", f"Lecture de la base impossible : {exc}")
            return
        for k, card in self.cards.items():
            card.set_value(f"{d[k]:.2f} s" if k == "avg_seconds" else str(d[k]))
        self.sev_chart.set_data([(s, d[k], theme.SEVERITY[s]) for s, k in
                                 (("Critical", "critical"), ("High", "high"), ("Medium", "medium"), ("Low", "low"))])
        self.cat_chart.set_data(d["categories"])
        self.mitre_chart.set_data(d["techniques"])
        rows = [[r[1], r[2], r[3], r[4], STATUS_LABEL.get(r[5], r[5]), _fmt_dt(r[6])] for r in d["recent"]]
        fill_table(self.table, rows, {2: theme.SEVERITY, 3: VERDICT_COLORS}, [r[0] for r in d["recent"]])

    def _open(self) -> None:
        inv_id = selected_data(self.table)
        if inv_id:
            self.state.open(inv_id)


# =====================================================================================================================
class NewInvestigationPage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        self.files: list[Path] = []
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.new"), "Incident intake : fichiers (import multiple, glisser-déposer), journaux collés "
                                  "ou saisie manuelle. Les fichiers sont copiés en quarantaine en lecture seule et ne sont "
                                  "jamais exécutés."))
        self.title = QLineEdit()
        self.title.setPlaceholderText("Titre de l'investigation (ex. Alerte EDR poste FIN-LT-042)")
        lay.addWidget(self.title)
        tabs = QTabWidget()
        # --- fichiers
        ftab = QWidget()
        fl = QVBoxLayout(ftab)
        self.drop = DropZone(t("drop.hint"))
        self.drop.files_dropped.connect(self.add_files)
        fl.addWidget(self.drop)
        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QListWidget.ExtendedSelection)
        fl.addWidget(self.file_list, 1)
        row = QHBoxLayout()
        self.btn_add = QPushButton(t("btn.add_files"))
        self.btn_add.clicked.connect(self._browse)
        self.btn_remove = QPushButton(t("btn.remove"))
        self.btn_remove.clicked.connect(self._remove)
        self.btn_clear = QPushButton(t("btn.clear"))
        self.btn_clear.clicked.connect(self._clear)
        for b in (self.btn_add, self.btn_remove, self.btn_clear):
            row.addWidget(b)
        row.addStretch(1)
        fl.addLayout(row)
        tabs.addTab(ftab, "Fichiers")
        # --- coller
        self.paste = QPlainTextEdit()
        self.paste.setPlaceholderText("Collez ici des journaux bruts (Syslog, CEF, LEEF, JSON, CSV, clé=valeur, texte d'alerte…)")
        tabs.addTab(self.paste, "Coller des journaux")
        # --- manuel
        mtab = QWidget()
        form = QFormLayout(mtab)
        self.m = {}
        for key, label in (("alert_name", "Nom de l'alerte"), ("source", "Source (EDR, SIEM…)"),
                           ("host", "Hôte"), ("user", "Utilisateur"), ("src_ip", "IP source"), ("dst_ip", "IP destination"),
                           ("process", "Processus"), ("command_line", "Ligne de commande"), ("file_hash", "Hash"),
                           ("timestamp", "Date/heure (ISO 8601)"), ("critical_asset", "Actif critique (oui/non)")):
            w = QLineEdit()
            self.m[key] = w
            form.addRow(label, w)
        self.m_sev = QComboBox()
        self.m_sev.addItems(["", "Critical", "High", "Medium", "Low", "Informational"])
        form.addRow("Sévérité initiale", self.m_sev)
        self.m_desc = QPlainTextEdit()
        self.m_desc.setMaximumHeight(100)
        form.addRow("Description", self.m_desc)
        tabs.addTab(mtab, "Saisie manuelle")
        lay.addWidget(tabs, 1)
        bottom = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.stage = QLabel("Prêt.")
        self.stage.setStyleSheet(f"color:{theme.MUTED}")
        self.btn_run = QPushButton(t("btn.run"))
        self.btn_run.setObjectName("Primary")
        self.btn_run.clicked.connect(self.run)
        bottom.addWidget(self.progress, 2)
        bottom.addWidget(self.stage, 3)
        bottom.addWidget(self.btn_run)
        lay.addLayout(bottom)

    # ---------------------------------------------------------------- fichiers
    def add_files(self, paths: list) -> None:
        known = {str(p) for p in self.files}
        for p in paths:
            p = Path(p)
            if str(p) not in known and p.is_file():
                self.files.append(p)
                known.add(str(p))
                item = QListWidgetItem(f"{p.name}    ({p.stat().st_size:,} o)    {p.parent}")
                item.setData(Qt.UserRole, str(p))
                self.file_list.addItem(item)

    def _browse(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Sélection des preuves", "",
                                                "Preuves (*.json *.ndjson *.jsonl *.csv *.txt *.log *.xml *.evtx *.eml *.msg "
                                                "*.pdf *.docx *.xlsx *.zip);;Tous les fichiers (*)")
        self.add_files(paths)

    def _remove(self) -> None:
        for item in self.file_list.selectedItems():
            self.files = [p for p in self.files if str(p) != item.data(Qt.UserRole)]
            self.file_list.takeItem(self.file_list.row(item))

    def _clear(self) -> None:
        self.files.clear()
        self.file_list.clear()

    def manual_fields(self) -> dict:
        d = {k: w.text().strip() for k, w in self.m.items() if w.text().strip()}
        if self.m_sev.currentText():
            d["severity"] = self.m_sev.currentText()
        if self.m_desc.toPlainText().strip():
            d["description"] = self.m_desc.toPlainText().strip()
        return d

    # ---------------------------------------------------------------- exécution
    def run(self) -> None:
        manual = self.manual_fields()
        pasted = self.paste.toPlainText()
        if not self.files and not pasted.strip() and not manual:
            QMessageBox.warning(self, "Investigation", "Ajoutez au moins un fichier, des journaux collés ou une saisie manuelle.")
            return
        try:
            inv_id = self.state.svc.create(self.title.text(), manual=manual, pasted_text=pasted)
        except Exception as exc:  # noqa: BLE001
            error_box(self, "Investigation", f"Création impossible : {exc}")
            return
        self.btn_run.setEnabled(False)
        self.state.running.add(inv_id)
        self.state.busy.emit(True, "Investigation en cours…")
        w = Worker(self.state.svc.run, inv_id, list(self.files))
        w.signals.progress.connect(self._on_progress)
        w.signals.finished.connect(lambda res, i=inv_id: self._done(i, res))
        w.signals.error.connect(lambda msg, i=inv_id: self._failed(i, msg))
        start(w)
        self.state.data_changed.emit()

    def _on_progress(self, v: int, msg: str) -> None:
        self.progress.setValue(v)
        self.stage.setText(msg)

    def _done(self, inv_id: int, res) -> None:  # noqa: ANN001
        self.state.running.discard(inv_id)
        self.state.busy.emit(False, "")
        self.btn_run.setEnabled(True)
        self.progress.setValue(100)
        self.stage.setText(f"Terminé : {res.verdict} / {res.severity} (score {res.risk_score})")
        self._clear()
        self.paste.clear()
        self.title.clear()
        for w in self.m.values():
            w.clear()
        self.m_desc.clear()
        self.m_sev.setCurrentIndex(0)
        self.state.data_changed.emit()
        self.state.open(inv_id)

    def _failed(self, inv_id: int, msg: str) -> None:
        self.state.running.discard(inv_id)
        self.state.busy.emit(False, "")
        self.btn_run.setEnabled(True)
        self.stage.setText("Échec : " + msg)
        self.state.data_changed.emit()
        error_box(self, "Investigation", f"L'investigation a échoué : {msg}\nElle reste disponible dans la file des incidents "
                                         "et peut être reprise.")


# =====================================================================================================================
class QueuePage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.queue"), "Toutes les investigations, filtrables par statut, sévérité et texte."))
        f = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Rechercher (référence, titre, type)…")
        self.search.returnPressed.connect(self.refresh)
        self.status = QComboBox()
        self.status.addItem("Tous statuts", None)
        for k, v in STATUS_LABEL.items():
            self.status.addItem(v, k)
        self.sev = QComboBox()
        self.sev.addItem("Toutes sévérités", None)
        for s in ("Critical", "High", "Medium", "Low", "Informational", "Unknown"):
            self.sev.addItem(s, s)
        self.status.currentIndexChanged.connect(self.refresh)
        self.sev.currentIndexChanged.connect(self.refresh)
        self.btn_refresh = QPushButton(t("btn.refresh"))
        self.btn_refresh.clicked.connect(self.refresh)
        for w in (self.search, self.status, self.sev, self.btn_refresh):
            f.addWidget(w)
        lay.addLayout(f)
        self.table = make_table(["Référence", "Titre", "Sévérité", "Verdict", "Confiance", "Score", "Type", "Statut",
                                 "Étape / erreur", "Analyste", "Créée le"])
        self.table.doubleClicked.connect(self.open_selected)
        lay.addWidget(self.table, 1)
        b = QHBoxLayout()
        self.btn_open = QPushButton(t("btn.open"))
        self.btn_open.setObjectName("Primary")
        self.btn_open.clicked.connect(self.open_selected)
        self.btn_resume = QPushButton(t("btn.resume") + " / " + t("btn.reanalyze"))
        self.btn_resume.clicked.connect(self.resume_selected)
        self.btn_delete = QPushButton(t("btn.delete"))
        self.btn_delete.setObjectName("Danger")
        self.btn_delete.clicked.connect(self.delete_selected)
        for w in (self.btn_open, self.btn_resume, self.btn_delete):
            b.addWidget(w)
        b.addStretch(1)
        lay.addLayout(b)
        state.data_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        invs = self.state.svc.list(self.status.currentData(), self.sev.currentData(), self.search.text().strip())
        rows = [[i.reference, i.title, i.severity, i.verdict, f"{i.confidence:.0%}", i.risk_score, i.incident_type,
                 STATUS_LABEL.get(i.status, i.status), i.error or i.stage, i.analyst, _fmt_dt(i.created_at)] for i in invs]
        fill_table(self.table, rows, {2: theme.SEVERITY, 3: VERDICT_COLORS}, [i.id for i in invs])

    def open_selected(self) -> None:
        inv_id = selected_data(self.table)
        if inv_id:
            self.state.open(inv_id)
        else:
            info_box(self, "File des incidents", "Sélectionnez une investigation.")

    def resume_selected(self) -> None:
        inv_id = selected_data(self.table)
        if not inv_id:
            info_box(self, "File des incidents", "Sélectionnez une investigation.")
            return
        if inv_id in self.state.running:
            info_box(self, "File des incidents", "Cette investigation est déjà en cours de traitement.")
            return
        self.state.running.add(inv_id)
        self.state.busy.emit(True, "Analyse en cours…")
        w = Worker(self.state.svc.resume, inv_id)
        w.signals.finished.connect(lambda _r, i=inv_id: self._end(i, None))
        w.signals.error.connect(lambda m, i=inv_id: self._end(i, m))
        start(w)
        self.refresh()

    def _end(self, inv_id: int, err: str | None) -> None:
        self.state.running.discard(inv_id)
        self.state.busy.emit(False, "")
        self.state.data_changed.emit()
        if err:
            error_box(self, "Reprise", err)
        else:
            self.state.open(inv_id)

    def delete_selected(self) -> None:
        inv_id = selected_data(self.table)
        if not inv_id:
            info_box(self, "File des incidents", "Sélectionnez une investigation.")
            return
        if inv_id in self.state.running:
            info_box(self, "File des incidents", "Impossible de supprimer une investigation en cours.")
            return
        if QMessageBox.question(self, "Suppression", "Supprimer définitivement cette investigation et ses données "
                                "(les fichiers en quarantaine sont conservés) ?") == QMessageBox.Yes:
            self.state.svc.delete(inv_id)
            if self.state.current_id == inv_id:
                self.state.current_id = None
            self.state.data_changed.emit()


# =====================================================================================================================
class HistoryPage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.history"), "Investigations terminées et journal d'audit des opérations (traçabilité)."))
        tabs = QTabWidget()
        w1 = QWidget()
        l1 = QVBoxLayout(w1)
        self.table = make_table(["Référence", "Titre", "Verdict", "Sévérité", "Type", "Catégorie", "Durée (s)", "Terminée le"])
        self.table.doubleClicked.connect(self._open)
        l1.addWidget(self.table)
        tabs.addTab(w1, "Investigations terminées")
        w2 = QWidget()
        l2 = QVBoxLayout(w2)
        self.audit = make_table(["Date (UTC)", "Acteur", "Action", "Investigation", "Détails"])
        l2.addWidget(self.audit)
        tabs.addTab(w2, "Journal d'audit")
        lay.addWidget(tabs, 1)
        row = QHBoxLayout()
        self.btn_refresh = QPushButton(t("btn.refresh"))
        self.btn_refresh.clicked.connect(self.refresh)
        self.btn_open = QPushButton(t("btn.open"))
        self.btn_open.clicked.connect(self._open)
        self.btn_export = QPushButton("Exporter l'historique (CSV)…")
        self.btn_export.clicked.connect(self.export_csv)
        for b in (self.btn_refresh, self.btn_open, self.btn_export):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        state.data_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        invs = self.state.svc.list("completed")
        self._rows = [[i.reference, i.title, i.verdict, i.severity, i.incident_type, i.threat_category, i.duration_seconds,
                       _fmt_dt(i.updated_at)] for i in invs]
        fill_table(self.table, self._rows, {2: VERDICT_COLORS, 3: theme.SEVERITY}, [i.id for i in invs])
        refs = {i.id: i.reference for i in self.state.svc.list()}
        logs = self.state.svc.audit_log(1000)
        fill_table(self.audit, [[_fmt_dt(a.ts), a.actor, a.action, refs.get(a.investigation_id, a.investigation_id or ""),
                                 a.details] for a in logs])

    def _open(self) -> None:
        inv_id = selected_data(self.table)
        if inv_id:
            self.state.open(inv_id)

    def export_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Exporter l'historique", "historique_investigations.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh, delimiter=";")
            w.writerow(["Référence", "Titre", "Verdict", "Sévérité", "Type", "Catégorie", "Durée (s)", "Terminée le"])
            w.writerows(self._rows)
        info_box(self, "Historique", f"Exporté : {path}")


__all__ = ["DashboardPage", "NewInvestigationPage", "QueuePage", "HistoryPage", "STATUS_LABEL", "STATUS_FR", "QSplitter"]

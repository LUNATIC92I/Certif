"""Espace d'investigation : synthèse, preuves, événements, détections, processus, chronologie, IOC, MITRE, IA, notes."""
from __future__ import annotations

import json

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                               QSplitter, QTabWidget, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..ai.engine import AIError, run_ai_analysis
from ..analysis.results import STATUS_FR
from . import theme
from .i18n import t
from .widgets import error_box, fill_table, info_box, make_table, page_header
from .workers import Worker, start


def _esc(s) -> str:  # noqa: ANN001
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class WorkspacePage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        self.inv_id: int | None = None
        lay = QVBoxLayout(self)
        self.header = page_header(t("nav.workspace"), "Aucune investigation ouverte : sélectionnez-en une dans la file des incidents.")
        lay.addWidget(self.header)
        bar = QHBoxLayout()
        self.btn_add = QPushButton("Ajouter des preuves…")
        self.btn_add.clicked.connect(self.add_evidence)
        self.btn_reanalyze = QPushButton(t("btn.reanalyze"))
        self.btn_reanalyze.clicked.connect(self.reanalyze)
        self.btn_ai = QPushButton("Analyse IA (fournisseur configuré)")
        self.btn_ai.setObjectName("Primary")
        self.btn_ai.clicked.connect(self.run_ai)
        self.btn_report = QPushButton("Générer un rapport →")
        self.btn_report.clicked.connect(lambda: self.state.navigate.emit("reports"))
        self.btn_response = QPushButton("Réponse à incident →")
        self.btn_response.clicked.connect(lambda: self.state.navigate.emit("response"))
        self.btn_ioc = QPushButton("IOC →")
        self.btn_ioc.clicked.connect(lambda: self.state.navigate.emit("ioc"))
        self.buttons = [self.btn_add, self.btn_reanalyze, self.btn_ai, self.btn_report, self.btn_response, self.btn_ioc]
        for b in self.buttons:
            bar.addWidget(b)
        bar.addStretch(1)
        self.busy = QLabel("")
        self.busy.setStyleSheet(f"color:{theme.TEAL}")
        bar.addWidget(self.busy)
        lay.addLayout(bar)

        self.tabs = QTabWidget()
        self.summary = QTextBrowser()
        self.summary.setOpenExternalLinks(False)
        self.tabs.addTab(self.summary, "Synthèse")
        self.files = make_table(["Fichier", "Format", "Source détectée", "Taille", "SHA256", "Statut", "Événements",
                                 "Importé le", "Message"])
        self.tabs.addTab(self.files, "Preuves")
        ev = QWidget()
        el = QVBoxLayout(ev)
        srow = QHBoxLayout()
        self.ev_search = QLineEdit()
        self.ev_search.setPlaceholderText("Filtrer les événements (texte, EVT-…, hôte, utilisateur, processus)…")
        self.ev_search.returnPressed.connect(self.load_events)
        self.btn_ev = QPushButton("Filtrer")
        self.btn_ev.clicked.connect(self.load_events)
        srow.addWidget(self.ev_search)
        srow.addWidget(self.btn_ev)
        el.addLayout(srow)
        split = QSplitter(Qt.Vertical)
        self.events = make_table(["Preuve", "Horodatage", "Source", "Type", "Hôte", "Utilisateur", "Processus", "Ligne de commande"])
        self.events.itemSelectionChanged.connect(self._show_raw)
        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        split.addWidget(self.events)
        split.addWidget(self.raw)
        split.setSizes([400, 160])
        el.addWidget(split)
        self.tabs.addTab(ev, "Événements")
        self.findings = make_table(["ID", "Règle", "Titre", "Catégorie", "Sévérité", "Statut", "Confiance", "MITRE",
                                    "Preuves", "Description"])
        self.tabs.addTab(self.findings, "Détections")
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Processus", "PID", "Utilisateur", "Ligne de commande", "SHA256", "Détections", "Preuve"])
        self.tabs.addTab(self.tree, "Arbre des processus")
        self.timeline = make_table(["Horodatage", "Preuve", "Hôte", "Utilisateur", "Type", "Tactique", "Détections", "Chaîne", "Résumé"])
        self.tabs.addTab(self.timeline, "Chronologie")
        self.chains = make_table(["Chaîne", "Hôtes", "Début", "Fin", "Événements", "Détections", "Écarts / limites"])
        self.tabs.addTab(self.chains, "Corrélation")
        self.iocs = make_table(["Indicateur", "Type", "Réputation", "Risque", "Source", "Justification", "Statut de validation"])
        self.tabs.addTab(self.iocs, "IOC")
        self.mitre = make_table(["Tactique", "Technique", "Nom", "Confiance", "Détections", "Preuves"])
        self.tabs.addTab(self.mitre, "MITRE ATT&&CK")
        self.ai = QTextBrowser()
        self.tabs.addTab(self.ai, "Analyse IA")
        nw = QWidget()
        nl = QVBoxLayout(nw)
        self.notes = QPlainTextEdit()
        self.notes.setPlaceholderText("Notes de l'analyste (conservées avec l'investigation et reprises dans le rapport technique).")
        self.btn_notes = QPushButton(t("btn.save"))
        self.btn_notes.clicked.connect(self.save_notes)
        nl.addWidget(self.notes)
        nl.addWidget(self.btn_notes, 0, Qt.AlignRight)
        self.tabs.addTab(nw, "Notes")
        lay.addWidget(self.tabs, 1)
        state.current_changed.connect(self.load)
        state.data_changed.connect(self._refresh_if_open)
        self._set_enabled(False)

    # ---------------------------------------------------------------- chargement
    def _set_enabled(self, on: bool) -> None:
        for b in self.buttons + [self.btn_notes, self.btn_ev]:
            b.setEnabled(on)

    def _refresh_if_open(self) -> None:
        if self.inv_id and self.isVisible():
            self.load(self.inv_id)

    def _title(self, text: str, sub: str) -> None:
        labels = self.header.findChildren(QLabel)
        labels[0].setText(text)
        labels[1].setText(sub)

    def load(self, inv_id: int) -> None:
        inv = self.state.svc.get(inv_id)
        if inv is None:
            self.inv_id = None
            self._set_enabled(False)
            self._title(t("nav.workspace"), "Investigation introuvable.")
            return
        self.inv_id = inv_id
        running = inv_id in self.state.running
        self._set_enabled(not running)
        self.busy.setText("Traitement en cours…" if running else "")
        self._title(f"{inv.reference} — {inv.title}",
                    f"Statut : {inv.status} · Sévérité : {inv.severity} · Verdict : {STATUS_FR.get(inv.verdict, inv.verdict)} "
                    f"· Confiance : {inv.confidence:.0%} · Score de risque : {inv.risk_score}/100 · Analyste : {inv.analyst}")
        res = inv.result()
        self._summary(inv, res)
        files = self.state.svc.files(inv_id)
        fill_table(self.files, [[f.original_name, f.detected_format, f.detected_source, f"{f.size:,}", f.sha256, f.status,
                                 f.event_count, f.imported_at.strftime("%Y-%m-%d %H:%M:%S") if f.imported_at else "",
                                 f.message] for f in files])
        self.load_events()
        fill_table(self.findings, [[f["finding_id"], f["rule_id"], f["title"], f["category"], f["severity"],
                                    STATUS_FR.get(f["status"], f["status"]), f"{f['confidence']:.0%}", ", ".join(f.get("mitre_ids", [])),
                                    ", ".join(f["evidence_ids"][:12]) + (" …" if len(f["evidence_ids"]) > 12 else ""),
                                    f["description"]] for f in res.get("findings", [])],
                   {4: theme.SEVERITY, 5: {STATUS_FR[k]: v for k, v in theme.VERDICT.items()}})
        self._tree(res.get("process_trees", []))
        fill_table(self.timeline, [[e["time"] or "(non horodaté)", e["evidence_id"], e["host"], e["user"], e["event_type"],
                                    e.get("tactic", ""), ", ".join(e.get("findings", [])), e.get("chain", ""), e["summary"]]
                                   for e in res.get("timeline", [])])
        for r in range(self.timeline.rowCount()):
            if self.timeline.item(r, 6) and self.timeline.item(r, 6).text():
                for c in range(self.timeline.columnCount()):
                    self.timeline.item(r, c).setForeground(QBrush(QColor(theme.SEVERITY["High"])))
        fill_table(self.chains, [[c["chain_id"], ", ".join(c.get("hosts", [])), c.get("start"), c.get("end"), c.get("event_count"),
                                  ", ".join(c.get("findings", [])), "; ".join(c.get("gaps", []))] for c in res.get("chains", [])])
        fill_table(self.iocs, [[i["value"], i["ioc_type"], i["reputation"], i["risk"], i["source"], i["justification"],
                                i["validation_status"]] for i in self._db_iocs(inv_id)],
                   {3: {"Critical": theme.SEVERITY["Critical"], "High": theme.SEVERITY["High"], "Medium": theme.SEVERITY["Medium"]}})
        fill_table(self.mitre, [[m["tactic"], m["technique_id"], m["technique_name"], f"{m.get('confidence', 0):.0%}",
                                 ", ".join(m.get("finding_ids", [])), ", ".join(m.get("evidence_ids", [])[:10])]
                                for m in res.get("mitre", [])])
        try:
            ai = json.loads(inv.ai_result_json or "{}")
        except ValueError:
            ai = {}
        self._ai(ai)
        self.notes.setPlainText(inv.analyst_notes or "")

    def _db_iocs(self, inv_id: int) -> list[dict]:
        return [{"value": i.value, "ioc_type": i.ioc_type, "reputation": i.reputation, "risk": i.risk, "source": i.source,
                 "justification": i.justification, "validation_status": i.validation_status}
                for i in self.state.svc.iocs(inv_id)]

    def _summary(self, inv, res: dict) -> None:  # noqa: ANN001
        if not res:
            msg = inv.error or "L'analyse n'a pas encore produit de résultat."
            self.summary.setHtml(f"<h3>Aucun résultat</h3><p>{_esc(msg)}</p><p>Utilisez « Réanalyser » pour (re)lancer l'analyse "
                                 "à partir des preuves déjà importées.</p>")
            return
        color = theme.VERDICT.get(res.get("verdict"), theme.TEXT)
        tri = res.get("triage", {})
        lim = "".join(f"<li>{_esc(x)}</li>" for x in res.get("limitations", []))
        recs = "".join(f"<li><b>{_esc(r['action_type'])}</b> → {_esc(r['target'])} <i>({_esc(r['priority'])})</i> : "
                       f"{_esc(r['justification'])}</li>" for r in res.get("recommendations", []))
        html = f"""
        <h2 style="color:{color}">Verdict : {_esc(STATUS_FR.get(res.get('verdict'), res.get('verdict')))}
          — confiance {res.get('confidence', 0):.0%}</h2>
        <p><b>Type d'incident :</b> {_esc(res.get('incident_type'))} &nbsp; · &nbsp; <b>Catégorie :</b> {_esc(res.get('threat_category'))}
          &nbsp; · &nbsp; <b>Sévérité :</b> {_esc(res.get('severity'))} &nbsp; · &nbsp; <b>Score :</b> {res.get('risk_score')}/100</p>
        <p><b>Base du verdict :</b> {_esc(res.get('stats', {}).get('verdict_basis', ''))}</p>
        <h3>Résumé</h3><p>{_esc(res.get('summary'))}</p>
        <h3>Triage</h3>
        <p><b>Sources :</b> {_esc(', '.join(tri.get('sources', [])))}<br><b>Hôtes :</b> {_esc(', '.join(tri.get('hosts', [])))}<br>
        <b>Utilisateurs :</b> {_esc(', '.join(tri.get('users', [])))}<br><b>Période :</b> {_esc(tri.get('first_seen'))} → {_esc(tri.get('last_seen'))}<br>
        <b>Sévérité initiale :</b> {_esc(tri.get('initial_severity'))}</p>
        <h3>Cause probable</h3><p>{_esc(res.get('root_cause'))}</p>
        <h3>Impact</h3><p>{_esc(res.get('impact'))}</p>
        <h3>Évaluation faux positif</h3><p>{_esc(res.get('false_positive_assessment'))}</p>
        <h3>Limites de l'analyse (données manquantes — non inventées)</h3><ul>{lim}</ul>
        <h3>Recommandations (propositions — aucune action exécutée)</h3><ul>{recs}</ul>
        """
        self.summary.setHtml(html)

    def load_events(self) -> None:
        if not self.inv_id:
            return
        evs = self.state.svc.events(self.inv_id, self.ev_search.text().strip(), 5000)
        self._raw = {e.evidence_id: e.raw for e in evs}
        fill_table(self.events, [[e.evidence_id, e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "(non horodaté)",
                                  e.source_product, e.event_type, e.host, e.user, e.process_name, e.command_line[:300]]
                                 for e in evs])

    def _show_raw(self) -> None:
        rows = self.events.selectionModel().selectedRows()
        if rows:
            eid = self.events.item(rows[0].row(), 0).text()
            self.raw.setPlainText(self._raw.get(eid, ""))

    def _tree(self, trees: list[dict]) -> None:
        self.tree.clear()

        def add(parent, node: dict) -> None:  # noqa: ANN001
            name = node["process_name"] + (" (parent déduit, non observé)" if node.get("inferred") else "")
            item = QTreeWidgetItem([name, str(node.get("pid", "")), node.get("user", ""), node.get("command_line", ""),
                                    node.get("sha256", ""), ", ".join(node.get("findings", [])), node.get("evidence_id", "")])
            if node.get("findings"):
                for c in range(7):
                    item.setForeground(c, QBrush(QColor(theme.SEVERITY["High"])))
            (parent.addChild(item) if parent else self.tree.addTopLevelItem(item))
            for ch in node.get("children", []):
                add(item, ch)

        for n in trees[:300]:
            add(None, n)
        self.tree.expandAll()
        for c in range(7):
            self.tree.resizeColumnToContents(c)
            if self.tree.columnWidth(c) > 420:
                self.tree.setColumnWidth(c, 420)

    def _ai(self, ai: dict) -> None:
        if not ai:
            self.ai.setHtml("<p>Aucune analyse IA. Cliquez sur « Analyse IA » : le moteur local déterministe est utilisé par "
                            "défaut ; un fournisseur distant n'est sollicité que s'il est configuré et que le mode Privacy "
                            "Protection est désactivé.</p>")
            return
        parts = [f"<h3>Fournisseur : {_esc(ai.get('provider'))} ({_esc(ai.get('model'))})</h3>",
                 f"<p>{_esc(ai.get('executive_summary'))}</p><h3>Affirmations étayées par des preuves</h3><ul>"]
        for a in ai.get("assessments", []):
            parts.append(f"<li><b>[{_esc(STATUS_FR.get(a['status'], a['status']))} · {a['confidence']:.0%}]</b> "
                         f"{_esc(a['statement'])}<br><small>Preuves : {_esc(', '.join(a['evidence_ids']))} · MITRE : "
                         f"{_esc(', '.join(a.get('mitre', [])))}</small></li>")
        parts.append("</ul>")
        if ai.get("rejected_assessments"):
            parts.append("<h3>Affirmations rejetées (non étayées)</h3><ul>")
            parts += [f"<li>{_esc(a['statement'])} — <i>{_esc(a.get('rejection_reason'))}</i></li>" for a in ai["rejected_assessments"]]
            parts.append("</ul>")
        parts.append("<h3>Hypothèses (non vérifiées)</h3><ul>")
        parts += [f"<li>{_esc(h['hypothesis'])}<br><small>Validation : {_esc(h['how_to_validate'])}</small></li>"
                  for h in ai.get("hypotheses", [])]
        parts.append("</ul><h3>Requêtes complémentaires</h3><ul>")
        for q in ai.get("additional_queries", []):
            parts.append(f"<li><b>{_esc(q.get('purpose') or q.get('name') or q.get('language', ''))}</b>"
                         f"<pre>{_esc(q.get('query'))}</pre></li>")
        parts.append("</ul><h3>Données manquantes</h3><ul>" + "".join(f"<li>{_esc(g)}</li>" for g in ai.get("gaps", [])) + "</ul>")
        parts.append("<h3>Questions pour l'analyste</h3><ul>" +
                     "".join(f"<li>{_esc(q)}</li>" for q in ai.get("analyst_questions", [])) + "</ul>")
        self.ai.setHtml("".join(parts))

    # ---------------------------------------------------------------- actions
    def _job(self, fn, *args, label: str, done_msg: str = "") -> None:  # noqa: ANN001, ANN002
        inv_id = self.inv_id
        self.state.running.add(inv_id)
        self._set_enabled(False)
        self.busy.setText(label)
        self.state.busy.emit(True, label)
        w = Worker(fn, *args)
        w.signals.progress.connect(lambda v, m: self.busy.setText(f"{label} {v}% – {m}"))
        w.signals.finished.connect(lambda _r: self._job_end(inv_id, None, done_msg))
        w.signals.error.connect(lambda m: self._job_end(inv_id, m, ""))
        start(w)

    def _job_end(self, inv_id: int, err: str | None, done_msg: str) -> None:
        self.state.running.discard(inv_id)
        self.state.busy.emit(False, "")
        self.busy.setText("")
        self.state.data_changed.emit()
        if self.inv_id == inv_id:
            self.load(inv_id)
        if err:
            error_box(self, "Investigation", err)
        elif done_msg:
            self.state.busy.emit(False, done_msg)

    def add_evidence(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Ajouter des preuves à l'investigation")
        if paths:
            from pathlib import Path
            self._job(self.state.svc.add_files, self.inv_id, [Path(p) for p in paths], label="Import et réanalyse…")

    def reanalyze(self) -> None:
        self._job(self.state.svc.analyze, self.inv_id, label="Réanalyse…")

    def run_ai(self) -> None:
        inv = self.state.svc.get(self.inv_id)
        if not inv or inv.status != "completed":
            info_box(self, "Analyse IA", "L'investigation doit être terminée avant l'analyse IA.")
            return
        st = self.state.ctx.settings
        if st.ai.provider not in ("local", "ollama") and not st.privacy_mode:
            if QMessageBox.question(self, "Analyse IA", f"Le paquet de preuves (événements pertinents, détections, IOC) sera "
                                    f"transmis au fournisseur « {st.ai.provider} ». Continuer ?") != QMessageBox.Yes:
                return
        inv_id = self.inv_id
        res, evs = inv.result(), self.state.svc.load_events(inv_id)
        valid = set(self.state.ctx.catalog.index.get("techniques", {}).keys())

        def job(progress=None):  # noqa: ANN001, ANN202
            if progress:
                progress(10, "Préparation du paquet de preuves")
            try:
                data = run_ai_analysis(st, self.state.ctx.secrets, res, evs, valid)
            except AIError:
                raise
            self.state.svc.save_ai_result(inv_id, data)
            return data

        self._job(job, label="Analyse IA…", done_msg="Analyse IA terminée.")
        self.tabs.setCurrentWidget(self.ai)

    def save_notes(self) -> None:
        if self.inv_id:
            self.state.svc.save_notes(self.inv_id, self.notes.toPlainText())
            info_box(self, "Notes", "Notes enregistrées.")

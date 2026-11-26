"""Pages : IOC Intelligence, MITRE ATT&CK Explorer, Threat Hunting, Detection Engineering."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTabWidget, QTextBrowser, QVBoxLayout,
                               QWidget)

from ..detection import generator as det
from ..hunting import library as hunt
from ..ti.engine import TIEngine, detect_type
from . import theme
from .i18n import t
from .widgets import error_box, fill_table, info_box, make_table, page_header
from .workers import Worker, start


def _esc(s) -> str:  # noqa: ANN001
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inv_combo(state, include_none: str | None = None) -> QComboBox:  # noqa: ANN001
    cb = QComboBox()
    cb.setMinimumWidth(360)

    def reload() -> None:
        cur = cb.currentData()
        cb.blockSignals(True)
        cb.clear()
        if include_none:
            cb.addItem(include_none, None)
        for i in state.svc.list("completed"):
            cb.addItem(f"{i.reference} — {i.title[:60]}", i.id)
        idx = cb.findData(state.current_id if cur is None else cur)
        cb.setCurrentIndex(max(0, idx))
        cb.blockSignals(False)
        cb.currentIndexChanged.emit(cb.currentIndex())

    cb.reload = reload  # type: ignore[attr-defined]
    state.data_changed.connect(reload)
    state.current_changed.connect(lambda i: (cb.setCurrentIndex(max(0, cb.findData(i)))))
    return cb


# =====================================================================================================================
class IOCPage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.ioc"), "IOC extraits des preuves. Aucun indicateur n'est considéré malveillant sans "
                                  "élément de preuve ; la réputation n'est vérifiée qu'avec un fournisseur configuré et le mode "
                                  "Privacy Protection désactivé. Seuls des indicateurs publics sont transmis."))
        self.ti_status = QLabel()
        self.ti_status.setWordWrap(True)
        self.ti_status.setStyleSheet(f"color:{theme.SEVERITY['Medium']}")
        lay.addWidget(self.ti_status)
        row = QHBoxLayout()
        self.inv = _inv_combo(state)
        self.inv.currentIndexChanged.connect(self.refresh)
        self.risk = QComboBox()
        self.risk.addItems(["Tous niveaux de risque", "Critical", "High", "Medium", "Low", "Info"])
        self.risk.currentIndexChanged.connect(self.refresh)
        row.addWidget(QLabel("Investigation :"))
        row.addWidget(self.inv)
        row.addWidget(self.risk)
        row.addStretch(1)
        lay.addLayout(row)
        tabs = QTabWidget()
        w = QWidget()
        wl = QVBoxLayout(w)
        self.table = make_table(["Indicateur", "Type", "Réputation", "Risque", "Source", "Justification", "Statut de validation",
                                 "Occurrences", "Preuves"])
        wl.addWidget(self.table)
        b = QHBoxLayout()
        self.btn_lookup = QPushButton(t("btn.lookup") + " (sélection)")
        self.btn_lookup.setObjectName("Primary")
        self.btn_lookup.clicked.connect(self.lookup_selected)
        self.btn_copy = QPushButton(t("btn.copy"))
        self.btn_copy.clicked.connect(self.copy_selected)
        self.btn_csv = QPushButton("Exporter CSV…")
        self.btn_csv.clicked.connect(self.export_csv)
        for x in (self.btn_lookup, self.btn_copy, self.btn_csv):
            b.addWidget(x)
        b.addStretch(1)
        wl.addLayout(b)
        tabs.addTab(w, "IOC de l'investigation")
        m = QWidget()
        ml = QVBoxLayout(m)
        mr = QHBoxLayout()
        self.manual = QLineEdit()
        self.manual.setPlaceholderText("Indicateur à vérifier (hash, IP publique, domaine, URL)")
        self.manual.returnPressed.connect(self.lookup_manual)
        self.btn_manual = QPushButton(t("btn.lookup"))
        self.btn_manual.clicked.connect(self.lookup_manual)
        mr.addWidget(self.manual)
        mr.addWidget(self.btn_manual)
        ml.addLayout(mr)
        self.manual_out = QTextBrowser()
        ml.addWidget(self.manual_out)
        tabs.addTab(m, "Recherche manuelle")
        h = QWidget()
        hl = QVBoxLayout(h)
        self.hist = make_table(["Date (UTC)", "Fournisseur", "Indicateur", "Type", "Statut", "Verdict", "Cache", "Résumé"])
        hl.addWidget(self.hist)
        self.btn_hist = QPushButton(t("btn.refresh"))
        self.btn_hist.clicked.connect(self.refresh_history)
        hl.addWidget(self.btn_hist, 0, Qt.AlignLeft)
        tabs.addTab(h, "Historique des recherches TI")
        lay.addWidget(tabs, 1)
        self.inv.reload()
        self.refresh_history()

    def showEvent(self, e):  # noqa: N802, ANN001
        self.ti_status.setText(self.state.ti.status_text())
        super().showEvent(e)

    def refresh(self) -> None:
        self.ti_status.setText(self.state.ti.status_text())
        inv_id = self.inv.currentData()
        iocs = self.state.svc.iocs(inv_id) if inv_id else []
        r = self.risk.currentText()
        if r in ("Critical", "High", "Medium", "Low", "Info"):
            iocs = [i for i in iocs if i.risk == r]
        self._rows = [[i.value, i.ioc_type, i.reputation, i.risk, i.source, i.justification, i.validation_status,
                       i.occurrences, ", ".join(json.loads(i.evidence_ids or "[]")[:10])] for i in iocs]
        fill_table(self.table, self._rows, {3: {"Critical": theme.SEVERITY["Critical"], "High": theme.SEVERITY["High"],
                                                "Medium": theme.SEVERITY["Medium"]}},
                   [(i.value, i.ioc_type) for i in iocs])

    def _selected(self) -> list[tuple[str, str]]:
        out = []
        for idx in self.table.selectionModel().selectedRows():
            it = self.table.item(idx.row(), 0)
            out.append(it.data(Qt.UserRole))
        return out

    def copy_selected(self) -> None:
        sel = self._selected()
        if sel:
            QGuiApplication.clipboard().setText("\n".join(v for v, _ in sel))

    def lookup_selected(self) -> None:
        sel = self._selected()
        if not sel:
            info_box(self, "IOC", "Sélectionnez un ou plusieurs IOC.")
            return
        inv_id = self.inv.currentData()
        ti: TIEngine = self.state.ti

        def job(progress=None):  # noqa: ANN001, ANN202
            out = []
            for n, (value, typ) in enumerate(sel):
                if progress:
                    progress(int(100 * n / len(sel)), value)
                results = ti.lookup(value, typ, inv_id)
                rep, summary, risk = TIEngine.aggregate(results)
                if rep != "Non vérifiée":
                    self.state.svc.update_ioc_reputation(inv_id, value, rep, risk, summary[:200])
                out.append((value, rep, summary))
            return out

        self.btn_lookup.setEnabled(False)
        w = Worker(job)
        w.signals.progress.connect(lambda v, m: self.state.busy.emit(True, f"Réputation {v}% : {m}"))
        w.signals.finished.connect(self._lookup_done)
        w.signals.error.connect(lambda m: (self.btn_lookup.setEnabled(True), self.state.busy.emit(False, ""),
                                           error_box(self, "Threat intelligence", m)))
        start(w)

    def _lookup_done(self, out: list) -> None:  # noqa: ANN001
        self.btn_lookup.setEnabled(True)
        self.state.busy.emit(False, "")
        self.refresh()
        self.refresh_history()
        info_box(self, "Threat intelligence", "\n".join(f"{v[:70]} : {rep} — {s[:160]}" for v, rep, s in out))

    def lookup_manual(self) -> None:
        value = self.manual.text().strip()
        if not value:
            return
        typ = detect_type(value)
        self.btn_manual.setEnabled(False)
        w = Worker(self.state.ti.lookup, value, typ, None, with_progress=False)
        w.signals.finished.connect(lambda res: self._manual_done(value, typ, res))
        w.signals.error.connect(lambda m: (self.btn_manual.setEnabled(True), error_box(self, "Threat intelligence", m)))
        start(w)

    def _manual_done(self, value: str, typ: str, results: list) -> None:  # noqa: ANN001
        self.btn_manual.setEnabled(True)
        rep, summary, _ = TIEngine.aggregate(results)
        rows = "".join(f"<tr><td>{_esc(r.provider)}</td><td>{_esc(r.status)}</td><td>{_esc(r.verdict)}</td>"
                       f"<td>{_esc(r.summary)}</td><td>{'oui' if r.from_cache else 'non'}</td></tr>" for r in results)
        self.manual_out.setHtml(f"<h3>{_esc(value)} <small>({_esc(typ)})</small></h3><p><b>Réputation agrégée :</b> {_esc(rep)}</p>"
                                f"<table border='1' cellpadding='4' cellspacing='0'><tr><th>Fournisseur</th><th>Statut</th>"
                                f"<th>Verdict</th><th>Résumé</th><th>Cache</th></tr>{rows}</table>")
        self.refresh_history()

    def refresh_history(self) -> None:
        h = self.state.ti.history(500)
        fill_table(self.hist, [[x.created_at.strftime("%Y-%m-%d %H:%M:%S"), x.provider, x.indicator, x.ioc_type, x.status,
                                x.verdict, "oui" if x.from_cache else "non", x.summary] for x in h])

    def export_csv(self) -> None:
        if not getattr(self, "_rows", None):
            info_box(self, "IOC", "Aucun IOC à exporter.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter les IOC", f"{self.inv.currentText().split(' ')[0]}_iocs.csv",
                                              "CSV (*.csv)")
        if path:
            with open(path, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh, delimiter=";")
                w.writerow(["Indicateur", "Type", "Réputation", "Risque", "Source", "Justification", "Statut de validation",
                            "Occurrences", "Preuves"])
                w.writerows(self._rows)
            info_box(self, "IOC", f"Exporté : {path}")


# =====================================================================================================================
class MitrePage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.mitre"), "Référentiel MITRE ATT&CK (Enterprise, STIX officiel) et techniques observées "
                                  "dans les investigations — chaque association est justifiée par des détections et des preuves."))
        row = QHBoxLayout()
        self.version = QLabel()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Rechercher une technique (ID, nom, description)…")
        self.search.returnPressed.connect(self.do_search)
        self.btn_search = QPushButton("Rechercher")
        self.btn_search.clicked.connect(self.do_search)
        self.btn_update = QPushButton("Mettre à jour (en ligne)")
        self.btn_update.clicked.connect(self.update_online)
        self.btn_import = QPushButton("Importer un bundle STIX…")
        self.btn_import.clicked.connect(self.import_bundle)
        for w in (self.version, self.search, self.btn_search, self.btn_update, self.btn_import):
            row.addWidget(w)
        lay.addLayout(row)
        tabs = QTabWidget()
        ow = QWidget()
        ol = QVBoxLayout(ow)
        orow = QHBoxLayout()
        self.inv = _inv_combo(state, "Toutes les investigations")
        self.inv.currentIndexChanged.connect(self.refresh_observed)
        orow.addWidget(QLabel("Investigation :"))
        orow.addWidget(self.inv)
        orow.addStretch(1)
        ol.addLayout(orow)
        self.observed = make_table(["Tactique", "Technique", "Nom", "Investigation", "Confiance", "Détections", "Preuves"])
        self.observed.itemSelectionChanged.connect(lambda: self._detail_from(self.observed, 1))
        ol.addWidget(self.observed)
        tabs.addTab(ow, "Techniques observées")
        bw = QWidget()
        bl = QHBoxLayout(bw)
        self.tactics = QListWidget()
        self.tactics.setMaximumWidth(260)
        self.tactics.currentItemChanged.connect(self._tactic_selected)
        self.techs = make_table(["ID", "Nom", "Plateformes", "Sous-technique"])
        self.techs.itemSelectionChanged.connect(lambda: self._detail_from(self.techs, 0))
        bl.addWidget(self.tactics)
        bl.addWidget(self.techs, 1)
        tabs.addTab(bw, "Matrice (navigation par tactique)")
        split = QSplitter(Qt.Vertical)
        split.addWidget(tabs)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        split.addWidget(self.detail)
        split.setSizes([450, 220])
        lay.addWidget(split, 1)
        self.reload_catalog()
        self.inv.reload()

    def reload_catalog(self) -> None:
        c = self.state.ctx.catalog
        self.version.setText(f"ATT&CK {c.version} · {len(c.index.get('techniques', {}))} techniques · {c.origin}")
        self.tactics.clear()
        for tac in c.tactics_sorted():
            it = QListWidgetItem(f"{tac['id']}  {tac['name']}")
            it.setData(Qt.UserRole, tac["shortname"])
            self.tactics.addItem(it)
        if self.tactics.count():
            self.tactics.setCurrentRow(0)

    def _tactic_selected(self, item, _prev=None) -> None:  # noqa: ANN001
        if item:
            self._fill_techs(self.state.ctx.catalog.techniques_for_tactic(item.data(Qt.UserRole)))

    def _fill_techs(self, techs: list[dict]) -> None:
        fill_table(self.techs, [[x["id"], x["name"], ", ".join(x.get("platforms", [])), "oui" if x.get("is_subtechnique") else ""]
                                for x in techs])

    def do_search(self) -> None:
        q = self.search.text().strip()
        if q:
            self._fill_techs(self.state.ctx.catalog.search(q))

    def _detail_from(self, table, col: int) -> None:  # noqa: ANN001
        rows = table.selectionModel().selectedRows()
        if not rows:
            return
        tid = table.item(rows[0].row(), col).text()
        x = self.state.ctx.catalog.resolve(tid)
        if not x:
            self.detail.setHtml(f"<p>Technique {_esc(tid)} absente du référentiel chargé.</p>")
            return
        tac = ", ".join(self.state.ctx.catalog.tactic_name(s) for s in x.get("tactics", []))
        self.detail.setHtml(f"<h3>{_esc(x['id'])} — {_esc(x['name'])}</h3><p><b>Tactiques :</b> {_esc(tac)} · "
                            f"<b>Plateformes :</b> {_esc(', '.join(x.get('platforms', [])))} · "
                            f"<a href='{_esc(x.get('url'))}'>{_esc(x.get('url'))}</a></p><p>{_esc(x.get('description'))}</p>"
                            + (f"<h4>Détection</h4><p>{_esc(x.get('detection'))}</p>" if x.get("detection") else ""))

    def refresh_observed(self) -> None:
        inv_id = self.inv.currentData()
        invs = {i.id: i.reference for i in self.state.svc.list()}
        rows = []
        for iid in ([inv_id] if inv_id else list(invs)):
            for m in self.state.svc.mitre(iid):
                rows.append([m.tactic, m.technique_id, m.technique_name, invs.get(iid, iid), f"{m.confidence:.0%}",
                             ", ".join(json.loads(m.finding_ids or "[]")), ", ".join(json.loads(m.evidence_ids or "[]")[:10])])
        fill_table(self.observed, rows)

    def _run(self, fn, *args) -> None:  # noqa: ANN001, ANN002
        self.btn_update.setEnabled(False)
        self.btn_import.setEnabled(False)
        self.state.busy.emit(True, "Mise à jour ATT&CK…")
        w = Worker(fn, *args, with_progress=False)
        w.signals.finished.connect(self._updated)
        w.signals.error.connect(self._update_failed)
        start(w)

    def _updated(self, info: dict) -> None:
        self.btn_update.setEnabled(True)
        self.btn_import.setEnabled(True)
        self.state.busy.emit(False, "")
        self.reload_catalog()
        self.state.svc.audit("mitre.update", json.dumps(info))
        info_box(self, "MITRE ATT&CK", f"Référentiel mis à jour : version {info['version']}, {info['techniques']} techniques.")

    def _update_failed(self, msg: str) -> None:
        self.btn_update.setEnabled(True)
        self.btn_import.setEnabled(True)
        self.state.busy.emit(False, "")
        error_box(self, "MITRE ATT&CK", f"Mise à jour impossible (l'index actuel est conservé) : {msg}")

    def update_online(self) -> None:
        if QMessageBox.question(self, "MITRE ATT&CK", "Télécharger le bundle STIX officiel depuis GitHub (mitre-attack/"
                                "attack-stix-data, ~45 Mo) ? Aucune donnée n'est envoyée.") == QMessageBox.Yes:
            self._run(self.state.ctx.catalog.update_online)

    def import_bundle(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Bundle STIX ATT&CK", "", "JSON (*.json)")
        if path:
            def job() -> dict:
                return self.state.ctx.catalog.update_from_bundle(json.loads(Path(path).read_text(encoding="utf-8")))
            self._run(job)


# =====================================================================================================================
class HuntingPage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.hunting"), "Hypothèses de chasse structurées (objectif, comportements, sources, requêtes "
                                  "KQL / SPL / Sigma, résultats attendus, validation, recommandations). Les champs à adapter à "
                                  "votre environnement sont signalés."))
        split = QSplitter()
        self.list = QListWidget()
        self.list.setMaximumWidth(340)
        for h in hunt.HYPOTHESES:
            it = QListWidgetItem(f"{h.hid}  {h.name}")
            it.setData(Qt.UserRole, h.hid)
            self.list.addItem(it)
        self.list.currentItemChanged.connect(self.on_select)
        split.addWidget(self.list)
        right = QWidget()
        rl = QVBoxLayout(right)
        self.info = QTextBrowser()
        rl.addWidget(self.info, 2)
        self.qtabs = QTabWidget()
        self.kql, self.spl, self.sigma = QPlainTextEdit(), QPlainTextEdit(), QPlainTextEdit()
        for w, n in ((self.kql, "KQL (Defender / Sentinel)"), (self.spl, "SPL (Splunk)"), (self.sigma, "Sigma")):
            w.setReadOnly(True)
            w.setStyleSheet("font-family: Consolas, 'DejaVu Sans Mono', monospace;")
            self.qtabs.addTab(w, n)
        rl.addWidget(self.qtabs, 3)
        row = QHBoxLayout()
        self.inv = _inv_combo(state, "Sans IOC d'investigation")
        self.btn_iocs = QPushButton("Injecter les hash de l'investigation")
        self.btn_iocs.clicked.connect(self.inject_iocs)
        self.btn_copy = QPushButton("Copier la requête affichée")
        self.btn_copy.clicked.connect(self.copy_query)
        self.btn_export = QPushButton("Exporter l'hypothèse (Markdown)…")
        self.btn_export.clicked.connect(self.export_md)
        for w in (self.inv, self.btn_iocs, self.btn_copy, self.btn_export):
            row.addWidget(w)
        row.addStretch(1)
        rl.addLayout(row)
        split.addWidget(right)
        split.setSizes([320, 900])
        lay.addWidget(split, 1)
        self.current = None
        self.inv.reload()
        self.list.setCurrentRow(0)

    def on_select(self, item, _prev=None) -> None:  # noqa: ANN001
        if item is not None:
            self.current = hunt.get(item.data(Qt.UserRole))
            self._render(self.current)

    def _render(self, h) -> None:  # noqa: ANN001
        if h is None:
            return
        li = lambda xs: "".join(f"<li>{_esc(x)}</li>" for x in xs)  # noqa: E731
        self.info.setHtml(f"<h2>{_esc(h.hid)} — {_esc(h.name)}</h2><p><b>Objectif :</b> {_esc(h.objective)}</p>"
                          f"<p><b>Hypothèse :</b> {_esc(h.hypothesis)}</p><p><b>Comportements recherchés :</b></p><ul>{li(h.behaviors)}</ul>"
                          f"<p><b>Sources de données :</b> {_esc(', '.join(h.data_sources))}</p>"
                          f"<p><b>Résultats attendus :</b> {_esc(h.expected_results)}</p><p><b>Validation :</b> {_esc(h.validation)}</p>"
                          f"<p><b>Recommandations :</b></p><ul>{li(h.recommendations)}</ul><p><b>MITRE :</b> {_esc(', '.join(h.mitre))}</p>"
                          f"<p style='color:{theme.SEVERITY['Medium']}'>⚠ {_esc(h.adapt_note)}</p>")
        self.kql.setPlainText(h.kql)
        self.spl.setPlainText(h.spl)
        self.sigma.setPlainText(h.sigma)

    def inject_iocs(self) -> None:
        inv_id = self.inv.currentData()
        if not inv_id or not self.current:
            info_box(self, "Threat hunting", "Choisissez une investigation terminée.")
            return
        hashes = [i.value for i in self.state.svc.iocs(inv_id) if i.ioc_type == "sha256" and i.risk in ("Critical", "High", "Medium")]
        if not hashes:
            info_box(self, "Threat hunting", "Aucun hash SHA256 à risque dans cette investigation.")
            return
        self.current = hunt.with_iocs(self.current, hashes)
        self._render(self.current)

    def copy_query(self) -> None:
        w = self.qtabs.currentWidget()
        QGuiApplication.clipboard().setText(w.toPlainText())
        self.state.busy.emit(False, "Requête copiée dans le presse-papiers.")

    def export_md(self) -> None:
        h = self.current
        if not h:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Exporter l'hypothèse", f"{h.hid}.md", "Markdown (*.md)")
        if path:
            md = [f"# {h.hid} — {h.name}", "", f"**Objectif :** {h.objective}", "", f"**Hypothèse :** {h.hypothesis}", "",
                  "## Comportements", *[f"- {b}" for b in h.behaviors], "", "## Sources de données",
                  *[f"- {d}" for d in h.data_sources], "", "## KQL", "```kql", h.kql, "```", "## SPL", "```spl", h.spl, "```",
                  "## Sigma", "```yaml", h.sigma, "```", "", f"**Résultats attendus :** {h.expected_results}", "",
                  f"**Validation :** {h.validation}", "", "## Recommandations", *[f"- {r}" for r in h.recommendations], "",
                  f"**MITRE :** {', '.join(h.mitre)}", "", f"> {h.adapt_note}"]
            Path(path).write_text("\n".join(md), encoding="utf-8")
            info_box(self, "Threat hunting", f"Exporté : {path}")


# =====================================================================================================================
class DetectionPage(QWidget):
    def __init__(self, state):  # noqa: ANN001
        super().__init__()
        self.state = state
        lay = QVBoxLayout(self)
        lay.addWidget(page_header(t("nav.detection"), "Règles de détection prêtes à adapter : Microsoft Sentinel, Defender XDR, "
                                  "Splunk SPL, Sigma, Elastic. Chaque règle comporte nom, description, sévérité, MITRE, "
                                  "tactiques, requête, mapping d'entités, faux positifs, étapes d'investigation et de réponse."))
        split = QSplitter()
        left = QWidget()
        ll = QVBoxLayout(left)
        self.inv = _inv_combo(state, "— Règles de la bibliothèque uniquement —")
        self.inv.currentIndexChanged.connect(self.reload_rules)
        ll.addWidget(self.inv)
        self.rules = QListWidget()
        self.rules.currentItemChanged.connect(self.render_current)
        ll.addWidget(self.rules)
        split.addWidget(left)
        right = QWidget()
        rl = QVBoxLayout(right)
        row = QHBoxLayout()
        self.fmt = QComboBox()
        for k, (label, _ext) in det.FORMATS.items():
            self.fmt.addItem(label, k)
        self.fmt.currentIndexChanged.connect(self.render_current)
        self.btn_copy = QPushButton(t("btn.copy"))
        self.btn_copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.out.toPlainText()))
        self.btn_save = QPushButton("Télécharger la règle…")
        self.btn_save.setObjectName("Primary")
        self.btn_save.clicked.connect(self.save_rule)
        self.btn_all = QPushButton("Exporter toutes les règles (5 formats)…")
        self.btn_all.clicked.connect(self.export_all)
        for w in (self.fmt, self.btn_copy, self.btn_save, self.btn_all):
            row.addWidget(w)
        row.addStretch(1)
        rl.addLayout(row)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setStyleSheet("font-family: Consolas, 'DejaVu Sans Mono', monospace;")
        rl.addWidget(self.out, 1)
        split.addWidget(right)
        split.setSizes([360, 900])
        lay.addWidget(split, 1)
        self._rules: list = []
        self.inv.reload()
        self.reload_rules()

    def reload_rules(self) -> None:
        rules = []
        inv_id = self.inv.currentData()
        if inv_id:
            inv = self.state.svc.get(inv_id)
            iocs = [{"value": i.value, "ioc_type": i.ioc_type, "risk": i.risk, "validation_status": i.validation_status}
                    for i in self.state.svc.iocs(inv_id)]
            r = det.from_investigation_iocs(inv.reference, iocs) if inv else None
            if r:
                rules.append(r)
            fired = {f.rule_id for f in self.state.svc.findings(inv_id)}
            rules += [det.from_hypothesis(h) for h in hunt.HYPOTHESES if fired & set(h.rules)]
        rules += [r for r in det.catalog_rules() if r.rule_id not in {x.rule_id for x in rules}]
        self._rules = rules
        self.rules.blockSignals(True)
        self.rules.clear()
        for r in rules:
            self.rules.addItem(f"{r.rule_id}  [{r.severity}]  {r.name}")
        self.rules.blockSignals(False)
        self.rules.setCurrentRow(0)
        self.render_current()

    def _rule(self):  # noqa: ANN202
        i = self.rules.currentRow()
        return self._rules[i] if 0 <= i < len(self._rules) else None

    def render_current(self, *_a) -> None:  # noqa: ANN002
        r = self._rule()
        if r is None:
            self.out.setPlainText("")
            return
        try:
            self.out.setPlainText(det.render(r, self.fmt.currentData()))
        except Exception as exc:  # noqa: BLE001
            self.out.setPlainText(f"Rendu impossible : {exc}")

    def save_rule(self) -> None:
        r = self._rule()
        if not r:
            return
        fmt = self.fmt.currentData()
        path, _ = QFileDialog.getSaveFileName(self, "Enregistrer la règle", f"{r.rule_id}_{fmt}{det.FORMATS[fmt][1]}")
        if path:
            Path(path).write_text(det.render(r, fmt), encoding="utf-8")
            self.state.svc.audit("detection.export", f"{r.rule_id} {fmt}")
            info_box(self, "Detection engineering", f"Règle enregistrée : {path}")

    def export_all(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Dossier de destination", str(self.state.ctx.paths.rules))
        if not d:
            return
        n = 0
        for r in self._rules:
            for fmt in det.FORMATS:
                det.export(r, fmt, Path(d) / fmt)
                n += 1
        self.state.svc.audit("detection.export_all", f"{n} fichiers")
        info_box(self, "Detection engineering", f"{n} fichiers exportés dans {d}")

"""Tests de bout en bout de l'interface (Qt offscreen) : pages, boutons câblés, investigation complète via l'UI."""
from __future__ import annotations

import pytest

pytest.importorskip("pytestqt")
from PySide6.QtCore import QMetaMethod  # noqa: E402
from PySide6.QtWidgets import QAbstractButton, QInputDialog, QMessageBox, QPushButton  # noqa: E402

from conftest import SCENARIOS, scenario_files  # noqa: E402


@pytest.fixture()
def win(home, qtbot, monkeypatch):
    for name in ("information", "critical", "warning", "about"):
        monkeypatch.setattr(QMessageBox, name, staticmethod(lambda *a, **k: QMessageBox.Ok))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.Yes))
    from ai_soc_analyst.ui.app import build

    _app, w, _ = build(["test"])
    qtbot.addWidget(w)
    w.show()
    yield w
    from ai_soc_analyst.ui.workers import wait_all
    wait_all(10000)
    w.state.ctx.db.dispose()


def test_twelve_pages(win):
    assert win.stack.count() == 12 and win.nav.count() == 12
    for i in range(12):
        win.nav.setCurrentRow(i)
        assert win.stack.currentIndex() == i


def test_no_decorative_button(win):
    """Chaque bouton de l'application est relié à une action (exigence : aucun bouton décoratif ou inactif)."""
    unconnected = [b.text() for b in win.findChildren(QPushButton)
                   if not b.isSignalConnected(QMetaMethod.fromSignal(b.clicked))]
    assert not unconnected, unconnected
    assert len(win.findChildren(QPushButton)) > 50


def test_full_investigation_through_ui(win, qtbot, tmp_path, monkeypatch):
    page = win.pages["new"]
    d = next(p for p in SCENARIOS if "malware_infection" in p.name)
    page.title.setText("UI e2e")
    page.add_files(scenario_files(d))
    assert page.file_list.count() == len(scenario_files(d))
    page.run()
    qtbot.waitUntil(lambda: not win.state.running and page.btn_run.isEnabled(), timeout=60000)
    inv = win.state.svc.list()[0]
    assert inv.status == "completed" and inv.verdict == "Confirmed"
    assert win.stack.currentWidget() is win.pages["workspace"]
    ws = win.pages["workspace"]
    assert ws.findings.rowCount() > 0 and ws.iocs.rowCount() > 0 and ws.timeline.rowCount() > 0
    # analyse IA (moteur local)
    ws.run_ai()
    qtbot.waitUntil(lambda: not win.state.running, timeout=30000)
    assert "Fournisseur : local" in ws.ai.toHtml()
    # tableau de bord alimenté par la base
    win.go("dashboard")
    win.pages["dashboard"].refresh()
    assert win.pages["dashboard"].cards["total"].value.text() == "1"
    # réponse : décision tracée
    win.go("response")
    rp = win.pages["response"]
    rp.inv.setCurrentIndex(rp.inv.findData(inv.id))
    rp.table.selectRow(0)
    monkeypatch.setattr(QInputDialog, "getText", staticmethod(lambda *a, **k: ("ok test", True)))
    rp.decide("Approuvée")
    assert any(a.status == "Approuvée" for a in win.state.svc.actions(inv.id))
    # rapports
    win.go("reports")
    rep = win.pages["reports"]
    rep.inv.setCurrentIndex(rep.inv.findData(inv.id))
    for k, cb in rep.fmt_boxes.items():
        cb.setChecked(True)
    rep.generate()
    qtbot.waitUntil(lambda: rep.btn_gen.isEnabled() and rep.table.rowCount() == 5, timeout=60000)
    # IOC : en mode Privacy, réputation non vérifiée sans appel réseau
    ioc = win.pages["ioc"]
    ioc.inv.setCurrentIndex(ioc.inv.findData(inv.id))
    ioc.refresh()
    assert "Privacy" in ioc.ti_status.text()
    ioc.table.selectRow(0)
    ioc.lookup_selected()
    qtbot.waitUntil(lambda: ioc.btn_lookup.isEnabled(), timeout=30000)
    assert all(r[2].startswith("Non vérifiée") for r in ioc._rows), {r[2] for r in ioc._rows}


def test_paste_and_manual_input(win, qtbot):
    page = win.pages["new"]
    page.paste.setPlainText("Mar  3 10:00:01 srv sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n" * 30)
    page.m["host"].setText("SRV-WEB-01")
    page.m["alert_name"].setText("Brute force SSH")
    page.run()
    qtbot.waitUntil(lambda: not win.state.running and page.btn_run.isEnabled(), timeout=60000)
    inv = win.state.svc.list()[0]
    assert inv.status == "completed"
    srcs = {f.detected_source for f in win.state.svc.files(inv.id)}
    assert srcs and any(e.source_product == "Saisie manuelle (analyste)" for e in win.state.svc.events(inv.id))


def test_hunting_detection_mitre_settings(win, qtbot, monkeypatch):
    h = win.pages["hunting"]
    h.list.setCurrentRow(1)
    assert "H-02" in h.info.toHtml() and h.kql.toPlainText()
    d = win.pages["detection"]
    for i in range(d.fmt.count()):
        d.fmt.setCurrentIndex(i)
        assert d.out.toPlainText().strip()
    m = win.pages["mitre"]
    m.search.setText("T1059")
    m.do_search()
    assert m.techs.rowCount() > 3
    s = win.pages["settings"]
    s.analyst.setText("Analyste Test")
    s.ai_keys["openai_api_key"].setText("sk-test-123456789012")
    s.save()
    assert win.state.ctx.settings.analyst_name == "Analyste Test"
    assert win.state.ctx.secrets.get("openai_api_key") == "sk-test-123456789012"
    assert "sk-test" not in win.state.ctx.paths.settings_file.read_text()


def test_settings_privacy_blocks_remote_ai(win, qtbot):
    s = win.pages["settings"]
    s.provider.setCurrentIndex(s.provider.findData("openai"))
    s.privacy.setChecked(True)
    errors = []
    import ai_soc_analyst.ui.pages_ops as ops
    ops.error_box = lambda _p, _t, m: errors.append(m)
    s.test_ai()
    qtbot.waitUntil(lambda: s.btn_test.isEnabled(), timeout=10000)
    assert errors and "Privacy" in errors[0]

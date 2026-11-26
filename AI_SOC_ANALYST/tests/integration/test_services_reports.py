"""Persistance, redémarrage, reprise après interruption, tableau de bord, décisions, rapports, CLI."""
from __future__ import annotations

import json
import zipfile

import pytest

from ai_soc_analyst.reporting.service import generate_reports, list_reports
from conftest import SCENARIOS, scenario_files


def test_persistence_after_restart(home, completed, svc):
    from ai_soc_analyst.core.paths import AppPaths
    from ai_soc_analyst.services.context import create_app_context
    from ai_soc_analyst.services.investigations import InvestigationService

    svc.ctx.db.dispose()
    svc2 = InvestigationService(create_app_context(AppPaths(home).ensure()))
    inv = svc2.get(completed)
    assert inv.status == "completed" and inv.verdict == "Confirmed"
    assert svc2.findings(completed) and svc2.iocs(completed) and svc2.events(completed) and svc2.files(completed)
    assert inv.result()["timeline"]


def test_interrupted_investigation_resumed(svc, completed):
    svc._set(completed, status="analyzing", result_json="{}")
    assert svc.recover_interrupted() == [completed]
    assert svc.get(completed).status == "interrupted"
    res = svc.resume(completed)
    assert svc.get(completed).status == "completed" and res.verdict == "Confirmed"


def test_import_failure_is_recorded_not_crashing(svc, tmp_path):
    inv_id = svc.create("Fichier invalide")
    bad = tmp_path / "x.bin"
    bad.write_bytes(bytes(range(256)) * 4)
    res = svc.run(inv_id, [bad, tmp_path / "absent.json"])
    files = svc.files(inv_id)
    assert {f.status for f in files} <= {"rejected", "error"} and len(files) == 2
    assert res.verdict == "Inconclusive" and svc.get(inv_id).status == "completed"


def test_dashboard_from_database(svc, completed):
    d = svc.dashboard()
    assert d["total"] == 1 and d["critical"] == 1 and d["confirmed"] == 1
    assert d["techniques"] and d["recent"][0][0] == completed


def test_response_decisions_are_audited_and_kept(svc, completed):
    acts = svc.actions(completed)
    assert acts and all(a.status == "Proposée" for a in acts)
    svc.decide_action(acts[0].id, "Approuvée", "ticket CHG-1")
    with pytest.raises(ValueError):
        svc.decide_action(acts[0].id, "Exécuter", "")
    svc.analyze(completed)  # la réanalyse conserve les décisions
    kept = [a for a in svc.actions(completed) if a.status == "Approuvée"]
    assert kept and kept[0].decision_comment == "ticket CHG-1"
    assert any(a.action == "response.decision" for a in svc.audit_log())


def test_multi_file_investigation(svc):
    d = next(p for p in SCENARIOS if "suspicious_network" in p.name)
    files = scenario_files(d)
    assert len(files) >= 2
    inv_id = svc.create("multi")
    svc.run(inv_id, files)
    assert len(svc.files(inv_id)) == len(files)
    assert len({e.file_id for e in svc.events(inv_id)}) == len(files)


def test_zip_of_scenarios(svc, tmp_path):
    d = next(p for p in SCENARIOS if "ransomware" in p.name)
    z = tmp_path / "evidence.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for f in scenario_files(d):
            zf.write(f, f.name)
    inv_id = svc.create("zip")
    res = svc.run(inv_id, [z])
    assert res.verdict == "Confirmed" and len(svc.files(inv_id)) == 2  # archive + membre


@pytest.mark.parametrize("level", ["technical", "executive"])
def test_reports_all_formats(svc, completed, tmp_path, level):
    paths = generate_reports(svc, completed, level, ["pdf", "docx", "html", "json", "csv"], tmp_path / level)
    by = {p.suffix: p for p in paths}
    assert by[".pdf"].read_bytes()[:5] == b"%PDF-"
    import docx
    doc = docx.Document(str(by[".docx"]))
    text = "\n".join(p.text for p in doc.paragraphs) + "\n".join(c.text for t in doc.tables for r in t.rows for c in r.cells)
    assert "INC-" in text
    html = by[".html"].read_text(encoding="utf-8")
    assert "<html" in html.lower() and "Ransomware" in html
    data = json.loads(by[".json"].read_text(encoding="utf-8"))["report"]
    assert data["meta"]["incident_id"].startswith("INC-")
    n_sections = len(data["sections"])
    assert n_sections == (19 if level == "technical" else 6)
    csv_text = by[".csv"].read_text(encoding="utf-8-sig")
    assert csv_text.splitlines()[0].count(";") >= 5
    assert len(list_reports(svc, completed)) == 5


def test_report_requires_completed(svc):
    inv_id = svc.create("vide")
    with pytest.raises(ValueError):
        generate_reports(svc, inv_id, "technical", ["pdf"])


def test_report_labels_hypotheses(svc, completed, tmp_path):
    from ai_soc_analyst.ai.engine import run_ai_analysis

    inv = svc.get(completed)
    svc.save_ai_result(completed, run_ai_analysis(svc.ctx.settings, svc.ctx.secrets, inv.result(), []))
    p = generate_reports(svc, completed, "technical", ["json"], tmp_path)[0]
    txt = p.read_text(encoding="utf-8")
    assert "Hypothèse" in txt or "hypothèse" in txt


def test_delete_investigation(svc, completed):
    svc.delete(completed)
    assert svc.get(completed) is None and not svc.events(completed)


def test_backup(svc, completed):
    p = svc.ctx.db.backup(svc.ctx.paths.backups, 2)
    assert p.exists() and p.stat().st_size > 0
    import sqlite3
    con = sqlite3.connect(p)
    assert con.execute("select count(*) from investigations").fetchone()[0] == 1
    con.close()

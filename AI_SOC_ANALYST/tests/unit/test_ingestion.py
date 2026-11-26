"""Ingestion : détection de format/source, parseurs, sécurité des archives, quarantaine."""
from __future__ import annotations

import io
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from ai_soc_analyst.core.settings import LimitSettings
from ai_soc_analyst.ingestion.intake import IntakeService
from ai_soc_analyst.ingestion.validation import detect_format
from conftest import DATA


@pytest.fixture()
def intake(tmp_path):
    return IntakeService(tmp_path / "q")


def write(tmp_path: Path, name: str, content) -> Path:  # noqa: ANN001
    p = tmp_path / name
    (p.write_bytes if isinstance(content, bytes) else p.write_text)(content)
    return p


def test_json_defender_import(intake, tmp_path):
    p = write(tmp_path, "alert.json", json.dumps([{"Timestamp": "2026-01-01T10:00:00Z", "DeviceName": "PC1",
                                                    "FileName": "cmd.exe", "ProcessCommandLine": "cmd /c whoami",
                                                    "ActionType": "ProcessCreated"}]))
    rec = intake.import_path(p)
    assert rec.status == "ok" and rec.detected_format == "json"
    assert len(rec.events) == 1 and rec.events[0].host == "PC1" and rec.events[0].process_name == "cmd.exe"
    assert len(rec.sha256) == 64 and rec.size == p.stat().st_size


def test_csv_import(intake, tmp_path):
    p = write(tmp_path, "export.csv", "_time,host,Image,CommandLine,EventCode\n"
                                      "2026-01-01 10:00:00,PC2,C:\\Windows\\System32\\cmd.exe,cmd /c dir,1\n")
    rec = intake.import_path(p)
    assert rec.detected_format == "csv" and rec.events and rec.events[0].host == "PC2"


def test_xml_windows_event(intake, tmp_path):
    xml = ("<Events><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
           "<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID>"
           "<TimeCreated SystemTime='2026-01-01T10:00:00Z'/><Computer>DC01</Computer></System><EventData>"
           "<Data Name='TargetUserName'>bob</Data><Data Name='IpAddress'>203.0.113.9</Data></EventData></Event></Events>")
    rec = intake.import_path(write(tmp_path, "sec.xml", xml))
    assert rec.detected_format == "xml" and rec.events[0].event_code in ("4625", 4625)
    assert rec.events[0].user == "bob"


def test_evtx_import_real_file(intake):
    rec = intake.import_path(DATA / "evtx" / "system.evtx")
    assert rec.detected_format == "evtx"
    assert rec.status in ("ok", "partial") and len(rec.events) > 100


def test_evtx_malformed_does_not_crash(intake):
    rec = intake.import_path(DATA / "evtx" / "dns_log_malformed.evtx")
    assert rec.status in ("ok", "partial", "error")
    assert rec.detected_format == "evtx"


def test_text_syslog_and_auth(intake, tmp_path):
    p = write(tmp_path, "auth.log", "Mar  3 10:00:01 srv sshd[123]: Failed password for root from 203.0.113.5 port 4242 ssh2\n")
    rec = intake.import_path(p)
    assert rec.detected_format in ("log", "txt") and rec.events
    assert rec.events[0].src_ip == "203.0.113.5"


def test_pasted_text(intake):
    rec = intake.import_pasted_text("CEF:0|Vendor|Prod|1.0|100|Port scan|5|src=203.0.113.1 dst=10.0.0.5 dpt=445")
    assert rec.events and rec.events[0].src_ip == "203.0.113.1"


def test_eml_import(intake, tmp_path):
    eml = ("From: Fake <billing@invoices-example.test>\nTo: alice@corp.example\nSubject: Facture\n"
           "Date: Tue, 03 Mar 2026 09:00:00 +0000\nMIME-Version: 1.0\nContent-Type: text/plain\n\n"
           "Voir http://203.0.113.80/facture\n")
    rec = intake.import_path(write(tmp_path, "mail.eml", eml))
    assert rec.detected_format == "eml" and any(e.event_type for e in rec.events)


def test_docx_xlsx_pdf_import(intake, tmp_path):
    import docx
    import openpyxl
    from reportlab.pdfgen import canvas

    d = docx.Document()
    d.add_paragraph("Connexion suspecte vers 203.0.113.44 depuis PC9")
    d.save(tmp_path / "note.docx")
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Timestamp", "DeviceName", "RemoteIP"])
    ws.append(["2026-01-01T10:00:00Z", "PC9", "203.0.113.45"])
    wb.save(tmp_path / "data.xlsx")
    c = canvas.Canvas(str(tmp_path / "rapport.pdf"))
    c.drawString(50, 800, "Alerte : 203.0.113.46 contacte par PC9")
    c.save()
    for name, fmt in (("note.docx", "docx"), ("data.xlsx", "xlsx"), ("rapport.pdf", "pdf")):
        rec = intake.import_path(tmp_path / name)
        assert rec.detected_format == fmt, (name, rec.status, rec.message)
        assert rec.status in ("ok", "partial"), (name, rec.message)
        assert rec.events, name


def test_multi_file_import(intake, tmp_path):
    a = write(tmp_path, "a.json", json.dumps({"DeviceName": "A", "ActionType": "ProcessCreated", "FileName": "x.exe"}))
    b = write(tmp_path, "b.log", "Mar  3 10:00:01 srv sshd[1]: Failed password for bob from 203.0.113.5 port 1 ssh2\n")
    res = intake.import_paths([a, b])
    assert len(res.files) == 2 and len(res.events) >= 2
    assert {f.detected_format for f in res.files} >= {"json"}


def test_zip_import_and_nested_files(intake, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("logs/a.json", json.dumps({"DeviceName": "Z", "ActionType": "ProcessCreated", "FileName": "y.exe"}))
    rec = intake.import_path(write(tmp_path, "bundle.zip", buf.getvalue()))
    assert rec.detected_format == "zip" and rec.children and rec.children[0].events


def _zip(tmp_path, name, members, compression=zipfile.ZIP_DEFLATED):  # noqa: ANN001
    p = tmp_path / name
    with zipfile.ZipFile(p, "w", compression) as z:
        for n, data in members:
            z.writestr(n, data)
    return p


def test_zip_bomb_rejected(tmp_path):
    intake = IntakeService(tmp_path / "q", LimitSettings(max_zip_ratio=50))
    rec = intake.import_path(_zip(tmp_path, "bomb.zip", [("big.txt", b"0" * 20_000_000)]))
    assert rec.status in ("rejected", "error") and "ZIP bomb" in rec.message


def test_zip_path_traversal_rejected(intake, tmp_path):
    rec = intake.import_path(_zip(tmp_path, "trav.zip", [("../../evil.txt", b"x")]))
    assert rec.status in ("rejected", "error") and "dangereux" in rec.message
    assert not (tmp_path.parent / "evil.txt").exists()


def test_zip_too_many_entries(tmp_path):
    intake = IntakeService(tmp_path / "q", LimitSettings(max_zip_entries=3))
    rec = intake.import_path(_zip(tmp_path, "many.zip", [(f"f{i}.txt", b"a") for i in range(10)]))
    assert rec.status in ("rejected", "error") and "entrées" in rec.message


def test_file_size_limit(tmp_path):
    intake = IntakeService(tmp_path / "q", LimitSettings(max_file_mb=1))
    rec = intake.import_path(write(tmp_path, "huge.log", b"a" * (1024 * 1024 + 10)))
    assert rec.status == "rejected" and "volumineux" in rec.message


def test_executable_is_quarantined_never_executed(intake, tmp_path):
    marker = tmp_path / "executed.flag"
    pe = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"\x00" * 200
    p = write(tmp_path, "payload.exe", pe)
    rec = intake.import_path(p)
    assert rec.detected_format in ("pe", "unknown") or rec.status in ("rejected", "error")
    assert not marker.exists()
    if rec.stored_path:
        mode = os.stat(rec.stored_path).st_mode
        assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        assert rec.stored_path.endswith(".quarantine")
        if rec.static_analysis:
            assert rec.static_analysis.get("executed") is False


def test_unknown_binary_rejected(intake, tmp_path):
    rec = intake.import_path(write(tmp_path, "blob.bin", bytes(range(256)) * 10))
    assert rec.status in ("rejected", "error")


def test_detect_format_magic_overrides_extension(tmp_path):
    p = write(tmp_path, "trompeur.txt", b"%PDF-1.4\n%fake")
    assert detect_format(p).fmt == "pdf"


def test_source_detection_examples(intake, tmp_path):
    sysmon = write(tmp_path, "s.json", json.dumps({"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                                                   "Image": "C:\\a.exe", "Computer": "PC"}))
    rec = intake.import_path(sysmon)
    assert "Sysmon" in rec.detected_source


def test_xml_entities_refused(intake, tmp_path):
    xml = ('<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]>'
           "<Events><Event><System><EventID>1</EventID></System><EventData><Data Name='x'>&b;</Data></EventData></Event></Events>")
    rec = intake.import_path(write(tmp_path, "xxe.xml", xml))
    assert rec.status in ("error", "rejected") and "XXE" in rec.message

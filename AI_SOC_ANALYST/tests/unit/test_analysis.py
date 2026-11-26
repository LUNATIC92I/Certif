"""Moteur d'analyse : IOC, processus, corrélation, MITRE, règles anti-hallucination."""
from __future__ import annotations

import pytest

from ai_soc_analyst.analysis.engine import analyze
from ai_soc_analyst.analysis.ioc import classify_ip, extract_from_text, extract_iocs, refang
from ai_soc_analyst.analysis.process_tree import build_trees, flatten_tree
from ai_soc_analyst.ingestion.normalizer import normalize_record


def ev(i: int, **rec):  # noqa: ANN003
    return normalize_record(rec, "Test", "test.json", i)


def test_refang_and_extraction():
    assert refang("hxxp://evil[.]example[.]com") == "http://evil.example.com"
    found = dict((v, t) for t, v in extract_from_text("hxxp://bad[.]example[.]com/x C:\\Users\\a\\report.xlsx net.webclient 8.8.8.8"))
    assert found.get("8.8.8.8") == "ipv4" and found.get("bad.example.com") == "domain"
    assert "report.xlsx" not in found and "net.webclient" not in found


@pytest.mark.parametrize("ip,cat", [("10.1.2.3", "interne"), ("192.168.1.1", "interne"), ("198.51.100.7", "documentation (RFC 5737)"),
                                    ("8.8.8.8", "publique")])
def test_classify_ip(ip, cat):
    assert classify_ip(ip)[1] == cat


def test_ioc_not_malicious_without_evidence():
    events = [ev(0, Timestamp="2026-01-01T10:00:00Z", DeviceName="PC", ActionType="ConnectionSuccess",
                 RemoteIP="8.8.8.8", RemotePort=53, InitiatingProcessFileName="svchost.exe")]
    iocs = extract_iocs(events, [])
    ip = next(i for i in iocs if i.value == "8.8.8.8")
    assert ip.risk in ("Info", "Low") and ip.reputation == "Non vérifiée"


def test_system_binary_hash_is_info(catalog):
    res = analyze([ev(0, Timestamp="2026-01-01T10:00:00Z", DeviceName="PC", ActionType="ProcessCreated", FileName="powershell.exe",
                      FolderPath="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                      SHA256="a" * 64, ProcessCommandLine="powershell -enc SQBFAFgA", InitiatingProcessFileName="winword.exe")], catalog)
    h = next(i for i in res.iocs if i.value == "a" * 64)
    assert h.risk == "Info"
    assert not any(r["action_type"] == "Block Malicious Hash" and r["target"] == "a" * 64 for r in res.recommendations)


def test_process_tree_parent_child_and_no_invented_parent():
    events = [ev(0, Timestamp="2026-01-01T10:00:00Z", DeviceName="PC", ActionType="ProcessCreated", FileName="cmd.exe",
                 ProcessId=200, InitiatingProcessFileName="explorer.exe", InitiatingProcessId=100, ProcessCommandLine="cmd /c x"),
              ev(1, Timestamp="2026-01-01T10:00:01Z", DeviceName="PC", ActionType="ProcessCreated", FileName="whoami.exe",
                 ProcessId=300, InitiatingProcessFileName="cmd.exe", InitiatingProcessId=200, ProcessCommandLine="whoami")]
    trees = build_trees(events, {})
    flat = flatten_tree(trees)
    names = [n["process_name"] for _d, n in flat]
    assert names[:3] == ["explorer.exe", "cmd.exe", "whoami.exe"]
    root = trees[0]
    assert root.get("inferred") is True and root["command_line"] == ""  # parent déduit : aucun détail inventé


def test_empty_input_is_inconclusive(catalog):
    res = analyze([], catalog)
    assert res.verdict == "Inconclusive" and not res.findings and res.limitations


def test_no_mitre_from_suspicious_filename_only(catalog):
    res = analyze([ev(0, Timestamp="2026-01-01T10:00:00Z", DeviceName="PC", ActionType="FileCreated",
                      FileName="mimikatz_ransomware_invoice.pdf", FolderPath="D:\\Partage\\Docs")], catalog)
    assert not res.mitre, res.mitre


def test_timeline_sorted_and_untimed_flagged(catalog):
    events = [ev(0, Timestamp="2026-01-01T10:05:00Z", DeviceName="PC", ActionType="ProcessCreated", FileName="b.exe"),
              ev(1, Timestamp="2026-01-01T10:00:00Z", DeviceName="PC", ActionType="ProcessCreated", FileName="a.exe"),
              ev(2, DeviceName="PC", ActionType="ProcessCreated", FileName="c.exe")]
    res = analyze(events, catalog)
    times = [e["time"] for e in res.timeline if e["time"]]
    assert times == sorted(times)
    assert any("horodat" in x.lower() for x in res.limitations)


def test_brute_force_then_success_correlated(catalog):
    events = [ev(i, Timestamp=f"2026-01-01T10:00:{i:02d}Z", Computer="SRV", EventID=4625, TargetUserName="admin",
                 IpAddress="203.0.113.10", LogonType=3) for i in range(25)]
    events.append(ev(30, Timestamp="2026-01-01T10:01:00Z", Computer="SRV", EventID=4624, TargetUserName="admin",
                     IpAddress="203.0.113.10", LogonType=3))
    res = analyze(events, catalog)
    tids = {m["technique_id"] for m in res.mitre}
    assert "T1110.001" in tids or "T1110" in {t.split(".")[0] for t in tids}
    assert res.chains and res.verdict in ("Likely", "Confirmed")


def test_every_finding_has_evidence(catalog):
    from conftest import SCENARIOS, scenario_files
    from ai_soc_analyst.ingestion.intake import IntakeService
    import tempfile
    from pathlib import Path

    for d in SCENARIOS:
        r = IntakeService(Path(tempfile.mkdtemp())).import_paths(scenario_files(d))
        res = analyze(r.events, catalog)
        ids = {e.evidence_id for e in r.events}
        for f in res.findings:
            assert f.evidence_ids and set(f.evidence_ids) <= ids, (d.name, f.rule_id)
        for m in res.mitre:
            assert m["evidence_ids"] and m["finding_ids"], (d.name, m["technique_id"])

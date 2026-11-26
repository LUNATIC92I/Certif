"""Les 8 scénarios synthétiques : résultats attendus (verdict, sévérité, règles, MITRE, IOC, sources)."""
from __future__ import annotations

import pytest

from conftest import SCENARIOS, expected, scenario_files


@pytest.mark.parametrize("d", SCENARIOS, ids=lambda d: d.name)
def test_scenario_expected_results(svc, d):
    exp = expected(d)
    inv_id = svc.create(d.name)
    res = svc.run(inv_id, scenario_files(d))
    assert res.verdict in exp["verdict_in"], res.stats["verdict_basis"]
    assert res.severity in exp["severity_in"]
    tids = {m["technique_id"] for m in res.mitre}
    assert set(exp["mitre_must_include"]) <= tids, tids
    rules = {f.rule_id for f in res.findings}
    assert set(exp["rules_must_include"]) <= rules, rules
    iocs = {i.value for i in res.iocs}
    assert set(exp.get("iocs_must_include", [])) <= iocs
    if exp.get("incident_type_contains"):
        assert exp["incident_type_contains"] in res.incident_type
    srcs = " ".join(f.detected_source for f in svc.files(inv_id))
    for s in exp.get("sources_must_include", []):
        assert s in srcs
    assert not res.stats["rule_errors"]
    inv = svc.get(inv_id)
    assert inv.status == "completed" and inv.verdict == res.verdict


def test_false_positive_scenario_proposes_no_containment(svc):
    d = next(p for p in SCENARIOS if "false_positive" in p.name)
    inv_id = svc.create("FP")
    svc.run(inv_id, scenario_files(d))
    kinds = {a.action_type for a in svc.actions(inv_id)}
    assert not kinds & {"Isolate Endpoint", "Disable Compromised Account", "Block Malicious Hash"}


def test_real_windows_system_log_not_overstated(svc):
    """Journal System réel (python-evtx, Apache-2.0) : installations de services/pilotes et PsExec, sans autre indice.
    L'outil ne doit pas conclure à une compromission confirmée sur ces seules données."""
    from conftest import DATA

    inv_id = svc.create("system.evtx")
    res = svc.run(inv_id, [DATA / "evtx" / "system.evtx"])
    assert res.verdict in ("Suspicious", "Inconclusive")
    assert res.severity in ("Medium", "Low", "Informational")
    ps = [f for f in res.findings if "PsExec" in f.title]
    assert len(ps) == 1 and ps[0].status == "Suspicious" and len(ps[0].evidence_ids) == 4

"""MITRE ATT&CK, bibliothèque de chasse et génération de règles."""
from __future__ import annotations

import json

import pytest
import yaml

from ai_soc_analyst.detection import generator as det
from ai_soc_analyst.hunting import library as hunt


def test_catalog_loaded(catalog):
    assert len(catalog.index["techniques"]) > 600
    assert catalog.resolve("T1059.001")["name"] == "PowerShell"
    assert catalog.tactic_name("impact") == "Impact"


@pytest.mark.parametrize("old,new", [("T1574.002", "T1574.001"), ("T1562.001", "T1685"), ("T1070.001", "T1685.005")])
def test_revoked_techniques_followed(catalog, old, new):
    assert catalog.resolve(old)["id"] == new


def test_update_from_bundle_rejects_incomplete(catalog, tmp_path):
    from ai_soc_analyst.mitre.engine import MitreCatalog

    c = MitreCatalog(tmp_path)
    with pytest.raises(ValueError):
        c.update_from_bundle({"type": "bundle", "objects": []})
    assert len(c.index["techniques"]) > 600  # index embarqué conservé


def test_all_rule_mitre_ids_exist(catalog):
    for h in hunt.HYPOTHESES:
        for t in h.mitre:
            assert catalog.resolve(t), (h.hid, t)


@pytest.mark.parametrize("h", hunt.HYPOTHESES, ids=lambda h: h.hid)
def test_hypothesis_complete(h):
    for field in ("objective", "hypothesis", "kql", "spl", "sigma", "expected_results", "validation"):
        assert getattr(h, field).strip(), field
    assert h.behaviors and h.data_sources and h.recommendations and h.mitre and h.adapt_note
    docs = list(yaml.safe_load_all(h.sigma))
    assert all(d.get("title") and d.get("id") for d in docs)


def test_sigma_rules_valid_pysigma():
    pytest.importorskip("sigma")
    from sigma.collection import SigmaCollection

    for h in hunt.HYPOTHESES:
        coll = SigmaCollection.from_yaml(h.sigma)
        assert not coll.errors, (h.hid, coll.errors)


@pytest.mark.parametrize("fmt", list(det.FORMATS))
def test_render_all_formats(fmt):
    for r in det.catalog_rules():
        out = det.render(r, fmt)
        assert out.strip()
        if fmt in ("sentinel", "sigma"):
            docs = [d for d in yaml.safe_load_all(out) if d]
            assert docs
        if fmt == "elastic":
            doc = json.loads(out)
            assert doc["query"] and doc["severity"] and doc["threat"]
        if fmt == "sentinel":
            d = yaml.safe_load(out)
            for k in ("name", "description", "severity", "query", "tactics", "relevantTechniques", "entityMappings"):
                assert k in d, k


def test_kql_generation_with_iocs():
    rule = det.from_investigation_iocs("INC-1", [{"value": "b" * 64, "ioc_type": "sha256", "risk": "High",
                                                  "validation_status": "Lié aux détections"},
                                                 {"value": "203.0.113.9", "ioc_type": "ipv4", "risk": "High",
                                                  "validation_status": "Lié aux détections"}])
    kql = det.render(rule, "defender")
    assert "b" * 64 in kql and "203.0.113.9" in kql


def test_ioc_rule_ignores_unvalidated():
    assert det.from_investigation_iocs("INC-1", [{"value": "c" * 64, "ioc_type": "sha256", "risk": "High",
                                                  "validation_status": "Non validé"}]) is None


def test_export_writes_file(tmp_path):
    r = det.catalog_rules()[0]
    p = det.export(r, "sigma", tmp_path)
    assert p.exists() and p.suffix == ".yml"

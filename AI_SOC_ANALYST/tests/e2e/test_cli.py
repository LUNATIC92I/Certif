"""Ligne de commande et autotest (identique à celui exécuté sur l'EXE Windows)."""
from __future__ import annotations

import json
import os
import subprocess
import sys

from conftest import ROOT, SCENARIOS, scenario_files


def _env(home):  # noqa: ANN001, ANN202
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), AI_SOC_HOME=str(home), QT_QPA_PLATFORM="offscreen")
    return env


def test_selftest(tmp_path):
    out = tmp_path / "selftest.json"
    r = subprocess.run([sys.executable, "-m", "ai_soc_analyst", "--selftest", "--selftest-out", str(out)],
                       env=_env(tmp_path / "h"), capture_output=True, text=True, timeout=300)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert r.returncode == 0 and data["ok"], data
    assert {c["check"] for c in data["checks"]} == {"contexte", "mitre", "analyse", "rapports", "interface"}


def test_cli_analyze_with_reports(tmp_path):
    d = next(p for p in SCENARIOS if "brute_force" in p.name)
    r = subprocess.run([sys.executable, "-m", "ai_soc_analyst", "analyze", *map(str, scenario_files(d)), "--report", "pdf",
                        "csv", "--out", str(tmp_path / "out")], env=_env(tmp_path / "h"), capture_output=True, text=True,
                       timeout=300)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout[: r.stdout.rindex("}") + 1])
    assert data["verdict"] in ("Likely", "Confirmed") and any(t.startswith("T1110") for t in data["mitre"])
    assert len(list((tmp_path / "out").iterdir())) == 2


def test_version():
    r = subprocess.run([sys.executable, "-m", "ai_soc_analyst", "--version"], env=_env("/tmp/unused"), capture_output=True,
                       text=True, timeout=60)
    assert "1.0.0" in r.stdout

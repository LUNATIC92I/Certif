"""Fixtures communes : chaque test utilise un dossier de données isolé (aucun impact sur les données réelles)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

DATA = ROOT / "tests" / "data"
SCENARIOS = sorted(p for p in (DATA / "scenarios").iterdir() if p.is_dir())


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    monkeypatch.setenv("AI_SOC_HOME", str(h))
    return h


@pytest.fixture()
def ctx(home):
    from ai_soc_analyst.core.paths import AppPaths
    from ai_soc_analyst.services.context import create_app_context

    c = create_app_context(AppPaths(home).ensure())
    yield c
    c.db.dispose()


@pytest.fixture()
def svc(ctx):
    from ai_soc_analyst.services.investigations import InvestigationService

    return InvestigationService(ctx)


@pytest.fixture(scope="session")
def catalog():
    from ai_soc_analyst.mitre.engine import MitreCatalog

    return MitreCatalog(None)


def scenario_files(d: Path) -> list[Path]:
    return [p for p in sorted(d.iterdir()) if p.name != "expected.json"]


def expected(d: Path) -> dict:
    return json.loads((d / "expected.json").read_text(encoding="utf-8"))


@pytest.fixture()
def completed(svc):
    """Investigation terminée sur le scénario ransomware."""
    d = next(p for p in SCENARIOS if "ransomware" in p.name)
    inv_id = svc.create("Ransomware test")
    svc.run(inv_id, scenario_files(d))
    return inv_id

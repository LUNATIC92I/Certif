"""Modèle de rapport SOC indépendant du format (exécutif ou technique).

Règle rédactionnelle : un fait n'est présenté comme confirmé que si la détection correspondante est « Confirmed ».
Les hypothèses (y compris celles de l'IA) sont systématiquement étiquetées comme telles.
"""
from __future__ import annotations

import json
from datetime import datetime

from .. import APP_NAME, __version__
from ..analysis.results import STATUS_FR

LEVELS = {"executive": "Executive Report", "technical": "Technical Investigation Report"}


def _p(text: str) -> dict:
    return {"type": "p", "text": text}


def _table(headers: list[str], rows: list[list], widths: list[float] | None = None) -> dict:
    return {"type": "table", "headers": headers, "rows": [[("" if c is None else str(c)) for c in r] for r in rows],
            "widths": widths}


def _bullets(items: list[str]) -> dict:
    return {"type": "bullets", "items": [i for i in items if i]}


def _kv(rows: list[tuple[str, str]]) -> dict:
    return {"type": "kv", "rows": [(k, "" if v is None else str(v)) for k, v in rows]}


def _status(s: str) -> str:
    return f"{s} ({STATUS_FR.get(s, s)})"


def build_report(inv, result: dict, files: list, actions: list, ai: dict | None, level: str,  # noqa: ANN001
                 tlp: str = "TLP:AMBER") -> dict:
    findings = result.get("findings", [])
    active = [f for f in findings if f["status"] != "False Positive"]
    triage = result.get("triage", {})
    iocs = result.get("iocs", [])
    mitre = result.get("mitre", [])
    meta = {
        "incident_name": inv.title, "incident_id": inv.reference, "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "analyst": inv.analyst, "severity": result.get("severity", inv.severity),
        "status": {"completed": "Investigation terminée"}.get(inv.status, inv.status),
        "verdict": _status(result.get("verdict", inv.verdict)), "confidence": f"{result.get('confidence', 0):.0%}",
        "risk_score": f"{result.get('risk_score', 0)}/100", "incident_type": result.get("incident_type", ""),
        "evidence_sources": ", ".join(triage.get("sources", [])) or "n/c",
        "level": LEVELS[level], "tlp": tlp, "generator": f"{APP_NAME} {__version__}",
    }
    sec: list[dict] = []

    def section(num: int, title: str, blocks: list[dict]) -> None:
        sec.append({"title": f"{num}. {title}", "blocks": [b for b in blocks if b]})

    exec_blocks = [_p(result.get("summary", "")),
                   _p("Conclusion : " + (
                       "l'incident est confirmé par les preuves analysées." if result.get("verdict") == "Confirmed" else
                       "l'activité malveillante est probable mais doit encore être confirmée." if result.get("verdict") == "Likely" else
                       "des signaux suspects existent sans permettre de conclure." if result.get("verdict") == "Suspicious" else
                       "l'activité analysée correspond à un comportement légitime (faux positif)." if result.get("verdict") == "False Positive"
                       else "les données disponibles ne permettent pas de conclure."))]
    if ai and ai.get("executive_summary") and ai.get("provider") not in (None, "local"):
        exec_blocks.append(_p(f"Synthèse assistée par IA ({ai.get('provider')} – {ai.get('model')}), vérifiée contre les "
                              f"preuves : {ai['executive_summary']}"))
    overview = _kv([("Type d'incident", result.get("incident_type")), ("Catégorie de menace", result.get("threat_category")),
                    ("Verdict", _status(result.get("verdict", ""))), ("Sévérité", result.get("severity")),
                    ("Hôtes concernés", ", ".join(triage.get("hosts", [])[:10]) or "n/c"),
                    ("Comptes concernés", ", ".join(triage.get("users", [])[:10]) or "n/c"),
                    ("Première activité observée", triage.get("first_seen")), ("Dernière activité observée", triage.get("last_seen"))])
    risk_rows = [("Score de risque", meta["risk_score"]), ("Sévérité", meta["severity"]), ("Confiance", meta["confidence"]),
                 ("Tactiques ATT&CK observées", ", ".join(sorted({m["tactic"] for m in mitre})) or "aucune")]
    rec = result.get("recommendations", [])
    act_rows = []
    by_key = {(a.action_type, a.target): a for a in actions}
    for r in rec:
        a = by_key.get((r["action_type"], r["target"]))
        act_rows.append([r["priority"], r["action_type"], r["target"][:80], r["justification"][:200],
                         a.status if a else "Proposée"])

    if level == "executive":
        section(1, "Executive Summary", exec_blocks)
        section(2, "Incident Overview", [overview])
        section(3, "Risk Assessment", [_kv(risk_rows)])
        section(4, "Impact Assessment", [_p(result.get("impact", ""))])
        section(5, "Recommended Actions", [_table(["Priorité", "Action", "Cible", "Justification", "Statut"], act_rows[:10])
                                           if act_rows else _p("Aucune action recommandée.")])
        section(6, "Final SOC Conclusion", [_p(_conclusion(result, inv))])
        return {"meta": meta, "sections": sec}

    # ------------------------------------------------------------ rapport technique (19 sections)
    section(1, "Executive Summary", exec_blocks)
    section(2, "Incident Overview", [overview])
    detection = [_kv([("Alertes d'origine", ", ".join(triage.get("alert_names", [])) or "aucune alerte fournie"),
                      ("Sévérité initiale (source)", triage.get("initial_severity")),
                      ("Sources des preuves", meta["evidence_sources"])])]
    ctxa = triage.get("analyst_context") or {}
    if ctxa.get("description"):
        detection.append(_p("Contexte fourni par l'analyste : " + str(ctxa["description"])))
    section(3, "Detection Context", detection)
    stats = result.get("stats", {})
    section(4, "Investigation Scope", [
        _kv([("Fichiers importés", str(len(files))), ("Événements analysés", str(stats.get("events", 0))),
             ("Événements horodatés", str(stats.get("events_with_timestamp", 0))),
             ("Hôtes présents dans les données", ", ".join(triage.get("all_hosts", [])[:15]) or "n/c")]),
        _bullets(["Limite : " + lim for lim in result.get("limitations", [])])])
    section(5, "Evidence Collected", [_table(["Fichier", "Format", "Source détectée", "Taille (o)", "SHA256", "Statut"],
                                             [[f.original_name, f.detected_format, f.detected_source, f.size, f.sha256,
                                               f"{f.status} – {f.message}"] for f in files][:60], [0.18, 0.07, 0.15, 0.08, 0.32, 0.2])])
    section(6, "IOC Analysis", [
        _p("La réputation n'est indiquée que si elle a été vérifiée auprès d'une source de threat intelligence ; sinon "
           "elle figure comme « Non vérifiée ». Aucun indicateur n'est considéré malveillant sans élément de preuve."),
        _table(["Indicateur", "Type", "Réputation", "Risque", "Statut de validation", "Justification", "Preuves"],
               [[i["value"][:90], i["ioc_type"], i["reputation"], i["risk"], i["validation_status"], i["justification"][:180],
                 ", ".join(i["evidence_ids"][:4])] for i in iocs if i["risk"] != "Info" or i["ioc_type"] in ("sha256", "url", "domain")][:80],
               [0.2, 0.07, 0.12, 0.07, 0.14, 0.28, 0.12])])
    procs = result.get("suspicious_processes", [])
    section(7, "Process Analysis", [
        _table(["Processus (PID)", "Parent (PPID)", "Ligne de commande", "Chemin", "Utilisateur", "Heure", "Signé", "Réseau", "Preuve"],
               [[f"{p['process_name']} ({p['pid']})", f"{p['parent_name']} ({p['ppid']})", p["command_line"][:160],
                 p["path"][:70], p["user"], p["time"], {True: "oui", False: "non"}.get(p["signed"], "n/c"),
                 ", ".join(p["network"][:3]), p["evidence_id"]] for p in procs][:40])
        if procs else _p("Aucun processus suspect reconstitué (télémétrie de processus absente ou sans anomalie).")])
    tl = [t for t in result.get("timeline", []) if t["findings"] or t["chain"]][:150]
    section(8, "Timeline of Events", [
        _p("Chronologie établie uniquement à partir des événements importés (aucun événement reconstitué)."),
        _table(["Heure (UTC)", "Preuve", "Hôte", "Type", "Description", "Détections", "Chaîne"],
               [[t["time"] or f"(non horodaté) {t['time_raw']}", t["evidence_id"], t["host"], t["event_type"], t["summary"][:160],
                 ", ".join(t["findings"]), t["chain"]] for t in tl], [0.13, 0.09, 0.11, 0.1, 0.37, 0.1, 0.1])])
    section(9, "MITRE ATT&CK Mapping", [
        _table(["Tactique", "ID", "Technique", "Événements justificatifs", "Détections", "Confiance"],
               [[m["tactic"], m["technique_id"], m["technique_name"], ", ".join(m["evidence_ids"][:5]), ", ".join(m["finding_ids"]),
                 f"{m['confidence']:.0%}"] for m in mitre]) if mitre else _p("Aucune technique ATT&CK justifiée par les preuves.")])
    chains = result.get("chains", [])
    section(10, "Attack Chain Analysis", [
        *[_p(f"{c['chain_id']} ({', '.join(c['hosts'])}) de {c['start']} à {c['end']} : {c['event_count']} événements corrélés, "
             f"détections {', '.join(c['findings'])}, tactiques : {' → '.join(c.get('tactics', [])) or 'n/c'}."
             + (" Lacunes : " + "; ".join(c["gaps"]) if c["gaps"] else "")) for c in chains],
        _table(["ID", "Détection", "Statut", "Confiance", "Sévérité", "Description", "Preuves"],
               [[f["finding_id"], f["title"], _status(f["status"]), f"{f['confidence']:.0%}", f["severity"], f["description"][:260],
                 ", ".join(f["evidence_ids"][:6])] for f in findings], [0.06, 0.17, 0.12, 0.07, 0.07, 0.38, 0.13])
        if findings else _p("Aucune détection.")])
    section(11, "Risk Assessment", [_kv(risk_rows)])
    section(12, "Root Cause Analysis", [_p(result.get("root_cause", ""))])
    section(13, "Impact Assessment", [_p(result.get("impact", ""))])
    section(14, "False Positive Assessment", [_p(result.get("false_positive_assessment", ""))])
    section(15, "Recommended Actions", [
        _p("Actions proposées uniquement : aucune action n'a été exécutée automatiquement par l'outil."),
        _table(["Priorité", "Action", "Cible", "Justification", "Statut"], act_rows) if act_rows else _p("Aucune.")])
    contain = [r for r in rec if r["action_type"] in ("Isolate Endpoint", "Block IP Address", "Block Domain",
                                                      "Disable Compromised Account", "Revoke Sessions", "Block Malicious Hash")]
    remed = [r for r in rec if r["action_type"] in ("Remove Persistence", "Quarantine File", "Reset Password",
                                                    "Collect Additional Evidence")]
    section(16, "Containment Recommendations", [_bullets([f"{r['action_type']} – {r['target']} : {r['procedure']}" for r in contain])
                                                if contain else _p("Aucun confinement requis par les preuves.")])
    section(17, "Remediation Recommendations", [_bullets([f"{r['action_type']} – {r['target']} : {r['procedure']}" for r in remed])
                                                if remed else _p("Aucune remédiation spécifique.")])
    section(18, "Lessons Learned", [_bullets(_lessons(result))])
    blocks = [_p(_conclusion(result, inv))]
    if ai:
        hyps = ai.get("hypotheses", [])
        if hyps:
            blocks.append(_p("Hypothèses à vérifier (non confirmées) :"))
            blocks.append(_bullets([f"{h['hypothesis']} — validation : {h['how_to_validate']}" for h in hyps]))
        rej = ai.get("rejected_assessments", [])
        if rej:
            blocks.append(_p(f"{len(rej)} affirmation(s) de l'IA rejetée(s) faute de preuve vérifiable (non reprises dans ce rapport)."))
    if inv.analyst_notes:
        blocks.append(_p("Notes de l'analyste : " + inv.analyst_notes))
    section(19, "Final SOC Conclusion", blocks)
    return {"meta": meta, "sections": sec}


def _lessons(result: dict) -> list[str]:
    out = []
    for lim in result.get("limitations", []):
        if "télémétrie" in lim or "réseau" in lim:
            out.append("Améliorer la collecte : " + lim)
    rules = {f["rule_id"] for f in result.get("findings", []) if f["status"] != "False Positive"}
    if rules & {"R-OFF-001", "R-MAIL-001"}:
        out.append("Renforcer le filtrage des pièces jointes à macros et la sensibilisation à l'hameçonnage.")
    if rules & {"R-AUTH-001"}:
        out.append("Généraliser le MFA et réduire l'exposition des services d'authentification.")
    if rules & {"R-RAN-001", "R-RAN-003"}:
        out.append("Vérifier l'isolation et l'immuabilité des sauvegardes ; tester la restauration.")
    if rules & {"R-PUA-001"}:
        out.append("Bloquer l'installation de logiciels non approuvés (WDAC/AppLocker) et rappeler la politique de licences.")
    if result.get("verdict") == "False Positive":
        out.append("Ajuster la règle de détection d'origine avec une exclusion précise et documentée.")
    out.append("Transformer les comportements observés en règles de détection (module Detection Engineering).")
    return out


def _conclusion(result: dict, inv) -> str:  # noqa: ANN001
    v = result.get("verdict")
    base = {"Confirmed": "Incident CONFIRMÉ", "Likely": "Incident PROBABLE (à confirmer)", "Suspicious": "Activité SUSPECTE",
            "Inconclusive": "Investigation NON CONCLUANTE", "False Positive": "FAUX POSITIF"}.get(v, v)
    return (f"{base} – {result.get('incident_type', '')}, sévérité {result.get('severity')}, confiance "
            f"{result.get('confidence', 0):.0%}. {result.get('root_cause', '')} Les conclusions reposent exclusivement sur les "
            "preuves référencées (identifiants EVT-/F-) ; toute information absente des données est signalée comme limite.")


def to_json(report: dict, result: dict) -> str:
    return json.dumps({"report": report, "investigation_result": result}, ensure_ascii=False, indent=2, default=str)

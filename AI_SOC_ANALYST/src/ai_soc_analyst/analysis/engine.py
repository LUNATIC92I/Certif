"""Moteur d'investigation SOC (local, déterministe) : triage, détection, corrélation, verdict et synthèse."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Callable

from ..ingestion.models import NormalizedEvent
from ..mitre.engine import MitreCatalog, build_mappings
from ..response.recommender import recommend
from .detectors import run_rules
from .ioc import extract_iocs
from .process_tree import build_trees, suspicious_processes
from .results import SEV_RANK, Finding, InvestigationResult
from .timeline import build_timeline, correlate

ProgressCb = Callable[[int, str], None]

INCIDENT_TYPES = [  # (règles, type d'incident, catégorie de menace)
    ({"R-RAN-001", "R-RAN-003", "R-RAN-004"}, "Ransomware", "Impact / Chiffrement de données"),
    ({"R-CRD-001", "R-CRD-002"}, "Vol d'identifiants", "Credential Access"),
    ({"R-LAT-001", "R-LAT-002", "R-LAT-003", "R-LAT-004", "R-LAT-005"}, "Mouvement latéral", "Lateral Movement"),
    ({"R-DLL-001"}, "Exécution de malware (DLL side-loading)", "Malware"),
    ({"R-LNX-001", "R-LNX-002"}, "Compromission de serveur Linux", "Malware / Accès distant"),
    ({"R-OFF-001", "R-MAIL-001"}, "Hameçonnage avec exécution de charge", "Phishing / Malware"),
    ({"R-PUA-001"}, "Logiciel non autorisé (activateur KMS)", "PUA / Non-conformité"),
    ({"R-PS-001", "R-LOL-001", "R-INJ-001", "R-STA-001"}, "Exécution de code malveillant", "Malware"),
    ({"R-AUTH-001"}, "Attaque par force brute / password spraying", "Credential Access"),
    ({"R-NET-001", "R-NET-002", "R-NET-003", "R-DNS-001", "R-DNS-002"}, "Communication réseau suspecte", "Command and Control"),
    ({"R-USB-001", "R-USB-002"}, "Exécution depuis un support amovible", "Malware / Support amovible"),
    ({"R-DEF-001", "R-DEF-002", "R-DEF-003"}, "Affaiblissement des défenses", "Defense Impairment"),
    ({"R-PER-001", "R-PER-002", "R-PER-003", "R-ACC-001", "R-ACC-002", "R-ACC-003", "R-ACC-004", "R-PRV-001"},
     "Persistance / modification de comptes", "Persistence"),
    ({"R-ALR-001"}, "Alerte de sécurité", "Alerte produit"),
    ({"R-EXE-001", "R-DIS-001"}, "Activité suspecte sur un poste", "Activité suspecte"),
]
CRITICAL_ASSET = re.compile(r"(?i)\b(dc\d*|ad\d*|pdc|srv-?ad|domain controller|exchange|sql|erp|backup|veeam)\b|-dc\d*\b")
STATUS_RANK = {"Confirmed": 4, "Likely": 3, "Suspicious": 2, "Inconclusive": 1, "False Positive": 0}


def assign_evidence_ids(events: list[NormalizedEvent], start: int = 1) -> None:
    for i, e in enumerate(events, start=start):
        if not e.evidence_id:
            e.evidence_id = f"EVT-{i:05d}"


def _fmt(dt) -> str:  # noqa: ANN001
    return dt.isoformat(sep=" ", timespec="seconds") if dt else "non disponible"


def analyze(events: list[NormalizedEvent], catalog: MitreCatalog, progress: ProgressCb | None = None,
            context: dict | None = None) -> InvestigationResult:
    context = context or {}
    p = progress or (lambda *_: None)
    assign_evidence_ids(events)
    ev_by_id = {e.evidence_id: e for e in events}

    p(10, "Application des règles comportementales")
    findings, rule_errors = run_rules(events)
    for f in findings:
        f.details.setdefault("hosts", sorted({ev_by_id[i].host for i in f.evidence_ids if i in ev_by_id and ev_by_id[i].host}))
        f.details.setdefault("users", sorted({ev_by_id[i].user for i in f.evidence_ids
                                              if i in ev_by_id and ev_by_id[i].user and ev_by_id[i].event_type != "logon_failure"})
                             or sorted({ev_by_id[i].user for i in f.evidence_ids if i in ev_by_id and ev_by_id[i].user})[:3])
        # Validation des techniques transmises par les produits : uniquement si elles existent dans ATT&CK
        f.mitre_ids = [t for t in f.mitre_ids if catalog.resolve(t)]

    p(25, "Évaluation des faux positifs")
    fp_notes = _false_positive_pass(findings)
    _corroborate(findings)

    from datetime import datetime as _dt

    def _first_ts(f: Finding):
        return min((ev_by_id[i].timestamp for i in f.evidence_ids if i in ev_by_id and ev_by_id[i].timestamp),
                   default=_dt.max)

    findings.sort(key=lambda f: (f.status == "False Positive", -SEV_RANK.get(f.severity, 0),
                                 -STATUS_RANK.get(f.status, 0), _first_ts(f), f.rule_id))
    for n, f in enumerate(findings, 1):
        f.finding_id = f"F-{n:03d}"
    flagged: dict[str, list[str]] = defaultdict(list)
    for f in findings:
        if f.status != "False Positive":
            for i in f.evidence_ids:
                flagged[i].append(f.finding_id)

    p(40, "Mappage MITRE ATT&CK")
    mitre = build_mappings(findings, catalog)
    tactic_of: dict[str, str] = {}
    for m in mitre:
        for i in m["evidence_ids"]:
            tactic_of.setdefault(i, m["tactic"])

    p(55, "Extraction des indicateurs")
    iocs = extract_iocs(events, findings)

    p(65, "Arbres de processus et corrélation temporelle")
    trees = build_trees(events, flagged)
    susp = suspicious_processes(trees)
    chain_of, chains = correlate(events, flagged)
    timeline = build_timeline(events, flagged, tactic_of)
    for row in timeline:
        row["chain"] = chain_of.get(row["evidence_id"], "")
    for c in chains:
        c["tactics"] = sorted({m["tactic"] for m in mitre if set(m["evidence_ids"]) & set(c["evidence_ids"])},
                              key=lambda t: next((m["tactic_order"] for m in mitre if m["tactic"] == t), 99))

    p(80, "Verdict, sévérité et risque")
    triage = _triage(events, findings, context)
    verdict, confidence, basis = _verdict(findings, chains, events)
    severity = _severity(findings, verdict, triage)
    risk = _risk(severity, verdict, mitre)
    itype, category = _classify(findings, verdict)
    limitations = _limitations(events, findings, rule_errors, iocs)
    root = _root_cause(findings, timeline, ev_by_id)
    impact = _impact(findings, triage, verdict)
    fp_text = _fp_text(findings, fp_notes, verdict)
    summary = _summary(verdict, confidence, severity, itype, triage, findings, mitre, basis)
    recs = recommend(findings, iocs, verdict, severity, triage, limitations)
    stats = {"events": len(events), "events_with_timestamp": sum(1 for e in events if e.timestamp),
             "findings": len(findings), "iocs": len(iocs), "mitre_techniques": len({m["technique_id"] for m in mitre}),
             "chains": len(chains), "event_types": dict(Counter(e.event_type for e in events).most_common()),
             "sources": dict(Counter(e.source_product for e in events).most_common()), "rule_errors": rule_errors,
             "verdict_basis": basis}
    p(95, "Synthèse")
    return InvestigationResult(triage, findings, iocs, mitre, timeline, chains, trees, susp, verdict, round(confidence, 2),
                               severity, risk, itype, category, summary, root, impact, fp_text, limitations, recs, stats)


# ------------------------------------------------------------------ étapes

def _false_positive_pass(findings: list[Finding]) -> list[str]:
    notes = []
    non_benign = [f for f in findings if not f.benign_context and f.status not in ("False Positive",)
                  and f.rule_id != "R-ALR-000"]
    strong_non_benign = [f for f in non_benign if f.status in ("Confirmed", "Likely") or SEV_RANK.get(f.severity, 0) >= 2]
    for f in findings:
        if f.benign_context and not strong_non_benign:
            f.status = "False Positive"
            f.confidence = 0.65
            notes.append(f"{f.title} : {f.benign_context}")
        elif f.benign_context:
            notes.append(f"{f.title} : contexte potentiellement légitime ({f.benign_context}), conservé car d'autres "
                         "comportements suspects non expliqués sont présents.")
    return notes


def _corroborate(findings: list[Finding]) -> None:
    """Élève le statut lorsque des comportements indépendants se corroborent sur un même hôte."""
    by_host: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        for h in f.details.get("hosts", []) or [""]:
            by_host[h].append(f)
    for host, fs in by_host.items():
        rules = {f.rule_id for f in fs if f.status != "False Positive"}
        if {"R-RAN-001", "R-RAN-003"} <= rules:
            for f in fs:
                if f.rule_id in ("R-RAN-001", "R-RAN-003"):
                    f.status, f.confidence = "Confirmed", max(f.confidence, 0.9)
                    f.details["corroboration"] = ("Suppression des sauvegardes et chiffrement massif observés sur le même "
                                                  "hôte : comportement de ransomware corroboré.")
        if "R-DLL-001" in rules and rules & {"R-NET-001", "R-NET-002", "R-PER-001", "R-PER-002", "R-PER-003"}:
            for f in fs:
                if f.rule_id == "R-DLL-001" and f.status == "Likely":
                    f.status, f.confidence = "Confirmed", max(f.confidence, 0.85)
                    f.details["corroboration"] = "Side-loading suivi d'une communication externe ou d'une persistance."


def _triage(events: list[NormalizedEvent], findings: list[Finding], context: dict) -> dict:
    def top(attr: str, n: int = 10) -> list[str]:
        c = Counter(getattr(e, attr) for e in events if getattr(e, attr))
        return [k for k, _ in c.most_common(n)]

    times = sorted(e.timestamp for e in events if e.timestamp)
    flagged_ev = {i for f in findings if f.status != "False Positive" for i in f.evidence_ids}
    flagged_events = [e for e in events if e.evidence_id in flagged_ev]
    alerts = [e for e in events if e.event_type == "alert"]
    return {
        "sources": sorted({e.source_product for e in events if e.source_product}),
        "files": sorted({e.file_ref for e in events if e.file_ref}),
        "hosts": sorted({e.host for e in flagged_events if e.host}) or top("host"),
        "all_hosts": top("host", 50),
        "users": sorted({e.user for e in flagged_events if e.user})[:15] or top("user"),
        "ips": sorted({ip for e in flagged_events for ip in (e.src_ip, e.dst_ip) if ip})[:20],
        "processes": sorted({e.process_name for e in flagged_events if e.process_name})[:20],
        "first_seen": _fmt(times[0]) if times else "non disponible",
        "last_seen": _fmt(times[-1]) if times else "non disponible",
        "initial_severity": max((a.alert_severity for a in alerts if a.alert_severity), default="non fournie par la source"),
        "alert_names": sorted({a.alert_name for a in alerts if a.alert_name})[:10],
        "analyst_context": context,
    }


def _verdict(findings: list[Finding], chains: list[dict], events: list[NormalizedEvent]) -> tuple[str, float, str]:
    active = [f for f in findings if f.status not in ("False Positive", "Inconclusive")]
    if not events:
        return "Inconclusive", 0.0, "Aucun événement exploitable n'a été importé."
    if not active:
        if any(f.status == "False Positive" for f in findings):
            return "False Positive", 0.7, ("Toutes les détections s'expliquent par un contexte légitime identifié "
                                           "(voir l'évaluation des faux positifs).")
        return "Inconclusive", 0.3, "Aucun comportement suspect détecté par les règles locales dans les données fournies."
    confirmed = [f for f in active if f.status == "Confirmed"]
    likely = [f for f in active if f.status == "Likely"]
    if confirmed:
        conf = min(0.97, max(f.confidence for f in confirmed) + 0.03 * (len(active) - 1))
        return "Confirmed", conf, "Au moins une détection est confirmée : " + "; ".join(
            f"{f.title}" for f in confirmed[:3]) + "."
    # corroboration multi-étapes dans une même chaîne
    for c in chains:
        in_chain = [f for f in likely if f.finding_id in c["findings"]]
        cats = {f.category.split(" /")[0] for f in in_chain}
        if len(in_chain) >= 3 and len(cats) >= 2:
            conf = min(0.95, max(f.confidence for f in in_chain) + 0.05)
            return "Confirmed", conf, (f"{len(in_chain)} comportements probables et corroborés dans la chaîne {c['chain_id']} "
                                       f"({', '.join(sorted(cats))}).")
    if likely:
        conf = min(0.9, max(f.confidence for f in likely) + 0.02 * (len(active) - 1))
        return "Likely", conf, "Comportements malveillants probables : " + "; ".join(f.title for f in likely[:3]) + "."
    conf = min(0.6, max(f.confidence for f in active))
    return "Suspicious", conf, "Signaux suspects isolés, insuffisants pour conclure : " + "; ".join(
        f.title for f in active[:3]) + "."


def _severity(findings: list[Finding], verdict: str, triage: dict) -> str:
    if verdict == "False Positive":
        return "Informational"
    active = [f for f in findings if f.status not in ("False Positive",)]
    if not active:
        return "Low"
    rank = max(SEV_RANK.get(f.severity, 0) for f in active if f.status != "Inconclusive") if any(
        f.status != "Inconclusive" for f in active) else 1
    if verdict == "Suspicious":
        rank = min(rank, 2)
    declared = str((triage.get("analyst_context") or {}).get("critical_asset", "")).strip().lower() in ("oui", "yes", "true", "1", "o", "y")
    if verdict in ("Confirmed", "Likely") and (declared or any(CRITICAL_ASSET.search(h or "") for h in triage.get("hosts", []))):
        rank = min(4, rank + 1)
    return {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"}[rank]


def _risk(severity: str, verdict: str, mitre: list[dict]) -> int:
    base = {"Critical": 85, "High": 65, "Medium": 45, "Low": 25, "Informational": 5}[severity]
    base += {"Confirmed": 10, "Likely": 5, "Suspicious": 0, "Inconclusive": -5, "False Positive": -5}.get(verdict, 0)
    base += min(10, 2 * len({m["tactic"] for m in mitre}))
    return max(0, min(100, base))


def _classify(findings: list[Finding], verdict: str) -> tuple[str, str]:
    rules = {f.rule_id for f in findings if f.status != "False Positive"}
    if verdict == "False Positive":
        return "Activité légitime (faux positif)", "Faux positif"
    for rset, itype, cat in INCIDENT_TYPES:
        if rules & rset:
            return itype, cat
    return "Aucun incident caractérisé", "Non déterminée"


def _limitations(events, findings, rule_errors, iocs) -> list[str]:  # noqa: ANN001
    lim = []
    if events and sum(1 for e in events if e.timestamp) < len(events):
        missing = len(events) - sum(1 for e in events if e.timestamp)
        lim.append(f"{missing} événement(s) sans horodatage exploitable : chronologie partielle")
    if not any(e.event_type == "process_creation" for e in events):
        lim.append("Aucune télémétrie de création de processus : l'arbre de processus ne peut pas être reconstitué")
    if not any(e.event_type in ("network_connection", "dns_query") for e in events):
        lim.append("Aucune donnée réseau (connexions/DNS) : C2 et exfiltration non évaluables")
    if any(i.reputation == "Non vérifiée" for i in iocs):
        lim.append("Réputation des IOC non vérifiée auprès de sources de threat intelligence")
    if len({e.source_product for e in events}) <= 1 and events:
        lim.append("Une seule source de données : corroboration croisée impossible")
    if rule_errors:
        lim.append(f"{len(rule_errors)} règle(s) de détection en erreur (voir le journal technique)")
    if any(f.rule_id == "R-ALR-000" for f in findings):
        lim.append("Informations saisies manuellement non corroborées par des journaux")
    return lim


def _root_cause(findings, timeline, ev_by_id) -> str:  # noqa: ANN001
    active = [f for f in findings if f.status not in ("False Positive", "Inconclusive")]
    if not active:
        return "Non déterminée : aucun comportement malveillant établi."
    first_time = {}
    for f in active:
        ts = [ev_by_id[i].timestamp for i in f.evidence_ids if i in ev_by_id and ev_by_id[i].timestamp]
        first_time[f.finding_id] = min(ts) if ts else None
    initial = [f for f in active if re.search(r"Initial Access|Credential Access", f.category)
               and f.rule_id in ("R-MAIL-001", "R-OFF-001", "R-AUTH-001", "R-USB-001")]
    earliest = sorted((f for f in active if first_time[f.finding_id]), key=lambda f: first_time[f.finding_id])
    if initial:
        f = initial[0]
        return (f"Vecteur d'accès initial le plus probable : {f.title} ({f.finding_id}, statut {f.status}). "
                f"Élément le plus ancien observé : {earliest[0].title} à {_fmt(first_time[earliest[0].finding_id])}."
                if earliest else f"Vecteur probable : {f.title} ({f.finding_id}).")
    if earliest:
        f = earliest[0]
        return (f"Premier comportement malveillant observé : {f.title} ({f.finding_id}) à {_fmt(first_time[f.finding_id])}. "
                "Le vecteur d'accès initial n'apparaît pas dans les données fournies : hypothèse à confirmer par des "
                "sources complémentaires (messagerie, proxy, journaux d'authentification).")
    return "Vecteur d'accès initial non visible dans les données (événements non horodatés)."


def _impact(findings, triage, verdict) -> str:  # noqa: ANN001
    if verdict in ("False Positive", "Inconclusive"):
        return "Aucun impact établi par les preuves disponibles."
    rules = {f.rule_id for f in findings if f.status in ("Confirmed", "Likely")}
    parts = []
    if rules & {"R-RAN-003", "R-RAN-004"}:
        parts.append("chiffrement de données (disponibilité et intégrité affectées)")
    if "R-RAN-001" in rules:
        parts.append("destruction des points de restauration")
    if rules & {"R-CRD-001", "R-CRD-002"}:
        parts.append("exposition d'identifiants (risque d'extension à d'autres systèmes)")
    if "R-AUTH-001" in rules and any("T1078" in f.mitre_ids for f in findings):
        parts.append("compte utilisateur potentiellement compromis")
    if rules & {"R-NET-001", "R-NET-002"}:
        parts.append("communication avec une infrastructure externe (C2 ou téléchargement)")
    if rules & {"R-PER-001", "R-PER-002", "R-PER-003"}:
        parts.append("persistance installée sur l'hôte")
    if not parts:
        parts.append("exécution de code ou d'outils non autorisés sur l'hôte")
    hosts = ", ".join(triage.get("hosts", [])[:5]) or "hôte non identifié"
    return f"Périmètre observé : {hosts}. Impact établi par les preuves : " + "; ".join(parts) + "."


def _fp_text(findings, notes, verdict) -> str:  # noqa: ANN001
    if verdict == "False Positive":
        return ("Faux positif probable : " + " ".join(notes) +
                " Recommandation : documenter l'exception (périmètre précis) et ajuster la règle de détection d'origine.")
    if notes:
        return "Éléments de contexte légitime examinés : " + " ".join(notes)
    return ("Aucun contexte légitime connu (outil d'administration, chemin de gestion de parc, alerte qualifiée bénigne) "
            "n'explique les comportements détectés.")


def _summary(verdict, confidence, severity, itype, triage, findings, mitre, basis) -> str:  # noqa: ANN001
    labels = {"Confirmed": "confirmé", "Likely": "probable", "Suspicious": "suspect", "Inconclusive": "non concluant",
              "False Positive": "faux positif"}
    active = [f for f in findings if f.status not in ("False Positive", "Inconclusive")]
    hosts = ", ".join(triage.get("hosts", [])[:4]) or "non identifiés"
    techs = ", ".join(sorted({m["technique_id"] for m in mitre})[:10]) or "aucune"
    return (f"Verdict : {labels.get(verdict, verdict)} (confiance {confidence:.0%}). Type d'incident : {itype}. "
            f"Sévérité évaluée : {severity}. Hôtes concernés : {hosts}. {len(active)} détection(s) retenue(s) ; "
            f"techniques ATT&CK observées : {techs}. Base du verdict : {basis}")

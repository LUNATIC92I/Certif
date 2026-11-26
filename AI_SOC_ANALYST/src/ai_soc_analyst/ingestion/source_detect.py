"""Identification de la source (produit) d'un ensemble d'enregistrements."""
from __future__ import annotations

from typing import Any

from .normalizer import flatten

# (source, champs caractéristiques, score par champ)
_SIGNATURES: list[tuple[str, tuple[str, ...]]] = [
    ("CrowdStrike Falcon", ("event_simplename", "aid", "cid", "sha256hashdata", "parentbasefilename",
                            "remoteaddressip4", "contextprocessid", "targetprocessid", "patterndisposition")),
    ("Microsoft Defender XDR", ("devicename", "actiontype", "initiatingprocessfilename", "initiatingprocesscommandline",
                                "processcommandline", "reportid", "deviceid", "initiatingprocessaccountname")),
    ("Microsoft Sentinel", ("timegenerated", "tenantid", "sourcesystem", "systemalertid", "incidentnumber",
                            "_resourceid", "alertname", "providername", "userprincipalname")),
    ("Elastic Security", ("@timestamp", "host.name", "process.name", "event.category", "event.action",
                          "process.parent.name", "agent.type", "ecs.version")),
    ("Splunk", ("_time", "_raw", "sourcetype", "_indextime", "splunk_server", "index")),
    ("IBM QRadar", ("qid", "qidname", "magnitude", "starttime", "logsourceid", "logsourcename", "offense_id")),
    ("Proofpoint", ("messagetime", "threatsinfomap", "clicktime", "senderip", "spamscore", "phishscore",
                    "quarantinefolder", "guid")),
    ("Varonis", ("varonis", "alert_rule", "data_store", "filer", "alert.rule.name", "datastore")),
    ("Rapid7 InsightIDR", ("rapid7", "investigation_rrn", "rrn", "insightidr", "detection_rule_rrn")),
    ("Sysmon", ("utctime", "processguid", "parentprocessguid", "hashes", "integritylevel", "logonguid")),
    ("Windows Security Log", ("subjectusername", "subjectlogonid", "logontype", "targetusername",
                              "newprocessname", "eventrecordid")),
]


def detect_source(records: list[dict[str, Any]], fmt: str, filename: str = "") -> str:
    if fmt == "evtx":
        prov = " ".join(str(r.get("Provider", "")) for r in records[:50]).lower()
        return "Sysmon" if "sysmon" in prov else "Windows Event Log"
    if fmt in ("eml", "msg"):
        return "Email (fichier message)"
    if fmt == "pe":
        return "Fichier exécutable (analyse statique)"
    sample = records[:200]
    keys: set[str] = set()
    values = ""
    for r in sample:
        flat = flatten(r)
        keys.update(k.lower() for k in flat)
        keys.update(k.split(".")[-1].lower() for k in flat)
        values += " " + " ".join(str(v)[:200] for v in list(flat.values())[:30]).lower()
    providers = values
    if {"_time", "sourcetype"} <= keys or {"_raw", "_time"} <= keys:
        return "Splunk (Sysmon)" if "sysmon" in values else "Splunk"
    if "microsoft-windows-sysmon" in providers or "sysmon" in providers and "utctime" in keys:
        return "Sysmon"
    scores = []
    for name, sig in _SIGNATURES:
        score = sum(1 for k in sig if k in keys)
        if name.split()[0].lower() in values:
            score += 1
        scores.append((score, name))
    scores.sort(reverse=True)
    if scores and scores[0][0] >= 2:
        return scores[0][1]
    if "cef_vendor" in keys or "leef_vendor" in keys:
        vendor = next((str(r.get("cef_vendor") or r.get("leef_vendor")) for r in sample
                       if r.get("cef_vendor") or r.get("leef_vendor")), "")
        return f"{vendor or 'Appliance'} (CEF/LEEF)"
    if "log_kind" in keys or ({"sourceip", "destinationip"} <= keys and "destinationport" in keys):
        return "Firewall Logs"
    if any("sshd" in str(r.get("ProcessName", "")) or "sudo" in str(r.get("ProcessName", "")) for r in sample) \
            or ("hostname" in keys and "processname" in keys and fmt in ("txt", "log")):
        return "Linux Syslog"
    if "eventid" in keys and ("computer" in keys or "provider" in keys):
        return "Windows Event Log"
    if fmt in ("pdf", "docx", "xlsx"):
        return f"Document ({fmt.upper()})"
    if "from" in keys and "subject" in keys:
        return "Email Security Alert"
    if "alertname" in keys or "alert_name" in keys or "severity" in keys:
        return "EDR / Security Alert"
    return "Inconnue"

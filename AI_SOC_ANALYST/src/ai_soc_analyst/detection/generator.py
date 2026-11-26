"""Detection Engineering : génération de règles Sentinel, Defender XDR, Splunk, Sigma et Elastic.

Les règles sont dérivées des hypothèses de la bibliothèque de chasse (logique éprouvée) ou des IOC validés d'une
investigation. Chaque règle comporte : nom, description, logique, sévérité, mapping ATT&CK, mapping d'entités,
détails personnalisés, faux positifs, étapes d'investigation et réponse recommandée.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from ..core.security import safe_filename
from ..hunting.library import HYPOTHESES, Hypothesis

FORMATS = {"sentinel": ("Microsoft Sentinel (règle analytique YAML)", ".yaml"),
           "defender": ("Microsoft Defender XDR (détection personnalisée)", ".kql"),
           "splunk": ("Splunk SPL (savedsearches.conf)", ".conf"),
           "sigma": ("Sigma YAML", ".yml"),
           "elastic": ("Elastic Security (règle KQL, JSON)", ".json")}

ELASTIC_QUERIES = {
    "H-01": 'process.name:("powershell.exe" or "pwsh.exe") and process.command_line:(*-enc* or *EncodedCommand* or '
            '*DownloadString* or *Net.WebClient* or *IEX*)',
    "H-02": 'event.category:library and dll.code_signature.exists:false and '
            'dll.path:(*\\\\Users\\\\Public\\\\* or *\\\\ProgramData\\\\* or *\\\\AppData\\\\*)',
    "H-03": 'event.category:process and process.command_line:(*delete*shadows* or *shadowcopy*delete* or '
            '*delete*catalog* or *recoveryenabled*no*)',
    "H-04": 'event.category:process and (process.command_line:(*comsvcs*MiniDump* or *sekurlsa* or *lsadump*) or '
            '(process.name:"procdump.exe" and process.command_line:*lsass*))',
    "H-05": 'process.name:"schtasks.exe" and process.command_line:*create* and '
            'process.command_line:(*powershell* or *AppData* or *Temp* or *mshta*)',
    "H-06": 'process.executable:(*KMSpico* or *AutoPico* or *KMSAuto*) or process.command_line:(*KMSpico* or *AutoPico*)',
    "H-07": 'event.category:process and process.executable:(D\\:\\\\* or E\\:\\\\* or F\\:\\\\* or G\\:\\\\*) '
            'and not process.executable:D\\:\\\\Program*',
    "H-08": 'event.category:authentication and event.outcome:failure',
    "H-09": 'event.category:authentication and event.outcome:failure',
    "H-10": 'process.parent.name:("WmiPrvSE.exe" or "wsmprovhost.exe") and process.name:("powershell.exe" or "cmd.exe")',
    "H-11": 'event.category:network and dns.question.name:* and dns.question.subdomain:?????????????????????????*',
    "H-12": 'event.category:registry and registry.path:(*CurrentVersion\\\\Run* or *Winlogon*) and '
            'registry.data.strings:(*AppData* or *Temp* or *powershell* or *mshta*)',
    "H-13": 'process.hash.sha256:("<SHA256_1>")',
}
SEVERITY = {"H-01": "High", "H-02": "Medium", "H-03": "High", "H-04": "High", "H-05": "Medium", "H-06": "Medium",
            "H-07": "Medium", "H-08": "Medium", "H-09": "High", "H-10": "Medium", "H-11": "Medium", "H-12": "Medium",
            "H-13": "High"}
TACTIC_NAMES = {  # nom Sentinel (sans espaces) des tactiques ATT&CK
    "T1059": "Execution", "T1027": "DefenseEvasion", "T1105": "CommandAndControl", "T1574": "Persistence",
    "T1490": "Impact", "T1486": "Impact", "T1003": "CredentialAccess", "T1053": "Persistence", "T1685": "DefenseEvasion",
    "T1543": "Persistence", "T1091": "InitialAccess", "T1110": "CredentialAccess", "T1078": "InitialAccess",
    "T1021": "LateralMovement", "T1047": "Execution", "T1568": "CommandAndControl", "T1071": "CommandAndControl",
    "T1547": "Persistence", "T1204": "Execution",
}


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: str
    mitre: list[str]
    tactics: list[str]
    kql_defender: str
    spl: str
    sigma: str
    elastic_query: str
    entity_mapping: dict[str, str]
    custom_details: dict[str, str]
    false_positives: list[str]
    investigation_steps: list[str]
    response: list[str]
    source: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _tactics(mitre: list[str]) -> list[str]:
    return sorted({TACTIC_NAMES.get(t.split(".")[0], "Execution") for t in mitre})


def from_hypothesis(h: Hypothesis) -> DetectionRule:
    return DetectionRule(
        rule_id=f"DET-{h.hid}", name=f"AI SOC – {h.name}", description=h.objective + " " + h.hypothesis,
        severity=SEVERITY.get(h.hid, "Medium"), mitre=h.mitre, tactics=_tactics(h.mitre), kql_defender=h.kql, spl=h.spl,
        sigma=h.sigma, elastic_query=ELASTIC_QUERIES.get(h.hid, ""),
        entity_mapping={"Host": "DeviceName", "Account": "AccountName", "Process": "ProcessCommandLine"},
        custom_details={"CommandLine": "ProcessCommandLine", "Parent": "InitiatingProcessFileName"},
        false_positives=["Outils d'administration et de déploiement légitimes (à exclure précisément)",
                         "Tests autorisés de l'équipe Red Team"],
        investigation_steps=["Qualifier l'hôte et l'utilisateur concernés", "Examiner l'arbre de processus et la ligne de commande",
                             "Rechercher la même activité sur d'autres hôtes", *[f"Valider : {h.validation}"]],
        response=h.recommendations, source=f"Bibliothèque de chasse {h.hid}")


def from_investigation_iocs(reference: str, iocs: list[dict]) -> DetectionRule | None:
    """Règle de surveillance des IOC validés d'une investigation (hash, IP, domaines)."""
    sel = [i for i in iocs if i.get("risk") in ("High", "Critical", "Medium")
           and i.get("validation_status") not in ("Non validé", "Binaire système légitime")]
    hashes = sorted({i["value"] for i in sel if i["ioc_type"] == "sha256"})
    ips = sorted({i["value"] for i in sel if i["ioc_type"] in ("ipv4", "ipv6")})
    domains = sorted({i["value"] for i in sel if i["ioc_type"] == "domain"})
    if not (hashes or ips or domains):
        return None

    def kql_list(v: list[str]) -> str:
        return ", ".join(f'"{x}"' for x in v) or '""'

    kql = (f"let hashes = dynamic([{kql_list(hashes)}]);\nlet ips = dynamic([{kql_list(ips)}]);\n"
           f"let domains = dynamic([{kql_list(domains)}]);\n"
           "union\n  (DeviceProcessEvents | where SHA256 in~ (hashes)),\n  (DeviceFileEvents | where SHA256 in~ (hashes)),\n"
           "  (DeviceNetworkEvents | where RemoteIP in (ips) or RemoteUrl has_any (domains))\n"
           "| project Timestamp, DeviceId, ReportId, DeviceName, ActionType, FileName, SHA256, RemoteIP, RemoteUrl,\n"
           "    InitiatingProcessAccountName, InitiatingProcessCommandLine")
    spl_terms = [f'Hashes="*{h}*"' for h in hashes] + [f'DestinationIp="{ip}"' for ip in ips] + \
                [f'QueryName="{d}"' for d in domains]
    spl = ("index=sysmon sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" (" + " OR ".join(spl_terms) +
           ")\n| table _time host Image Hashes DestinationIp QueryName")
    sel_lines = []
    if hashes:
        sel_lines.append("    sel_hash:\n        Hashes|contains:\n" + "\n".join(f"            - '{h}'" for h in hashes))
    if ips:
        sel_lines.append("    sel_ip:\n        DestinationIp:\n" + "\n".join(f"            - '{ip}'" for ip in ips))
    sigma = (f"title: IOC watch {reference}\nid: {uuid.uuid5(uuid.NAMESPACE_URL, reference)}\nstatus: experimental\n"
             f"description: Surveillance des IOC validés de l'investigation {reference}\nauthor: AI SOC ANALYST\n"
             f"date: 2026-11-26\nlogsource:\n    product: windows\n    service: sysmon\ndetection:\n"
             + ("\n".join(sel_lines) if sel_lines else "    sel_none:\n        EventID: -1")
             + "\n    condition: 1 of sel_*\nfalsepositives:\n    - Réutilisation légitime d'une adresse IP partagée\nlevel: high\n")
    elastic = " or ".join([f'process.hash.sha256:"{h}"' for h in hashes] + [f'destination.ip:"{ip}"' for ip in ips] +
                          [f'dns.question.name:"{d}"' for d in domains])
    return DetectionRule(
        rule_id=f"DET-IOC-{reference}", name=f"AI SOC – Surveillance IOC {reference}",
        description=f"Détecte la réapparition des indicateurs validés lors de l'investigation {reference}.",
        severity="High", mitre=[], tactics=["CommandAndControl", "Execution"], kql_defender=kql, spl=spl, sigma=sigma,
        elastic_query=elastic, entity_mapping={"Host": "DeviceName", "IP": "RemoteIP", "FileHash": "SHA256"},
        custom_details={"Url": "RemoteUrl", "CommandLine": "InitiatingProcessCommandLine"},
        false_positives=["Adresse IP réattribuée à un service légitime (vérifier la date d'expiration des IOC)"],
        investigation_steps=["Confirmer que l'hôte n'était pas dans le périmètre initial", "Contenir et analyser l'hôte",
                             f"Relier à l'investigation {reference}"],
        response=["Isoler l'hôte si exécution ou communication confirmée", "Ajouter les hôtes au périmètre de l'incident"],
        source=f"IOC validés de {reference}", extra={"hashes": hashes, "ips": ips, "domains": domains})


def catalog_rules() -> list[DetectionRule]:
    return [from_hypothesis(h) for h in HYPOTHESES]


# ------------------------------------------------------------------ rendu par format

def _header_comment(r: DetectionRule, prefix: str) -> str:
    lines = [f"Règle : {r.name}", f"Description : {r.description}", f"Sévérité : {r.severity}",
             f"MITRE ATT&CK : {', '.join(r.mitre) or 'n/a'}", "Faux positifs : " + "; ".join(r.false_positives),
             "Investigation : " + " | ".join(r.investigation_steps), "Réponse : " + " | ".join(r.response),
             "Générée par AI SOC ANALYST – à valider en environnement de test avant activation."]
    return "\n".join(f"{prefix} {ln}" for ln in lines)


def _defender_query(kql: str) -> str:
    """Les détections personnalisées Defender exigent Timestamp, DeviceId et ReportId dans les résultats."""
    if re.search(r"\|\s*summarize", kql) or re.search(r"\bjoin\b", kql):
        return kql + "\n// NB : requête agrégée – pour une règle de détection personnalisée Defender, conserver les colonnes\n" \
                     "// Timestamp, DeviceId et ReportId (par ex. arg_max(Timestamp, DeviceId, ReportId))."
    return kql


def render(rule: DetectionRule, fmt: str) -> str:
    if fmt == "sentinel":
        doc = {
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, rule.rule_id)), "name": rule.name, "description": rule.description,
            "severity": rule.severity, "requiredDataConnectors": [{"connectorId": "MicrosoftThreatProtection",
                                                                   "dataTypes": ["DeviceProcessEvents"]}],
            "queryFrequency": "1h", "queryPeriod": "1h", "triggerOperator": "gt", "triggerThreshold": 0,
            "tactics": rule.tactics, "relevantTechniques": [t.split(".")[0] for t in rule.mitre],
            "query": rule.kql_defender,
            "entityMappings": [{"entityType": k, "fieldMappings": [{"identifier": "HostName" if k == "Host" else
                                                                    "Name" if k == "Account" else "CommandLine" if k == "Process"
                                                                    else "Address" if k == "IP" else "Value",
                                                                    "columnName": v}]} for k, v in rule.entity_mapping.items()],
            "customDetails": rule.custom_details, "version": "1.0.0", "kind": "Scheduled",
            "falsePositives": rule.false_positives, "investigationSteps": rule.investigation_steps,
            "recommendedResponse": rule.response,
        }
        return "# " + _header_comment(rule, "#")[2:] + "\n" + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=120)
    if fmt == "defender":
        meta = {"Detection name": rule.name, "Frequency": "Every hour", "Severity": rule.severity,
                "Category": rule.tactics[0] if rule.tactics else "Execution", "MITRE techniques": rule.mitre,
                "Impacted entities": rule.entity_mapping, "Custom details": rule.custom_details}
        return (_header_comment(rule, "//") + "\n// Métadonnées : " + json.dumps(meta, ensure_ascii=False) + "\n"
                + _defender_query(rule.kql_defender) + "\n")
    if fmt == "splunk":
        name = re.sub(r"[\[\]]", "", rule.name)
        search = " \\\n".join(rule.spl.splitlines())
        return (_header_comment(rule, "#") + f"\n[{name}]\nsearch = {search}\ndescription = {rule.description}\n"
                "cron_schedule = 0 * * * *\ndispatch.earliest_time = -60m\ndispatch.latest_time = now\nenableSched = 1\n"
                "alert.track = 1\ncounttype = number of events\nrelation = greater than\nquantity = 0\n"
                f"action.notable.param.rule_title = {name}\naction.notable.param.severity = {rule.severity.lower()}\n"
                f"action.correlationsearch.annotations = {json.dumps({'mitre_attack': rule.mitre})}\n")
    if fmt == "sigma":
        return "# " + _header_comment(rule, "#")[2:] + "\n" + rule.sigma
    if fmt == "elastic":
        threat = [{"framework": "MITRE ATT&CK", "technique": [{"id": t.split(".")[0], "reference":
                   f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/", "name": t}]} for t in rule.mitre]
        doc = {"rule_id": str(uuid.uuid5(uuid.NAMESPACE_URL, rule.rule_id)), "name": rule.name,
               "description": rule.description, "type": "query", "language": "kuery", "query": rule.elastic_query,
               "index": ["logs-endpoint.events.*", "winlogbeat-*", "logs-windows.*"], "severity": rule.severity.lower(),
               "risk_score": {"Critical": 99, "High": 73, "Medium": 47, "Low": 21}.get(rule.severity, 47),
               "interval": "5m", "from": "now-6m", "threat": threat, "false_positives": rule.false_positives,
               "note": "## Investigation\n" + "\n".join(f"- {s}" for s in rule.investigation_steps) +
                       "\n## Réponse\n" + "\n".join(f"- {s}" for s in rule.response),
               "tags": ["AI SOC ANALYST"], "enabled": False, "version": 1}
        return json.dumps(doc, ensure_ascii=False, indent=2)
    raise ValueError(f"Format inconnu : {fmt}")


def export(rule: DetectionRule, fmt: str, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (safe_filename(f"{rule.rule_id}_{fmt}") + FORMATS[fmt][1])
    path.write_text(render(rule, fmt), encoding="utf-8")
    return path

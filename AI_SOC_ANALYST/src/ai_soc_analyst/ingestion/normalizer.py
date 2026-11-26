"""Normalisation des enregistrements bruts (dict) vers NormalizedEvent.

Les alias couvrent les schémas courants : Windows/Sysmon, Microsoft Defender XDR (Advanced Hunting),
Microsoft Sentinel, CrowdStrike Falcon, Splunk (CIM), Elastic (ECS), QRadar, Proofpoint, Rapid7, Varonis.
Aucune valeur n'est inventée : un champ absent reste vide.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from .models import NormalizedEvent

# ------------------------------------------------------------------ utilitaires

def flatten(d: Any, prefix: str = "", out: dict | None = None, depth: int = 0) -> dict[str, Any]:
    out = {} if out is None else out
    if isinstance(d, dict) and depth < 6:
        for k, v in d.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                flatten(v, key, out, depth + 1)
            else:
                out[key] = v
                if isinstance(v, list) and v and all(isinstance(i, dict) for i in v) and depth < 4:
                    for i, item in enumerate(v[:20]):
                        flatten(item, f"{key}[{i}]", out, depth + 1)
    return out


def _lc_index(flat: dict[str, Any]) -> dict[str, Any]:
    idx: dict[str, Any] = {}
    for k, v in flat.items():
        idx.setdefault(k.lower(), v)
        short = k.split(".")[-1].lower()
        idx.setdefault(short, v)
    return idx


def first(idx: dict[str, Any], *names: str) -> str:
    for n in names:
        v = idx.get(n.lower())
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v if x is not None)
        s = str(v).strip()
        if s and s.lower() not in ("null", "none", "-", "n/a", "nan"):
            return s
    return ""


_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
               "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S",
               "%m/%d/%Y %I:%M:%S %p", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%b %d %Y %H:%M:%S",
               "%d/%b/%Y:%H:%M:%S %z")


def parse_timestamp(value: Any) -> datetime | None:
    """Convertit en datetime UTC naïf ; None si non interprétable (jamais d'heure inventée)."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{10}(\d{3})?(\.\d+)?", value)):
        num = float(value)
        if num > 1e12:
            num /= 1000.0
        if not 631152000 <= num <= 4102444800:  # 1990-2100
            return None
        dt = datetime.fromtimestamp(num, tz=timezone.utc)
    else:
        s = str(value).strip().replace("Z", "+00:00")
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # nanosecondes -> microsecondes
        dt = None
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            for fmt in _TS_FORMATS:
                try:
                    dt = datetime.strptime(s, fmt)
                    break
                except ValueError:
                    continue
        if dt is None:
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"'))[-1] if path else ""


_HASH_KV = re.compile(r"(MD5|SHA1|SHA256|IMPHASH)=([0-9A-Fa-f]+)")


def parse_hashes(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for algo, h in _HASH_KV.findall(value or ""):
        out[algo.lower()] = h.lower()
    if not out and value:
        v = value.strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}", v):
            out["sha256"] = v
        elif re.fullmatch(r"[0-9a-f]{40}", v):
            out["sha1"] = v
        elif re.fullmatch(r"[0-9a-f]{32}", v):
            out["md5"] = v
    return out


def _int_or_none(v: str) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _bool_or_none(v: str) -> bool | None:
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "signed", "valid", "oui"):
        return True
    if s in ("false", "0", "no", "unsigned", "notsigned", "non", "invalid"):
        return False
    return None


# ------------------------------------------------------------------ types d'événements

WIN_EVENT_TYPES = {
    "4688": "process_creation", "4624": "logon_success", "4625": "logon_failure", "4648": "logon_success",
    "4720": "account_change", "4722": "account_change", "4724": "account_change", "4726": "account_change",
    "4728": "group_change", "4732": "group_change", "4756": "group_change", "4697": "service_install",
    "4698": "scheduled_task", "4702": "scheduled_task", "1102": "log_cleared", "104": "log_cleared",
    "7045": "service_install", "4104": "powershell_script", "4103": "powershell_script", "4663": "file_create",
    "4740": "account_change", "4771": "logon_failure", "4776": "logon_failure", "5140": "generic",
    "6416": "usb_device", "4656": "process_access",
}
SYSMON_TYPES = {
    "1": "process_creation", "3": "network_connection", "7": "image_load", "8": "process_access",
    "10": "process_access", "11": "file_create", "12": "registry_set", "13": "registry_set", "14": "registry_set",
    "22": "dns_query", "23": "file_delete", "26": "file_delete", "15": "file_create",
}
ACTION_TYPES = {  # Defender XDR ActionType / CrowdStrike event_simpleName / ECS event.action
    "processcreated": "process_creation", "processrollup2": "process_creation", "syntheticprocessrollup2": "process_creation",
    "connectionsuccess": "network_connection", "connectionattempt": "network_connection",
    "networkconnectip4": "network_connection", "networkconnectip6": "network_connection",
    "dnsrequest": "dns_query", "dnsqueryresponse": "dns_query", "dnsquery": "dns_query",
    "registryvalueset": "registry_set", "asepvalueupdate": "registry_set", "reggenericvalueupdate": "registry_set",
    "filecreated": "file_create", "newexecutablewritten": "file_create", "pefilewritten": "file_create",
    "filedeleted": "file_delete", "filerenamed": "file_rename", "imageloaded": "image_load",
    "classifiedmoduleload": "image_load", "logonsuccess": "logon_success", "userlogon": "logon_success",
    "logonfailed": "logon_failure", "userlogonfailed2": "logon_failure", "serviceinstalled": "service_install",
    "scheduledtaskcreated": "scheduled_task", "scheduledtaskregistered": "scheduled_task",
    "usbdrivemounted": "usb_device", "dcusbdeviceconnected": "usb_device", "removablemediavolumemounted": "usb_device",
    "openprocessapicall": "process_access", "useraccountcreated": "account_change",
    "start": "process_creation", "exec": "process_creation", "process_started": "process_creation",
    "connection_attempted": "network_connection", "lookup_requested": "dns_query", "creation": "file_create",
    "deletion": "file_delete", "logged-in": "logon_success", "logon-failed": "logon_failure",
}


def infer_event_type(idx: dict[str, Any], ev: NormalizedEvent) -> str:
    provider = first(idx, "provider", "providername", "provider.name", "channel", "event.provider").lower()
    code = ev.event_code
    if code:
        if "sysmon" in provider or (ev.source_product == "Sysmon"):
            if code in SYSMON_TYPES:
                return SYSMON_TYPES[code]
        if code in WIN_EVENT_TYPES and "sysmon" not in provider:
            return WIN_EVENT_TYPES[code]
        key = re.sub(r"[^a-z0-9_-]", "", code.lower())
        if key in ACTION_TYPES:
            return ACTION_TYPES[key]
    action = re.sub(r"[^a-z0-9_-]", "", ev.action.lower())
    if action in ACTION_TYPES:
        return ACTION_TYPES[action]
    if ev.alert_name or first(idx, "alertname", "alert_name", "detectname", "threatname", "rule.name", "signature"):
        return "alert"
    if ev.email_from or ev.email_subject:
        return "email"
    if ev.dns_query:
        return "dns_query"
    if ev.registry_key:
        return "registry_set"
    if ev.image_loaded:
        return "image_load"
    if ev.command_line or (ev.process_name and ev.parent_name):
        return "process_creation"
    if ev.dst_ip and (ev.dst_port or ev.src_ip):
        return "network_connection"
    if ev.url:
        return "web_request"
    return "generic"


# ------------------------------------------------------------------ normalisation principale

def normalize_record(rec: dict[str, Any], source_product: str = "", file_ref: str = "", index: int = 0,
                     raw_text: str | None = None) -> NormalizedEvent:
    flat = flatten(rec)
    idx = _lc_index(flat)
    ev = NormalizedEvent(file_ref=file_ref, record_index=index, source_product=source_product)
    ev.timestamp_raw = first(idx, "utctime", "timecreated", "timecreated.systemtime", "systemtime", "timestamp",
                             "@timestamp", "timegenerated", "_time", "eventtime", "event_time", "time",
                             "starttime", "devicetime", "creationtime", "datetime", "date", "messagetime",
                             "createdtime", "created_at", "detecttime", "context_timestamp")
    ev.timestamp = parse_timestamp(ev.timestamp_raw)
    ev.event_code = first(idx, "eventid", "event_id", "eventcode", "actiontype", "event_simplename",
                          "event.code", "qid", "eventtype_id")
    ev.action = first(idx, "event.action", "action", "operation", "activity", "eventname", "event_name")
    ev.host = first(idx, "computer", "computername", "devicename", "hostname", "host.name", "host",
                    "dest_host", "agent.hostname", "workstationname", "machine", "endpoint")
    ev.user = first(idx, "user", "username", "user.name", "accountname", "account", "subjectusername",
                    "userprincipalname", "initiatingprocessaccountname", "targetusername", "user_name",
                    "recipient_user", "actor")
    domain = first(idx, "subjectdomainname", "accountdomain", "user.domain", "targetdomainname")
    if domain and ev.user and "\\" not in ev.user and "@" not in ev.user and domain not in ("-", "NT AUTHORITY"):
        ev.user = f"{domain}\\{ev.user}"
    ev.target_user = first(idx, "targetusername", "target_user", "membername", "samaccountname")
    ev.group_name = first(idx, "targetgroupname", "groupname", "group")
    ev.src_ip = first(idx, "sourceip", "src_ip", "srcip", "source.ip", "ipaddress", "clientip", "src",
                      "localip", "callingstationid", "client.ip", "source_address", "localaddressip4")
    ev.dst_ip = first(idx, "destinationip", "dst_ip", "dstip", "destination.ip", "remoteip", "dest_ip", "dest",
                      "dst", "remoteaddressip4", "remoteaddressip6", "destination_address")
    ev.src_port = _int_or_none(first(idx, "sourceport", "src_port", "srcport", "source.port", "localport", "spt"))
    ev.dst_port = _int_or_none(first(idx, "destinationport", "dst_port", "dstport", "destination.port",
                                     "remoteport", "dest_port", "dpt"))
    ev.dst_host = first(idx, "destinationhostname", "remoteurl", "destination.domain", "dest_host", "dhost")
    ev.protocol = first(idx, "protocol", "network.transport", "proto", "transport")
    ev.process_path = first(idx, "image", "newprocessname", "folderpath", "imagefilename", "process.executable",
                            "process_path", "processpath", "path", "filepath", "exe", "process.path")
    ev.process_name = first(idx, "filename", "process.name", "process_name", "processname", "originalfilename",
                            "initiatingprocessfilename_child") or basename(ev.process_path)
    if ev.process_name and ("\\" in ev.process_name or "/" in ev.process_name):
        if not ev.process_path:
            ev.process_path = ev.process_name
        ev.process_name = basename(ev.process_name)
    if ev.process_path and ev.process_name and not re.search(r"\.\w{2,4}$", ev.process_path) \
            and not ev.process_path.lower().endswith(ev.process_name.lower()):
        ev.process_path = ev.process_path.rstrip("\\/") + "\\" + ev.process_name
    ev.pid = first(idx, "processid", "newprocessid", "pid", "process.pid", "targetprocessid", "processid_dec")
    ev.command_line = first(idx, "commandline", "processcommandline", "process.command_line", "command_line",
                            "cmdline", "process.args", "cmd")
    ev.parent_path = first(idx, "parentimage", "parentprocessname", "process.parent.executable",
                           "initiatingprocessfolderpath", "parent_process_path", "parentimagefilename")
    ev.parent_name = first(idx, "initiatingprocessfilename", "parentbasefilename", "process.parent.name",
                           "parent_process_name", "parentprocess", "parent_name") or basename(ev.parent_path)
    if ev.parent_path and ev.parent_name and not ev.parent_path.lower().endswith(ev.parent_name.lower()) \
            and not re.search(r"\.\w{2,4}$", ev.parent_path):
        ev.parent_path = ev.parent_path.rstrip("\\/") + "\\" + ev.parent_name
    ev.ppid = first(idx, "parentprocessid", "initiatingprocessid", "process.parent.pid", "ppid",
                    "creatorprocessid", "parentprocessid_dec")
    ev.parent_command_line = first(idx, "parentcommandline", "initiatingprocesscommandline",
                                   "process.parent.command_line", "parent_command_line")
    hashes = parse_hashes(first(idx, "hashes", "hash"))
    ev.sha256 = (first(idx, "sha256", "sha256hashdata", "process.hash.sha256", "file.hash.sha256", "sha256hash")
                 or hashes.get("sha256", "")).lower()
    ev.sha1 = (first(idx, "sha1", "process.hash.sha1", "file.hash.sha1") or hashes.get("sha1", "")).lower()
    ev.md5 = (first(idx, "md5", "md5hashdata", "process.hash.md5", "file.hash.md5") or hashes.get("md5", "")).lower()
    ev.signed = _bool_or_none(first(idx, "signed", "issigned", "process.code_signature.exists",
                                    "signaturestatus", "file.code_signature.trusted"))
    ev.signer = first(idx, "signature", "signer", "process.code_signature.subject_name", "publisher", "company")
    ev.target_file = first(idx, "targetfilename", "file.path", "target_file", "objectname", "targetfilepath",
                            "file_path", "newfilename")
    ev.target_process = first(idx, "targetimage", "target.process.executable", "targetprocess")
    ev.granted_access = first(idx, "grantedaccess", "accessmask", "desiredaccess")
    ev.image_loaded = first(idx, "imageloaded", "dll.path", "loadedmodule", "modulepath")
    loaded_signed = first(idx, "imageloaded_signed", "dll.code_signature.exists")
    if loaded_signed:
        ev.image_loaded_signed = _bool_or_none(loaded_signed)
    elif ev.image_loaded and first(idx, "signed"):
        ev.image_loaded_signed = _bool_or_none(first(idx, "signed"))
    ev.registry_key = first(idx, "targetobject", "registrykey", "registry.path", "registry.key", "regobjectname",
                            "registry_path", "objectname_reg")
    ev.registry_value = first(idx, "details", "registryvaluedata", "registry.data.strings", "regstringvalue",
                              "registry_value_data", "registryvaluename")
    ev.dns_query = first(idx, "queryname", "dns.question.name", "domainname", "query", "dns_query", "qname")
    ev.dns_answer = first(idx, "queryresults", "dns.answers.data", "ipaddresses", "answer")
    ev.dns_rcode = first(idx, "querystatus", "dns.response_code", "rcode", "reply_code")
    ev.url = first(idx, "url", "remoteurl", "url.full", "request_url", "uri", "clickurl")
    ev.logon_type = first(idx, "logontype", "logon_type", "winlog.event_data.logontype")
    ev.service_name = first(idx, "servicename", "service_name", "service")
    ev.task_name = first(idx, "taskname", "task_name")
    ev.email_from = first(idx, "sender", "senderfromaddress", "from", "email.from.address", "mailfrom",
                          "headerfrom", "fromaddress")
    ev.email_to = first(idx, "recipient", "recipientemailaddress", "to", "email.to.address", "recipients",
                        "toaddresses")
    ev.email_reply_to = first(idx, "replyto", "reply_to", "headerreplyto")
    ev.email_subject = first(idx, "subject", "email.subject", "messagesubject")
    ev.email_auth = first(idx, "authenticationdetails", "spf", "dmarc", "authentication_results")
    ev.alert_name = first(idx, "alertname", "alert_name", "title", "detectname", "threatname", "rule.name",
                          "signature", "qidname", "detection_name", "displayname", "rulename")
    ev.alert_severity = first(idx, "severity", "alertseverity", "event.severity", "severityname", "magnitude",
                              "priority")
    ev.alert_verdict = first(idx, "verdict", "classification", "determination", "detectionstatus",
                             "patterndisposition_description", "actiontaken", "threatstatus", "remediationstatus",
                             "event.outcome", "outcome", "result")
    ev.message = first(idx, "message", "description", "msg", "rawmessage", "summary", "rendered_message")
    techniques: list[str] = []
    for k, v in flat.items():
        if re.search(r"(?i)(mitre|technique|attack)", k) and v:
            techniques += re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(v))
    ev.mitre_hint = sorted(set(techniques))
    for att_key in ("attachments", "attachmentnames", "filenames", "attachment"):
        v = idx.get(att_key)
        if v:
            ev.attachments = [str(x) for x in (v if isinstance(v, list) else re.split(r"[;,]\s*", str(v))) if x]
            break
    ev.event_type = infer_event_type(idx, ev)
    if ev.event_type == "file_create" and not ev.target_file and ev.process_path and ev.event_code.lower() in (
            "filecreated", "newexecutablewritten", "pefilewritten"):
        ev.target_file = ev.process_path
    if ev.event_type in ("logon_failure", "logon_success") and not ev.src_ip:
        ev.src_ip = first(idx, "ipaddress", "workstationname")
    try:
        ev.raw = raw_text if raw_text is not None else json.dumps(rec, ensure_ascii=False, default=str)[:20000]
    except (TypeError, ValueError):
        ev.raw = str(rec)[:20000]
    known = {f.lower() for f in NormalizedEvent.model_fields}
    ev.extra = {k: (v if isinstance(v, (str, int, float, bool)) or v is None else str(v))
                for k, v in list(flat.items())[:80] if k.split(".")[-1].lower() not in known}
    return ev


def normalize_many(records: Iterable[dict[str, Any]], source_product: str, file_ref: str,
                   start_index: int = 0) -> list[NormalizedEvent]:
    return [normalize_record(r, source_product, file_ref, i) for i, r in enumerate(records, start=start_index)]

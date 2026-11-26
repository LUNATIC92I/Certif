"""Parseur de journaux texte : Syslog (RFC 3164/5424), CEF, LEEF, clé=valeur (pare-feux), sshd, JSON lines."""
from __future__ import annotations

import json
import re
from datetime import datetime

_SYSLOG_3164 = re.compile(r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
                          r"(?P<app>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
_SYSLOG_5424 = re.compile(r"^<\d+>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+\S+\s+"
                          r"(?:\[.*?\]|-)\s*(?P<msg>.*)$")
_ISO_PREFIX = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$")
_KV = re.compile(r'(\w[\w.\-]*)=("([^"]*)"|\S+)')
_SSH_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)"
                       r"(?: port (?P<port>\d+))?")
_SSH_OK = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from "
                     r"(?P<ip>[\d.:a-fA-F]+)(?: port (?P<port>\d+))?")
_SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$")
_IPTABLES = re.compile(r"SRC=(?P<src>\S+)\s+DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)(?:.*?SPT=(?P<spt>\d+))?"
                       r"(?:.*?DPT=(?P<dpt>\d+))?")


def _parse_cef(line: str) -> dict | None:
    m = re.search(r"CEF:(\d+)\|", line)
    if not m:
        return None
    body = line[m.start():]
    parts = re.split(r"(?<!\\)\|", body, maxsplit=7)
    if len(parts) < 8:
        return None
    rec = {"cef_vendor": parts[1], "cef_product": parts[2], "cef_version": parts[3], "signature_id": parts[4],
           "alert_name": parts[5], "severity": parts[6]}
    ext = parts[7]
    keys = list(re.finditer(r"(?:^|\s)(\w+)=", ext))
    for i, k in enumerate(keys):
        end = keys[i + 1].start() if i + 1 < len(keys) else len(ext)
        rec[k.group(1)] = ext[k.end():end].strip()
    cef_map = {"src": "SourceIp", "dst": "DestinationIp", "spt": "SourcePort", "dpt": "DestinationPort",
               "suser": "User", "duser": "TargetUserName", "dhost": "DestinationHostName", "shost": "Hostname",
               "request": "Url", "fname": "FileName", "filePath": "FilePath", "fileHash": "Hash",
               "act": "Action", "proto": "Protocol", "msg": "Message", "rt": "Timestamp", "sproc": "ProcessName",
               "cs1": "cs1", "dproc": "ProcessName"}
    for k, v in list(rec.items()):
        if k in cef_map:
            rec[cef_map[k]] = v
    return rec


def _parse_leef(line: str) -> dict | None:
    m = re.search(r"LEEF:([\d.]+)\|", line)
    if not m:
        return None
    parts = line[m.start():].split("|", 5)
    if len(parts) < 6:
        return None
    rec = {"leef_vendor": parts[1], "leef_product": parts[2], "alert_name": parts[4]}
    sep = "\t"
    for kv in parts[5].split(sep):
        if "=" in kv:
            k, v = kv.split("=", 1)
            rec[k.strip()] = v.strip()
    for a, b in (("src", "SourceIp"), ("dst", "DestinationIp"), ("srcPort", "SourcePort"), ("dstPort", "DestinationPort"),
                 ("usrName", "User"), ("devTime", "Timestamp"), ("sev", "Severity")):
        if a in rec:
            rec[b] = rec[a]
    return rec


def parse_line(line: str, year: int | None = None) -> dict:
    line = line.rstrip("\r\n")
    rec: dict = {"message": line}
    s = line.strip()
    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    cef = _parse_cef(line)
    if cef:
        cef["message"] = line
        return cef
    leef = _parse_leef(line)
    if leef:
        leef["message"] = line
        return leef
    msg = line
    m = _SYSLOG_5424.match(line) or _SYSLOG_3164.match(line)
    if m:
        ts = m.group("ts")
        if _SYSLOG_3164.match(line) and year:
            try:
                ts = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S").isoformat()
            except ValueError:
                pass
        rec.update({"Timestamp": ts, "Hostname": m.group("host"), "ProcessName": m.group("app"),
                    "ProcessId": m.group("pid") if m.group("pid") not in (None, "-") else ""})
        msg = m.group("msg")
    else:
        m2 = _ISO_PREFIX.match(line)
        if m2:
            rec["Timestamp"] = m2.group("ts")
            msg = m2.group("rest")
    fail = _SSH_FAIL.search(msg)
    ok = _SSH_OK.search(msg)
    if fail:
        rec.update({"ActionType": "LogonFailed", "User": fail.group("user"), "SourceIp": fail.group("ip"),
                    "SourcePort": fail.group("port") or "", "LogonType": "network(ssh)"})
    elif ok:
        rec.update({"ActionType": "LogonSuccess", "User": ok.group("user"), "SourceIp": ok.group("ip"),
                    "SourcePort": ok.group("port") or "", "LogonType": "network(ssh)"})
    sudo = _SUDO.search(msg)
    if sudo:
        rec.update({"User": sudo.group("user"), "CommandLine": sudo.group("cmd").strip(), "ActionType": "exec"})
    ipt = _IPTABLES.search(msg)
    if ipt:
        rec.update({"SourceIp": ipt.group("src"), "DestinationIp": ipt.group("dst"), "Protocol": ipt.group("proto"),
                    "SourcePort": ipt.group("spt") or "", "DestinationPort": ipt.group("dpt") or "",
                    "Action": "DROP" if "DROP" in msg.upper() else ("ACCEPT" if "ACCEPT" in msg.upper() else "")})
    elif not (fail or ok or sudo):
        kvs = {k: (q if q else v) for k, v, q in _KV.findall(msg)}
        if len(kvs) >= 3:
            for k, v in kvs.items():
                rec.setdefault(k, v)
            low = {k.lower(): v for k, v in kvs.items()}
            for a, b in (("srcip", "SourceIp"), ("dstip", "DestinationIp"), ("srcport", "SourcePort"),
                         ("dstport", "DestinationPort"), ("src", "SourceIp"), ("dst", "DestinationIp"),
                         ("user", "User"), ("action", "Action"), ("devname", "Hostname"), ("proto", "Protocol"),
                         ("url", "Url"), ("hostname", "DestinationHostName")):
                if a in low and b not in rec:
                    rec[b] = low[a]
            if "date" in low and "time" in low and "Timestamp" not in rec:
                rec["Timestamp"] = f"{low['date']} {low['time']}"
            if any(k in low for k in ("srcip", "dstip", "src", "dst")) and "ActionType" not in rec:
                rec["log_kind"] = "firewall"
    rec["message"] = line
    return rec


def parse_text_lines(text: str, limit: int, year: int | None = None) -> list[dict]:
    year = year or datetime.now().year
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        out.append(parse_line(line, year))
        if len(out) >= limit:
            break
    return out

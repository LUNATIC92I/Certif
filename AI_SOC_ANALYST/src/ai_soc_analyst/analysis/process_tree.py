"""Construction des arbres de processus (relations parent/enfant) à partir des données disponibles.

Un nœud parent n'est créé que si l'événement enfant le décrit (nom ou chemin du parent) ;
il est alors marqué « observé via l'enfant » et aucune autre information n'est inventée.
"""
from __future__ import annotations

from collections import defaultdict

from ..ingestion.models import NormalizedEvent


def _node(ev: NormalizedEvent, flagged: dict[str, list[str]]) -> dict:
    return {"key": f"{ev.host}|{ev.pid}|{ev.process_name}", "process_name": ev.process_name, "pid": ev.pid,
            "parent_name": ev.parent_name, "ppid": ev.ppid, "command_line": ev.command_line,
            "path": ev.process_path, "sha256": ev.sha256, "md5": ev.md5, "user": ev.user,
            "time": ev.timestamp.isoformat(sep=" ") if ev.timestamp else (ev.timestamp_raw or "non horodaté"),
            "signed": ev.signed, "signer": ev.signer, "host": ev.host, "evidence_id": ev.evidence_id,
            "findings": flagged.get(ev.evidence_id, []), "network": [], "children": [], "inferred": False}


def build_trees(events: list[NormalizedEvent], flagged: dict[str, list[str]]) -> list[dict]:
    procs = [e for e in events if e.event_type == "process_creation" and (e.process_name or e.process_path)]
    by_host: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for e in procs:
        by_host[e.host].append(e)
    net_by_pid: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for e in events:
        if e.event_type in ("network_connection", "dns_query") and e.pid:
            net_by_pid[(e.host, e.pid)].append(e)
    roots_all: list[dict] = []
    for host, evs in by_host.items():
        evs.sort(key=lambda e: (e.timestamp is None, e.timestamp or 0, e.record_index))
        nodes_by_pid: dict[str, dict] = {}
        nodes: list[dict] = []
        for e in evs:
            n = _node(e, flagged)
            for c in net_by_pid.get((host, e.pid), [])[:20]:
                n["network"].append({"evidence_id": c.evidence_id, "dst": f"{c.dst_ip}:{c.dst_port}" if c.dst_ip else "",
                                     "dns": c.dns_query})
            nodes.append(n)
            if e.pid:
                nodes_by_pid[e.pid] = n  # le PID le plus récent l'emporte (réutilisation de PID)
        roots: list[dict] = []
        inferred: dict[tuple[str, str], dict] = {}
        for n in nodes:
            parent = nodes_by_pid.get(n["ppid"]) if n["ppid"] else None
            if parent is not None and parent is not n and _lc(parent["process_name"]) == _lc(n["parent_name"] or parent["process_name"]):
                parent["children"].append(n)
            elif n["parent_name"] or n["ppid"]:
                key = (n["parent_name"].lower(), n["ppid"])
                p = inferred.get(key)
                if p is None:
                    p = {"key": f"{host}|{n['ppid']}|{n['parent_name']}", "process_name": n["parent_name"] or "(parent inconnu)",
                         "pid": n["ppid"], "parent_name": "", "ppid": "", "command_line": "", "path": "",
                         "sha256": "", "md5": "", "user": "", "time": "", "signed": None, "signer": "", "host": host,
                         "evidence_id": "", "findings": [], "network": [], "children": [], "inferred": True}
                    inferred[key] = p
                    roots.append(p)
                p["children"].append(n)
            else:
                roots.append(n)
        for r in roots:
            r["host_root"] = host
        roots_all.extend(roots)
    return roots_all


def _lc(s: str) -> str:
    return (s or "").lower()


def flatten_tree(roots: list[dict], depth: int = 0) -> list[tuple[int, dict]]:
    out = []
    for r in roots:
        out.append((depth, r))
        out.extend(flatten_tree(r["children"], depth + 1))
    return out


def suspicious_processes(roots: list[dict]) -> list[dict]:
    out = []
    for _, n in flatten_tree(roots):
        if n["findings"]:
            out.append({k: n[k] for k in ("process_name", "pid", "parent_name", "ppid", "command_line", "path", "sha256",
                                          "user", "time", "signed", "host", "evidence_id", "findings")}
                       | {"network": [c["dst"] or c["dns"] for c in n["network"]]})
    return out

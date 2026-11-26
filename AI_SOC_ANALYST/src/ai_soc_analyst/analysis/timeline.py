"""Timeline et corrélation temporelle des événements en chaînes d'attaque potentielles.

Deux événements sont reliés s'ils partagent un hôte ET une relation concrète (même processus, relation
parent/enfant, même hash, même IOC réseau) dans une fenêtre de temps. Aucun événement manquant n'est inventé :
les « trous » sont signalés comme tels.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from ..ingestion.models import NormalizedEvent

WINDOW = timedelta(minutes=60)


class _UF:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, a: int) -> int:
        while self.p[a] != a:
            self.p[a] = self.p[self.p[a]]
            a = self.p[a]
        return a

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def build_timeline(events: list[NormalizedEvent], flagged: dict[str, list[str]], tactic_of: dict[str, str]) -> list[dict]:
    rows = []
    for e in sorted(events, key=lambda x: (x.timestamp is None, x.timestamp or 0, x.record_index)):
        rows.append({"evidence_id": e.evidence_id,
                     "time": e.timestamp.isoformat(sep=" ", timespec="seconds") if e.timestamp else "",
                     "time_raw": e.timestamp_raw, "host": e.host, "user": e.user, "event_type": e.event_type,
                     "summary": e.short(), "source": e.source_product, "file": e.file_ref,
                     "findings": flagged.get(e.evidence_id, []), "tactic": tactic_of.get(e.evidence_id, ""),
                     "chain": ""})
    return rows


def correlate(events: list[NormalizedEvent], flagged: dict[str, list[str]]) -> tuple[dict[str, str], list[dict]]:
    timed = [e for e in events if e.timestamp]
    uf = _UF(len(timed))
    idx_by_key: dict[tuple, list[int]] = defaultdict(list)
    for i, e in enumerate(timed):
        h = e.host.lower()
        if e.pid:
            idx_by_key[("pid", h, e.pid)].append(i)
        if e.ppid:
            idx_by_key[("pid", h, e.ppid)].append(i)
        for hv in (e.sha256, e.md5):
            if hv:
                idx_by_key[("hash", hv)].append(i)
        for ip in (e.dst_ip,):
            if ip:
                idx_by_key[("ip", ip)].append(i)
        if e.dns_query:
            idx_by_key[("dns", e.dns_query.lower())].append(i)
        if e.event_type in ("logon_failure", "logon_success") and (e.src_ip or e.user):
            idx_by_key[("auth", e.src_ip or e.user.lower())].append(i)
    for members in idx_by_key.values():
        members.sort(key=lambda k: timed[k].timestamp)
        for a, b in zip(members, members[1:]):
            if timed[b].timestamp - timed[a].timestamp <= WINDOW:
                uf.union(a, b)
    groups: dict[int, list[int]] = defaultdict(list)
    for i in range(len(timed)):
        groups[uf.find(i)].append(i)
    chains = []
    chain_of: dict[str, str] = {}
    n = 0
    for members in sorted(groups.values(), key=lambda m: min(timed[k].timestamp for k in m)):
        evs = [timed[k] for k in members]
        flagged_ids = [e.evidence_id for e in evs if e.evidence_id in flagged]
        if len(evs) < 2 or not flagged_ids:
            continue
        n += 1
        cid = f"CHAIN-{n:02d}"
        for e in evs:
            chain_of[e.evidence_id] = cid
        evs.sort(key=lambda e: e.timestamp)
        gaps = []
        for a, b in zip(evs, evs[1:]):
            if b.timestamp - a.timestamp > timedelta(minutes=30):
                gaps.append(f"Intervalle de {int((b.timestamp - a.timestamp).total_seconds() // 60)} min sans événement "
                            f"entre {a.evidence_id} et {b.evidence_id} (données manquantes possibles)")
        chains.append({"chain_id": cid, "hosts": sorted({e.host for e in evs if e.host}),
                       "start": evs[0].timestamp.isoformat(sep=" ", timespec="seconds"),
                       "end": evs[-1].timestamp.isoformat(sep=" ", timespec="seconds"),
                       "event_count": len(evs), "evidence_ids": [e.evidence_id for e in evs][:200],
                       "flagged_evidence_ids": flagged_ids, "findings": sorted({f for x in flagged_ids for f in flagged[x]}),
                       "gaps": gaps})
    return chain_of, chains

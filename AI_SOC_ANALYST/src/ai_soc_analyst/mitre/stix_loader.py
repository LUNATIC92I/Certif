"""Construction de l'index ATT&CK à partir du bundle STIX officiel (mitre-attack/attack-stix-data)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
            "enterprise-attack/enterprise-attack.json")

TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "stealth", "defense-impairment", "credential-access",
                "discovery", "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]


def _clean(desc: str, max_len: int = 700) -> str:
    desc = re.sub(r"\(Citation:[^)]*\)", "", desc or "")
    desc = re.sub(r"\[([^\]]+)\]\(https?://[^)]+\)", r"\1", desc)
    desc = re.sub(r"<code>|</code>", "", desc)
    desc = re.sub(r"\s+", " ", desc).strip()
    if len(desc) > max_len:
        cut = desc[:max_len]
        desc = cut[: cut.rfind(". ") + 1] if ". " in cut else cut + "…"
    return desc


def build_index(bundle: dict[str, Any]) -> dict[str, Any]:
    objects = bundle.get("objects", [])
    version = next((o.get("x_mitre_version", "") for o in objects if o.get("type") == "x-mitre-collection"), "")
    tactics = {}
    for o in objects:
        if o.get("type") == "x-mitre-tactic" and not o.get("x_mitre_deprecated"):
            ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
            short = o.get("x_mitre_shortname", "")
            tactics[short] = {"id": ext.get("external_id", ""), "name": o.get("name", ""), "shortname": short,
                              "order": TACTIC_ORDER.index(short) if short in TACTIC_ORDER else 99}
    techniques = {}
    for o in objects:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tid = ext.get("external_id", "")
        phases = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        techniques[tid] = {
            "id": tid, "name": o.get("name", ""), "tactics": phases, "url": ext.get("url", ""),
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")), "platforms": o.get("x_mitre_platforms", []),
            "description": _clean(o.get("description", "")),
            "detection": _clean(o.get("x_mitre_detection", ""), 400),
        }
    for tid, t in techniques.items():
        if "." in tid and tid.split(".")[0] in techniques:
            t["parent_name"] = techniques[tid.split(".")[0]]["name"]
    # Techniques révoquées -> remplaçantes (ex. T1574.002 -> T1574.001 en v20)
    ids = {}
    for o in objects:
        if o.get("type") == "attack-pattern":
            ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
            if ext:
                ids[o["id"]] = ext.get("external_id", "")
    revoked = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            old, new = ids.get(o.get("source_ref", "")), ids.get(o.get("target_ref", ""))
            if old and new and new in techniques:
                revoked[old] = new
    return {"source": "MITRE ATT&CK Enterprise (STIX 2.1)", "version": version, "tactics": tactics,
            "techniques": techniques, "revoked": revoked}


def build_index_file(stix_path: Path, out_path: Path) -> dict[str, Any]:
    index = build_index(json.loads(stix_path.read_text(encoding="utf-8")))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(index, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return index

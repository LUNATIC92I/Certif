"""MITRE ATT&CK Engine : référentiel (index STIX embarqué ou mis à jour) et mappage justifié par les preuves."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.logging_setup import get_logger
from ..core.paths import resource_dir

log = get_logger("mitre")
BUNDLED = resource_dir() / "mitre" / "data" / "attack_index.json"


class MitreCatalog:
    def __init__(self, cache_dir: Path | None = None):
        self.cache_file = (cache_dir / "attack_index.json") if cache_dir else None
        self.index: dict[str, Any] = {}
        self.origin = ""
        self.reload()

    def reload(self) -> None:
        for path, origin in ((self.cache_file, "mise à jour locale"), (BUNDLED, "index embarqué")):
            if path and path.exists():
                try:
                    self.index = json.loads(path.read_text(encoding="utf-8"))
                    self.origin = origin
                    return
                except ValueError:
                    log.error("Index ATT&CK illisible : %s", path)
        self.index = {"techniques": {}, "tactics": {}, "revoked": {}, "version": "?"}
        self.origin = "indisponible"

    @property
    def version(self) -> str:
        return str(self.index.get("version", "?"))

    def resolve(self, technique_id: str) -> dict | None:
        """Renvoie la technique, en suivant les révocations (ex. T1574.002 -> T1574.001)."""
        tid = technique_id.strip().upper()
        seen = set()
        while tid in self.index.get("revoked", {}) and tid not in seen:
            seen.add(tid)
            tid = self.index["revoked"][tid]
        return self.index.get("techniques", {}).get(tid)

    def tactic_name(self, shortname: str) -> str:
        t = self.index.get("tactics", {}).get(shortname)
        return t["name"] if t else shortname.replace("-", " ").title()

    def tactic_order(self, shortname: str) -> int:
        t = self.index.get("tactics", {}).get(shortname)
        return t.get("order", 99) if t else 99

    def tactics_sorted(self) -> list[dict]:
        return sorted(self.index.get("tactics", {}).values(), key=lambda t: (t.get("order", 99), t["name"]))

    def techniques_for_tactic(self, shortname: str) -> list[dict]:
        return sorted((t for t in self.index.get("techniques", {}).values() if shortname in t["tactics"]),
                      key=lambda t: t["id"])

    def search(self, text: str) -> list[dict]:
        q = text.lower().strip()
        return [t for t in self.index.get("techniques", {}).values()
                if q in t["id"].lower() or q in t["name"].lower() or q in t.get("description", "").lower()][:300]

    def update_from_bundle(self, bundle: dict) -> dict:
        from .stix_loader import build_index

        index = build_index(bundle)
        if len(index["techniques"]) < 100:
            raise ValueError("Bundle STIX incomplet : moins de 100 techniques")
        if not self.cache_file:
            raise ValueError("Aucun répertoire de cache configuré")
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        self.cache_file.write_text(json.dumps(index, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        self.reload()
        return {"version": index["version"], "techniques": len(index["techniques"])}

    def update_online(self, timeout: float = 120.0) -> dict:
        import httpx

        from .stix_loader import STIX_URL

        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(STIX_URL)
            resp.raise_for_status()
            return self.update_from_bundle(resp.json())


def build_mappings(findings: list, catalog: MitreCatalog) -> list[dict]:
    """Une entrée par (technique, tactique) justifiée par au moins une finding et ses événements."""
    agg: dict[tuple[str, str], dict] = {}
    for f in findings:
        if f.status == "False Positive":
            continue
        for raw_id in f.mitre_ids:
            tech = catalog.resolve(raw_id)
            if not tech:
                continue
            for tactic in tech["tactics"] or ["unknown"]:
                key = (tech["id"], tactic)
                entry = agg.setdefault(key, {
                    "technique_id": tech["id"], "technique_name": tech["name"],
                    "tactic": catalog.tactic_name(tactic), "tactic_short": tactic,
                    "tactic_order": catalog.tactic_order(tactic),
                    "description": tech.get("description", ""), "url": tech.get("url", ""),
                    "evidence_ids": [], "finding_ids": [], "confidence": 0.0,
                    "requested_id": raw_id if raw_id != tech["id"] else "",
                })
                entry["finding_ids"].append(f.finding_id)
                entry["evidence_ids"] = sorted(set(entry["evidence_ids"]) | set(f.evidence_ids))
                entry["confidence"] = max(entry["confidence"], f.confidence)
    return sorted(agg.values(), key=lambda e: (e["tactic_order"], e["technique_id"]))

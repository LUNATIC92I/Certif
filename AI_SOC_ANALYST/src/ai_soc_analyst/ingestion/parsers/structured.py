"""Parseurs de formats structurés : JSON / JSON Lines, CSV, XML (événements Windows), EVTX."""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterator

_CONTAINER_KEYS = ("events", "records", "Records", "data", "results", "value", "hits", "alerts", "items",
                   "incidents", "rows", "entities", "detections", "logs", "resources")


def read_text(path: Path, max_bytes: int | None = None) -> str:
    raw = path.read_bytes() if max_bytes is None else path.open("rb").read(max_bytes)
    for enc in ("utf-8-sig", "utf-16"):
        try:
            if enc == "utf-16" and not raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                continue
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1")


def _explode(obj: Any, depth: int = 0) -> list[dict]:
    """Trouve la liste d'enregistrements dans un document JSON (exports SIEM, API, Elastic hits...)."""
    if isinstance(obj, list):
        out: list[dict] = []
        for item in obj:
            if isinstance(item, dict):
                if "_source" in item and isinstance(item["_source"], dict):
                    out.append(item["_source"])
                else:
                    out.append(item)
        return out
    if isinstance(obj, dict) and depth < 4:
        lowered = {str(k).lower(): k for k in obj}
        for key in _CONTAINER_KEYS:
            if key.lower() in lowered:
                inner = obj[lowered[key.lower()]]
                if isinstance(inner, dict) and "hits" in inner:
                    inner = inner["hits"]
                found = _explode(inner, depth + 1)
                if found:
                    # Contexte d'incident (Sentinel/Defender) : on garde les attributs racine dans un enregistrement
                    context = {k: v for k, v in obj.items() if not isinstance(v, (list, dict))}
                    return ([context | {"_record_kind": "incident_context"}] if len(context) >= 2 else []) + found
        return [obj]
    return []


def parse_json(path: Path) -> list[dict]:
    text = read_text(path).strip()
    try:
        return _explode(json.loads(text))
    except json.JSONDecodeError:
        records = []
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSON invalide ligne {n} : {exc.msg}") from exc
            records.extend(_explode(obj) if isinstance(obj, (list, dict)) else [])
        if not records:
            raise ValueError("Aucun enregistrement JSON exploitable")
        return records


def parse_csv(path: Path) -> list[dict]:
    text = read_text(path)
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        raise ValueError("CSV sans ligne d'en-tête")
    rows = []
    for row in reader:
        rows.append({(k or "").strip(): (v.strip() if isinstance(v, str) else v) for k, v in row.items() if k})
    return rows


_NS = re.compile(r"^\{[^}]+\}")


def _strip(tag: str) -> str:
    return _NS.sub("", tag)


def windows_event_xml_to_dict(elem: ET.Element) -> dict:
    """Convertit un élément <Event> (schéma Windows) en dictionnaire plat."""
    d: dict[str, Any] = {}
    for child in elem.iter():
        tag = _strip(child.tag)
        if tag == "Provider":
            d["Provider"] = child.get("Name", "")
        elif tag == "TimeCreated":
            d["TimeCreated"] = child.get("SystemTime", "")
        elif tag == "Execution":
            d.setdefault("ExecutionProcessID", child.get("ProcessID", ""))
        elif tag == "Security" and child.get("UserID"):
            d.setdefault("SecurityUserID", child.get("UserID"))
        elif tag in ("EventID", "Computer", "Channel", "Level", "Task", "Keywords", "EventRecordID"):
            d[tag] = (child.text or "").strip()
        elif tag == "Data":
            name = child.get("Name")
            if name:
                d[name] = (child.text or "").strip()
            else:
                d.setdefault("Data", []).append((child.text or "").strip())
    return d


def parse_xml(path: Path) -> list[dict]:
    text = read_text(path)
    try:
        root = ET.fromstring(text.encode("utf-8") if not text.lstrip().startswith("<?xml") else text.encode("utf-8"))
    except ET.ParseError:
        # Fichier contenant plusieurs <Event> sans racine (export wevtutil /f:xml)
        root = ET.fromstring(("<Events>" + re.sub(r"<\?xml[^>]*\?>", "", text) + "</Events>").encode("utf-8"))
    events = [e for e in root.iter() if _strip(e.tag) == "Event"]
    if events:
        return [windows_event_xml_to_dict(e) for e in events]
    # XML générique : un enregistrement par enfant direct de la racine
    out = []
    for child in list(root):
        rec = {_strip(c.tag): (c.text or "").strip() for c in child.iter() if c is not child and (c.text or "").strip()}
        rec.update({k: v for k, v in child.attrib.items()})
        if rec:
            out.append(rec)
    return out or [{"message": ET.tostring(root, encoding="unicode")[:20000]}]


def iter_evtx(path: Path, limit: int) -> Iterator[tuple[dict, str]]:
    from Evtx.Evtx import Evtx  # python-evtx (lecture seule, pur Python)

    with Evtx(str(path)) as log:
        for n, record in enumerate(log.records()):
            if n >= limit:
                break
            try:
                xml = record.xml()
                elem = ET.fromstring(xml.encode("utf-8"))
                yield windows_event_xml_to_dict(elem), xml
            except Exception:  # noqa: BLE001 - un enregistrement corrompu ne doit pas bloquer l'import
                continue

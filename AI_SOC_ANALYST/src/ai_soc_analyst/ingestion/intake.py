"""INCIDENT INTAKE : validation, quarantaine, détection de format/source, parsing et normalisation.

Règles de sûreté :
- aucun fichier importé n'est exécuté ; la copie de travail est stockée en quarantaine sans extension,
  en lecture seule, sous un nom dérivé de son SHA256 ;
- les archives sont contrôlées (ZIP bomb, path traversal, chiffrement) avant d'être lues membre par membre,
  directement en mémoire, sans extraction sur disque des chemins d'origine.
"""
from __future__ import annotations

import io
import os
import shutil
import stat
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)
from pathlib import Path
from typing import Callable

from ..core.logging_setup import get_logger
from ..core.security import safe_filename
from ..core.settings import LimitSettings
from .models import NormalizedEvent
from .normalizer import normalize_record
from .parsers import documents, structured, text
from .source_detect import detect_source
from .static_analysis import analyze_file
from .validation import IntakeError, ZipLimits, check_zip_safety, detect_format, sha256_file

log = get_logger("intake")
ProgressCb = Callable[[int, str], None]


@dataclass
class FileRecord:
    original_name: str
    size: int
    sha256: str
    imported_at: datetime
    detected_format: str = "unknown"
    detected_source: str = "Inconnue"
    status: str = "pending"  # ok / partial / error / rejected
    message: str = ""
    stored_path: str = ""
    events: list[NormalizedEvent] = field(default_factory=list)
    children: list["FileRecord"] = field(default_factory=list)
    static_analysis: dict = field(default_factory=dict)

    def all_records(self):
        yield self
        for c in self.children:
            yield from c.all_records()


@dataclass
class IntakeResult:
    files: list[FileRecord] = field(default_factory=list)
    events: list[NormalizedEvent] = field(default_factory=list)

    def all_files(self) -> list[FileRecord]:
        return [r for f in self.files for r in f.all_records()]


class IntakeService:
    def __init__(self, quarantine_dir: Path, limits: LimitSettings | None = None):
        self.quarantine = quarantine_dir
        self.limits = limits or LimitSettings()
        self.quarantine.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- quarantaine
    def _store(self, data: bytes | None, src: Path | None, sha256: str) -> Path:
        target = self.quarantine / sha256[:2] / f"{sha256}.quarantine"
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            tmp = target.with_suffix(".tmp")
            if data is not None:
                tmp.write_bytes(data)
            else:
                shutil.copyfile(src, tmp)  # type: ignore[arg-type]
            os.replace(tmp, target)
            try:
                os.chmod(target, stat.S_IREAD)  # lecture seule, aucun bit d'exécution
            except OSError:
                pass
        return target

    # ---------------------------------------------------------------- API publique
    def import_paths(self, paths: list[Path], progress: ProgressCb | None = None) -> IntakeResult:
        result = IntakeResult()
        for i, p in enumerate(paths):
            if progress:
                progress(int(100 * i / max(1, len(paths))), f"Import de {p.name}")
            rec = self.import_path(p)
            result.files.append(rec)
        result.events = [e for f in result.all_files() for e in f.events]
        return result

    def import_path(self, path: Path) -> FileRecord:
        now = utcnow()
        name = path.name
        try:
            if not path.is_file():
                raise IntakeError("Le chemin indiqué n'est pas un fichier lisible.")
            size = path.stat().st_size
            if size > self.limits.max_file_mb * 1024 * 1024:
                raise IntakeError(f"Fichier trop volumineux ({size / 1048576:.1f} Mo, limite {self.limits.max_file_mb} Mo).")
            digest = sha256_file(path)
        except (IntakeError, OSError) as exc:
            return FileRecord(name, 0, "", now, status="rejected", message=str(exc))
        stored = self._store(None, path, digest)
        rec = FileRecord(name, size, digest, now, stored_path=str(stored))
        self._process(rec, stored, original_name=name, depth=0)
        return rec

    def import_bytes(self, name: str, data: bytes, depth: int = 0) -> FileRecord:
        import hashlib

        digest = hashlib.sha256(data).hexdigest()
        stored = self._store(data, None, digest)
        rec = FileRecord(safe_filename(name), len(data), digest, utcnow(), stored_path=str(stored))
        self._process(rec, stored, original_name=name, depth=depth)
        return rec

    def import_pasted_text(self, content: str) -> FileRecord:
        return self.import_bytes("log_colle.txt", content.encode("utf-8"))

    @staticmethod
    def manual_event(fields: dict[str, str]) -> NormalizedEvent | None:
        """Événement issu de la saisie manuelle de l'analyste (clairement étiqueté comme tel)."""
        useful = {k: v.strip() for k, v in fields.items() if isinstance(v, str) and v.strip()}
        if not useful:
            return None
        rec = {"AlertName": useful.get("alert_name", "Saisie manuelle"), "Hostname": useful.get("host", ""),
               "User": useful.get("user", ""), "SourceIp": useful.get("src_ip", useful.get("ip", "")),
               "DestinationIp": useful.get("dst_ip", ""), "AlertSource": useful.get("source", ""),
               "ProcessName": useful.get("process", ""), "CommandLine": useful.get("command_line", ""),
               "SHA256": useful.get("file_hash", useful.get("hash", "")), "Description": useful.get("description", ""),
               "Timestamp": useful.get("timestamp", ""), "Severity": useful.get("severity", "")}
        ev = normalize_record({k: v for k, v in rec.items() if v}, "Saisie manuelle (analyste)", "saisie_manuelle", 0)
        ev.event_type = "alert"
        return ev

    # ---------------------------------------------------------------- traitement
    def _process(self, rec: FileRecord, stored: Path, original_name: str, depth: int) -> None:
        try:
            info = self._detect(stored, original_name)
            rec.detected_format = info.fmt
            limit = self.limits.max_events_per_file
            raw_records: list[dict] = []
            raw_texts: list[str | None] = []
            fmt = info.fmt
            if fmt == "json":
                raw_records = structured.parse_json(stored)
            elif fmt == "csv":
                raw_records = structured.parse_csv(stored)
            elif fmt in ("txt", "log"):
                raw_records = text.parse_text_lines(structured.read_text(stored), limit)
            elif fmt == "xml":
                raw_records = structured.parse_xml(stored)
            elif fmt == "evtx":
                for r, xml in structured.iter_evtx(stored, limit):
                    raw_records.append(r)
                    raw_texts.append(xml)
            elif fmt == "eml":
                raw_records = documents.parse_eml(stored)
            elif fmt == "msg":
                raw_records = documents.parse_msg(stored)
            elif fmt == "pdf":
                raw_records = text.parse_text_lines(documents.pdf_text(stored), limit)
            elif fmt == "docx":
                raw_records = text.parse_text_lines(documents.docx_text(stored), limit)
            elif fmt == "xlsx":
                raw_records = documents.xlsx_records(stored, limit)
            elif fmt == "pe":
                rec.static_analysis = analyze_file(stored)
                rec.detected_source = "Fichier exécutable (analyse statique)"
                rec.status = "ok"
                rec.message = "Exécutable analysé statiquement (jamais exécuté)."
                ev = normalize_record({"ActionType": "FileImported", "FileName": original_name, "SHA256": rec.sha256,
                                       "Description": "; ".join(rec.static_analysis.get("indicators", []))},
                                      "Analyse statique", original_name, 0)
                ev.event_type = "file_create"
                ev.target_file = original_name
                ev.extra["static_analysis"] = rec.static_analysis
                rec.events = [ev]
                return
            elif fmt == "zip":
                self._process_zip(rec, stored, depth)
                return
            raw_records = raw_records[:limit]
            rec.detected_source = detect_source(raw_records, fmt, original_name)
            events = []
            for i, r in enumerate(raw_records):
                rt = raw_texts[i] if i < len(raw_texts) else None
                events.append(normalize_record(r, rec.detected_source, original_name, i, rt))
            rec.events = events
            rec.status = "ok" if events else "partial"
            rec.message = f"{len(events)} événement(s) normalisé(s)" + (" (limite atteinte)" if len(raw_records) >= limit else "")
        except IntakeError as exc:
            rec.status, rec.message = "rejected", str(exc)
        except Exception as exc:  # noqa: BLE001 - un fichier invalide ne doit jamais interrompre l'import
            log.exception("Échec du parsing de %s", original_name)
            rec.status, rec.message = "error", f"Lecture impossible ({type(exc).__name__}) : {exc}"[:500]

    def _detect(self, stored: Path, original_name: str):
        with stored.open("rb") as f:
            head = f.read(8192)
        return detect_format(stored, head, original_name)

    def _process_zip(self, rec: FileRecord, stored: Path, depth: int) -> None:
        if depth >= self.limits.max_zip_depth:
            raise IntakeError("Archive imbriquée au-delà de la profondeur autorisée.")
        limits = ZipLimits(self.limits.max_zip_total_mb * 1048576, self.limits.max_zip_entries,
                           self.limits.max_zip_ratio, self.limits.max_file_mb * 1048576)
        members = check_zip_safety(stored, limits)
        rec.detected_source = "Archive ZIP"
        with zipfile.ZipFile(stored) as z:
            for info in members:
                with z.open(info) as fh:
                    data = _read_limited(fh, limits.max_member_bytes)
                child = self.import_bytes(info.filename, data, depth + 1)
                rec.children.append(child)
        ok = sum(1 for c in rec.children if c.status in ("ok", "partial"))
        rec.status = "ok" if ok == len(rec.children) else ("partial" if ok else "error")
        rec.message = f"{len(rec.children)} fichier(s) dans l'archive, {ok} traité(s)"


def _read_limited(fh: io.BufferedIOBase, max_bytes: int) -> bytes:
    data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise IntakeError("Membre d'archive plus volumineux que déclaré (ZIP bomb ?).")
    return data

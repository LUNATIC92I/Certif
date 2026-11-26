"""Validation des fichiers importés : signature réelle, taille, archives sûres."""
from __future__ import annotations

import hashlib
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ..core.security import is_unsafe_archive_member

SUPPORTED = ("json", "csv", "txt", "log", "xml", "evtx", "eml", "msg", "pdf", "docx", "xlsx", "zip", "pe")


class IntakeError(Exception):
    """Erreur de validation compréhensible par l'analyste."""


@dataclass
class FormatInfo:
    fmt: str
    mime: str
    note: str = ""


_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def _looks_text(head: bytes) -> bool:
    if not head:
        return True
    if head.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in head[:4096]:
        return False
    try:
        head.decode("utf-8")
        return True
    except UnicodeDecodeError:
        printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in head[:4096])
        return printable / max(1, len(head[:4096])) > 0.85


def detect_format(path: Path, head: bytes | None = None, name: str | None = None) -> FormatInfo:
    """Identifie le format d'après la signature du contenu, l'extension (du nom d'origine) ne servant qu'à départager.

    ``path`` est toujours le fichier réellement lu (copie en quarantaine) ; ``name`` le nom d'origine éventuel.
    """
    if head is None:
        with path.open("rb") as f:
            head = f.read(8192)
    ext = Path(name or path.name).suffix.lower().lstrip(".")
    if head.startswith(b"ElfFile\x00"):
        return FormatInfo("evtx", "application/x-ms-evtx")
    if head.startswith(b"%PDF-"):
        return FormatInfo("pdf", "application/pdf")
    if head.startswith(b"MZ"):
        return FormatInfo("pe", "application/vnd.microsoft.portable-executable",
                          "Exécutable Windows : analyse statique uniquement, jamais exécuté")
    if head.startswith(_OLE):
        if ext == "msg" or b"__substg1.0_" in head or ext not in ("doc", "xls"):
            return FormatInfo("msg", "application/vnd.ms-outlook")
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        try:
            with zipfile.ZipFile(path) as z:
                names = set(z.namelist())
        except zipfile.BadZipFile as exc:
            raise IntakeError(f"Archive ZIP corrompue : {exc}") from exc
        if "word/document.xml" in names:
            return FormatInfo("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
        if "xl/workbook.xml" in names:
            return FormatInfo("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        return FormatInfo("zip", "application/zip")
    if _looks_text(head):
        text = head.decode("utf-8", errors="replace").lstrip("﻿ \t\r\n")
        if text.startswith(("{", "[")):
            return FormatInfo("json", "application/json")
        if text.startswith("<"):
            return FormatInfo("xml", "application/xml")
        first = text.splitlines()[0] if text else ""
        if ext == "eml" or any(text.lower().startswith(h) for h in ("received:", "return-path:", "from:",
                                                                     "delivered-to:", "message-id:", "mime-version:")):
            return FormatInfo("eml", "message/rfc822")
        if ext == "csv" or (first.count(",") >= 2 and not first.startswith(("<", "CEF:", "LEEF:"))
                            and ext not in ("log", "txt")):
            return FormatInfo("csv", "text/csv")
        return FormatInfo("log" if ext == "log" else "txt", "text/plain")
    raise IntakeError("Format binaire non pris en charge : seuls les formats listés peuvent être importés.")


@dataclass
class ZipLimits:
    max_total_bytes: int
    max_entries: int
    max_ratio: int
    max_member_bytes: int


def check_zip_safety(path: Path, limits: ZipLimits) -> list[zipfile.ZipInfo]:
    """Contrôle anti ZIP bomb et anti path traversal avant toute extraction."""
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise IntakeError(f"Archive ZIP invalide : {exc}") from exc
    with z:
        infos = z.infolist()
        if len(infos) > limits.max_entries:
            raise IntakeError(f"Archive refusée : {len(infos)} entrées (limite {limits.max_entries}).")
        total = 0
        safe: list[zipfile.ZipInfo] = []
        for info in infos:
            if info.is_dir():
                continue
            if is_unsafe_archive_member(info.filename):
                raise IntakeError(f"Archive refusée : chemin dangereux détecté ({info.filename!r}).")
            if info.flag_bits & 0x1:
                raise IntakeError(f"Archive refusée : membre chiffré ({info.filename}). Fournissez une archive non chiffrée.")
            if info.file_size > limits.max_member_bytes:
                raise IntakeError(f"Archive refusée : {info.filename} dépasse la taille maximale par fichier.")
            ratio = info.file_size / max(1, info.compress_size)
            if info.file_size > 1_000_000 and ratio > limits.max_ratio:
                raise IntakeError(f"Archive refusée : taux de compression suspect ({ratio:.0f}:1) – possible ZIP bomb.")
            total += info.file_size
            if total > limits.max_total_bytes:
                raise IntakeError("Archive refusée : taille décompressée totale supérieure à la limite (ZIP bomb ?).")
            safe.append(info)
        return safe

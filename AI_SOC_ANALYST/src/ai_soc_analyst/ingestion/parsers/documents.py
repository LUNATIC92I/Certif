"""Parseurs de messages et de documents : EML, MSG, PDF, DOCX, XLSX (lecture seule, sans exécution)."""
from __future__ import annotations

import email
import hashlib
import re
from email import policy
from pathlib import Path

_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)


def _auth_summary(msg) -> str:  # noqa: ANN001
    vals = []
    for h in ("Authentication-Results", "Received-SPF", "ARC-Authentication-Results"):
        for v in msg.get_all(h, []) or []:
            vals.append(str(v))
    text = " ".join(vals).lower()
    found = []
    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{proto}=(\w+)", text)
        if m:
            found.append(f"{proto}={m.group(1)}")
    if not found and "received-spf" in " ".join(msg.keys()).lower():
        spf = str(msg.get("Received-SPF", "")).split()[0:1]
        if spf:
            found.append(f"spf={spf[0].lower()}")
    return " ".join(found)


def parse_eml(path: Path) -> list[dict]:
    msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
    body_parts, attachments = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename:
            attachments.append({"name": filename, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
                                "content_type": part.get_content_type()})
        elif part.get_content_type() in ("text/plain", "text/html"):
            try:
                body_parts.append(part.get_content())
            except (LookupError, UnicodeDecodeError):
                body_parts.append(payload.decode("latin-1", errors="replace"))
    body = "\n".join(body_parts)
    received = msg.get_all("Received", []) or []
    origin_ip = ""
    for r in reversed(received):
        m = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", str(r))
        if m:
            origin_ip = m.group(1)
            break
    record = {
        "Timestamp": str(msg.get("Date", "")), "From": str(msg.get("From", "")), "To": str(msg.get("To", "")),
        "ReplyTo": str(msg.get("Reply-To", "")), "Subject": str(msg.get("Subject", "")),
        "MessageId": str(msg.get("Message-ID", "")), "ReturnPath": str(msg.get("Return-Path", "")),
        "AuthenticationDetails": _auth_summary(msg), "SourceIp": origin_ip,
        "Attachments": [a["name"] for a in attachments], "Urls": sorted(set(_URL.findall(body)))[:200],
        "message": body[:20000], "ActionType": "EmailReceived",
    }
    records = [record]
    for a in attachments:
        records.append({"Timestamp": record["Timestamp"], "ActionType": "EmailAttachment", "TargetFilename": a["name"],
                        "SHA256": a["sha256"], "size": a["size"], "content_type": a["content_type"],
                        "From": record["From"], "Subject": record["Subject"]})
    for u in record["Urls"]:
        records.append({"Timestamp": record["Timestamp"], "ActionType": "EmailUrl", "Url": u,
                        "From": record["From"], "Subject": record["Subject"]})
    return records


def parse_msg(path: Path) -> list[dict]:
    import extract_msg

    m = extract_msg.openMsg(str(path))
    try:
        body = m.body or ""
        attachments = []
        for att in m.attachments:
            data = getattr(att, "data", b"") or b""
            if isinstance(data, bytes):
                attachments.append({"name": att.longFilename or att.shortFilename or "piece_jointe",
                                    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
        record = {"Timestamp": str(m.date or ""), "From": m.sender or "", "To": m.to or "", "Subject": m.subject or "",
                  "ReplyTo": getattr(m, "replyTo", "") or "", "Attachments": [a["name"] for a in attachments],
                  "Urls": sorted(set(_URL.findall(body)))[:200], "message": body[:20000],
                  "ActionType": "EmailReceived", "AuthenticationDetails": ""}
        headers = getattr(m, "header", None)
        if headers is not None:
            record["AuthenticationDetails"] = _auth_summary(headers)
        out = [record]
        for a in attachments:
            out.append({"Timestamp": record["Timestamp"], "ActionType": "EmailAttachment", "TargetFilename": a["name"],
                        "SHA256": a["sha256"], "size": a["size"], "From": record["From"], "Subject": record["Subject"]})
        return out
    finally:
        m.close()


def pdf_text(path: Path, max_pages: int = 300) -> str:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    if reader.is_encrypted:
        raise ValueError("PDF chiffré : impossible d'extraire le texte sans mot de passe")
    return "\n".join((p.extract_text() or "") for p in reader.pages[:max_pages])


def docx_text(path: Path) -> str:
    import docx

    d = docx.Document(str(path))
    lines = [p.text for p in d.paragraphs]
    for table in d.tables:
        for row in table.rows:
            lines.append(" | ".join(c.text for c in row.cells))
    return "\n".join(lines)


def xlsx_records(path: Path, limit: int) -> list[dict]:
    import openpyxl

    fh = path.open("rb")  # objet fichier : le nom en quarantaine n'a pas d'extension .xlsx
    wb = openpyxl.load_workbook(fh, read_only=True, data_only=True)  # formules non évaluées, macros ignorées
    out: list[dict] = []
    try:
        for ws in wb.worksheets:
            rows = ws.iter_rows(values_only=True)
            header = next(rows, None)
            if not header:
                continue
            names = [str(h).strip() if h is not None else f"col{i}" for i, h in enumerate(header)]
            for row in rows:
                if row is None or all(v is None for v in row):
                    continue
                rec = {names[i]: ("" if v is None else str(v)) for i, v in enumerate(row) if i < len(names)}
                rec["_sheet"] = ws.title
                out.append(rec)
                if len(out) >= limit:
                    return out
    finally:
        wb.close()
        fh.close()
    return out

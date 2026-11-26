"""Génération et enregistrement des rapports d'une investigation."""
from __future__ import annotations

import json
from pathlib import Path

from ..core.logging_setup import get_logger
from ..core.security import safe_filename
from ..db.models import Report
from .model import build_report, to_json
from .renderers import render_docx, render_html, render_ioc_csv, render_pdf, sha256_of

log = get_logger("reporting")
FORMATS = ("pdf", "docx", "html", "json", "csv")


def generate_reports(svc, inv_id: int, level: str, formats: list[str], out_dir: Path | None = None,  # noqa: ANN001
                     tlp: str = "TLP:AMBER") -> list[Path]:
    if level not in ("executive", "technical"):
        raise ValueError("Niveau de rapport invalide")
    inv = svc.get(inv_id)
    if inv is None or inv.status != "completed":
        raise ValueError("L'investigation doit être terminée avant de générer un rapport.")
    result = inv.result()
    try:
        ai = json.loads(inv.ai_result_json or "{}") or None
    except ValueError:
        ai = None
    report = build_report(inv, result, svc.files(inv_id), svc.actions(inv_id), ai, level, tlp)
    out_dir = out_dir or (svc.ctx.paths.reports / inv.reference)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = safe_filename(f"{inv.reference}_{level}")
    paths = []
    for fmt in formats:
        if fmt not in FORMATS:
            raise ValueError(f"Format inconnu : {fmt}")
        if fmt == "csv":
            p = out_dir / f"{safe_filename(inv.reference)}_iocs.csv"
            render_ioc_csv(result, p)
        else:
            p = out_dir / f"{base}.{fmt}"
            {"pdf": render_pdf, "docx": render_docx, "html": render_html}.get(fmt, lambda r, q: q.write_text(
                to_json(r, result), encoding="utf-8"))(report, p)
        digest = sha256_of(p)
        with svc.ctx.db.session() as s:
            s.add(Report(investigation_id=inv_id, level=level, fmt=fmt, path=str(p), sha256=digest))
        paths.append(p)
    svc.audit("report.generate", f"{level} : {', '.join(formats)}", inv_id)
    log.info("Rapports générés pour %s : %s", inv.reference, [x.name for x in paths])
    return paths


def list_reports(svc, inv_id: int | None = None) -> list[Report]:  # noqa: ANN001
    from sqlalchemy import select

    with svc.ctx.db.session() as s:
        q = select(Report).order_by(Report.created_at.desc())
        if inv_id:
            q = q.where(Report.investigation_id == inv_id)
        return list(s.scalars(q).all())

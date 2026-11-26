"""Service applicatif des investigations : création, import, analyse, persistance, reprise et statistiques."""
from __future__ import annotations

import json
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable

from sqlalchemy import delete, func, select

from ..analysis.engine import analyze
from ..analysis.results import Finding as FindingDC, IOCRecord, InvestigationResult
from ..core.logging_setup import get_logger
from ..db.models import (AuditLog, Event, Finding, ImportedFile, Investigation, IOC, MitreMapping, ResponseAction,
                         utcnow)
from ..ingestion.intake import FileRecord, IntakeService
from ..ingestion.models import NormalizedEvent
from .context import AppContext

log = get_logger("service")
ProgressCb = Callable[[int, str], None]
ACTIVE = ("importing", "analyzing")


def _dumps(o) -> str:  # noqa: ANN001
    return json.dumps(o, ensure_ascii=False, default=str)


class InvestigationService:
    def __init__(self, ctx: AppContext):
        self.ctx = ctx

    # ------------------------------------------------------------ audit
    def audit(self, action: str, details: str = "", investigation_id: int | None = None) -> None:
        with self.ctx.db.session() as s:
            s.add(AuditLog(actor=self.ctx.settings.analyst_name, action=action, details=details[:4000],
                           investigation_id=investigation_id))

    # ------------------------------------------------------------ création
    def create(self, title: str, analyst: str = "", manual: dict | None = None, pasted_text: str = "") -> int:
        with self.ctx.db.session() as s:
            day = datetime.now().strftime("%Y%m%d")
            count = s.scalar(select(func.count()).select_from(Investigation)
                             .where(Investigation.reference.like(f"INC-{day}-%"))) or 0
            ref = f"INC-{day}-{count + 1:04d}"
            while s.scalar(select(Investigation.id).where(Investigation.reference == ref)):
                count += 1
                ref = f"INC-{day}-{count + 1:04d}"
            inv = Investigation(reference=ref, title=title.strip() or f"Investigation {ref}",
                                analyst=analyst or self.ctx.settings.analyst_name,
                                manual_input=_dumps(manual or {}), pasted_text=pasted_text, status="new")
            s.add(inv)
            s.flush()
            inv_id = inv.id
        self.audit("investigation.create", ref, inv_id)
        return inv_id

    # ------------------------------------------------------------ import + analyse
    def run(self, inv_id: int, paths: list[Path], progress: ProgressCb | None = None) -> InvestigationResult:
        p = progress or (lambda *_: None)
        start = time.monotonic()
        self._set(inv_id, status="importing", stage="Import des preuves", error="")
        try:
            intake = IntakeService(self.ctx.paths.quarantine, self.ctx.settings.limits)
            records: list[FileRecord] = []
            for i, path in enumerate(paths):
                p(int(30 * i / max(1, len(paths))), f"Import : {path.name}")
                records.append(intake.import_path(path))
            with self.ctx.db.session() as s:
                inv = s.get(Investigation, inv_id)
                pasted, manual = inv.pasted_text, json.loads(inv.manual_input or "{}")
            if pasted.strip():
                records.append(intake.import_pasted_text(pasted))
            manual_ev = IntakeService.manual_event(manual)
            self._store_files_and_events(inv_id, records, manual_ev)
            self.audit("investigation.import", f"{len(records)} fichier(s)", inv_id)
        except Exception as exc:  # noqa: BLE001
            log.exception("Échec de l'import pour l'investigation %s", inv_id)
            self._set(inv_id, status="failed", stage="Import", error=f"{type(exc).__name__}: {exc}")
            raise
        return self.analyze(inv_id, progress=lambda v, m: p(30 + int(v * 0.7), m), started=start)

    def analyze(self, inv_id: int, progress: ProgressCb | None = None, started: float | None = None) -> InvestigationResult:
        """(Ré)analyse à partir des événements persistés : sert aussi à reprendre une investigation interrompue."""
        start = started or time.monotonic()
        self._set(inv_id, status="analyzing", stage="Analyse")
        try:
            events = self.load_events(inv_id)
            with self.ctx.db.session() as s:
                inv = s.get(Investigation, inv_id)
                context = {"title": inv.title, "analyst": inv.analyst, **json.loads(inv.manual_input or "{}")}
            result = analyze(events, self.ctx.catalog, progress, context)
            self._persist_result(inv_id, result, time.monotonic() - start)
            self.audit("investigation.analyze", f"verdict={result.verdict} severity={result.severity}", inv_id)
            return result
        except Exception as exc:  # noqa: BLE001
            log.exception("Échec de l'analyse %s", inv_id)
            self._set(inv_id, status="failed", stage="Analyse", error=f"{type(exc).__name__}: {exc}")
            raise

    def add_files(self, inv_id: int, paths: list[Path], progress: ProgressCb | None = None) -> InvestigationResult:
        intake = IntakeService(self.ctx.paths.quarantine, self.ctx.settings.limits)
        records = [intake.import_path(pth) for pth in paths]
        self._store_files_and_events(inv_id, records, None)
        return self.analyze(inv_id, progress)

    # ------------------------------------------------------------ persistance
    def _set(self, inv_id: int, **fields) -> None:
        with self.ctx.db.session() as s:
            inv = s.get(Investigation, inv_id)
            for k, v in fields.items():
                setattr(inv, k, v)

    def _store_files_and_events(self, inv_id: int, records: list[FileRecord], manual_ev: NormalizedEvent | None) -> None:
        with self.ctx.db.session() as s:
            n = s.scalar(select(func.count()).select_from(Event).where(Event.investigation_id == inv_id)) or 0

            def store(rec: FileRecord, parent_id: int | None) -> None:
                nonlocal n
                row = ImportedFile(investigation_id=inv_id, parent_id=parent_id, original_name=rec.original_name[:500],
                                   stored_path=rec.stored_path, imported_at=rec.imported_at, size=rec.size,
                                   detected_format=rec.detected_format, detected_source=rec.detected_source,
                                   sha256=rec.sha256, status=rec.status, message=rec.message,
                                   event_count=len(rec.events), static_analysis_json=_dumps(rec.static_analysis))
                s.add(row)
                s.flush()
                for ev in rec.events:
                    n += 1
                    ev.evidence_id = f"EVT-{n:05d}"
                    s.add(self._event_row(inv_id, row.id, ev))
                for child in rec.children:
                    store(child, row.id)

            for rec in records:
                store(rec, None)
            if manual_ev is not None:
                n += 1
                manual_ev.evidence_id = f"EVT-{n:05d}"
                s.add(self._event_row(inv_id, None, manual_ev))

    @staticmethod
    def _event_row(inv_id: int, file_id: int | None, ev: NormalizedEvent) -> Event:
        data = ev.model_dump(mode="json", exclude={"raw"})
        return Event(investigation_id=inv_id, file_id=file_id, evidence_id=ev.evidence_id, record_index=ev.record_index,
                     timestamp=ev.timestamp, source_product=ev.source_product[:60], event_type=ev.event_type,
                     host=ev.host[:255], user=ev.user[:255], process_name=ev.process_name[:255],
                     command_line=ev.command_line, data_json=_dumps(data), raw=ev.raw[:20000])

    def load_events(self, inv_id: int) -> list[NormalizedEvent]:
        with self.ctx.db.session() as s:
            rows = s.scalars(select(Event).where(Event.investigation_id == inv_id).order_by(Event.id)).all()
            out = []
            for r in rows:
                ev = NormalizedEvent.model_validate(json.loads(r.data_json))
                ev.raw = r.raw
                ev.evidence_id = r.evidence_id
                out.append(ev)
            return out

    def _persist_result(self, inv_id: int, res: InvestigationResult, duration: float) -> None:
        with self.ctx.db.session() as s:
            for model in (Finding, IOC, MitreMapping):
                s.execute(delete(model).where(model.investigation_id == inv_id))
            # les décisions déjà prises sur des actions sont conservées
            kept = {(a.action_type, a.target) for a in s.scalars(select(ResponseAction).where(
                ResponseAction.investigation_id == inv_id, ResponseAction.status != "Proposée"))}
            s.execute(delete(ResponseAction).where(ResponseAction.investigation_id == inv_id,
                                                   ResponseAction.status == "Proposée"))
            for f in res.findings:
                s.add(Finding(investigation_id=inv_id, finding_id=f.finding_id, rule_id=f.rule_id, title=f.title,
                              category=f.category, description=f.description, severity=f.severity, status=f.status,
                              confidence=f.confidence, evidence_ids=_dumps(f.evidence_ids), mitre_ids=_dumps(f.mitre_ids),
                              details_json=_dumps(f.details | {"benign_context": f.benign_context})))
            for i in res.iocs:
                s.add(IOC(investigation_id=inv_id, value=i.value, ioc_type=i.ioc_type, reputation=i.reputation, risk=i.risk,
                          source=i.source, justification=i.justification, validation_status=i.validation_status,
                          occurrences=i.occurrences, evidence_ids=_dumps(i.evidence_ids)))
            for m in res.mitre:
                s.add(MitreMapping(investigation_id=inv_id, tactic=m["tactic"], technique_id=m["technique_id"],
                                   technique_name=m["technique_name"], description=m["description"],
                                   evidence_ids=_dumps(m["evidence_ids"]), finding_ids=_dumps(m["finding_ids"]),
                                   confidence=m["confidence"]))
            for a in res.recommendations:
                if (a["action_type"], a["target"]) in kept:
                    continue
                s.add(ResponseAction(investigation_id=inv_id, action_type=a["action_type"], target=a["target"][:1000],
                                     objective=a["objective"], justification=a["justification"], risk=a["risk"],
                                     impact=a["impact"], prerequisites=a["prerequisites"], procedure=a["procedure"],
                                     priority=a["priority"], evidence_ids=_dumps(a["evidence_ids"])))
            inv = s.get(Investigation, inv_id)
            inv.status, inv.stage, inv.error = "completed", "Terminée", ""
            inv.verdict, inv.confidence, inv.severity = res.verdict, res.confidence, res.severity
            inv.risk_score, inv.incident_type, inv.threat_category = res.risk_score, res.incident_type, res.threat_category
            inv.summary = res.summary
            inv.duration_seconds = round(duration, 2)
            inv.result_json = _dumps(res.to_dict())

    # ------------------------------------------------------------ reprise après interruption
    def recover_interrupted(self) -> list[int]:
        with self.ctx.db.session() as s:
            rows = s.scalars(select(Investigation).where(Investigation.status.in_(ACTIVE))).all()
            for inv in rows:
                inv.status, inv.error = "interrupted", "Interrompue (fermeture ou arrêt de l'application) : reprise possible."
            ids = [r.id for r in rows]
        for i in ids:
            self.audit("investigation.interrupted", "", i)
        return ids

    def resume(self, inv_id: int, progress: ProgressCb | None = None) -> InvestigationResult:
        return self.analyze(inv_id, progress)

    # ------------------------------------------------------------ lecture / mise à jour
    def get(self, inv_id: int) -> Investigation | None:
        with self.ctx.db.session() as s:
            return s.get(Investigation, inv_id)

    def list(self, status: str | None = None, severity: str | None = None, text: str = "") -> list[Investigation]:
        with self.ctx.db.session() as s:
            q = select(Investigation).order_by(Investigation.created_at.desc())
            if status:
                q = q.where(Investigation.status == status)
            if severity:
                q = q.where(Investigation.severity == severity)
            if text:
                like = f"%{text}%"
                q = q.where(Investigation.title.like(like) | Investigation.reference.like(like) |
                            Investigation.incident_type.like(like))
            return list(s.scalars(q).all())

    def files(self, inv_id: int) -> list[ImportedFile]:
        with self.ctx.db.session() as s:
            return list(s.scalars(select(ImportedFile).where(ImportedFile.investigation_id == inv_id)
                                  .order_by(ImportedFile.id)).all())

    def events(self, inv_id: int, text: str = "", limit: int = 5000) -> list[Event]:
        with self.ctx.db.session() as s:
            q = select(Event).where(Event.investigation_id == inv_id)
            if text:
                like = f"%{text}%"
                q = q.where(Event.command_line.like(like) | Event.host.like(like) | Event.user.like(like) |
                            Event.process_name.like(like) | Event.evidence_id.like(like) | Event.raw.like(like) |
                            Event.event_type.like(like))
            return list(s.scalars(q.order_by(Event.timestamp.is_(None), Event.timestamp, Event.id).limit(limit)).all())

    def findings(self, inv_id: int) -> list[Finding]:
        with self.ctx.db.session() as s:
            return list(s.scalars(select(Finding).where(Finding.investigation_id == inv_id).order_by(Finding.finding_id)).all())

    def iocs(self, inv_id: int) -> list[IOC]:
        with self.ctx.db.session() as s:
            return list(s.scalars(select(IOC).where(IOC.investigation_id == inv_id).order_by(IOC.id)).all())

    def mitre(self, inv_id: int) -> list[MitreMapping]:
        with self.ctx.db.session() as s:
            return list(s.scalars(select(MitreMapping).where(MitreMapping.investigation_id == inv_id)).all())

    def actions(self, inv_id: int) -> list[ResponseAction]:
        with self.ctx.db.session() as s:
            return list(s.scalars(select(ResponseAction).where(ResponseAction.investigation_id == inv_id)
                                  .order_by(ResponseAction.id)).all())

    def decide_action(self, action_id: int, decision: str, comment: str) -> None:
        if decision not in ("Approuvée", "Rejetée", "Réalisée", "Proposée"):
            raise ValueError("Décision invalide")
        with self.ctx.db.session() as s:
            a = s.get(ResponseAction, action_id)
            a.status, a.decision_comment = decision, comment
            a.decided_by, a.decided_at = self.ctx.settings.analyst_name, utcnow()
            inv_id = a.investigation_id
            label = f"{a.action_type} → {a.target}"
        self.audit("response.decision", f"{decision} : {label} ({comment})", inv_id)

    def update_ioc_reputation(self, inv_id: int, value: str, reputation: str, risk: str | None, provider_summary: str) -> None:
        with self.ctx.db.session() as s:
            for ioc in s.scalars(select(IOC).where(IOC.investigation_id == inv_id, IOC.value == value)):
                ioc.reputation = reputation
                ioc.validation_status = f"Réputation vérifiée ({provider_summary})"
                if risk:
                    ioc.risk = risk

    def save_notes(self, inv_id: int, notes: str) -> None:
        self._set(inv_id, analyst_notes=notes)
        self.audit("investigation.notes", f"{len(notes)} caractères", inv_id)

    def save_ai_result(self, inv_id: int, data: dict) -> None:
        self._set(inv_id, ai_result_json=_dumps(data))
        self.audit("ai.analysis", f"fournisseur={data.get('provider')}", inv_id)

    def delete(self, inv_id: int) -> None:
        with self.ctx.db.session() as s:
            inv = s.get(Investigation, inv_id)
            ref = inv.reference if inv else str(inv_id)
            for model in (Event, Finding, IOC, MitreMapping, ResponseAction):
                s.execute(delete(model).where(model.investigation_id == inv_id))
            s.execute(delete(ImportedFile).where(ImportedFile.investigation_id == inv_id))
            if inv:
                s.delete(inv)
        self.audit("investigation.delete", ref)

    def audit_log(self, limit: int = 2000) -> list[AuditLog]:
        with self.ctx.db.session() as s:
            return list(s.scalars(select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)).all())

    # ------------------------------------------------------------ tableau de bord
    def dashboard(self) -> dict:
        with self.ctx.db.session() as s:
            invs = s.scalars(select(Investigation)).all()
            sev = Counter(i.severity for i in invs if i.status == "completed")
            verdicts = Counter(i.verdict for i in invs if i.status == "completed")
            cats = Counter(i.threat_category for i in invs if i.status == "completed" and i.threat_category)
            durations = [i.duration_seconds for i in invs if i.status == "completed" and i.duration_seconds]
            tech = Counter()
            for m in s.scalars(select(MitreMapping)):
                tech[f"{m.technique_id} {m.technique_name}"] += 1
            recent = sorted(invs, key=lambda i: i.created_at, reverse=True)[:12]
            return {
                "total": len(invs), "critical": sev.get("Critical", 0), "high": sev.get("High", 0),
                "medium": sev.get("Medium", 0), "low": sev.get("Low", 0) + sev.get("Informational", 0),
                "confirmed": verdicts.get("Confirmed", 0), "likely": verdicts.get("Likely", 0),
                "false_positives": verdicts.get("False Positive", 0),
                "avg_seconds": round(sum(durations) / len(durations), 2) if durations else 0.0,
                "categories": cats.most_common(8), "techniques": tech.most_common(10),
                "recent": [(i.id, i.reference, i.title, i.severity, i.verdict, i.status, i.created_at) for i in recent],
                "by_status": Counter(i.status for i in invs),
            }

    def result(self, inv_id: int) -> dict:
        inv = self.get(inv_id)
        return inv.result() if inv else {}


def result_from_dict(d: dict) -> InvestigationResult:
    """Reconstruit un InvestigationResult depuis le JSON persisté (pour la génération de rapports)."""
    findings = [FindingDC(**f) for f in d.get("findings", [])]
    iocs = [IOCRecord(**i) for i in d.get("iocs", [])]
    fields = {k: d[k] for k in InvestigationResult.__dataclass_fields__ if k in d and k not in ("findings", "iocs")}
    return InvestigationResult(findings=findings, iocs=iocs, **fields)

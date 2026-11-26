"""Schéma de la base de données (SQLAlchemy 2.0, SQLite)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class JSONText(Text):
    """Marqueur documentaire : colonne texte contenant du JSON."""


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reference: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(300))
    analyst: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    stage: Mapped[str] = mapped_column(String(60), default="")
    severity: Mapped[str] = mapped_column(String(12), default="Unknown", index=True)
    verdict: Mapped[str] = mapped_column(String(20), default="Inconclusive", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    incident_type: Mapped[str] = mapped_column(String(120), default="")
    threat_category: Mapped[str] = mapped_column(String(120), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    manual_input: Mapped[str] = mapped_column(JSONText, default="{}")
    pasted_text: Mapped[str] = mapped_column(Text, default="")
    result_json: Mapped[str] = mapped_column(JSONText, default="{}")
    ai_result_json: Mapped[str] = mapped_column(JSONText, default="{}")
    analyst_notes: Mapped[str] = mapped_column(Text, default="")
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str] = mapped_column(Text, default="")

    files: Mapped[list["ImportedFile"]] = relationship(back_populates="investigation", cascade="all, delete-orphan")

    def result(self) -> dict:
        try:
            return json.loads(self.result_json or "{}")
        except ValueError:
            return {}


class ImportedFile(Base):
    __tablename__ = "imported_files"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("imported_files.id"), nullable=True)
    original_name: Mapped[str] = mapped_column(String(500))
    stored_path: Mapped[str] = mapped_column(String(1000), default="")
    imported_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    size: Mapped[int] = mapped_column(Integer, default=0)
    detected_format: Mapped[str] = mapped_column(String(20), default="unknown")
    detected_source: Mapped[str] = mapped_column(String(60), default="Inconnue")
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    message: Mapped[str] = mapped_column(Text, default="")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    static_analysis_json: Mapped[str] = mapped_column(JSONText, default="{}")

    investigation: Mapped[Investigation] = relationship(back_populates="files")


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    file_id: Mapped[int | None] = mapped_column(ForeignKey("imported_files.id", ondelete="CASCADE"), nullable=True)
    evidence_id: Mapped[str] = mapped_column(String(20), index=True)  # ex. EVT-00012
    record_index: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    source_product: Mapped[str] = mapped_column(String(60), default="")
    event_type: Mapped[str] = mapped_column(String(40), default="generic", index=True)
    host: Mapped[str] = mapped_column(String(255), default="")
    user: Mapped[str] = mapped_column(String(255), default="")
    process_name: Mapped[str] = mapped_column(String(255), default="")
    command_line: Mapped[str] = mapped_column(Text, default="")
    data_json: Mapped[str] = mapped_column(JSONText, default="{}")
    raw: Mapped[str] = mapped_column(Text, default="")


Index("ix_events_inv_evid", Event.investigation_id, Event.evidence_id)


class IOC(Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    value: Mapped[str] = mapped_column(String(2000))
    ioc_type: Mapped[str] = mapped_column(String(30), index=True)
    reputation: Mapped[str] = mapped_column(String(60), default="Non vérifiée")
    risk: Mapped[str] = mapped_column(String(20), default="Info")
    source: Mapped[str] = mapped_column(String(200), default="")
    justification: Mapped[str] = mapped_column(Text, default="")
    validation_status: Mapped[str] = mapped_column(String(60), default="Non validé")
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    evidence_ids: Mapped[str] = mapped_column(JSONText, default="[]")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str] = mapped_column(String(20))
    rule_id: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(12))
    status: Mapped[str] = mapped_column(String(20))  # Confirmed / Likely / Suspicious / Inconclusive / False Positive
    confidence: Mapped[float] = mapped_column(Float)
    evidence_ids: Mapped[str] = mapped_column(JSONText, default="[]")
    mitre_ids: Mapped[str] = mapped_column(JSONText, default="[]")
    details_json: Mapped[str] = mapped_column(JSONText, default="{}")


class MitreMapping(Base):
    __tablename__ = "mitre_mappings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    tactic: Mapped[str] = mapped_column(String(60))
    technique_id: Mapped[str] = mapped_column(String(16), index=True)
    technique_name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_ids: Mapped[str] = mapped_column(JSONText, default="[]")
    finding_ids: Mapped[str] = mapped_column(JSONText, default="[]")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    action_type: Mapped[str] = mapped_column(String(60))
    target: Mapped[str] = mapped_column(String(1000), default="")
    objective: Mapped[str] = mapped_column(Text, default="")
    justification: Mapped[str] = mapped_column(Text, default="")
    risk: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    prerequisites: Mapped[str] = mapped_column(Text, default="")
    procedure: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(String(12), default="Medium")
    status: Mapped[str] = mapped_column(String(20), default="Proposée")  # Proposée / Approuvée / Rejetée / Réalisée
    decided_by: Mapped[str] = mapped_column(String(120), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decision_comment: Mapped[str] = mapped_column(Text, default="")
    evidence_ids: Mapped[str] = mapped_column(JSONText, default="[]")


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    investigation_id: Mapped[int] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    level: Mapped[str] = mapped_column(String(20))  # executive / technical
    fmt: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(1000))
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TISearch(Base):
    __tablename__ = "ti_searches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    provider: Mapped[str] = mapped_column(String(40))
    indicator: Mapped[str] = mapped_column(String(2000))
    ioc_type: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30))  # ok / not_found / error / skipped
    verdict: Mapped[str] = mapped_column(String(40), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    raw_json: Mapped[str] = mapped_column(JSONText, default="{}")
    from_cache: Mapped[bool] = mapped_column(Boolean, default=False)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(80))
    investigation_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details: Mapped[str] = mapped_column(Text, default="")

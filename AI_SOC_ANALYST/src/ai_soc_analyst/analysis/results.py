"""Structures de résultats d'investigation."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

STATUSES = ("Confirmed", "Likely", "Suspicious", "Inconclusive", "False Positive")
STATUS_FR = {"Confirmed": "Confirmé", "Likely": "Probable", "Suspicious": "Suspect", "Inconclusive": "Non concluant",
             "False Positive": "Faux positif"}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0, "Unknown": 0}


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    title: str
    category: str
    description: str
    severity: str
    status: str
    confidence: float
    evidence_ids: list[str]
    mitre_ids: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    benign_context: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class IOCRecord:
    value: str
    ioc_type: str
    reputation: str = "Non vérifiée"
    risk: str = "Info"
    source: str = ""
    justification: str = ""
    validation_status: str = "Non validé"
    occurrences: int = 1
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class InvestigationResult:
    triage: dict[str, Any]
    findings: list[Finding]
    iocs: list[IOCRecord]
    mitre: list[dict]
    timeline: list[dict]
    chains: list[dict]
    process_trees: list[dict]
    suspicious_processes: list[dict]
    verdict: str
    confidence: float
    severity: str
    risk_score: int
    incident_type: str
    threat_category: str
    summary: str
    root_cause: str
    impact: str
    false_positive_assessment: str
    limitations: list[str]
    recommendations: list[dict]
    stats: dict[str, Any]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        d["iocs"] = [i.to_dict() for i in self.iocs]
        return d

"""Modèle d'événement normalisé commun à toutes les sources."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

EVENT_TYPES = (
    "process_creation", "process_access", "image_load", "network_connection", "dns_query", "registry_set",
    "file_create", "file_delete", "file_rename", "logon_success", "logon_failure", "service_install",
    "scheduled_task", "account_change", "group_change", "log_cleared", "powershell_script", "usb_device",
    "email", "alert", "firewall", "web_request", "generic",
)


class NormalizedEvent(BaseModel):
    evidence_id: str = ""
    file_ref: str = ""  # nom du fichier source
    record_index: int = 0
    timestamp: datetime | None = None
    timestamp_raw: str = ""
    source_product: str = ""
    event_type: str = "generic"
    event_code: str = ""  # Event ID Windows, ActionType Defender, event_simpleName CrowdStrike...
    action: str = ""
    host: str = ""
    user: str = ""
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    dst_host: str = ""
    protocol: str = ""
    process_name: str = ""
    process_path: str = ""
    pid: str = ""
    command_line: str = ""
    parent_name: str = ""
    parent_path: str = ""
    ppid: str = ""
    parent_command_line: str = ""
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    signed: bool | None = None
    signer: str = ""
    target_file: str = ""
    target_process: str = ""
    granted_access: str = ""
    image_loaded: str = ""
    image_loaded_signed: bool | None = None
    registry_key: str = ""
    registry_value: str = ""
    dns_query: str = ""
    dns_answer: str = ""
    dns_rcode: str = ""
    url: str = ""
    logon_type: str = ""
    service_name: str = ""
    task_name: str = ""
    target_user: str = ""
    group_name: str = ""
    email_from: str = ""
    email_to: str = ""
    email_reply_to: str = ""
    email_subject: str = ""
    email_auth: str = ""
    attachments: list[str] = Field(default_factory=list)
    alert_name: str = ""
    alert_severity: str = ""
    alert_verdict: str = ""
    mitre_hint: list[str] = Field(default_factory=list)
    message: str = ""
    raw: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    def text_blob(self) -> str:
        """Concaténation des champs textuels utiles à l'extraction d'IOC."""
        parts = [self.command_line, self.parent_command_line, self.process_path, self.parent_path, self.url,
                 self.dns_query, self.dns_answer, self.registry_key, self.registry_value, self.target_file,
                 self.image_loaded, self.src_ip, self.dst_ip, self.dst_host, self.sha256, self.sha1, self.md5,
                 self.email_from, self.email_to, self.email_reply_to, self.email_subject, self.message,
                 " ".join(self.attachments), self.alert_name]
        return "\n".join(p for p in parts if p)

    def short(self) -> str:
        bits = [self.event_type]
        if self.process_name:
            bits.append(self.process_name)
        if self.command_line:
            bits.append(self.command_line[:160])
        elif self.message:
            bits.append(self.message[:160])
        if self.dst_ip:
            bits.append(f"→ {self.dst_ip}:{self.dst_port or ''}")
        if self.dns_query:
            bits.append(f"DNS {self.dns_query}")
        if self.registry_key:
            bits.append(self.registry_key[:120])
        if self.target_file:
            bits.append(self.target_file[:120])
        return " | ".join(bits)

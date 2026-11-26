"""Paramètres applicatifs validés par Pydantic et persistés en JSON (sans secrets)."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from .logging_setup import get_logger

log = get_logger("settings")

AIProvider = Literal["local", "openai", "anthropic", "azure_openai", "ollama"]
TI_PROVIDERS = ("virustotal", "abuseipdb", "otx", "urlhaus", "malwarebazaar", "threatfox")


class AISettings(BaseModel):
    provider: AIProvider = "local"
    openai_model: str = "gpt-4o-mini"
    anthropic_model: str = "claude-sonnet-5-5"
    azure_endpoint: str = ""
    azure_deployment: str = ""
    azure_api_version: str = "2024-10-21"
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.1"
    timeout_seconds: float = Field(60.0, ge=5, le=600)
    max_events_in_prompt: int = Field(60, ge=10, le=500)


class TISettings(BaseModel):
    enabled: dict[str, bool] = Field(default_factory=lambda: {p: False for p in TI_PROVIDERS})
    timeout_seconds: float = Field(20.0, ge=3, le=120)
    cache_hours: int = Field(24, ge=0, le=720)


class LimitSettings(BaseModel):
    max_file_mb: int = Field(200, ge=1, le=4096)
    max_zip_total_mb: int = Field(1024, ge=1, le=16384)
    max_zip_entries: int = Field(5000, ge=1, le=100000)
    max_zip_ratio: int = Field(150, ge=5, le=10000)
    max_zip_depth: int = Field(2, ge=0, le=5)
    max_events_per_file: int = Field(500000, ge=1000, le=10_000_000)


class Settings(BaseModel):
    language: Literal["fr", "en"] = "fr"
    analyst_name: str = "Analyste SOC"
    privacy_mode: bool = True  # aucune transmission externe tant que désactivé explicitement
    ai: AISettings = Field(default_factory=AISettings)
    ti: TISettings = Field(default_factory=TISettings)
    limits: LimitSettings = Field(default_factory=LimitSettings)
    password_hash: str = ""  # contrôle d'accès local optionnel (PBKDF2)
    backups_to_keep: int = Field(7, ge=1, le=100)


def load_settings(path: Path) -> Settings:
    if not path.exists():
        return Settings()
    try:
        return Settings.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, ValidationError) as exc:
        log.error("Paramètres invalides, valeurs par défaut utilisées : %s", exc)
        backup = path.with_suffix(".invalid.json")
        try:
            path.replace(backup)
        except OSError:
            pass
        return Settings()


def save_settings(settings: Settings, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(settings.model_dump_json(indent=2), encoding="utf-8")
    os.replace(tmp, path)

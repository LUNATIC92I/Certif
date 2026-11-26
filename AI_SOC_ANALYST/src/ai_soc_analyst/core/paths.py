"""Emplacements des données applicatives (base, quarantaine, rapports, journaux, sauvegardes)."""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


def _default_home() -> Path:
    override = os.environ.get("AI_SOC_HOME")
    if override:
        return Path(override)
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        if (exe_dir / "portable.ini").exists():  # version portable : données à côté de l'exécutable
            return exe_dir / "data"
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "AI_SOC_ANALYST"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "ai_soc_analyst"


def resource_dir() -> Path:
    """Répertoire des ressources embarquées (compatible PyInstaller)."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return Path(base) / "ai_soc_analyst"
    return Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class AppPaths:
    home: Path

    @property
    def db_file(self) -> Path:
        return self.home / "data" / "ai_soc_analyst.db"

    @property
    def quarantine(self) -> Path:
        return self.home / "quarantine"

    @property
    def reports(self) -> Path:
        return self.home / "reports"

    @property
    def rules(self) -> Path:
        return self.home / "rules"

    @property
    def logs(self) -> Path:
        return self.home / "logs"

    @property
    def backups(self) -> Path:
        return self.home / "backups"

    @property
    def cache(self) -> Path:
        return self.home / "cache"

    @property
    def settings_file(self) -> Path:
        return self.home / "config" / "settings.json"

    @property
    def secrets_file(self) -> Path:
        return self.home / "config" / "secrets.bin"

    @property
    def key_file(self) -> Path:
        return self.home / "config" / "master.key"

    def ensure(self) -> "AppPaths":
        for p in (self.db_file.parent, self.quarantine, self.reports, self.rules, self.logs, self.backups,
                  self.cache, self.settings_file.parent):
            p.mkdir(parents=True, exist_ok=True)
        return self


def get_paths() -> AppPaths:
    return AppPaths(_default_home()).ensure()

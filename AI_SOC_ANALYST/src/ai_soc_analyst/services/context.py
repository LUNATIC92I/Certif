"""Contexte applicatif partagé (chemins, paramètres, secrets, base, catalogue ATT&CK)."""
from __future__ import annotations

from dataclasses import dataclass

from ..core.logging_setup import get_logger, setup_logging
from ..core.paths import AppPaths, get_paths
from ..core.secrets import SecretStore
from ..core.settings import Settings, load_settings, save_settings
from ..db.session import Database
from ..mitre.engine import MitreCatalog


@dataclass
class AppContext:
    paths: AppPaths
    settings: Settings
    secrets: SecretStore
    db: Database
    catalog: MitreCatalog

    def save_settings(self) -> None:
        save_settings(self.settings, self.paths.settings_file)


def create_app_context(paths: AppPaths | None = None) -> AppContext:
    paths = paths or get_paths()
    setup_logging(paths.logs)
    log = get_logger("app")
    settings = load_settings(paths.settings_file)
    db = Database(paths.db_file)
    if not db.integrity_ok():
        log.error("Contrôle d'intégrité SQLite en échec : restaurez une sauvegarde depuis %s", paths.backups)
    ctx = AppContext(paths, settings, SecretStore(paths.secrets_file, paths.key_file), db, MitreCatalog(paths.cache))
    log.info("Contexte initialisé (données : %s)", paths.home)
    return ctx

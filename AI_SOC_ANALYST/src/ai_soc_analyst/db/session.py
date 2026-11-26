"""Moteur SQLite, sessions et sauvegardes de la base."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..core.logging_setup import get_logger
from .models import Base

log = get_logger("db")
SCHEMA_VERSION = 1


class Database:
    def __init__(self, db_file: Path):
        self.db_file = db_file
        db_file.parent.mkdir(parents=True, exist_ok=True)
        self.engine: Engine = create_engine(f"sqlite:///{db_file}", future=True,
                                            connect_args={"check_same_thread": False, "timeout": 30})

        @event.listens_for(self.engine, "connect")
        def _pragmas(dbapi_conn, _):  # noqa: ANN001
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

        Base.metadata.create_all(self.engine)
        with self.engine.begin() as conn:
            conn.exec_driver_sql(f"PRAGMA user_version={SCHEMA_VERSION}")
        self._factory = sessionmaker(self.engine, expire_on_commit=False, future=True)

    @contextmanager
    def session(self):
        s: Session = self._factory()
        try:
            yield s
            s.commit()
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    def integrity_ok(self) -> bool:
        with self.engine.connect() as conn:
            return conn.exec_driver_sql("PRAGMA integrity_check").scalar() == "ok"

    def backup(self, backup_dir: Path, keep: int = 7) -> Path:
        """Sauvegarde cohérente via l'API de backup SQLite (sûre même en cours d'utilisation)."""
        backup_dir.mkdir(parents=True, exist_ok=True)
        target = backup_dir / f"ai_soc_analyst_{datetime.now():%Y%m%d_%H%M%S_%f}.db"
        src = sqlite3.connect(self.db_file)
        dst = sqlite3.connect(target)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        backups = sorted(backup_dir.glob("ai_soc_analyst_*.db"))
        for old in backups[:-keep]:
            try:
                old.unlink()
            except OSError:
                pass
        log.info("Sauvegarde de la base créée : %s", target.name)
        return target

    def dispose(self) -> None:
        self.engine.dispose()

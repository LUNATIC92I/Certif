"""Journalisation applicative avec rotation et masquage des données sensibles."""
from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

_PATTERNS = [
    (re.compile(r"(?i)\b(authorization|proxy-authorization)(\s*[:=]\s*)(?:(bearer|basic|token|apikey)\s+)?[^\s\",;]+"),
     r"\1\2***"),
    (re.compile(r"(?i)(api[_-]?key|apikey|x-apikey|auth-key|password|passwd|secret|token)"
                r"(\s*[:=]\s*|\"\s*:\s*\")([^\s\",;]+)"), r"\1\2***"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer ***"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b"), "sk-***"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"), r"***@\1"),
]


def redact(text: str) -> str:
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        record.msg = redact(msg)
        record.args = ()
        return True


_CONFIGURED = False


def setup_logging(log_dir: Path, level: int = logging.INFO) -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger("ai_soc")
    if _CONFIGURED:
        return logger
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(log_dir / "ai_soc_analyst.log", maxBytes=5_000_000, backupCount=5,
                                  encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
    handler.addFilter(RedactingFilter())
    logger.addHandler(handler)
    logger.setLevel(level)
    _CONFIGURED = True
    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"ai_soc.{name}")

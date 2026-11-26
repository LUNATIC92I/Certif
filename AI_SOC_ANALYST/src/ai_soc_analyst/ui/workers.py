"""Exécution des traitements longs hors du thread de l'interface (QThreadPool)."""
from __future__ import annotations

import traceback
from typing import Any, Callable

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot

from ..core.logging_setup import get_logger

log = get_logger("ui.worker")


class WorkerSignals(QObject):
    progress = Signal(int, str)
    finished = Signal(object)
    error = Signal(str)


class Worker(QRunnable):
    """Exécute fn(*args, progress=cb, **kwargs) ; les exceptions sont converties en signal d'erreur lisible."""

    def __init__(self, fn: Callable[..., Any], *args, with_progress: bool = True, **kwargs):
        super().__init__()
        self.fn, self.args, self.kwargs, self.with_progress = fn, args, kwargs, with_progress
        self.signals = WorkerSignals()
        self.setAutoDelete(True)

    @Slot()
    def run(self) -> None:
        try:
            if self.with_progress:
                self.kwargs["progress"] = lambda v, m: self.signals.progress.emit(int(v), str(m))
            result = self.fn(*self.args, **self.kwargs)
        except Exception as exc:  # noqa: BLE001
            log.error("Tâche en échec : %s\n%s", exc, traceback.format_exc())
            self.signals.error.emit(f"{type(exc).__name__} : {exc}")
            return
        self.signals.finished.emit(result)


_ACTIVE: set[Worker] = set()


def start(worker: Worker) -> Worker:
    _ACTIVE.add(worker)
    worker.signals.finished.connect(lambda *_: _ACTIVE.discard(worker))
    worker.signals.error.connect(lambda *_: _ACTIVE.discard(worker))
    QThreadPool.globalInstance().start(worker)
    return worker


def wait_all(timeout_ms: int = 30000) -> bool:
    return QThreadPool.globalInstance().waitForDone(timeout_ms)

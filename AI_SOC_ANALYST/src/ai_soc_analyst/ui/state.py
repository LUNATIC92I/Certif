"""État partagé de l'interface : investigation courante et notification des changements de données."""
from __future__ import annotations

from PySide6.QtCore import QObject, Signal


class AppState(QObject):
    current_changed = Signal(int)
    data_changed = Signal()
    navigate = Signal(str)
    busy = Signal(bool, str)

    def __init__(self, ctx, svc, ti):  # noqa: ANN001
        super().__init__()
        self.ctx, self.svc, self.ti = ctx, svc, ti
        self.current_id: int | None = None
        self.running: set[int] = set()

    def open(self, inv_id: int, page: str = "workspace") -> None:
        self.current_id = inv_id
        self.current_changed.emit(inv_id)
        if page:
            self.navigate.emit(page)

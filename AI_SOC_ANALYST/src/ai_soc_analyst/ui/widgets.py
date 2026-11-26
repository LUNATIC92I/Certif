"""Widgets réutilisables : cartes, graphiques, zone de dépôt, tableaux."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import theme


class Card(QFrame):
    def __init__(self, label: str, value: str = "0", color: str = theme.TEXT):
        super().__init__()
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        self.value = QLabel(value)
        self.value.setObjectName("CardValue")
        self.value.setStyleSheet(f"color:{color}")
        self.label = QLabel(label)
        self.label.setObjectName("CardLabel")
        lay.addWidget(self.value)
        lay.addWidget(self.label)

    def set_value(self, v: str) -> None:
        self.value.setText(v)


class BarChart(QWidget):
    """Graphique en barres horizontales dessiné avec QPainter (aucune dépendance externe)."""

    def __init__(self, title: str):
        super().__init__()
        self.title = title
        self.data: list[tuple[str, float]] = []
        self.setMinimumHeight(220)

    def set_data(self, data: Iterable[tuple[str, float]]) -> None:
        self.data = list(data)
        self.update()

    def paintEvent(self, _):  # noqa: N802, ANN001
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(10, 8, -10, -8)
        p.setPen(QColor(theme.TEXT))
        f = QFont(self.font())
        f.setBold(True)
        p.setFont(f)
        p.drawText(r.left(), r.top() + 14, self.title)
        p.setFont(self.font())
        if not self.data:
            p.setPen(QColor(theme.MUTED))
            p.drawText(r, Qt.AlignCenter, "Aucune donnée")
            return
        top = r.top() + 26
        row_h = max(16, min(28, (r.height() - 30) // max(1, len(self.data))))
        label_w = int(r.width() * 0.45)
        mx = max(v for _, v in self.data) or 1
        palette = [theme.TEAL, theme.ACCENT, "#7C5CFF", "#F46036", "#F2C14E", "#2EA043", "#D7263D", "#2E86AB"]
        for i, (label, v) in enumerate(self.data):
            y = top + i * row_h
            p.setPen(QColor(theme.MUTED))
            p.drawText(QRectF(r.left(), y, label_w - 8, row_h), Qt.AlignVCenter | Qt.AlignLeft,
                       p.fontMetrics().elidedText(label, Qt.ElideRight, label_w - 8))
            w = (r.width() - label_w - 40) * v / mx
            p.setBrush(QBrush(QColor(palette[i % len(palette)])))
            p.setPen(Qt.NoPen)
            p.drawRoundedRect(QRectF(r.left() + label_w, y + 4, max(2, w), row_h - 8), 3, 3)
            p.setPen(QColor(theme.TEXT))
            p.drawText(QRectF(r.left() + label_w + w + 6, y, 40, row_h), Qt.AlignVCenter, f"{v:g}")


class DonutChart(QWidget):
    def __init__(self, title: str):
        super().__init__()
        self.title = title
        self.data: list[tuple[str, float, str]] = []
        self.setMinimumHeight(220)

    def set_data(self, data: Iterable[tuple[str, float, str]]) -> None:
        self.data = [d for d in data if d[1] > 0]
        self.update()

    def paintEvent(self, _):  # noqa: N802, ANN001
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = self.rect().adjusted(10, 8, -10, -8)
        f = QFont(self.font())
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(theme.TEXT))
        p.drawText(r.left(), r.top() + 14, self.title)
        p.setFont(self.font())
        total = sum(v for _, v, _ in self.data)
        size = min(r.height() - 40, r.width() // 2)
        box = QRectF(r.left() + 10, r.top() + 30, size, size)
        if not total:
            p.setPen(QColor(theme.MUTED))
            p.drawText(r, Qt.AlignCenter, "Aucune donnée")
            return
        start = 90 * 16
        for label, v, color in self.data:
            span = -int(360 * 16 * v / total)
            p.setPen(QPen(QColor(color), size * 0.18, Qt.SolidLine, Qt.FlatCap))
            inner = box.adjusted(size * 0.09, size * 0.09, -size * 0.09, -size * 0.09)
            p.drawArc(inner, start, span)
            start += span
        p.setPen(QColor(theme.TEXT))
        p.drawText(box, Qt.AlignCenter, f"{int(total)}")
        lx = box.right() + 20
        for i, (label, v, color) in enumerate(self.data):
            y = box.top() + i * 22
            p.setBrush(QColor(color))
            p.setPen(Qt.NoPen)
            p.drawRoundedRect(QRectF(lx, y + 5, 12, 12), 2, 2)
            p.setPen(QColor(theme.TEXT))
            p.drawText(QRectF(lx + 18, y, r.right() - lx - 18, 22), Qt.AlignVCenter, f"{label} ({int(v)})")


class DropZone(QFrame):
    files_dropped = Signal(list)

    def __init__(self, text: str):
        super().__init__()
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(90)
        lay = QVBoxLayout(self)
        lbl = QLabel(text)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"color:{theme.MUTED}")
        lay.addWidget(lbl)

    def _hover(self, on: bool) -> None:
        self.setProperty("hover", "true" if on else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e):  # noqa: N802, ANN001
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._hover(True)

    def dragLeaveEvent(self, e):  # noqa: N802, ANN001
        self._hover(False)

    def dropEvent(self, e):  # noqa: N802, ANN001
        self._hover(False)
        paths = [Path(u.toLocalFile()) for u in e.mimeData().urls() if u.isLocalFile()]
        files = []
        for p in paths:
            if p.is_dir():
                files += [x for x in p.rglob("*") if x.is_file()][:500]
            elif p.is_file():
                files.append(p)
        if files:
            self.files_dropped.emit(files)


def make_table(headers: list[str], stretch_last: bool = True, selection: str = "rows") -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows if selection == "rows" else QAbstractItemView.SelectItems)
    t.setSortingEnabled(True)
    t.horizontalHeader().setSortIndicator(-1, Qt.AscendingOrder)
    t.verticalHeader().setVisible(False)
    t.setWordWrap(False)
    h = t.horizontalHeader()
    h.setSectionResizeMode(QHeaderView.Interactive)
    h.setStretchLastSection(stretch_last)
    return t


def fill_table(t: QTableWidget, rows: list[list], colors: dict[int, dict[str, str]] | None = None,
               user_data: list | None = None) -> None:
    t.setSortingEnabled(False)
    t.setRowCount(0)
    t.setRowCount(len(rows))
    for i, row in enumerate(rows):
        for j, v in enumerate(row):
            item = QTableWidgetItem("" if v is None else str(v))
            item.setToolTip(str(v)[:2000] if v is not None else "")
            if colors and j in colors and str(v) in colors[j]:
                item.setForeground(QBrush(QColor(colors[j][str(v)])))
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            if user_data is not None and j == 0:
                item.setData(Qt.UserRole, user_data[i])
            t.setItem(i, j, item)
    t.setSortingEnabled(True)
    t.resizeColumnsToContents()
    for c in range(t.columnCount()):
        if t.columnWidth(c) > 420:
            t.setColumnWidth(c, 420)


def selected_data(t: QTableWidget):  # noqa: ANN201
    rows = t.selectionModel().selectedRows() if t.selectionModel() else []
    if not rows:
        return None
    item = t.item(rows[0].row(), 0)
    return item.data(Qt.UserRole) if item else None


def page_header(title: str, subtitle: str) -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 6)
    a = QLabel(title)
    a.setObjectName("PageTitle")
    b = QLabel(subtitle)
    b.setObjectName("PageSub")
    b.setWordWrap(True)
    lay.addWidget(a)
    lay.addWidget(b)
    return w


def hbox(*widgets, stretch: bool = True) -> QHBoxLayout:  # noqa: ANN002
    lay = QHBoxLayout()
    for w in widgets:
        lay.addWidget(w)
    if stretch:
        lay.addStretch(1)
    return lay


def error_box(parent: QWidget, title: str, message: str) -> None:
    QMessageBox.critical(parent, title, message + "\n\nLes détails techniques sont enregistrés dans le journal de l'application.")


def info_box(parent: QWidget, title: str, message: str) -> None:
    QMessageBox.information(parent, title, message)

"""Fenêtre principale : barre latérale, pages, barre d'état, cycle de vie (sauvegarde, reprise)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QCloseEvent, QIcon
from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QListWidget,
                               QListWidgetItem, QMainWindow, QMessageBox, QProgressBar, QStackedWidget, QVBoxLayout,
                               QWidget)

from .. import APP_NAME, APP_SUBTITLE, __version__
from ..core.logging_setup import get_logger
from ..core.paths import resource_dir
from ..core.security import verify_password
from . import theme
from .i18n import apply_translation, t
from .pages_core import DashboardPage, HistoryPage, NewInvestigationPage, QueuePage
from .pages_intel import DetectionPage, HuntingPage, IOCPage, MitrePage
from .pages_ops import ReportsPage, ResponsePage, SettingsPage
from .state import AppState
from .workers import wait_all
from .workspace import WorkspacePage

log = get_logger("ui")

PAGES = [("dashboard", "nav.dashboard", "▣"), ("new", "nav.new", "＋"), ("queue", "nav.queue", "☰"),
         ("workspace", "nav.workspace", "⌕"), ("ioc", "nav.ioc", "◆"), ("mitre", "nav.mitre", "▦"),
         ("hunting", "nav.hunting", "⌖"), ("detection", "nav.detection", "⚙"), ("response", "nav.response", "⛨"),
         ("reports", "nav.reports", "▤"), ("history", "nav.history", "⟲"), ("settings", "nav.settings", "⚒")]


class LoginDialog(QDialog):
    def __init__(self, stored_hash: str):
        super().__init__()
        self.stored = stored_hash
        self.attempts = 0
        self.setWindowTitle(f"{APP_NAME} — accès protégé")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Mot de passe local :"))
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        lay.addWidget(self.pw)
        self.msg = QLabel("")
        self.msg.setStyleSheet(f"color:{theme.SEVERITY['High']}")
        lay.addWidget(self.msg)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.check)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def check(self) -> None:
        if verify_password(self.pw.text(), self.stored):
            self.accept()
            return
        self.attempts += 1
        self.pw.clear()
        self.msg.setText(f"Mot de passe incorrect ({self.attempts}/5).")
        if self.attempts >= 5:
            self.reject()


class MainWindow(QMainWindow):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.setWindowTitle(f"{APP_NAME} {__version__} — {APP_SUBTITLE}")
        icon = resource_dir() / "resources" / "app.ico"
        if icon.exists():
            self.setWindowIcon(QIcon(str(icon)))
        self.resize(1480, 900)
        central = QWidget()
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(250)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 8)
        brand = QLabel(APP_NAME)
        brand.setObjectName("Brand")
        sub = QLabel("Intelligent Security Investigation\n& Incident Response Platform")
        sub.setObjectName("BrandSub")
        sl.addWidget(brand)
        sl.addWidget(sub)
        self.nav = QListWidget()
        sl.addWidget(self.nav, 1)
        self.mode = QLabel()
        self.mode.setWordWrap(True)
        self.mode.setStyleSheet(f"color:{theme.MUTED}; padding: 8px 14px; font-size: 8pt;")
        sl.addWidget(self.mode)
        ver = QLabel(f"v{__version__}")
        ver.setStyleSheet(f"color:{theme.MUTED}; padding: 0 14px; font-size: 8pt;")
        sl.addWidget(ver)
        root.addWidget(side)
        self.stack = QStackedWidget()
        content = QWidget()
        cl = QVBoxLayout(content)
        cl.setContentsMargins(18, 14, 18, 10)
        cl.addWidget(self.stack)
        root.addWidget(content, 1)
        self.setCentralWidget(central)

        self.pages: dict[str, QWidget] = {}
        factories = {"dashboard": DashboardPage, "new": NewInvestigationPage, "queue": QueuePage, "workspace": WorkspacePage,
                     "ioc": IOCPage, "mitre": MitrePage, "hunting": HuntingPage, "detection": DetectionPage,
                     "response": ResponsePage, "reports": ReportsPage, "history": HistoryPage, "settings": SettingsPage}
        for key, label, glyph in PAGES:
            page = factories[key](state)
            self.pages[key] = page
            self.stack.addWidget(page)
            item = QListWidgetItem(f"{glyph}   {t(label)}")
            item.setData(Qt.UserRole, key)
            self.nav.addItem(item)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)
        state.navigate.connect(self.go)
        state.busy.connect(self._busy)
        state.data_changed.connect(self._update_mode)

        self.progress = QProgressBar()
        self.progress.setMaximumWidth(180)
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.statusBar().addPermanentWidget(self.progress)
        self.statusBar().showMessage(f"Données : {state.ctx.paths.home}")
        self._menus()
        self._update_mode()
        apply_translation(self)

    def _menus(self) -> None:
        m = self.menuBar().addMenu("&Fichier")
        a = QAction("Nouvelle investigation", self)
        a.setShortcut("Ctrl+N")
        a.triggered.connect(lambda: self.go("new"))
        m.addAction(a)
        a = QAction("Sauvegarder la base", self)
        a.triggered.connect(self.pages["settings"].backup)
        m.addAction(a)
        m.addSeparator()
        a = QAction("Quitter", self)
        a.setShortcut("Ctrl+Q")
        a.triggered.connect(self.close)
        m.addAction(a)
        h = self.menuBar().addMenu("&Aide")
        a = QAction("À propos", self)
        a.triggered.connect(self.about)
        h.addAction(a)

    def about(self) -> None:
        c = self.state.ctx.catalog
        QMessageBox.about(self, APP_NAME, f"<b>{APP_NAME}</b> {__version__}<br>{APP_SUBTITLE}<br><br>"
                          f"MITRE ATT&CK {c.version} ({c.origin})<br>Données : {self.state.ctx.paths.home}<br><br>"
                          "Aucun fichier importé n'est exécuté. Aucune action de réponse n'est exécutée automatiquement.")

    def go(self, key: str) -> None:
        keys = [k for k, _, _ in PAGES]
        if key in keys:
            self.nav.setCurrentRow(keys.index(key))

    def _busy(self, on: bool, msg: str) -> None:
        self.progress.setVisible(on or bool(self.state.running))
        if msg:
            self.statusBar().showMessage(msg, 0 if on else 8000)

    def _update_mode(self) -> None:
        s = self.state.ctx.settings
        privacy = "Privacy Protection : ACTIF" if s.privacy_mode else "Privacy Protection : désactivé"
        self.mode.setText(f"{privacy}\nIA : {s.ai.provider}\nTI : {', '.join(self.state.ti.configured()) or 'non configurée'}")

    def closeEvent(self, e: QCloseEvent) -> None:  # noqa: N802
        if self.state.running and QMessageBox.question(
                self, APP_NAME, "Une analyse est en cours. Quitter quand même ? Elle pourra être reprise au prochain "
                "démarrage.") != QMessageBox.Yes:
            e.ignore()
            return
        wait_all(3000)
        try:
            self.state.ctx.db.backup(self.state.ctx.paths.backups, self.state.ctx.settings.backups_to_keep)
        except Exception:  # noqa: BLE001
            log.exception("Sauvegarde de fermeture impossible")
        e.accept()

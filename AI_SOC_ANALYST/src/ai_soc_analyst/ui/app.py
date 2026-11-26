"""Démarrage de l'interface graphique."""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from .. import APP_NAME, __version__
from ..core.logging_setup import get_logger
from ..services.context import create_app_context
from ..services.investigations import InvestigationService
from ..ti.engine import TIEngine
from . import theme
from .i18n import set_language


def _excepthook(exc_type, exc, tb) -> None:  # noqa: ANN001
    """Toute exception non interceptée est journalisée et signalée sans faire planter l'application."""
    get_logger("ui").error("Exception non gérée", exc_info=(exc_type, exc, tb))
    app = QApplication.instance()
    if app is not None:
        QMessageBox.critical(None, APP_NAME, f"Une erreur inattendue s'est produite : {exc}\n\n"
                                             "L'application reste utilisable ; le détail est consigné dans le journal.")


def build(argv: list[str] | None = None):  # noqa: ANN201
    """Crée l'application, le contexte et la fenêtre (utilisé aussi par les tests)."""
    from .main_window import LoginDialog, MainWindow
    from .state import AppState

    app = QApplication.instance() or QApplication(argv or sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setStyleSheet(theme.QSS)
    ctx = create_app_context()
    set_language(ctx.settings.language)
    svc = InvestigationService(ctx)
    interrupted = svc.recover_interrupted()
    state = AppState(ctx, svc, TIEngine(ctx))
    if ctx.settings.password_hash:
        dlg = LoginDialog(ctx.settings.password_hash)
        if dlg.exec() != QDialog.Accepted:
            svc.audit("security.login_failed")
            return app, None, interrupted
        svc.audit("security.login")
    win = MainWindow(state)
    return app, win, interrupted


def main(argv: list[str] | None = None) -> int:
    sys.excepthook = _excepthook
    app, win, interrupted = build(argv)
    if win is None:
        return 1
    win.show()
    if interrupted:
        QMessageBox.information(win, APP_NAME, f"{len(interrupted)} investigation(s) interrompue(s) lors de la dernière "
                                "session. Elles sont marquées « Interrompue » dans la file des incidents et peuvent être "
                                "reprises (bouton « Reprendre / Réanalyser »).")
    return app.exec()

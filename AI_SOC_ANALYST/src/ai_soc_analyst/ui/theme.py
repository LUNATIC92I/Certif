"""Thème « Dark SOC Dashboard »."""

BG = "#0B1118"
PANEL = "#111A24"
PANEL_2 = "#162230"
LINE = "#22303D"
TEXT = "#E6EDF3"
MUTED = "#8B98A5"
ACCENT = "#1E90FF"
TEAL = "#00C2B8"
SEVERITY = {"Critical": "#D7263D", "High": "#F46036", "Medium": "#F2C14E", "Low": "#2E86AB", "Informational": "#6C757D",
            "Unknown": "#6C757D"}
VERDICT = {"Confirmed": "#D7263D", "Likely": "#F46036", "Suspicious": "#F2C14E", "Inconclusive": "#8B98A5",
           "False Positive": "#2EA043"}

QSS = f"""
QWidget {{ background: {BG}; color: {TEXT}; font-family: "Segoe UI", "Inter", "DejaVu Sans", Arial; font-size: 10pt; }}
QMainWindow::separator {{ background: {LINE}; }}
#Sidebar {{ background: #0A0F15; border-right: 1px solid {LINE}; }}
#Sidebar QListWidget {{ background: transparent; border: none; outline: 0; }}
#Sidebar QListWidget::item {{ padding: 10px 14px; border-radius: 6px; margin: 2px 8px; color: {MUTED}; }}
#Sidebar QListWidget::item:selected {{ background: {PANEL_2}; color: {TEXT}; border-left: 3px solid {TEAL}; }}
#Sidebar QListWidget::item:hover {{ background: #121C27; color: {TEXT}; }}
#Brand {{ color: {TEXT}; font-size: 14pt; font-weight: 700; padding: 16px 14px 0 14px; background: transparent; }}
#BrandSub {{ color: {TEAL}; font-size: 8pt; padding: 0 14px 12px 14px; background: transparent; }}
#PageTitle {{ font-size: 17pt; font-weight: 700; background: transparent; }}
#PageSub {{ color: {MUTED}; background: transparent; }}
QFrame#Card {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 10px; }}
QLabel#CardValue {{ font-size: 20pt; font-weight: 700; background: transparent; }}
QLabel#CardLabel {{ color: {MUTED}; font-size: 8.5pt; background: transparent; }}
QLabel {{ background: transparent; }}
QPushButton {{ background: {PANEL_2}; border: 1px solid {LINE}; border-radius: 6px; padding: 6px 14px; color: {TEXT}; }}
QPushButton:hover {{ border-color: {ACCENT}; }}
QPushButton:disabled {{ color: #556270; border-color: #1A2430; }}
QPushButton#Primary {{ background: {ACCENT}; border: 1px solid {ACCENT}; color: white; font-weight: 600; }}
QPushButton#Primary:hover {{ background: #3AA0FF; }}
QPushButton#Danger {{ background: #3A1418; border: 1px solid #D7263D; color: #FFB3BC; }}
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {{ background: {PANEL}; border: 1px solid {LINE};
    border-radius: 6px; padding: 5px 8px; selection-background-color: {ACCENT}; }}
QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QTableView, QTableWidget, QTreeWidget, QListWidget {{ background: {PANEL}; alternate-background-color: #0F1822;
    border: 1px solid {LINE}; border-radius: 6px; gridline-color: {LINE}; selection-background-color: #1B3A5C; }}
QHeaderView::section {{ background: #0E1621; color: {TEXT}; padding: 6px; border: none; border-bottom: 2px solid {TEAL};
    font-weight: 600; }}
QTabWidget::pane {{ border: 1px solid {LINE}; border-radius: 6px; top: -1px; }}
QTabBar::tab {{ background: {PANEL}; padding: 7px 14px; border: 1px solid {LINE}; border-bottom: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px; color: {MUTED}; margin-right: 2px; }}
QTabBar::tab:selected {{ background: {PANEL_2}; color: {TEXT}; border-bottom: 2px solid {TEAL}; }}
QProgressBar {{ background: {PANEL}; border: 1px solid {LINE}; border-radius: 5px; text-align: center; height: 16px; }}
QProgressBar::chunk {{ background: {TEAL}; border-radius: 4px; }}
QGroupBox {{ border: 1px solid {LINE}; border-radius: 8px; margin-top: 14px; padding: 10px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; color: {TEAL}; font-weight: 600; }}
QCheckBox::indicator {{ width: 15px; height: 15px; border: 1px solid #3A4D60; border-radius: 3px; background: {PANEL}; }}
QCheckBox::indicator:checked {{ background: {TEAL}; border-color: {TEAL}; image: none; }}
QSpinBox, QDoubleSpinBox {{ min-height: 24px; padding: 2px 6px; }}
QScrollBar:vertical {{ background: {BG}; width: 10px; }}
QScrollBar::handle:vertical {{ background: #2A3846; border-radius: 4px; min-height: 30px; }}
QScrollBar:horizontal {{ background: {BG}; height: 10px; }}
QScrollBar::handle:horizontal {{ background: #2A3846; border-radius: 4px; min-width: 30px; }}
QStatusBar {{ background: #0A0F15; color: {MUTED}; border-top: 1px solid {LINE}; }}
QToolTip {{ background: {PANEL_2}; color: {TEXT}; border: 1px solid {ACCENT}; }}
QFrame#DropZone {{ border: 2px dashed #2F4A63; border-radius: 10px; background: #0E1722; }}
QFrame#DropZone[hover="true"] {{ border-color: {TEAL}; background: #0F2230; }}
QSplitter::handle {{ background: {LINE}; }}
QMenuBar {{ background: #0A0F15; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {PANEL_2}; }}
QMenu {{ background: {PANEL}; border: 1px solid {LINE}; }}
"""

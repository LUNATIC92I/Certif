# -*- mode: python ; coding: utf-8 -*-
# Spécification PyInstaller : build « onedir » contenant
#   AI_SOC_ANALYST.exe      application graphique (sans console)
#   AI_SOC_ANALYST_cli.exe  même application avec console (analyse en ligne de commande, autotest)
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent
PKG = ROOT / "src" / "ai_soc_analyst"
ICON = str(PKG / "resources" / "app.ico")

datas = [
    (str(PKG / "mitre" / "data"), "ai_soc_analyst/mitre/data"),
    (str(PKG / "reporting" / "templates"), "ai_soc_analyst/reporting/templates"),
    (str(PKG / "resources"), "ai_soc_analyst/resources"),
]
for _pkg in ("docx", "reportlab", "extract_msg", "openpyxl"):  # gabarits et données internes des bibliothèques
    datas += collect_data_files(_pkg)
hiddenimports = collect_submodules("ai_soc_analyst") + ["Evtx.Evtx", "Evtx.Views", "extract_msg", "yara", "pefile",
                                                       "openpyxl.cell._writer", "sqlalchemy.dialects.sqlite"]
excludes = ["tkinter", "matplotlib", "numpy", "pandas", "IPython", "pytest", "PySide6.QtWebEngineCore",
            "PySide6.QtQml", "PySide6.QtQuick", "PySide6.Qt3DCore", "PySide6.QtMultimedia"]

a = Analysis([str(ROOT / "packaging" / "launcher.py")], pathex=[str(ROOT / "src")], datas=datas,
             hiddenimports=hiddenimports, excludes=excludes, noarchive=False,
             # python-docx résout ses gabarits via « docx/parts/../templates » : le paquet doit exister sur disque
             module_collection_mode={"docx": "pyz+py"})
pyz = PYZ(a.pure)

version_file = str(ROOT / "packaging" / "version_info.txt") if sys.platform == "win32" else None
gui = EXE(pyz, a.scripts, [], exclude_binaries=True, name="AI_SOC_ANALYST", console=False, icon=ICON,
          version=version_file, upx=False)
cli = EXE(pyz, a.scripts, [], exclude_binaries=True, name="AI_SOC_ANALYST_cli", console=True, icon=ICON,
          version=version_file, upx=False)
coll = COLLECT(gui, cli, a.binaries, a.datas, name="AI_SOC_ANALYST", upx=False)

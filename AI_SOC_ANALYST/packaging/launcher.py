"""Point d'entrée de l'exécutable PyInstaller."""
import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from ai_soc_analyst.cli import main

    sys.exit(main())

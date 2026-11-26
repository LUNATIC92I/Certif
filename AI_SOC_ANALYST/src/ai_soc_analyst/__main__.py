import multiprocessing
import sys

from ai_soc_analyst.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())

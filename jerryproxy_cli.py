"""PyInstaller-compatible JerryProxy launcher."""

import multiprocessing
import sys

from jerryproxy.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())

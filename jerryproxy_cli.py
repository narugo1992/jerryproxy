"""PyInstaller-compatible JerryProxy launcher."""

import multiprocessing
import sys

from jerryproxy.cli import main
from jerryproxy.runtime.guardian import main as guardian_main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if "--jerryproxy-guardian" in sys.argv:
        marker = sys.argv.index("--jerryproxy-guardian")
        sys.exit(guardian_main(sys.argv[marker + 1 :]))
    sys.exit(main())

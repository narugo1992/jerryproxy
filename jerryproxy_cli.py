"""PyInstaller-compatible JerryProxy launcher."""

import sys

from jerryproxy.cli import main

if __name__ == "__main__":
    sys.exit(main())

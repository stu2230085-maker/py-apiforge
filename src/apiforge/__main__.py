"""Module execution entrypoint (`python -m apiforge`)."""

import sys

from apiforge.cli import main

if __name__ == "__main__":
    sys.exit(main())

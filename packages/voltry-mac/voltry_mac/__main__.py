"""``python -m voltry_mac`` runs the same command line as ``voltry-mac``."""

from __future__ import annotations

from voltry_mac.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

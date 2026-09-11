#!/usr/bin/env python3
"""ERSEC 29.1.0 command-line bootstrap.

Fast-paths version checks and lazy-loads the heavyweight assessment engine.
The actual engine remains in :mod:`ersec_core` while the public ``ersec``
module preserves backwards-compatible imports.
"""
from __future__ import annotations

import sys

VERSION = "29.1.0"


def main() -> int:
    if any(arg in ("--version", "-V") for arg in sys.argv[1:]):
        print(f"ERSEC {VERSION}")
        return 0
    from ersec_core import main as _main
    return _main()


if __name__ == "__main__":
    raise SystemExit(main())

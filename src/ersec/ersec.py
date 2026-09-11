#!/usr/bin/env python3
"""ERSEC 29.1.1 compatibility facade and lazy public API.

The security engine now lives in :mod:`ersec_core`; this module intentionally
stays tiny so importing/version-checking ERSEC does not eagerly import every
scanner, assurance engine and optional integration.
"""
from __future__ import annotations

import importlib
import sys

ERSEC_VERSION = "29.1.1"
_CORE = "ersec.ersec_core"
_core_module = None


def _core():
    global _core_module
    if _core_module is None:
        _core_module = importlib.import_module(_CORE)
    return _core_module


def __getattr__(name):
    if name == "ERSEC_VERSION":
        return ERSEC_VERSION
    value = getattr(_core(), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(dir(_core())))


def main() -> int:
    return _core().main()


if __name__ == "__main__":
    if any(arg in ("--version", "-V") for arg in sys.argv[1:]):
        print(f"ERSEC {ERSEC_VERSION}")
        raise SystemExit(0)
    raise SystemExit(main())

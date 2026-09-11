"""Report serialization boundary for ERSEC.

The writer is deliberately small and dependency-free. It provides atomic
writes for machine-readable and text artifacts so interrupted scans cannot
silently replace a previously valid report with a truncated file.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from ersec.ersec_schema import canonical_json
from ersec.ersec_quality import validate_report_semantics
from ersec.ersec_input_safety import redact, validate_structure


class ReportSerializationError(RuntimeError):
    """Raised when an output artifact cannot be safely serialized."""


def _atomic_replace_text(destination: str | os.PathLike[str], text: str) -> str:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = None
    temp_name = None
    try:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent), text=True)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fd = None
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_name, path)
        temp_name = None
        return str(path)
    except (OSError, TypeError, ValueError) as exc:
        raise ReportSerializationError(f"failed to atomically write {path}: {exc}") from exc
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


class AtomicReportWriter:
    """Write ERSEC artifacts using a fail-safe replace operation."""

    def write_json(self, report: Mapping[str, Any], destination: str, *, validate: bool = True) -> dict[str, Any]:
        if validate:
            contract = validate_report_semantics(report)
            if not contract["valid"]:
                raise ReportSerializationError("refusing to write invalid ERSEC report: " + "; ".join(contract["errors"]))
        safe_report = redact(report)
        validate_structure(safe_report)
        text = json.dumps(safe_report, indent=2, ensure_ascii=False, sort_keys=False, default=str) + "\n"
        return {"path": _atomic_replace_text(destination, text), "format": "json", "validated": validate}

    def write_text(self, text: str, destination: str, *, encoding: str = "utf-8") -> dict[str, Any]:
        if encoding.lower().replace("_", "-") != "utf-8":
            raise ReportSerializationError("ERSEC report boundary only permits UTF-8 text artifacts")
        safe_text = redact(text)
        return {"path": _atomic_replace_text(destination, safe_text), "format": "text", "validated": False}

    def write_canonical_json(self, value: Any, destination: str) -> dict[str, Any]:
        safe_value = redact(value)
        validate_structure(safe_value)
        return {"path": _atomic_replace_text(destination, canonical_json(safe_value) + "\n"), "format": "canonical-json", "validated": False}


class SafeReportWriter:
    """Adapter implementing the ReportWriter protocol."""

    def __init__(self, writer: AtomicReportWriter | None = None):
        self.writer = writer or AtomicReportWriter()

    def write(self, report: Mapping[str, Any], destination: str) -> dict[str, Any]:
        return self.writer.write_json(report, destination, validate=True)

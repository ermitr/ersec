"""Finding normalization boundary. No detector is allowed to mutate global output here."""
from __future__ import annotations
from typing import Any, Iterable, Sequence

def deduplicate_findings(findings: Sequence[Any]) -> list[Any]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Any] = []
    for finding in findings:
        category = str(getattr(finding, "category", ""))
        url = str(getattr(finding, "url", ""))
        parameter = str(getattr(finding, "parameter", ""))
        key = (category, url.split("?", 1)[0], parameter)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique

def normalize_findings(findings: Sequence[Any], consolidator=None) -> list[Any]:
    unique = deduplicate_findings(findings)
    if consolidator is not None:
        unique = list(consolidator(unique))
    return unique

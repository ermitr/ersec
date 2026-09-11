"""Stable, dependency-free ERSEC artifact contracts.

This module intentionally validates only structural invariants that ERSEC can
promise across releases. It does not attempt to prove security from an output
file; it detects malformed/incomplete artifacts so consumers can fail closed.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping

REPORT_SCHEMA = "ersec-scan-report/1"
FINDING_SCHEMA = "ersec-finding/1"
EVIDENCE_SCHEMA = "ersec-evidence/1"
CONTRACT_SCHEMA = "ersec-contract/2"
SCHEMA_COMPATIBILITY = {
    REPORT_SCHEMA: {"current": 1, "backward_read": [1], "notes": "Stable scan report structure; additive fields permitted."},
    FINDING_SCHEMA: {"current": 1, "backward_read": [1], "notes": "Finding identity/severity fields are stable."},
    EVIDENCE_SCHEMA: {"current": 1, "backward_read": [1], "notes": "Evidence is redacted before persistence."},
    CONTRACT_SCHEMA: {"current": 2, "backward_read": [1, 2], "notes": "Contract v1 remains readable; v2 adds lifecycle metadata."},
    "ersec-contract/1": {"current": 1, "backward_read": [1], "notes": "Legacy contract schema retained for read compatibility."},
}

def schema_compatibility(schema: str, version: int) -> Dict[str, Any]:
    meta = SCHEMA_COMPATIBILITY.get(schema)
    if not meta:
        return {"compatible": False, "schema": schema, "version": version, "reason": "unsupported schema"}
    return {"compatible": version in meta["backward_read"], "schema": schema, "version": version, **meta}



def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def content_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _require_mapping(obj: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(obj, Mapping):
        raise ValueError(f"{label} must be a JSON object")
    return obj


def validate_finding(finding: Any, index: int | None = None) -> List[str]:
    label = f"finding[{index}]" if index is not None else "finding"
    f = _require_mapping(finding, label)
    errors: List[str] = []
    for key in ("finding_id", "category", "severity", "confidence", "url"):
        if key not in f or f.get(key) in (None, ""):
            errors.append(f"{label} missing {key}")
    evidence = f.get("evidence")
    if evidence is None:
        errors.append(f"{label} missing evidence")
    elif not isinstance(evidence, Mapping):
        errors.append(f"{label}.evidence must be an object")
    elif evidence.get("schema") not in {None, EVIDENCE_SCHEMA}:
        errors.append(f"{label}.evidence has unsupported schema")
    return errors


def validate_contract_bundle(bundle: Any) -> Dict[str, Any]:
    obj = _require_mapping(bundle, "contract bundle")
    schema = obj.get("schema")
    if schema not in {CONTRACT_SCHEMA, "ersec-contract/1"}:
        raise ValueError(f"unsupported contract schema: {schema!r}")
    contracts = obj.get("contracts", [])
    if not isinstance(contracts, list):
        raise ValueError("contracts must be a list")
    errors: List[str] = []
    for i, contract in enumerate(contracts):
        if not isinstance(contract, Mapping):
            errors.append(f"contract[{i}] must be an object")
            continue
        if not contract.get("contract_id"):
            errors.append(f"contract[{i}] missing contract_id")
        automation = contract.get("automation", {})
        if not isinstance(automation, Mapping):
            errors.append(f"contract[{i}].automation must be an object")
        elif automation.get("status") not in {"draft", "active", "expired", None}:
            errors.append(f"contract[{i}] has invalid automation.status")
    return {"valid": not errors, "schema": schema, "contract_count": len(contracts), "errors": errors}


def validate_report(report: Any, *, require_complete: bool = False) -> Dict[str, Any]:
    obj = _require_mapping(report, "report")
    errors: List[str] = []
    if obj.get("schema") != REPORT_SCHEMA:
        errors.append(f"unsupported report schema: {obj.get('schema')!r}")
    if not isinstance(obj.get("schema_version"), int):
        errors.append("schema_version must be an integer")
    if not obj.get("tool_version"):
        errors.append("tool_version is required")
    if not obj.get("target"):
        errors.append("target is required")
    findings = obj.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be a list")
    else:
        seen_ids = set()
        for i, finding in enumerate(findings):
            errors.extend(validate_finding(finding, i))
            if isinstance(finding, Mapping):
                finding_id = finding.get("finding_id")
                if finding_id in seen_ids:
                    errors.append(f"finding[{i}] duplicates finding_id: {finding_id}")
                elif finding_id:
                    seen_ids.add(finding_id)
    status = obj.get("scan_status")
    if status not in {"completed", "incomplete", "unreachable", "invalid_target", "error"}:
        errors.append(f"invalid scan_status: {status!r}")
    if require_complete and status != "completed":
        errors.append(f"scan is not complete: {status!r}")
    completeness = obj.get("completeness")
    if not isinstance(completeness, Mapping):
        errors.append("completeness object is required")
    else:
        for key in ("status", "request_budget_exhausted", "component_failures"):
            if key not in completeness:
                errors.append(f"completeness missing {key}")
        if completeness.get("status") != status and status in {"completed", "incomplete"}:
            errors.append("completeness.status must match scan_status")
    return {
        "valid": not errors,
        "schema": obj.get("schema"),
        "schema_version": obj.get("schema_version"),
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "scan_status": status,
        "errors": errors,
    }


def behavior_assurance_coverage(model: Any, verification: Any) -> Dict[str, Any]:
    """Return transparent model-cell coverage; never converts missing cells to pass."""
    identities = getattr(model, "identities", [])
    resources = getattr(model, "resources", [])
    rows = verification.get("verifications", []) if isinstance(verification, Mapping) else []
    applicable = 0
    tested = 0
    counts = {k: 0 for k in ("pass", "violation", "inconclusive", "not_tested", "out_of_scope")}
    observed = set()
    for resource in resources:
        for identity in identities:
            for method in getattr(resource, "methods", ("GET",)):
                applicable += 1
                observed.add((resource.resource_id, identity.name, str(method).upper()))
    for row in rows:
        key = (str(row.get("resource_id", "")), str(row.get("identity", "")), str(row.get("method", "")).upper())
        verdict = str(row.get("verdict", "inconclusive"))
        if key in observed:
            if verdict in counts:
                counts[verdict] += 1
            else:
                counts["inconclusive"] += 1
            if verdict in {"pass", "violation", "inconclusive"}:
                tested += 1
    ratio = round(tested / applicable, 4) if applicable else 0.0
    return {
        "schema": "ersec-security-behavior-coverage/1",
        "applicable_cells": applicable,
        "tested_cells": min(tested, applicable),
        "coverage_ratio": ratio,
        "counts": counts,
        "untested_cells": max(applicable - tested, 0),
        "statement": "Coverage measures exercised model cells only. Untested behavior is not treated as secure.",
    }

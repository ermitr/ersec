"""Authorization model utilities for ERSEC's security-behavior assurance wedge.

This module deliberately contains no secret material. Credential references are
opaque names resolved by an operator-controlled environment/secret provider.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

SCHEMA = "ersec-authorization-model/1"
CREDENTIAL_REF_SCHEMA = "ersec-credential-ref/1"

_ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")

@dataclass(frozen=True)
class CredentialRef:
    """An operator-managed credential reference; never a credential value."""
    name: str
    source: str = "environment"
    required: bool = True
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name or any(ch.isspace() for ch in self.name):
            raise ValueError("credential reference name must be non-empty and whitespace-free")
        if self.source not in {"environment", "file", "provider"}:
            raise ValueError("credential reference source must be environment, file, or provider")
        if self.source == "environment" and not _ENV_RE.fullmatch(self.name):
            raise ValueError("environment credential references must use an uppercase variable name")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": CREDENTIAL_REF_SCHEMA,
            "name": self.name,
            "source": self.source,
            "required": self.required,
            "description": self.description,
        }


def validate_credential_references(refs: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    errors: List[str] = []
    normalized: List[Dict[str, Any]] = []
    seen = set()
    for i, raw in enumerate(refs):
        if not isinstance(raw, Mapping):
            errors.append(f"credential[{i}] must be an object")
            continue
        try:
            ref = CredentialRef(
                str(raw.get("name", "")),
                str(raw.get("source", "environment")),
                bool(raw.get("required", True)),
                str(raw.get("description", "")),
            )
        except ValueError as exc:
            errors.append(f"credential[{i}]: {exc}")
            continue
        if ref.name in seen:
            errors.append(f"credential[{i}] duplicates name {ref.name}")
        seen.add(ref.name)
        normalized.append(ref.to_dict())
    return {"valid": not errors, "schema": SCHEMA, "credentials": normalized, "errors": errors}


def build_authorization_matrix(model: Any) -> Dict[str, Any]:
    """Generate a deterministic principal x resource x method matrix."""
    rows: List[Dict[str, Any]] = []
    identities = list(getattr(model, "identities", []))
    resources = list(getattr(model, "resources", []))
    for ident in identities:
        for resource in resources:
            raw = resource.expected.get(ident.name, {}) if isinstance(resource.expected, dict) else {}
            raw = raw if isinstance(raw, dict) else {}
            status = raw.get("status")
            if status is None:
                status = [200] if resource.owner == ident.name or (resource.tenant and resource.tenant == ident.tenant) else [403, 404]
            if isinstance(status, int):
                status = [status]
            relationship = "owner" if resource.owner == ident.name else ("same_tenant" if resource.tenant and resource.tenant == ident.tenant else "cross_tenant")
            for method in resource.methods:
                rows.append({
                    "cell_id": hashlib.sha256(f"{ident.name}|{resource.resource_id}|{method}".encode()).hexdigest()[:16],
                    "identity": ident.name,
                    "role": ident.role,
                    "tenant": ident.tenant,
                    "resource_id": resource.resource_id,
                    "resource_tenant": resource.tenant,
                    "relationship": relationship,
                    "method": method,
                    "expected_status": sorted({int(x) for x in status}),
                    "forbidden_fields": list(raw.get("forbidden_fields", [])) if isinstance(raw.get("forbidden_fields", []), list) else [],
                    "required_fields": list(raw.get("required_fields", [])) if isinstance(raw.get("required_fields", []), list) else [],
                })
    return {
        "schema": SCHEMA,
        "model_fingerprint": model.validate().get("fingerprint"),
        "cell_count": len(rows),
        "cells": rows,
        "denominator_definition": "Each modeled identity/resource/method combination is one applicable authorization cell.",
        "statement": "Authorization coverage counts modeled cells; it does not infer security for cells that were not executed.",
    }


def remediation_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> Dict[str, Any]:
    """Compare two assurance runs and identify whether prior violations resolved."""
    before_v = {str(x.get("case_id")): x for x in before.get("violations", []) if isinstance(x, Mapping)}
    after_v = {str(x.get("case_id")): x for x in after.get("violations", []) if isinstance(x, Mapping)}
    current_cases = {str(x.get("case_id")): x for x in after.get("cases", []) if isinstance(x, Mapping) and x.get("case_id")}
    resolved_candidates = sorted(set(before_v) - set(after_v))
    unresolved = sorted(cid for cid in resolved_candidates if str(current_cases.get(cid, {}).get("verdict", "")).lower() not in {"pass"})
    resolved = sorted(set(resolved_candidates) - set(unresolved))
    persistent = sorted(set(before_v) & set(after_v))
    introduced = sorted(set(after_v) - set(before_v))
    status = "verified" if resolved and not unresolved and not persistent and not introduced else ("partial" if resolved or unresolved else "unchanged")
    return {
        "schema": "ersec-authorization-remediation/1",
        "status": status,
        "previous_violation_count": len(before_v),
        "current_violation_count": len(after_v),
        "resolved": resolved,
        "unverified_resolution": unresolved,
        "persistent": persistent,
        "introduced": introduced,
        "statement": "Remediation is verified only for previously observed modeled violations; absence of a current observation is not proof of a global fix.",
    }

"""Quality and compatibility helpers for ERSEC's stable assurance contracts.

This module is intentionally deterministic and dependency-free.  It provides
three small primitives used by CI and integration tests:

* artifact compatibility checks;
* golden-fixture manifest validation;
* cross-format finding identity checks.

None of these functions decides whether an application is secure.  They only
check whether ERSEC's own outputs are structurally coherent enough to be
consumed as assurance evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from ersec.ersec_schema import (
    FINDING_SCHEMA,
    REPORT_SCHEMA,
    validate_finding,
    validate_report,
)

QUALITY_SCHEMA = "ersec-quality-manifest/1"


@dataclass(frozen=True)
class GoldenFixture:
    fixture_id: str
    purpose: str
    expected_verdict: str
    oracle: str
    notes: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "fixture_id": self.fixture_id,
            "purpose": self.purpose,
            "expected_verdict": self.expected_verdict,
            "oracle": self.oracle,
            "notes": self.notes,
        }


_ALLOWED_VERDICTS = {
    "pass",
    "violation",
    "inconclusive",
    "not_tested",
    "blocked",
    "out_of_scope",
    "unmodeled",
    "observation_unavailable",
}


def validate_quality_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, Mapping):
        return {"valid": False, "errors": ["manifest must be an object"]}
    errors: list[str] = []
    if manifest.get("schema") != QUALITY_SCHEMA:
        errors.append("unsupported quality manifest schema")
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list):
        errors.append("fixtures must be a list")
        fixtures = []
    seen: set[str] = set()
    for i, fixture in enumerate(fixtures):
        if not isinstance(fixture, Mapping):
            errors.append(f"fixture[{i}] must be an object")
            continue
        fixture_id = str(fixture.get("fixture_id", ""))
        if not fixture_id:
            errors.append(f"fixture[{i}] missing fixture_id")
        elif fixture_id in seen:
            errors.append(f"duplicate fixture_id: {fixture_id}")
        seen.add(fixture_id)
        if fixture.get("expected_verdict") not in _ALLOWED_VERDICTS:
            errors.append(f"fixture[{i}] has invalid expected_verdict")
        if not fixture.get("purpose"):
            errors.append(f"fixture[{i}] missing purpose")
        if not fixture.get("oracle"):
            errors.append(f"fixture[{i}] missing oracle")
    return {"valid": not errors, "fixture_count": len(fixtures), "errors": errors}


def finding_identity(finding: Mapping[str, Any]) -> str:
    """Return the stable primary identity used for cross-format comparisons."""
    value = finding.get("finding_id")
    if not value:
        raise ValueError("finding_id is required")
    return str(value)


def finding_identity_set(findings: Iterable[Mapping[str, Any]]) -> set[str]:
    identities: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            raise ValueError("finding must be an object")
        identities.add(finding_identity(finding))
    return identities


def validate_report_semantics(report: Any) -> dict[str, Any]:
    """Validate stable report structure plus finding/evidence identity invariants."""
    result = validate_report(report)
    errors = list(result.get("errors", []))
    if not isinstance(report, Mapping):
        return {**result, "errors": errors}
    findings = report.get("findings", [])
    ids: set[str] = set()
    for index, finding in enumerate(findings if isinstance(findings, list) else []):
        if not isinstance(finding, Mapping):
            continue
        fid = str(finding.get("finding_id", ""))
        if fid and fid in ids:
            errors.append(f"duplicate finding_id: {fid}")
        ids.add(fid)
        evidence = finding.get("evidence")
        if isinstance(evidence, Mapping) and evidence.get("schema") not in {None, "ersec-evidence/1"}:
            errors.append(f"finding[{index}] unsupported evidence schema: {evidence.get('schema')!r}")
        elif evidence is None:
            errors.append(f"finding[{index}] missing evidence")
    return {**result, "valid": not errors, "errors": errors, "unique_finding_ids": len(ids)}


def cross_format_identity_check(*finding_sets: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Ensure machine-readable result variants describe the same findings."""
    if not finding_sets:
        return {"valid": True, "finding_count": 0, "mismatches": []}
    baseline = finding_identity_set(finding_sets[0])
    mismatches: list[dict[str, Any]] = []
    for index, current in enumerate(finding_sets[1:], start=2):
        current_ids = finding_identity_set(current)
        if current_ids != baseline:
            mismatches.append({
                "set_index": index,
                "missing": sorted(baseline - current_ids),
                "unexpected": sorted(current_ids - baseline),
            })
    return {"valid": not mismatches, "finding_count": len(baseline), "mismatches": mismatches}


DEFAULT_GOLDEN_FIXTURES: tuple[GoldenFixture, ...] = (
    GoldenFixture("auth-bola-positive", "Cross-tenant object must be denied", "violation", "authoritative_state"),
    GoldenFixture("auth-bola-negative", "Same-tenant object remains readable", "pass", "response_fields"),
    GoldenFixture("auth-bola-ambiguous", "Authorization response without authoritative observer", "observation_unavailable", "observer"),
    GoldenFixture("revoked-session", "Revoked identity cannot access protected object", "violation", "identity_state"),
    GoldenFixture("safe-unmodeled", "Discovered endpoint without reviewed security property", "unmodeled", "coverage"),
)

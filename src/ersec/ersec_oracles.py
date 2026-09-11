"""Deterministic security-behavior oracle primitives.

Oracles answer only the property they are given. They never infer security from
missing observations. This module is a foundation for the authorization and
stateful assurance wedges described in the roadmap.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence


class Verdict(str, Enum):
    PASS = "pass"
    VIOLATION = "violation"
    INCONCLUSIVE = "inconclusive"
    NOT_TESTED = "not_tested"
    BLOCKED = "blocked"
    OUT_OF_SCOPE = "out_of_scope"
    UNMODELED = "unmodeled"
    OBSERVATION_UNAVAILABLE = "observation_unavailable"


@dataclass(frozen=True)
class OracleResult:
    verdict: Verdict
    evidence: dict[str, Any]
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "evidence": self.evidence, "reason": self.reason}


def status_oracle(observed_status: int | None, allowed_statuses: Sequence[int]) -> OracleResult:
    """Grade HTTP status only; absence of a response is never a pass."""
    if observed_status is None:
        return OracleResult(Verdict.OBSERVATION_UNAVAILABLE, {}, "no HTTP status observed")
    expected = {int(v) for v in allowed_statuses}
    verdict = Verdict.PASS if int(observed_status) in expected else Verdict.VIOLATION
    return OracleResult(verdict, {"observed_status": int(observed_status), "allowed_statuses": sorted(expected)})


def forbidden_fields_oracle(payload: Mapping[str, Any] | None, forbidden_fields: Sequence[str]) -> OracleResult:
    """Require that named fields are absent; a missing payload is inconclusive."""
    if payload is None:
        return OracleResult(Verdict.OBSERVATION_UNAVAILABLE, {}, "response body was not observable")
    present = sorted({str(field) for field in forbidden_fields if field in payload})
    verdict = Verdict.PASS if not present else Verdict.VIOLATION
    return OracleResult(verdict, {"forbidden_fields": sorted(set(map(str, forbidden_fields))), "present": present})


def ownership_oracle(observed_owner: str | None, expected_owner: str) -> OracleResult:
    """Verify a read-only ownership postcondition from an authoritative observer."""
    if observed_owner is None:
        return OracleResult(Verdict.OBSERVATION_UNAVAILABLE, {}, "authoritative ownership was unavailable")
    verdict = Verdict.PASS if str(observed_owner) == str(expected_owner) else Verdict.VIOLATION
    return OracleResult(verdict, {"observed_owner": str(observed_owner), "expected_owner": str(expected_owner)})

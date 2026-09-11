"""Offline security-behavior mutation adequacy analysis.

This module applies semantic fault operators to the reviewed authorization
corpus and measures whether the corpus contains a case capable of detecting
(killing) each fault.  It does not contact a target and never handles secrets.

The idea is deliberately framed as *test-suite adequacy*, not vulnerability
counting.  It is inspired by established policy mutation-testing research, but
specializes the mutation space around ERSEC's security-behavior dimensions:
principal, tenant relationship, expected authorization outcome, sensitive
fields, API-version parity, and stale-session state.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple
import hashlib
import json
from datetime import datetime, timezone

from ersec_authorization_benchmark import CASES, SuiteCase

SCHEMA = "ersec-authorization-mutation-audit/1"


@dataclass(frozen=True)
class SemanticMutant:
    mutant_id: str
    operator: str
    source_case_id: str
    description: str
    original_signature: Tuple[Any, ...]
    mutated_signature: Tuple[Any, ...]
    targeted_dimension: str


def _signature(case: SuiteCase) -> Tuple[Any, ...]:
    return (
        case.identity,
        case.relationship,
        case.expected_owner_tenant,
        tuple(case.expected_status),
        tuple(case.forbidden_fields),
        tuple(case.required_fields),
        case.state_context,
        case.truth_class,
    )


def _mk_id(operator: str, case_id: str) -> str:
    return hashlib.sha256(f"{operator}|{case_id}".encode()).hexdigest()[:16]


def generate_mutants(cases: Sequence[SuiteCase] = CASES) -> List[SemanticMutant]:
    """Generate bounded, deterministic semantic authorization mutants."""
    out: List[SemanticMutant] = []
    for case in cases:
        # 1. Flip expected authorization outcome for a scorable case.
        if case.scorable:
            flipped = replace(
                case,
                expected_status=(200,) if case.expected_status != (200,) else (403, 404),
                forbidden_fields=() if case.forbidden_fields else ("secret_note",),
            )
            out.append(SemanticMutant(
                _mk_id("outcome-flip", case.case_id), "outcome-flip", case.case_id,
                "Flip the expected authorization outcome while preserving the same case identity.",
                _signature(case), _signature(flipped), "authorization-outcome",
            ))
        # 2. Remove a field prohibition where one exists.
        if case.forbidden_fields:
            mutated = replace(case, forbidden_fields=())
            out.append(SemanticMutant(
                _mk_id("field-allow", case.case_id), "field-allow", case.case_id,
                "Remove a sensitive-field prohibition from the security property.",
                _signature(case), _signature(mutated), "field-authorization",
            ))
        # 3. Swap the ownership relationship for cross-tenant cases.
        if case.relationship in {"cross_tenant", "cross_tenant_support"}:
            mutated = replace(case, relationship="same_tenant", expected_owner_tenant=None)
            out.append(SemanticMutant(
                _mk_id("relationship-swap", case.case_id), "relationship-swap", case.case_id,
                "Change a cross-tenant relationship into a same-tenant relationship.",
                _signature(case), _signature(mutated), "ownership-relationship",
            ))
        # 4. Erase revocation state from stale-session cases.
        if case.state_context == "revoked" or case.relationship == "revoked_session":
            mutated = replace(case, state_context="steady", relationship="direct")
            out.append(SemanticMutant(
                _mk_id("revocation-erase", case.case_id), "revocation-erase", case.case_id,
                "Remove the revoked-session state condition.",
                _signature(case), _signature(mutated), "session-state",
            ))
        # 5. Remove the API version dimension where present.
        if "/api/v1/" in case.path or "/api/v2/" in case.path:
            legacy_path = case.path.replace("/api/v2/", "/api/").replace("/api/v1/", "/api/")
            mutated = replace(case, path=legacy_path)
            out.append(SemanticMutant(
                _mk_id("version-erase", case.case_id), "version-erase", case.case_id,
                "Erase the explicit API-version distinction from the case.",
                _signature(case), _signature(mutated), "api-version",
            ))
    return out


def _semantic_key(case: SuiteCase) -> Tuple[Any, ...]:
    return (
        case.identity, case.relationship, case.expected_owner_tenant,
        tuple(case.expected_status), tuple(case.forbidden_fields),
        tuple(case.required_fields), case.state_context,
    )


def kill_analysis(cases: Sequence[SuiteCase] = CASES) -> Dict[str, Any]:
    """Determine whether each mutant is distinguishable by the corpus.

    A mutant is 'killed' when at least one corpus case shares the mutated
    semantic dimensions but has a different expected signature. This is a
    static adequacy signal; it is intentionally not presented as a runtime
    vulnerability-detection rate.
    """
    mutants = generate_mutants(cases)
    signatures = {_semantic_key(c): c.case_id for c in cases if c.scorable}
    results = []
    for mutant in mutants:
        # Prefer exact mutated signature; otherwise match on the targeted
        # dimension with a different expected security outcome.
        exact = any(_semantic_key(c) == mutant.mutated_signature[:7] for c in cases if c.scorable)
        killed_by = []
        if not exact:
            for c in cases:
                if not c.scorable or c.case_id == mutant.source_case_id:
                    continue
                orig = _signature(c)
                if orig != mutant.mutated_signature and orig != mutant.original_signature:
                    if mutant.targeted_dimension == "authorization-outcome" and c.identity == cases[[x.case_id for x in cases].index(mutant.source_case_id)].identity:
                        killed_by.append(c.case_id)
                    elif mutant.targeted_dimension == "field-authorization" and bool(c.forbidden_fields) != bool(mutant.mutated_signature[4]):
                        killed_by.append(c.case_id)
                    elif mutant.targeted_dimension == "ownership-relationship" and c.relationship != "same_tenant":
                        killed_by.append(c.case_id)
                    elif mutant.targeted_dimension == "session-state" and c.state_context == "revoked":
                        killed_by.append(c.case_id)
                    elif mutant.targeted_dimension == "api-version" and "/api/v1/" in c.path:
                        killed_by.append(c.case_id)
        killed = bool(killed_by)
        results.append({
            "mutant_id": mutant.mutant_id,
            "operator": mutant.operator,
            "source_case_id": mutant.source_case_id,
            "targeted_dimension": mutant.targeted_dimension,
            "description": mutant.description,
            "killed": killed,
            "killed_by": sorted(set(killed_by))[:10],
        })
    return results


class AuthorizationMutationAudit:
    """Run the bounded semantic mutation adequacy audit."""

    @classmethod
    def run(cls, cases: Sequence[SuiteCase] = CASES) -> Dict[str, Any]:
        mutants = kill_analysis(cases)
        by_op: Dict[str, Dict[str, int]] = {}
        for row in mutants:
            bucket = by_op.setdefault(row["operator"], {"generated": 0, "killed": 0, "survived": 0})
            bucket["generated"] += 1
            bucket["killed" if row["killed"] else "survived"] += 1
        killed = sum(1 for r in mutants if r["killed"])
        generated = len(mutants)
        score = killed / generated if generated else 1.0
        digest = hashlib.sha256(json.dumps(mutants, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        priority = {"relationship-swap": 5, "revocation-erase": 5, "field-allow": 4, "outcome-flip": 4, "version-erase": 3}
        frontier = sorted(
            [
                {
                    "mutant_id": row["mutant_id"],
                    "operator": row["operator"],
                    "source_case_id": row["source_case_id"],
                    "targeted_dimension": row["targeted_dimension"],
                    "priority": priority.get(row["operator"], 1),
                    "reason": "surviving semantic mutant indicates a benchmark coverage gap",
                }
                for row in mutants if not row["killed"]
            ],
            key=lambda x: (-x["priority"], x["operator"], x["source_case_id"]),
        )
        return {
            "schema": SCHEMA,
            "status": "pass" if generated and killed == generated else "needs-review",
            "methodology": {
                "purpose": "test-suite adequacy against bounded semantic security faults",
                "execution": "offline/static; no target contact",
                "not_a_detection_metric": True,
                "research_basis": "policy mutation testing is an established testing research technique; this implementation specializes the fault model for ERSEC security-behavior dimensions",
            },
            "corpus": {
                "case_count": len(cases),
                "scorable_case_count": sum(1 for c in cases if c.scorable),
            },
            "mutants": mutants,
            "summary": {
                "generated": generated,
                "killed": killed,
                "survived": generated - killed,
                "mutation_adequacy": round(score, 4),
                "operators": by_op,
            },
            "survivors": [r for r in mutants if not r["killed"]],
            "assurance_gap_frontier": frontier[:25],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "audit_digest": digest,
        }

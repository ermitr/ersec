"""Semantic authorization assurance for the ERSEC multi-tenant wedge.

The engine consumes explicit model expectations plus observed read-only
verification rows. It never treats a missing observer or missing execution as
secure. Values from response bodies are not persisted; only field paths and
bounded structural metadata are used for semantic checks.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from ersec_behavior import ModelIdentity, ModelResource, SecurityBehaviorModel
from ersec_oracles import Verdict

AUTHORIZATION_ASSURANCE_SCHEMA = "ersec-authorization-assurance/1"


def json_field_paths(value: Any, prefix: str = "", *, max_depth: int = 5, max_fields: int = 200) -> List[str]:
    """Return bounded JSON field paths without returning sensitive values."""
    out: List[str] = []
    if max_depth < 0 or len(out) >= max_fields:
        return out
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out.append(path)
            if len(out) >= max_fields:
                break
            out.extend(json_field_paths(child, path, max_depth=max_depth - 1, max_fields=max_fields - len(out)))
            if len(out) >= max_fields:
                break
    elif isinstance(value, list) and max_depth > 0:
        for child in value[:10]:
            out.extend(json_field_paths(child, prefix + "[]" if prefix else "[]", max_depth=max_depth - 1, max_fields=max_fields - len(out)))
            if len(out) >= max_fields:
                break
    return sorted(set(out))[:max_fields]


def _field_present(paths: Sequence[str], wanted: str) -> bool:
    wanted = str(wanted)
    return any(p == wanted or p.startswith(wanted + ".") or p.startswith(wanted + "[]") for p in paths)


@dataclass(frozen=True)
class AuthorizationCase:
    identity: str
    role: str
    tenant: str
    resource_id: str
    method: str
    expected_status: tuple[int, ...]
    forbidden_fields: tuple[str, ...] = ()
    required_fields: tuple[str, ...] = ()

    def key(self) -> str:
        return f"{self.identity}|{self.resource_id}|{self.method}"


class AuthorizationAssuranceEngine:
    """Plan and evaluate bounded semantic authorization cases."""

    def plan(self, model: SecurityBehaviorModel) -> List[AuthorizationCase]:
        cases: List[AuthorizationCase] = []
        for identity in model.identities:
            for resource in model.resources:
                expected = model._expected_for_resource(resource, identity)
                raw = resource.expected.get(identity.name, {}) if isinstance(resource.expected, dict) else {}
                if not isinstance(raw, dict):
                    raw = {}
                forbidden = tuple(sorted({str(x) for x in raw.get("forbidden_fields", []) if str(x).strip()}))
                required = tuple(sorted({str(x) for x in raw.get("required_fields", []) if str(x).strip()}))
                for method in resource.methods:
                    cases.append(AuthorizationCase(identity.name, identity.role, identity.tenant,
                                                    resource.resource_id, method,
                                                    tuple(expected["status"]), forbidden, required))
        return cases

    def evaluate(self, model: SecurityBehaviorModel, verification: Mapping[str, Any]) -> Dict[str, Any]:
        rows = verification.get("verifications", []) if isinstance(verification, Mapping) else []
        observed: Dict[str, Mapping[str, Any]] = {}
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, Mapping):
                continue
            key = f"{row.get('identity','')}|{row.get('resource_id','')}|{str(row.get('method','GET')).upper()}"
            observed[key] = row

        cases = self.plan(model)
        results: List[Dict[str, Any]] = []
        counterexamples: List[Dict[str, Any]] = []
        for case in cases:
            row = observed.get(case.key())
            if row is None:
                results.append(self._base_result(case, Verdict.NOT_TESTED.value, "authorization cell was not executed"))
                continue
            verdict = str(row.get("verdict", "inconclusive"))
            if verdict in {"not_tested", "blocked", "out_of_scope"}:
                results.append(self._base_result(case, verdict, str(row.get("reason", "authorization cell unavailable"))))
                continue
            if verdict == "inconclusive":
                results.append(self._base_result(case, Verdict.INCONCLUSIVE.value, str(row.get("error", "execution was inconclusive"))))
                continue

            observed_status = row.get("status")
            if observed_status not in case.expected_status:
                result = self._base_result(case, Verdict.VIOLATION.value,
                                           f"observed HTTP status {observed_status!r} is outside the modeled expectation")
                result["observed_status"] = observed_status
                result["expected_status"] = list(case.expected_status)
                result["evidence_strength"] = "status"
                results.append(result)
                counterexamples.append(self._counterexample(case, result, row, "status"))
                continue

            paths = [str(x) for x in row.get("observed_fields", [])] if isinstance(row.get("observed_fields", []), list) else []
            forbidden_present = [field for field in case.forbidden_fields if _field_present(paths, field)]
            required_missing = [field for field in case.required_fields if not _field_present(paths, field)]

            if forbidden_present:
                result = self._base_result(case, Verdict.VIOLATION.value, "forbidden response fields were observable")
                result["forbidden_fields_present"] = forbidden_present
                result["evidence_strength"] = "response_fields"
                results.append(result)
                counterexamples.append(self._counterexample(case, result, row, "forbidden_fields"))
            elif case.required_fields and not paths:
                result = self._base_result(case, Verdict.OBSERVATION_UNAVAILABLE.value, "response fields were not observable")
                results.append(result)
            elif required_missing:
                result = self._base_result(case, Verdict.VIOLATION.value, "required response fields were not observable")
                result["required_fields_missing"] = required_missing
                result["evidence_strength"] = "response_fields"
                results.append(result)
                counterexamples.append(self._counterexample(case, result, row, "required_fields"))
            else:
                result = self._base_result(case, Verdict.PASS.value, "modeled status and semantic field expectations matched")
                if case.forbidden_fields:
                    result["forbidden_fields_present"] = []
                if case.required_fields:
                    result["required_fields_missing"] = []
                results.append(result)

        counts = {key: sum(1 for r in results if r["verdict"] == key)
                  for key in ("pass", "violation", "inconclusive", "not_tested", "blocked", "out_of_scope", "observation_unavailable")}
        tested = counts["pass"] + counts["violation"]
        applicable = len(results)
        coverage = tested / applicable if applicable else 0.0
        status = "fail" if counts["violation"] else ("inconclusive" if any(counts[k] for k in ("inconclusive", "not_tested", "blocked", "out_of_scope", "observation_unavailable")) else "pass")
        return {
            "schema": AUTHORIZATION_ASSURANCE_SCHEMA,
            "status": status,
            "applicable_cases": applicable,
            "tested_cases": tested,
            "coverage_ratio": round(coverage, 4),
            "counts": counts,
            "violations": [r for r in results if r["verdict"] == "violation"][:200],
            "counterexamples": counterexamples[:200],
            "cases": results[:2000],
            "statement": "Semantic authorization assurance evaluates explicit identity/resource expectations; missing execution or observation is never treated as secure.",
        }

    @staticmethod
    def _base_result(case: AuthorizationCase, verdict: str, reason: str) -> Dict[str, Any]:
        return {
            "case_id": case.key(),
            "identity": case.identity,
            "role": case.role,
            "tenant": case.tenant,
            "resource_id": case.resource_id,
            "method": case.method,
            "expected_status": list(case.expected_status),
            "forbidden_fields": list(case.forbidden_fields),
            "required_fields": list(case.required_fields),
            "verdict": verdict,
            "reason": reason,
        }

    @staticmethod
    def _counterexample(case: AuthorizationCase, result: Mapping[str, Any], row: Mapping[str, Any], cause: str) -> Dict[str, Any]:
        return {
            "identity": case.identity,
            "role": case.role,
            "tenant": case.tenant,
            "resource_id": case.resource_id,
            "method": case.method,
            "url": row.get("url"),
            "expected_status": list(case.expected_status),
            "observed_status": row.get("status"),
            "cause": cause,
            "summary": str(result.get("reason", "authorization property violated")),
            "evidence_ref": row.get("finding_id"),
        }


def build_multitenant_ground_truth() -> Dict[str, Any]:
    """Return a small deterministic corpus used to exercise the authorization wedge."""
    return {
        "schema": "ersec-authorization-ground-truth/1",
        "name": "ERSEC multi-tenant authorization starter corpus",
        "version": 1,
        "cases": [
            {"id": "BOLA-ALLOW-001", "family": "horizontal-bola", "expected": "pass",
             "actor": {"role": "user", "tenant": "tenant_a"}, "resource": {"tenant": "tenant_a"}, "status": [200]},
            {"id": "BOLA-DENY-001", "family": "horizontal-bola", "expected": "violation",
             "actor": {"role": "user", "tenant": "tenant_b"}, "resource": {"tenant": "tenant_a"}, "status": [403, 404]},
            {"id": "RBAC-ALLOW-001", "family": "vertical-privilege", "expected": "pass",
             "actor": {"role": "admin", "tenant": "global"}, "resource": {"tenant": "tenant_a"}, "status": [200]},
            {"id": "RBAC-DENY-001", "family": "vertical-privilege", "expected": "violation",
             "actor": {"role": "user", "tenant": "tenant_a"}, "resource": {"tenant": "tenant_a"}, "status": [403, 404]},
            {"id": "FIELD-DENY-001", "family": "field-authorization", "expected": "violation",
             "actor": {"role": "support", "tenant": "tenant_a"}, "resource": {"tenant": "tenant_a"},
             "status": [200], "forbidden_fields": ["payment.card_number", "payment.cvv"]},
            {"id": "REVOCATION-001", "family": "revoked-session", "expected": "pass",
             "actor": {"role": "user", "tenant": "tenant_a"}, "resource": {"tenant": "tenant_a"}, "status": [401, 403]},
        ],
        "statement": "Ground truth labels describe intended security behavior; they are test expectations, not proofs about arbitrary deployments.",
    }

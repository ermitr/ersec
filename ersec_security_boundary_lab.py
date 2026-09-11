"""ERSEC 29.1.0 Security Boundary Lab.

Deterministic planner/evaluator for authorized identity, tenant, object and
field-boundary checks. It creates test obligations but never performs network
requests or handles credential values.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping

VERSION = "29.1.0"
SCHEMA = "ersec-security-boundary-lab/1"


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(v: Any) -> str:
    return hashlib.sha256(_canon(v).encode()).hexdigest()


def _safe_ref(value: Any) -> bool:
    s = str(value or "")
    return not any(k in s.lower() for k in ("password", "passwd", "secret", "token", "bearer", "private_key", "credential_value"))


def _validate_spec(spec: Mapping[str, Any]) -> None:
    for identity in spec.get("identities", {}).values() if isinstance(spec.get("identities"), Mapping) else []:
        if not isinstance(identity, Mapping):
            continue
        for key in ("credential", "token", "password", "secret", "bearer_token", "credential_value"):
            if key in identity:
                raise ValueError("credential material is forbidden; use credential_ref only")
        if "credential_ref" in identity and not _safe_ref(identity.get("credential_ref")):
            raise ValueError("credential_ref appears to contain credential material")



def _identity_pairs(identities: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """Return conservative identity comparison pairs.

    Pairs are generated only when identities differ on a security-relevant
    boundary (tenant or role). No credential material is touched.
    """
    rows = [(str(k), v if isinstance(v, Mapping) else {}) for k, v in identities.items()]
    out: list[tuple[str, str, str]] = []
    for i, (left_id, left) in enumerate(rows):
        for right_id, right in rows[i + 1:]:
            lt, rt = left.get("tenant"), right.get("tenant")
            lr, rr = left.get("role"), right.get("role")
            if lt != rt:
                out.append((left_id, right_id, "cross_tenant"))
            elif lr != rr:
                out.append((left_id, right_id, "cross_role"))
    return out


def compile_differential_matrix(spec: Mapping[str, Any]) -> dict[str, Any]:
    """Compile a read-only identity x resource authorization matrix.

    The compiler produces obligations only. It never logs in, mutates state,
    sends requests, or stores credential values. A matrix row represents a
    comparison between two modeled identities against one resource.
    """
    _validate_spec(spec)
    identities = spec.get("identities", {}) if isinstance(spec.get("identities"), Mapping) else {}
    resources = spec.get("resources", []) if isinstance(spec.get("resources"), list) else []
    properties = spec.get("properties", []) if isinstance(spec.get("properties"), list) else []
    pairs = _identity_pairs(identities)
    cases: list[dict[str, Any]] = []
    for prop in properties:
        if not isinstance(prop, Mapping):
            continue
        rid = str(prop.get("resource") or "")
        resource = next((r for r in resources if isinstance(r, Mapping) and str(r.get("id")) == rid), None)
        if resource is None:
            raise ValueError(f"property references unknown resource: {rid}")
        methods = [str(x).upper() for x in prop.get("methods", resource.get("methods", ["GET"]))]
        methods = [m for m in methods if m in {"GET", "HEAD", "OPTIONS"}] or ["GET"]
        expected = [int(x) for x in prop.get("expected_status", [403, 404]) if str(x).lstrip("-").isdigit()]
        for subject, comparator, relation in pairs:
            # If the property names a subject, only compare that subject.
            if prop.get("subject") and str(prop.get("subject")) not in {subject, comparator}:
                continue
            for method in methods:
                key = {"property": prop.get("id"), "resource": rid, "subject": subject, "comparator": comparator, "relation": relation, "method": method}
                cid = _digest(key)[:24]
                cases.append({
                    "case_id": f"matrix-{cid}", "property_id": str(prop.get("id") or cid),
                    "subject": subject, "comparator": comparator, "comparison": relation,
                    "resource": rid, "method": method, "subject_tenant": identities[subject].get("tenant"),
                    "comparator_tenant": identities[comparator].get("tenant"),
                    "subject_role": identities[subject].get("role"),
                    "comparator_role": identities[comparator].get("role"),
                    "expected_denial_status": expected,
                    "forbidden_fields": [str(x) for x in prop.get("forbidden", []) if str(x).strip()],
                    "side_effects_forbidden": True,
                    "safety": {"network": False, "destructive": False, "credential_material": False, "authorized_harness_required": True},
                })
    plan = {"schema": SCHEMA, "version": VERSION, "mode": "differential_identity_matrix",
            "cases": cases, "statistics": {"identities": len(identities), "identity_pairs": len(pairs),
            "resources": len(resources), "properties": len(properties), "cases": len(cases)},
            "governance": {"offline": True, "network_contact": False, "destructive_actions": False,
            "credential_material": False, "operator_authorization_required": True, "missing_evidence_is_not_pass": True,
            "pairing": "tenant-or-role-difference-only"}}
    plan["digest"] = _digest(plan)
    return plan

def compile_lab(spec: Mapping[str, Any]) -> dict[str, Any]:
    _validate_spec(spec)
    identities = spec.get("identities", {}) if isinstance(spec.get("identities"), Mapping) else {}
    resources = spec.get("resources", []) if isinstance(spec.get("resources"), list) else []
    properties = spec.get("properties", []) if isinstance(spec.get("properties"), list) else []
    cases = []
    for prop in properties:
        if not isinstance(prop, Mapping):
            continue
        subject = str(prop.get("subject") or "")
        resource_id = str(prop.get("resource") or "")
        if subject and subject not in identities:
            raise ValueError(f"property references unknown identity: {subject}")
        resource = next((r for r in resources if isinstance(r, Mapping) and str(r.get("id")) == resource_id), None)
        if resource is None:
            raise ValueError(f"property references unknown resource: {resource_id}")
        forbidden = tuple(sorted({str(x) for x in prop.get("forbidden", []) if str(x).strip()}))
        expected = tuple(int(x) for x in prop.get("expected_status", [403, 404]) if str(x).lstrip("-").isdigit())
        methods = [str(x).upper() for x in prop.get("methods", resource.get("methods", ["GET"]))]
        methods = [m for m in methods if m in {"GET", "HEAD", "OPTIONS"}]
        if not methods:
            methods = ["GET"]
        for method in methods:
            cid = _digest({"property": prop.get("id"), "subject": subject, "resource": resource_id, "method": method})[:24]
            cases.append({
                "case_id": f"boundary-{cid}", "property_id": str(prop.get("id") or cid),
                "subject": subject, "resource": resource_id, "method": method,
                "tenant": identities.get(subject, {}).get("tenant"),
                "role": identities.get(subject, {}).get("role"),
                "expected_status": list(expected), "forbidden_fields": list(forbidden),
                "side_effects_forbidden": True,
                "safety": {"network": False, "destructive": False, "credential_material": False, "authorized_harness_required": True},
            })
    plan = {"schema": SCHEMA, "version": VERSION, "cases": cases,
            "statistics": {"identities": len(identities), "resources": len(resources), "properties": len(properties), "cases": len(cases)},
            "governance": {"offline": True, "network_contact": False, "destructive_actions": False, "credential_material": False,
                           "operator_authorization_required": True, "missing_evidence_is_not_pass": True}}
    plan["digest"] = _digest(plan)
    return plan


def evaluate(plan: Mapping[str, Any], evidence: Mapping[str, Any]) -> dict[str, Any]:
    rows = evidence.get("observations", []) if isinstance(evidence, Mapping) else []
    by_id = {str(r.get("case_id")): r for r in rows if isinstance(r, Mapping) and r.get("case_id")}
    results = []
    for case in plan.get("cases", []):
        row = by_id.get(str(case.get("case_id")))
        if row is None:
            results.append({"case_id": case["case_id"], "verdict": "not_tested", "reason": "authorized harness produced no observation"}); continue
        verdict = str(row.get("verdict", "inconclusive")).lower()
        if verdict in {"blocked", "out_of_scope", "not_tested", "inconclusive", "unmodeled"}:
            results.append({"case_id": case["case_id"], "verdict": verdict, "reason": str(row.get("reason", "observation unavailable"))}); continue
        if row.get("side_effect_observed") is True:
            results.append({"case_id": case["case_id"], "verdict": "violation", "reason": "forbidden side effect observed", "evidence_ref": row.get("evidence_ref")}); continue
        status = row.get("status")
        if status not in case.get("expected_status", []):
            results.append({"case_id": case["case_id"], "verdict": "violation", "reason": "observed status violates modeled boundary", "expected_status": case.get("expected_status"), "observed_status": status, "evidence_ref": row.get("evidence_ref")}); continue
        fields = [str(x) for x in row.get("observed_fields", [])] if isinstance(row.get("observed_fields", []), list) else []
        forbidden = [f for f in case.get("forbidden_fields", []) if any(p == f or p.startswith(f + ".") or p.startswith(f + "[]") for p in fields)]
        if forbidden:
            results.append({"case_id": case["case_id"], "verdict": "violation", "reason": "forbidden response fields observable", "forbidden_fields": forbidden, "evidence_ref": row.get("evidence_ref")})
        else:
            results.append({"case_id": case["case_id"], "verdict": "pass", "reason": "modeled boundary matched observed status and fields", "evidence_ref": row.get("evidence_ref")})
    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in ("pass", "violation", "inconclusive", "not_tested", "blocked", "out_of_scope", "unmodeled")}
    status = "fail" if counts["violation"] else ("pass" if sum(counts[v] for v in ("inconclusive", "not_tested", "blocked", "out_of_scope", "unmodeled")) == 0 else "inconclusive")
    out = {"schema": SCHEMA, "version": VERSION, "status": status, "counts": counts, "results": results,
           "violations": [r for r in results if r["verdict"] == "violation"],
           "governance": {"offline": True, "network_contact": False, "missing_evidence_is_not_pass": True}}
    out["digest"] = _digest(out)
    return out


def load(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))

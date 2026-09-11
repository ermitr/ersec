"""ERSEC 29.1.1 counterfactual evidence bundles.

Offline comparison of baseline and controlled-policy-mutation evidence.  This
module does not generate exploits or contact targets; it evaluates evidence
already produced by an authorized harness and preserves uncertainty.
"""
from __future__ import annotations
import hashlib, json
from typing import Any, Mapping, Sequence

VERSION = "29.1.1"
SCHEMA = "ersec-counterfactual-evidence/1"
_TERMINAL = {"pass", "violation", "inconclusive", "not_tested", "blocked", "unmodeled"}


def _norm(v: Any) -> str:
    return str(v).strip().lower()


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def build_counterfactual(baseline: Mapping[str, Any], counterfactual: Mapping[str, Any],
                         evidence_refs: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Compare controlled baseline/counterfactual observations conservatively.

    A meaningful counterfactual is established only when the controlled
    mutation is identified, both observations are valid, and the security
    verdict changes in the expected direction. Missing/invalid evidence is
    never converted into PASS.
    """
    bv, cv = _norm(baseline.get("verdict")), _norm(counterfactual.get("verdict"))
    mutation = counterfactual.get("mutation") or baseline.get("mutation") or {}
    if bv not in _TERMINAL or cv not in _TERMINAL:
        relation, status = "invalid_observation", "not_tested"
    elif bv == "pass" and cv == "violation":
        relation, status = "security_property_sensitive_to_mutation", "pass"
    elif bv == cv:
        relation, status = "no_observed_verdict_change", "inconclusive"
    elif bv == "violation" and cv == "pass":
        relation, status = "unexpected_improvement", "inconclusive"
    else:
        relation, status = "ambiguous_verdict_change", "inconclusive"

    refs = [dict(x) for x in (evidence_refs or []) if isinstance(x, Mapping)]
    out = {
        "schema": SCHEMA, "version": VERSION, "status": status,
        "relation": relation,
        "baseline": dict(baseline), "counterfactual": dict(counterfactual),
        "mutation": dict(mutation) if isinstance(mutation, Mapping) else {"id": str(mutation)},
        "evidence_refs": refs,
        "evidence_digests": {"baseline": _digest(baseline), "counterfactual": _digest(counterfactual)},
        "trace_ids": sorted({str(x.get("trace_id")) for x in refs if x.get("trace_id")}),
        "policy_decision_ids": sorted({str(x.get("policy_decision_id")) for x in refs if x.get("policy_decision_id")}),
        "statement": "Counterfactual evidence is a controlled differential observation, not an exploit proof.",
    }
    out["digest"] = _digest(out)
    return out


def load(path: str) -> Any:
    with open(path, encoding="utf-8") as f: return json.load(f)


def save(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True); f.write("\n")

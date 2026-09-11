"""ERSEC 29.1.0 Security Behavior Assurance Compiler.

Compiles reviewed security-behavior policy into a deterministic assurance plan.
It does not execute network requests. It turns policy + observed inventory +
optional runtime-control evidence into reviewable test obligations, coverage,
and safe regression contracts.

The trust boundary is deliberately deterministic: YAML/JSON is input, not
authority; PASS is never inferred from missing observations.
"""
from __future__ import annotations

import hashlib, json
from dataclasses import dataclass, asdict
from pathlib import Path
from ersec_input_safety import bounded_text, loads_json, load_yaml, redact, validate_structure
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

VERSION = "29.1.0"
SCHEMA = "ersec-security-behavior-assurance-compiler/1"

VERDICTS = {"pass", "violation", "inconclusive", "not_tested", "blocked", "observation_unavailable", "unmodeled", "hypothesis"}
CONTROL_STATES = {"observed_enforced", "observed_gap", "configured_only", "insufficient_telemetry", "not_applicable"}


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(v: Any) -> str:
    return hashlib.sha256(_canon(v).encode()).hexdigest()


def _slug(*parts: Any) -> str:
    raw = "|".join(str(x) for x in parts)
    return "ob-" + hashlib.sha256(raw.encode()).hexdigest()[:20]


def load_document(path: str) -> Dict[str, Any]:
    p = Path(path)
    text = bounded_text(p.read_text(encoding="utf-8"), label=f"{p.name} input")
    if p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml  # optional dependency; common on Kali
        except ImportError as exc:
            raise ValueError("YAML policy requires PyYAML; install with: python3 -m pip install PyYAML") from exc
        obj = load_yaml(text, label=f"{p.name} YAML")
    else:
        obj = loads_json(text, label=f"{p.name} JSON")
    if not isinstance(obj, dict):
        raise ValueError("ERSEC assurance policy must be a mapping/object")
    return obj


def save_document(path: str, obj: Mapping[str, Any]) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class Obligation:
    id: str
    subject: str
    resource: str
    action: str
    expected: str
    severity: str = "high"
    fields: Tuple[str, ...] = ()
    forbidden_fields: Tuple[str, ...] = ()
    side_effects: str = "none"
    safety: str = "read_only"
    observers: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AssuranceCell:
    id: str
    policy_id: str
    subject: str
    resource: str
    action: str
    expected: str
    scenario: str
    safety: str
    observer_requirements: Tuple[str, ...]
    status: str = "not_tested"
    evidence_refs: Tuple[str, ...] = ()
    reason: str = ""


def _tuple(value: Any) -> Tuple[str, ...]:
    return tuple(str(x) for x in value) if isinstance(value, (list, tuple)) else ()


def parse_policy(doc: Mapping[str, Any]) -> Tuple[List[Obligation], List[str]]:
    errors: List[str] = []
    obligations: List[Obligation] = []
    policy = doc.get("policy", doc)
    if not isinstance(policy, Mapping):
        return [], ["policy must be an object"]
    rules = policy.get("rules", [])
    if not isinstance(rules, list):
        return [], ["policy.rules must be a list"]
    for i, rule in enumerate(rules):
        if not isinstance(rule, Mapping):
            errors.append(f"rules[{i}] must be an object"); continue
        rid = str(rule.get("id") or "")
        if not rid: errors.append(f"rules[{i}] missing id"); continue
        subject = str(rule.get("subject") or "")
        resource = str(rule.get("resource") or "")
        action = str(rule.get("action") or "")
        expected = str(rule.get("expect") or rule.get("expected") or "")
        if not subject or not resource or not action: errors.append(f"rule {rid}: subject/resource/action required")
        if expected not in {"allow", "deny"}: errors.append(f"rule {rid}: expect must be allow or deny")
        obligations.append(Obligation(rid, subject, resource, action, expected,
            str(rule.get("severity") or "high"), _tuple(rule.get("fields")), _tuple(rule.get("forbidden_fields")),
            str(rule.get("side_effects") or "none"), str(rule.get("safety") or "read_only"), _tuple(rule.get("observers"))))
    return obligations, errors


def normalize_inventory(items: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, Mapping): continue
        method = str(item.get("method") or "GET").upper()
        route = str(item.get("route") or item.get("url") or "")
        if not route: continue
        operation_id = str(item.get("operation_id") or item.get("id") or _slug(method, route))
        row = dict(item); row.update({"operation_id": operation_id, "method": method, "route": route})
        row["status"] = "observed" if item.get("observed", True) else "declared_only"
        row["provenance"] = item.get("provenance", []) if isinstance(item.get("provenance", []), list) else [str(item.get("provenance"))]
        out[operation_id] = row
    return sorted(out.values(), key=lambda x: x["operation_id"])


def build_inventory(document: Mapping[str, Any]) -> Dict[str, Any]:
    sources = document.get("inventory", document)
    all_items: List[Mapping[str, Any]] = []
    if isinstance(sources, Mapping):
        for key in ("openapi", "graphql", "har", "browser", "traffic", "crawler", "manual", "runtime", "operations"):
            value = sources.get(key, [])
            if isinstance(value, list): all_items.extend(x for x in value if isinstance(x, Mapping))
    elif isinstance(sources, list): all_items = [x for x in sources if isinstance(x, Mapping)]
    normalized = normalize_inventory(all_items)
    return {
        "schema": "ersec-api-behavior-inventory/1", "version": VERSION,
        "operations": normalized, "operation_count": len(normalized),
        "observed_count": sum(x["status"] == "observed" for x in normalized),
        "declared_only_count": sum(x["status"] == "declared_only" for x in normalized),
        "digest": _digest(normalized),
    }


def compile_policy(policy_doc: Mapping[str, Any], inventory: Optional[Mapping[str, Any]] = None,
                   runtime_controls: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    obligations, errors = parse_policy(policy_doc)
    policy = policy_doc.get("policy", policy_doc)
    policy_id = str(policy.get("id") or "security-behavior-policy-29.1.0") if isinstance(policy, Mapping) else "security-behavior-policy-29.1.0"
    cells: List[AssuranceCell] = []
    for o in obligations:
        # Every reviewed rule gets at least one deterministic owner/peer scenario.
        scenarios = ["declared-relationship"]
        if o.expected == "deny": scenarios += ["cross-identity", "field-leakage"]
        for scenario in scenarios:
            cid = _slug(policy_id, o.id, scenario)
            cells.append(AssuranceCell(cid, o.id, o.subject, o.resource, o.action, o.expected, scenario, o.safety, o.observers))
    controls = evaluate_runtime_controls(runtime_controls or {})
    inv = dict(inventory or {"operations": [], "operation_count": 0, "observed_count": 0, "declared_only_count": 0})
    report = {
        "schema": SCHEMA, "version": VERSION, "policy_id": policy_id,
        "policy_digest": _digest(policy_doc), "inventory_digest": inv.get("digest"),
        "validation": {"valid": not errors, "errors": errors},
        "obligations": [asdict(x) for x in obligations],
        "assurance_cells": [asdict(x) for x in cells],
        "runtime_controls": controls,
        "coverage": {"applicable": len(cells), "tested": 0, "not_tested": len(cells), "ratio": 0.0,
                      "statement": "Coverage is an observation metric, not proof of security."},
        "regression_contracts": [
            {"contract_id": "rc-" + _digest(asdict(o))[:20], "policy_rule": o.id, "expected": o.expected,
             "forbidden_fields": list(o.forbidden_fields), "allowed_states": ["pass"], "requires_review": True}
            for o in obligations
        ],
    }
    report["compile_digest"] = _digest({k:v for k,v in report.items() if k != "compile_digest"})
    return report


def evaluate_runtime_controls(doc: Mapping[str, Any]) -> Dict[str, Any]:
    raw = doc.get("controls", doc.get("runtime_controls", [])) if isinstance(doc, Mapping) else []
    if isinstance(raw, Mapping): raw = raw.get("items", [])
    rows = []
    if not isinstance(raw, list): raw = []
    for i, item in enumerate(raw):
        if not isinstance(item, Mapping): continue
        state = str(item.get("state") or "insufficient_telemetry")
        if state not in CONTROL_STATES: state = "insufficient_telemetry"
        rows.append({"control_id": str(item.get("control_id") or f"control-{i+1}"), "route": str(item.get("route") or ""),
                     "required_control": str(item.get("required_control") or ""), "state": state,
                     "trace_id": str(item.get("trace_id") or ""), "policy_decision_id": str(item.get("policy_decision_id") or ""),
                     "service_revision": str(item.get("service_revision") or "")})
    counts = {state: sum(x["state"] == state for x in rows) for state in sorted(CONTROL_STATES)}
    return {"schema": "ersec-runtime-control-evidence/1", "version": VERSION, "controls": rows, "counts": counts,
            "statement": "Configured-only or missing telemetry is not equivalent to observed enforcement."}


def merge_observations(plan: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    cells = {str(c.get("id")): dict(c) for c in plan.get("assurance_cells", []) if isinstance(c, Mapping)}
    for ev in evidence:
        if not isinstance(ev, Mapping): continue
        cid = str(ev.get("cell_id") or "")
        if cid not in cells: continue
        verdict = str(ev.get("verdict") or "inconclusive")
        if verdict not in VERDICTS: verdict = "inconclusive"
        cells[cid]["status"] = verdict
        cells[cid]["evidence_refs"] = tuple(str(x) for x in ev.get("evidence_refs", [])) if isinstance(ev.get("evidence_refs", []), list) else ()
        cells[cid]["reason"] = str(ev.get("reason") or "")
    rows = list(cells.values())
    tested = sum(x["status"] != "not_tested" for x in rows)
    out = dict(plan); out["assurance_cells"] = rows
    out["coverage"] = {"applicable": len(rows), "tested": tested, "not_tested": len(rows)-tested,
                        "ratio": round(tested/len(rows), 4) if rows else 0.0,
                        "statement": "Coverage is an observation metric, not proof of security."}
    out["merge_digest"] = _digest(out)
    return out


def validate_plan(plan: Mapping[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []
    if plan.get("version") != VERSION: errors.append("version must be 29.1.0")
    if not isinstance(plan.get("assurance_cells"), list): errors.append("assurance_cells must be a list")
    seen = set()
    for cell in plan.get("assurance_cells", []):
        cid = str(cell.get("id") or "") if isinstance(cell, Mapping) else ""
        if not cid: errors.append("assurance cell missing id")
        elif cid in seen: errors.append(f"duplicate assurance cell: {cid}")
        seen.add(cid)
        if isinstance(cell, Mapping) and cell.get("status") not in VERDICTS: errors.append(f"invalid verdict for {cid}")
    return {"schema": "ersec-assurance-plan-validation/1", "version": VERSION, "valid": not errors, "errors": errors, "cell_count": len(seen)}


def compile_file(policy_path: str, output_path: str, inventory_path: Optional[str] = None, controls_path: Optional[str] = None) -> Dict[str, Any]:
    policy = load_document(policy_path)
    inv = load_document(inventory_path) if inventory_path else {}
    controls = load_document(controls_path) if controls_path else {}
    result = compile_policy(policy, build_inventory(inv) if inv else None, controls)
    save_document(output_path, result)
    return result

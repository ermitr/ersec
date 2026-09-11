"""ERSEC 29.1.0 producer/link learning for stateful assurance.

Learns safe producer/consumer relationships from reviewed API inventory,
OpenAPI Links, Location headers, and response-derived identifiers. The module
only compiles evidence into replayable obligations; it never contacts a target,
executes requests, or accepts credentials.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from ersec_input_safety import bounded_text, loads_json, load_yaml, redact, validate_structure
from typing import Any, Dict, List, Mapping, Sequence

VERSION = "29.1.0"
SCHEMA = "ersec-stateful-producer-links/1"


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(v: Any) -> str:
    return hashlib.sha256(_canon(v).encode()).hexdigest()


def load(path: str) -> Dict[str, Any]:
    p = Path(path); text = bounded_text(p.read_text(encoding="utf-8"), label=f"{p.name} input")
    if p.suffix.lower() in {".yaml", ".yml"}:
        import yaml
        obj = load_yaml(text, label=f"{p.name} YAML")
    else:
        obj = loads_json(text, label=f"{p.name} JSON")
    if not isinstance(obj, dict): raise ValueError("producer/link document must be an object")
    return obj


def save(path: str, obj: Mapping[str, Any]) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _reject_credentials(v: Any, path: str = "root") -> None:
    if isinstance(v, Mapping):
        for k, x in v.items():
            if str(k).lower() in {"token", "bearer_token", "password", "secret", "credential", "credentials", "api_key", "private_key"}:
                raise ValueError(f"credential material is not accepted at {path}.{k}")
            _reject_credentials(x, f"{path}.{k}")
    elif isinstance(v, list):
        for i, x in enumerate(v): _reject_credentials(x, f"{path}[{i}]")


def _operation_index(inventory: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    rows = inventory.get("operations", inventory.get("inventory", []))
    if isinstance(rows, Mapping): rows = rows.get("operations", [])
    return {str(r.get("operation_id") or r.get("id")): r for r in rows if isinstance(r, Mapping) and (r.get("operation_id") or r.get("id"))}


def _refs_from_links(op: Mapping[str, Any]) -> List[Dict[str, Any]]:
    out = []
    links = op.get("links", op.get("openapi_links", []))
    if isinstance(links, Mapping): links = [links]
    if not isinstance(links, list): return out
    for link in links:
        if not isinstance(link, Mapping): continue
        target = str(link.get("operation_id") or link.get("operationId") or link.get("target_operation_id") or "").strip()
        if target:
            out.append({"kind": "openapi_link", "target_operation_id": target, "parameter_mapping": dict(link.get("parameters", {})) if isinstance(link.get("parameters", {}), Mapping) else {}})
    return out


def _refs_from_location(op: Mapping[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for key in ("location", "location_template", "location_header"):
        val = op.get(key)
        if isinstance(val, str) and val.strip():
            out.append({"kind": "location", "location_template": val.strip()})
    return out


def _refs_from_producers(op: Mapping[str, Any]) -> List[Dict[str, Any]]:
    raw = op.get("produces", op.get("producer_fields", []))
    if isinstance(raw, str): raw = [raw]
    if not isinstance(raw, list): return []
    return [{"kind": "producer_field", "field": str(x)} for x in raw if str(x).strip()]


def learn(inventory: Mapping[str, Any], observations: Mapping[str, Any] | None = None, max_links: int = 128) -> Dict[str, Any]:
    _reject_credentials(inventory); _reject_credentials(observations or {})
    idx = _operation_index(inventory)
    observations = observations or {}
    links: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    for oid, op in sorted(idx.items()):
        candidates = _refs_from_links(op)
        candidates += _refs_from_location(op)
        candidates += _refs_from_producers(op)
        observed = observations.get(oid, {}) if isinstance(observations, Mapping) else {}
        derived = observed.get("derived_links", []) if isinstance(observed, Mapping) else []
        if isinstance(derived, list):
            for row in derived:
                if isinstance(row, Mapping) and row.get("target_operation_id"):
                    candidates.append({"kind": "observed_identifier", **dict(row)})
        for c in candidates:
            target = str(c.get("target_operation_id") or "").strip()
            if target and target not in idx:
                unresolved.append({"source_operation_id": oid, **c, "reason": "target operation not present in inventory"})
                continue
            row = {"source_operation_id": oid, **c}
            row["relationship_id"] = "link-" + _digest(row)[:20]
            links.append(row)
            if len(links) >= max_links: break
        if len(links) >= max_links: break
    obligations = []
    for link in links:
        obligations.append({
            "id": "producer-obligation-" + link["relationship_id"][5:],
            "relationship_id": link["relationship_id"],
            "source_operation_id": link["source_operation_id"],
            "target_operation_id": link.get("target_operation_id"),
            "kind": link["kind"],
            "assertions": [
                "producer output remains bound to the intended consumer input",
                "cross-tenant/object rebinding cannot change the authorized relationship",
                "missing producer evidence is not PASS",
            ],
            "required_evidence": ["relationship_id", "source_observation", "target_observation"],
            "missing_evidence_verdict": "not_tested",
        })
    out = {
        "schema": SCHEMA, "version": VERSION,
        "safety": {"network_access": False, "destructive_actions": False, "credential_material": False, "authorized_harness_required": True},
        "relationships": links, "unresolved_relationships": unresolved,
        "obligations": obligations,
        "counts": {"relationships": len(links), "obligations": len(obligations), "unresolved": len(unresolved)},
        "statement": "Producer/link learning compiles reviewed or observed relationships into bounded stateful obligations; it does not execute requests or invent authorization truth.",
    }
    out["digest"] = _digest(out)
    return out


def evaluate(plan: Mapping[str, Any], evidence: Mapping[str, Any]) -> Dict[str, Any]:
    if plan.get("schema") != SCHEMA: raise ValueError("unsupported producer/link plan schema")
    _reject_credentials(evidence)
    supplied = evidence.get("relationships", {})
    if not isinstance(supplied, Mapping): raise ValueError("evidence.relationships must be an object")
    rows = []
    for obligation in plan.get("obligations", []):
        oid = str(obligation.get("id")); item = supplied.get(oid)
        if not isinstance(item, Mapping):
            rows.append({"obligation_id": oid, "verdict": "not_tested", "reason": "required producer/link evidence absent"}); continue
        if item.get("blocked"):
            verdict = "blocked"; reason = "authorized harness reported execution blocked"
        elif item.get("oracle_available") is False:
            verdict = "inconclusive"; reason = "authoritative relationship oracle unavailable"
        elif str(item.get("verdict")) in {"pass", "violation", "inconclusive", "not_tested", "blocked", "unmodeled"}:
            verdict = str(item["verdict"]); reason = "harness-supplied verdict"
        else:
            verdict = "inconclusive"; reason = "evidence lacks trusted verdict"
        rows.append({"obligation_id": oid, "relationship_id": obligation.get("relationship_id"), "verdict": verdict, "reason": reason, "trace_id": item.get("trace_id"), "service_revision": item.get("service_revision")})
    counts = {v: sum(x["verdict"] == v for x in rows) for v in ("pass", "violation", "inconclusive", "not_tested", "blocked", "unmodeled")}
    status = "violation" if counts["violation"] else ("pass" if rows and counts["pass"] == len(rows) else "inconclusive")
    out = {"schema": "ersec-stateful-producer-links-result/1", "version": VERSION, "plan_digest": plan.get("digest"), "results": rows, "counts": counts, "status": status, "statement": "Producer/link evaluation never treats missing evidence as PASS."}
    out["digest"] = _digest(out)
    return out


def compile_file(path: str, output: str, observations_path: str | None = None, max_links: int = 128) -> Dict[str, Any]:
    inv = load(path); obs = load(observations_path) if observations_path else {}
    result = learn(inv, obs, max_links); save(output, result); return result

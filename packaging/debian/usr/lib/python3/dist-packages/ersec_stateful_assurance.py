"""ERSEC 29.1.0 stateful security-behavior assurance.

Compiles reviewed workflow invariants into bounded, safe scenarios and evaluates
read-only evidence supplied by an authorized harness. It never performs network
requests, never accepts credential material, and never treats missing evidence as
PASS.
"""
from __future__ import annotations
import hashlib, json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping

VERSION = "29.1.0"
SCHEMA = "ersec-stateful-assurance/1"
VERDICTS = ("pass", "violation", "inconclusive", "not_tested", "blocked", "unmodeled")


def _canon(x: Any) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(x: Any) -> str:
    return hashlib.sha256(_canon(x).encode("utf-8")).hexdigest()


def load(path: str) -> Dict[str, Any]:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise ValueError("PyYAML is required for YAML workflow documents") from exc
        value = yaml.safe_load(text)
    else:
        value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("stateful assurance document must be an object")
    return value


def save(path: str, value: Mapping[str, Any]) -> None:
    p = Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _reject_credentials(value: Any, path: str = "root") -> None:
    if isinstance(value, Mapping):
        for k, v in value.items():
            key = str(k).lower()
            if key in {"token", "bearer_token", "password", "secret", "credential", "credentials", "api_key", "private_key"}:
                raise ValueError(f"credential material is not accepted at {path}.{k}")
            _reject_credentials(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _reject_credentials(v, f"{path}[{i}]")


def _transition_map(workflow: Mapping[str, Any]) -> Dict[str, List[Mapping[str, Any]]]:
    out: Dict[str, List[Mapping[str, Any]]] = {}
    for t in workflow.get("transitions", []):
        if not isinstance(t, Mapping):
            raise ValueError("workflow transitions must be objects")
        src = str(t.get("from", "")).strip()
        dst = str(t.get("to", "")).strip()
        action = str(t.get("action", "")).strip()
        if not src or not dst or not action:
            raise ValueError("each transition requires from, to and action")
        out.setdefault(src, []).append(t)
    return out


def compile_plan(doc: Mapping[str, Any], max_negative_paths: int = 32) -> Dict[str, Any]:
    _reject_credentials(doc)
    workflows = doc.get("workflows", [])
    if "workflow" in doc and not workflows:
        workflows = [doc["workflow"]]
    if not isinstance(workflows, list) or not workflows:
        raise ValueError("workflows must be a non-empty list")
    max_negative_paths = max(1, min(int(max_negative_paths), 256))
    plans: List[Dict[str, Any]] = []
    for wi, wf in enumerate(workflows):
        if not isinstance(wf, Mapping):
            raise ValueError("workflow entries must be objects")
        wid = str(wf.get("id") or wf.get("workflow") or f"workflow-{wi+1}")
        states = [str(x) for x in wf.get("states", [])]
        if not states:
            raise ValueError(f"workflow {wid} requires states")
        transitions = _transition_map(wf)
        invariants = wf.get("invariants", [])
        if not isinstance(invariants, list):
            raise ValueError(f"workflow {wid} invariants must be a list")
        for inv_i, inv in enumerate(invariants):
            if not isinstance(inv, Mapping):
                raise ValueError(f"workflow {wid} invariant {inv_i} must be an object")
            iid = str(inv.get("id") or f"{wid}-invariant-{inv_i+1}")
            statement = str(inv.get("statement", "")).strip()
            if not statement:
                raise ValueError(f"workflow {wid} invariant {iid} requires statement")
            plans.append({
                "id": iid,
                "workflow_id": wid,
                "statement": statement,
                "oracle": dict(inv.get("oracle", {"type": "state_transition"})) if isinstance(inv.get("oracle", {}), Mapping) else {"type": "state_transition"},
                "safety": str(inv.get("safety", "read_only")),
                "scenario_ids": [],
            })
        scenarios: List[Dict[str, Any]] = []
        sid_base = f"{wid}:baseline"
        scenarios.append({"id": sid_base, "kind": "baseline", "steps": [], "expected": "valid_flow", "safety": "read_only"})
        negative_specs = [
            ("skip-prerequisite", "omit a prerequisite transition"),
            ("reverse-transition", "attempt a reverse transition"),
            ("replay-terminal-action", "replay a terminal action"),
            ("tenant-switch", "change tenant context between steps"),
            ("object-rebind", "change object reference between steps"),
            ("stale-session", "use a stale or revoked session context"),
        ]
        for kind, description in negative_specs[:max_negative_paths]:
            scenarios.append({"id": f"{wid}:{kind}", "kind": kind, "description": description,
                              "steps": [], "expected": "invariant_must_hold", "safety": "read_only"})
        for inv in plans:
            if inv["workflow_id"] == wid:
                inv["scenario_ids"] = [s["id"] for s in scenarios]
        plans[-len([x for x in plans if x["workflow_id"] == wid]):] if False else None
        out_workflow = {
            "id": wid, "states": states,
            "transitions": [dict(t) for src in transitions for t in transitions[src]],
            "scenario_count": len(scenarios), "scenarios": scenarios,
        }
        # Require every generated scenario to have an explicit evidence slot.
        out_workflow["evidence_contract"] = {
            "required": ["scenario_id", "observed_state", "observed_events"],
            "optional": ["trace_id", "policy_decision_id", "service_revision"],
            "missing_evidence_verdict": "not_tested",
        }
        # Store workflow as an assurance plan row.
        plans.append({"workflow_id": wid, "workflow": out_workflow, "kind": "workflow_plan"})

    result = {
        "schema": SCHEMA, "version": VERSION,
        "safety": {"network_access": False, "destructive_actions": False, "credential_material": False,
                   "authorized_harness_required": True},
        "workflows": [x["workflow"] for x in plans if x.get("kind") == "workflow_plan"],
        "invariants": [x for x in plans if x.get("kind") != "workflow_plan"],
        "verdict_vocabulary": list(VERDICTS),
        "statement": "This artifact plans bounded stateful assurance; it does not execute a target or infer business truth without reviewed invariants.",
    }
    result["digest"] = _digest(result)
    return result


def evaluate(plan: Mapping[str, Any], evidence: Mapping[str, Any]) -> Dict[str, Any]:
    if str(plan.get("schema")) != SCHEMA:
        raise ValueError("unsupported stateful assurance plan schema")
    _reject_credentials(evidence)
    rows: List[Dict[str, Any]] = []
    ev = evidence.get("scenarios", {})
    if not isinstance(ev, Mapping):
        raise ValueError("evidence.scenarios must be an object")
    for scenario in [s for wf in plan.get("workflows", []) for s in wf.get("scenarios", []) if isinstance(s, Mapping)]:
        sid = str(scenario.get("id"))
        item = ev.get(sid)
        if item is None:
            rows.append({"scenario_id": sid, "verdict": "not_tested", "reason": "no evidence supplied"})
            continue
        if not isinstance(item, Mapping):
            rows.append({"scenario_id": sid, "verdict": "inconclusive", "reason": "evidence is not an object"})
            continue
        if item.get("blocked"):
            verdict = "blocked"; reason = "authorized harness reported execution blocked"
        elif item.get("oracle_available") is False:
            verdict = "inconclusive"; reason = "authoritative oracle unavailable"
        elif "verdict" in item and str(item["verdict"]) in VERDICTS:
            verdict = str(item["verdict"]); reason = "harness-supplied verdict"
        else:
            verdict = "inconclusive"; reason = "evidence lacks an explicit trusted verdict"
        rows.append({"scenario_id": sid, "verdict": verdict, "reason": reason,
                     "trace_id": item.get("trace_id"), "policy_decision_id": item.get("policy_decision_id"),
                     "service_revision": item.get("service_revision")})
    counts = {v: sum(r["verdict"] == v for r in rows) for v in VERDICTS}
    out = {"schema": "ersec-stateful-assurance-result/1", "version": VERSION,
           "plan_digest": plan.get("digest"), "results": rows, "counts": counts,
           "status": "violation" if counts["violation"] else ("pass" if rows and counts["pass"] == len(rows) else "inconclusive"),
           "statement": "Stateful assurance evaluates supplied evidence; it never converts missing or unavailable observations into PASS."}
    out["digest"] = _digest(out)
    return out


def compile_file(path: str, output: str, max_negative_paths: int = 32) -> Dict[str, Any]:
    result = compile_plan(load(path), max_negative_paths)
    save(output, result)
    return result


def evaluate_file(plan_path: str, evidence_path: str, output: str) -> Dict[str, Any]:
    result = evaluate(load(plan_path), load(evidence_path))
    save(output, result)
    return result

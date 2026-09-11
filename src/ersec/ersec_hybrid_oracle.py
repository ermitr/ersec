"""ERSEC 29.1.1 hybrid security oracle and runtime control correlator.

Offline evidence fusion only. Semantic response evidence is reconciled with
explicit authoritative downstream observations (DB/audit/queue/webhook/OPA/
OpenTelemetry metadata). Conflicts are never silently resolved to PASS.
"""
from __future__ import annotations

import hashlib, json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

VERSION = "29.1.1"
SCHEMA = "ersec-hybrid-oracle/1"


@dataclass(frozen=True)
class Observation:
    source: str
    verdict: str
    evidence: Mapping[str, Any]
    authority: int = 0


def _norm(v: Any) -> str:
    return str(v).strip().lower()


def _valid(v: Any) -> bool:
    return _norm(v) in {"pass", "violation", "inconclusive", "not_tested", "blocked", "unmodeled"}


def evaluate_hybrid(semantic: Mapping[str, Any] | None,
                    authoritative: Sequence[Mapping[str, Any]] | None = None) -> dict[str, Any]:
    """Fuse semantic and authoritative evidence conservatively.

    PASS requires at least one PASS semantic observation and no authoritative
    violation/conflict. An authoritative violation dominates semantic PASS.
    Conflicting authoritative observers produce observer_conflict/inconclusive.
    """
    semantic = semantic or {}
    auth = list(authoritative or [])
    observations: list[Observation] = []
    if _valid(semantic.get("verdict")):
        observations.append(Observation("semantic", _norm(semantic["verdict"]), semantic.get("evidence", {}), 1))
    for item in auth:
        if not isinstance(item, Mapping) or not _valid(item.get("verdict")):
            continue
        observations.append(Observation(str(item.get("source", "authoritative")), _norm(item["verdict"]), item.get("evidence", {}), 2))

    auth_obs = [o for o in observations if o.authority >= 2]
    auth_verdicts = {o.verdict for o in auth_obs if o.verdict in {"pass", "violation"}}
    semantic_v = next((o.verdict for o in observations if o.source == "semantic"), None)
    auth_conflict = len(auth_verdicts) > 1
    semantic_conflict = semantic_v in {"pass", "violation"} and any(o.verdict in {"pass", "violation"} and o.verdict != semantic_v for o in auth_obs)
    conflict = auth_conflict or semantic_conflict

    if auth_conflict:
        verdict, reason = "inconclusive", "observer_conflict"
    elif semantic_conflict and len(auth_obs) <= 1:
        verdict, reason = "inconclusive", "observer_conflict"
    elif len(auth_obs) >= 2 and auth_verdicts == {"violation"}:
        verdict, reason = "violation", "authoritative_observers_agree_violation"
    elif "violation" in auth_verdicts:
        verdict, reason = "violation", "authoritative_observer_violation"
    elif auth_obs and all(o.verdict == "pass" for o in auth_obs) and semantic_v == "pass":
        verdict, reason = "pass", "semantic_and_authoritative_agreement"
    elif semantic_v == "violation":
        verdict, reason = "violation", "semantic_observer_violation"
    elif semantic_v == "pass" and not auth_obs:
        verdict, reason = "inconclusive", "authoritative_observation_missing"
    elif auth_obs and all(o.verdict == "pass" for o in auth_obs) and semantic_v is None:
        verdict, reason = "inconclusive", "semantic_observation_missing"
    else:
        verdict, reason = "inconclusive", "insufficient_consistent_evidence"

    payload = {
        "schema": SCHEMA, "version": VERSION, "verdict": verdict, "reason": reason,
        "semantic": dict(semantic), "authoritative": [dict(x) for x in auth],
        "observer_conflict": conflict,
        "evidence_sources": [o.source for o in observations],
    }
    payload["digest"] = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return payload


def correlate_runtime_controls(manifest: Mapping[str, Any], telemetry: Sequence[Mapping[str, Any]] | None) -> dict[str, Any]:
    """Correlate expected controls with OTel/OPA/gateway-style observations."""
    telemetry = list(telemetry or [])
    rows = []
    for control in manifest.get("controls", []):
        cid = str(control.get("id", ""))
        expected = str(control.get("decision", control.get("expected_decision", ""))).lower()
        service = str(control.get("service", ""))
        revision = str(control.get("service_revision", ""))
        matches = [t for t in telemetry if str(t.get("control_id", t.get("policy_decision_id", ""))) == cid and (not service or str(t.get("service", "")) == service)]
        if not matches:
            state = "insufficient_telemetry"
        else:
            revisions = {str(t.get("service_revision", "")) for t in matches if t.get("service_revision") is not None}
            decisions = {str(t.get("decision", "")).lower() for t in matches}
            if revision and revisions and revision not in revisions:
                state = "insufficient_telemetry"
            elif expected and expected not in decisions:
                state = "observed_gap"
            elif any(t.get("authoritative") is True and t.get("enforced") is True for t in matches):
                state = "observed_enforced"
            elif any(t.get("configured") is True for t in matches):
                state = "configured_only"
            else:
                state = "insufficient_telemetry"
        rows.append({"control_id": cid, "state": state, "observations": len(matches)})
    counts = {k: sum(1 for r in rows if r["state"] == k) for k in ("observed_enforced", "observed_gap", "configured_only", "insufficient_telemetry", "not_applicable")}
    out = {"schema": "ersec-runtime-control-correlation/1", "version": VERSION, "controls": rows, "counts": counts}
    out["digest"] = hashlib.sha256(json.dumps(out, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return out


def load(path: str) -> Any:
    with open(path, encoding="utf-8") as f: return json.load(f)


def save(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f: json.dump(data, f, indent=2, sort_keys=True); f.write("\n")

"""Security Behavior Assurance lineage, trust lattice, frontier and delta analysis.

This module is deliberately deterministic and offline.  It does not contact
application targets or handle credential values.  It turns existing ERSEC
benchmark evidence into a property-level assurance record that can be compared
across runs and tied to source/build/deployment metadata supplied by the
operator.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence
import hashlib
import json

SCHEMA = "ersec-assurance-lineage/1"


class OracleTier(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    AUTHORITATIVE = "authoritative"


_ORACLE_SCORES = {
    OracleTier.UNKNOWN.value: 0,
    OracleTier.LOW.value: 25,
    OracleTier.MEDIUM.value: 50,
    OracleTier.HIGH.value: 75,
    OracleTier.AUTHORITATIVE.value: 100,
}


@dataclass(frozen=True)
class LineageNode:
    kind: str
    node_id: str
    digest: str | None = None
    metadata: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class AssuranceDelta:
    case_id: str
    before_verdict: str
    after_verdict: str
    transition: str
    assurance_effect: str
    reason: str


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def oracle_trust(strength: str | None, *, authoritative: bool = False) -> dict[str, Any]:
    tier = OracleTier.AUTHORITATIVE if authoritative else OracleTier(strength or OracleTier.UNKNOWN.value) if (strength or "unknown") in _ORACLE_SCORES else OracleTier.UNKNOWN
    return {
        "tier": tier.value,
        "score": _ORACLE_SCORES[tier.value],
        "authoritative": tier is OracleTier.AUTHORITATIVE,
    }


def build_oracle_lattice(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize evidence strength without changing any verdict."""
    counts = {tier.value: 0 for tier in OracleTier}
    cases = []
    for row in rows:
        strength = str(row.get("oracle_strength", "unknown"))
        authoritative = bool(row.get("authoritative_observer", False))
        trust = oracle_trust(strength, authoritative=authoritative)
        counts[trust["tier"]] += 1
        cases.append({"case_id": row.get("case_id"), **trust})
    observed = [c["score"] for c in cases if c["score"] > 0]
    mean = sum(observed) / len(observed) if observed else 0.0
    return {
        "schema": "ersec-oracle-trust-lattice/1",
        "cases": len(cases),
        "counts": counts,
        "mean_trust_score": round(mean, 2),
        "case_trust": cases,
        "interpretation": "trust score describes evidence strength, not vulnerability severity or probability",
    }


def _case_rows(result: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    index: dict[str, Mapping[str, Any]] = {}
    for variant in result.get("variants", []) if isinstance(result.get("variants"), Sequence) else []:
        if not isinstance(variant, Mapping):
            continue
        for row in variant.get("cases", []) if isinstance(variant.get("cases"), Sequence) else []:
            if isinstance(row, Mapping) and row.get("case_id"):
                index[f"{variant.get('name')}:{row['case_id']}"] = row
    return index


def _lineage_for_case(variant: str, row: Mapping[str, Any], *, build: Mapping[str, Any], deployment: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    case_id = str(row.get("case_id", ""))
    evidence = row.get("evidence") if isinstance(row.get("evidence"), Mapping) else {
        "status": row.get("status"),
        "observed_fields": row.get("observed_fields", []),
        "verdict": row.get("verdict"),
    }
    evidence_digest = _digest(evidence)
    nodes = [
        asdict(LineageNode("policy", case_id, _digest({"case_id": case_id, "policy_truth": row.get("policy_truth")}))),
        asdict(LineageNode("scenario", f"{variant}:{case_id}", _digest({k: row.get(k) for k in ("identity", "url", "method")}))),
        asdict(LineageNode("evidence", f"{variant}:{case_id}:evidence", evidence_digest)),
    ]
    for kind, meta in (("source", source), ("build", build), ("deployment", deployment)):
        if meta:
            nodes.append(asdict(LineageNode(kind, str(meta.get("id") or kind), meta.get("digest"), meta)))
    return {
        "case_id": case_id,
        "variant": variant,
        "verdict": row.get("verdict", "missing"),
        "truth_class": row.get("truth_class"),
        "relationship": row.get("relationship"),
        "nodes": nodes,
        "lineage_digest": _digest(nodes),
    }


def build_lineage(result: Mapping[str, Any], *, source: Mapping[str, Any] | None = None, build: Mapping[str, Any] | None = None, deployment: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Create property-level provenance without ingesting secrets."""
    source = dict(source or {})
    build = dict(build or {})
    deployment = dict(deployment or {})
    records = []
    for variant in result.get("variants", []) if isinstance(result.get("variants"), Sequence) else []:
        if not isinstance(variant, Mapping):
            continue
        name = str(variant.get("name", "unknown"))
        for row in variant.get("cases", []) if isinstance(variant.get("cases"), Sequence) else []:
            if isinstance(row, Mapping):
                records.append(_lineage_for_case(name, row, source=source, build=build, deployment=deployment))
    root = {
        "schema": SCHEMA,
        "benchmark_id": result.get("benchmark_id"),
        "corpus_digest": ((result.get("methodology") or {}).get("corpus_manifest") or {}).get("corpus_digest") if isinstance(result.get("methodology"), Mapping) else None,
        "nodes": records,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "privacy": {"credential_values_included": False, "raw_bodies_included": False},
    }
    root["lineage_digest"] = _digest({k: v for k, v in root.items() if k != "lineage_digest"})
    return root


def compare_runs(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    """Produce a conservative property-level behavioral delta."""
    b = _case_rows(before)
    a = _case_rows(after)
    keys = sorted(set(b) | set(a))
    deltas: list[dict[str, Any]] = []
    for key in keys:
        case_id = key.split(":", 1)[1] if ":" in key else key
        bv = str(b.get(key, {}).get("verdict", "missing"))
        av = str(a.get(key, {}).get("verdict", "missing"))
        if bv == av:
            transition, effect, reason = "unchanged", "none", "same observed verdict"
        elif bv == "violation" and av == "pass":
            transition, effect, reason = "remediated_verified", "improved", "previous violation received an explicit PASS"
        elif bv == "violation" and av in {"missing", "not_tested", "observation_unavailable", "inconclusive"}:
            transition, effect, reason = "remediation_unverified", "unknown", "previous violation is no longer directly observed but no explicit PASS proves remediation"
        elif bv == "pass" and av == "violation":
            transition, effect, reason = "regression", "degraded", "previously passing property now contradicts its reviewed behavior"
        else:
            transition, effect, reason = "changed", "needs_review", "verdict changed without a high-confidence remediation transition"
        deltas.append(asdict(AssuranceDelta(case_id, bv, av, transition, effect, reason)))
    summary = {k: sum(1 for d in deltas if d["transition"] == k) for k in {d["transition"] for d in deltas}}
    return {
        "schema": "ersec-assurance-delta/1",
        "status": "fail" if any(d["transition"] == "regression" for d in deltas) else "pass",
        "deltas": deltas,
        "summary": summary,
        "comparison_digest": _digest(deltas),
    }



def to_otel_events(delta: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Convert an assurance delta into privacy-minimized OpenTelemetry-style events.

    Dynamic IDs live in attributes; event names remain stable. The output is a
    transport-neutral representation and does not require the OpenTelemetry SDK.
    """
    if not isinstance(delta, Mapping):
        return []
    events = []
    for item in delta.get("deltas", []) if isinstance(delta.get("deltas"), Sequence) else []:
        if not isinstance(item, Mapping):
            continue
        events.append({
            "name": "ersec.security.assurance.delta",
            "time_unix_nano": int(datetime.now(timezone.utc).timestamp() * 1_000_000_000),
            "severity_number": 9 if item.get("transition") == "regression" else 5,
            "attributes": {
                "ersec.case_id": str(item.get("case_id", "")),
                "ersec.transition": str(item.get("transition", "")),
                "ersec.assurance_effect": str(item.get("assurance_effect", "")),
            },
            "body": "Security assurance property transition",
        })
    return events

def build_assurance_frontier(*, coverage: Mapping[str, Any] | None = None, mutation: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Rank the next best assurance obligations from explicit gaps only."""
    frontier: list[dict[str, Any]] = []
    coverage = coverage or {}
    mutation = mutation or {}
    for survivor in mutation.get("survivors", []) if isinstance(mutation.get("survivors"), Sequence) else []:
        if isinstance(survivor, Mapping):
            frontier.append({
                "source": "semantic_mutation_survivor",
                "id": survivor.get("mutant_id"),
                "dimension": survivor.get("targeted_dimension"),
                "priority": survivor.get("priority", 1),
                "reason": survivor.get("description") or "unresolved semantic mutant",
                "required_oracle": "reviewed semantic oracle",
            })
    for dim in coverage.get("uncovered_dimensions", []) if isinstance(coverage.get("uncovered_dimensions"), Sequence) else []:
        frontier.append({
            "source": "coverage_gap",
            "id": f"coverage:{dim}",
            "dimension": dim,
            "priority": 3,
            "reason": "applicable policy dimension has not been exercised",
            "required_oracle": "appropriate authoritative or strong semantic observer",
        })
    frontier.sort(key=lambda x: (-int(x.get("priority", 0)), str(x.get("dimension", "")), str(x.get("id", ""))))
    return {
        "schema": "ersec-assurance-frontier/1",
        "count": len(frontier),
        "items": frontier[:50],
        "interpretation": "frontier items are recommended next assurance obligations, not vulnerability claims",
    }


def build_research_artifact(result: Mapping[str, Any], *, source: Mapping[str, Any] | None = None, build: Mapping[str, Any] | None = None, deployment: Mapping[str, Any] | None = None, mutation: Mapping[str, Any] | None = None, coverage: Mapping[str, Any] | None = None) -> dict[str, Any]:
    rows = []
    for variant in result.get("variants", []) if isinstance(result.get("variants"), Sequence) else []:
        if isinstance(variant, Mapping):
            rows.extend([r for r in variant.get("cases", []) if isinstance(r, Mapping)])
    artifact = {
        "schema": SCHEMA,
        "assurance_lineage": build_lineage(result, source=source, build=build, deployment=deployment),
        "oracle_trust_lattice": build_oracle_lattice(rows),
        "assurance_delta": None,
        "assurance_frontier": build_assurance_frontier(coverage=coverage, mutation=mutation),
        "principles": {
            "ai_not_source_of_truth": True,
            "untested_not_secure": True,
            "credential_values_excluded": True,
            "target_contacted": False,
        },
    }
    artifact["artifact_digest"] = _digest({k: v for k, v in artifact.items() if k != "artifact_digest"})
    return artifact

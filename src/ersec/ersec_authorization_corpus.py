"""Canonical authorization corpus and relationship-graph utilities for ERSEC."""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from typing import Any, Mapping, Sequence

SCHEMA = "ersec-authorization-corpus/1"


def _case_dict(case: Any) -> dict[str, Any]:
    return {
        "id": case.case_id,
        "family": case.family,
        "identity": case.identity,
        "path": case.path,
        "truth_class": case.truth_class,
        "relationship": case.relationship,
        "expected_owner_tenant": case.expected_owner_tenant,
        "state_context": case.state_context,
        "oracle_strength": case.oracle_strength,
        "expected_status": list(case.expected_status),
        "forbidden_fields": list(case.forbidden_fields),
        "required_fields": list(case.required_fields),
        "vulnerable_should_violate": bool(case.vulnerable_should_violate),
    }


def canonical_corpus(cases: Sequence[Any]) -> dict[str, Any]:
    rows = [_case_dict(case) for case in cases]
    rows.sort(key=lambda x: x["id"])
    digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "schema": SCHEMA,
        "version": 2,
        "case_count": len(rows),
        "cases": rows,
        "digest": digest,
        "denominator": "one explicit case is one applicable assurance obligation; ambiguous cases remain visible and are excluded from precision/recall.",
    }


def relationship_graph(cases: Sequence[Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    for case in cases:
        actor = f"identity:{case.identity}"
        tenant = case.expected_owner_tenant or ("tenant:unknown" if case.relationship == "unknown" else None)
        resource = f"resource:{case.path}"
        nodes.setdefault(actor, {"id": actor, "kind": "identity", "name": case.identity})
        nodes.setdefault(resource, {"id": resource, "kind": "resource", "path": case.path})
        edges.append({"from": actor, "to": resource, "kind": case.relationship})
        if tenant:
            tenant_id = f"tenant:{tenant}"
            nodes.setdefault(tenant_id, {"id": tenant_id, "kind": "tenant", "name": tenant})
            edges.append({"from": actor, "to": tenant_id, "kind": "actor_tenant"})
            edges.append({"from": resource, "to": tenant_id, "kind": "resource_owner_tenant"})
    unique_edges = sorted({(e["from"], e["to"], e["kind"]) for e in edges})
    return {
        "schema": "ersec-authorization-relationship-graph/1",
        "node_count": len(nodes),
        "edge_count": len(unique_edges),
        "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
        "edges": [{"from": a, "to": b, "kind": c} for a, b, c in unique_edges],
        "statement": "Relationships are benchmark metadata and do not by themselves prove application authorization behavior.",
    }


def family_scorecards(cases: Sequence[Any], score: Mapping[str, Any]) -> dict[str, Any]:
    observed = score.get("cases", []) if isinstance(score.get("cases"), list) else []
    by_case = {str(item.get("case_id")): item for item in observed if isinstance(item, Mapping)}
    output: dict[str, Any] = {}
    for case in cases:
        row = output.setdefault(case.family, {
            "applicable": 0,
            "scorable": 0,
            "ambiguous": 0,
            "observed": 0,
            "violations": 0,
            "passes": 0,
            "inconclusive": 0,
            "observation_unavailable": 0,
            "relationships": set(),
        })
        row["applicable"] += 1
        row["scorable"] += int(case.scorable)
        row["ambiguous"] += int(not case.scorable)
        row["relationships"].add(case.relationship)
        verdict = str(by_case.get(case.case_id, {}).get("verdict", ""))
        if verdict:
            row["observed"] += 1
            if verdict == "violation": row["violations"] += 1
            elif verdict == "pass": row["passes"] += 1
            elif verdict == "inconclusive": row["inconclusive"] += 1
            elif verdict == "observation_unavailable": row["observation_unavailable"] += 1
    for row in output.values():
        row["relationships"] = sorted(row["relationships"])
        row["coverage_ratio"] = round(row["observed"] / row["applicable"], 4) if row["applicable"] else 1.0
    return output


def build_corpus_manifest(cases: Sequence[Any], *, benchmark_id: str) -> dict[str, Any]:
    corpus = canonical_corpus(cases)
    families: dict[str, int] = {}
    truths: dict[str, int] = {}
    relationships: dict[str, int] = {}
    for case in cases:
        families[case.family] = families.get(case.family, 0) + 1
        truths[case.truth_class] = truths.get(case.truth_class, 0) + 1
        relationships[case.relationship] = relationships.get(case.relationship, 0) + 1
    return {
        "schema": "ersec-authorization-benchmark-manifest/2",
        "benchmark_id": benchmark_id,
        "corpus_schema": corpus["schema"],
        "corpus_version": corpus["version"],
        "corpus_digest": corpus["digest"],
        "case_count": corpus["case_count"],
        "truth_classes": dict(sorted(truths.items())),
        "families": dict(sorted(families.items())),
        "relationships": dict(sorted(relationships.items())),
        "safety": {"loopback_only": True, "methods": ["GET"], "state_changes": False, "external_targets": False},
        "methodology": "Canonical corpus metadata is derived directly from benchmark case declarations; the manifest is not a substitute for independent truth review.",
    }


def validate_manifest(manifest: Mapping[str, Any], cases: Sequence[Any]) -> list[str]:
    errors: list[str] = []
    expected = build_corpus_manifest(cases, benchmark_id=str(manifest.get("benchmark_id", "")))
    for key in ("schema", "case_count", "corpus_digest"):
        if manifest.get(key) != expected.get(key):
            errors.append(f"manifest {key} does not match canonical corpus")
    if manifest.get("case_count") != len(cases):
        errors.append("manifest case_count differs from CASES")
    return errors

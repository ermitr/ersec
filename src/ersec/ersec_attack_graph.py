"""ERSEC 29.1.1 Security Behavior Attack Graph.

Builds a provenance-aware graph from local workspace/assurance artifacts. It
never asserts compromise: every edge has evidence and confidence metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

VERSION = "29.1.1"
SCHEMA = "ersec-security-behavior-attack-graph/1"
MAX_PATH_EDGES = 6


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _host(value: Any) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _id(kind: str, value: Any) -> str:
    return f"{kind}-{hashlib.sha256(_canon(value).encode('utf-8')).hexdigest()[:24]}"


def build(workspace: Mapping[str, Any]) -> dict[str, Any]:
    nodes_by_id: dict[str, dict[str, Any]] = {}
    edges_by_id: dict[str, dict[str, Any]] = {}

    def node(kind: str, key: Any, label: str, attrs: Mapping[str, Any] | None = None) -> str:
        nid = _id(kind, key)
        nodes_by_id.setdefault(nid, {"id": nid, "kind": kind, "label": label, "attributes": dict(attrs or {})})
        return nid

    def edge(src: str, dst: str, relation: str, evidence: Any, confidence: str = "medium") -> None:
        refs = sorted({str(x) for x in (evidence or []) if str(x)})
        confidence = confidence if confidence in {"low", "medium", "high"} else "low"
        eid = _id("edge", {"src": src, "dst": dst, "relation": relation, "evidence": refs})
        existing = edges_by_id.get(eid)
        if existing is None:
            edges_by_id[eid] = {"id": eid, "source": src, "target": dst, "relation": relation,
                                 "confidence": confidence, "evidence_refs": refs}
        else:
            # Merge repeated provenance without ever silently increasing confidence.
            existing["evidence_refs"] = sorted(set(existing["evidence_refs"]) | set(refs))
            if {"low": 0, "medium": 1, "high": 2}[confidence] < {"low": 0, "medium": 1, "high": 2}[existing["confidence"]]:
                existing["confidence"] = confidence

    assets = workspace.get("assets", []) if isinstance(workspace.get("assets", []), list) else []
    services = workspace.get("services", []) if isinstance(workspace.get("services", []), list) else []
    operations = workspace.get("operations", []) if isinstance(workspace.get("operations", []), list) else []
    identities = workspace.get("identities", []) if isinstance(workspace.get("identities", []), list) else []
    findings = workspace.get("findings", []) if isinstance(workspace.get("findings", []), list) else []
    evidence_rows = workspace.get("evidence", []) if isinstance(workspace.get("evidence", []), list) else []

    for asset in assets:
        if not isinstance(asset, Mapping) or not _host(asset.get("host")):
            continue
        host = _host(asset["host"])
        node("asset", host, host, asset)

    for service in services:
        if not isinstance(service, Mapping) or not _host(service.get("host")):
            continue
        host = _host(service["host"])
        sid = node("service", {"host": host, "port": service.get("port"), "scheme": service.get("scheme")},
                   f"{host}:{service.get('port')}", service)
        aid = node("asset", host, host)
        edge(aid, sid, "exposes", service.get("evidence_refs", []), service.get("confidence", "medium"))

    for operation in operations:
        if not isinstance(operation, Mapping) or not _host(operation.get("host")):
            continue
        host = _host(operation["host"])
        method = str(operation.get("method") or "GET").upper()
        path = str(operation.get("path") or "/")
        query_names = sorted(str(x) for x in (operation.get("query_parameter_names") or []))
        key = {"method": method, "host": host, "path": path, "query_parameter_names": query_names}
        oid = node("operation", key, f"{method} {path}", operation)
        edge(node("asset", host, host), oid, "serves", operation.get("evidence_refs", []), "medium")

    for identity in identities:
        if not isinstance(identity, Mapping):
            continue
        label = identity.get("name") or identity.get("id")
        if label:
            node("identity", str(label), str(label), identity)

    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        finding_key = finding.get("id") or {"rule": finding.get("rule_id"), "host": _host(finding.get("host"))}
        fid = node("finding", finding_key, str(finding.get("rule_id") or "finding"), finding)
        host = _host(finding.get("host"))
        if host:
            severity = str(finding.get("severity") or "").lower()
            edge(node("asset", host, host), fid, "affected_by",
                 [finding.get("source_evidence")] if finding.get("source_evidence") else [],
                 "high" if severity in {"high", "critical"} else "medium")

    for evidence in evidence_rows:
        if not isinstance(evidence, Mapping) or not evidence.get("id"):
            continue
        node("evidence", str(evidence["id"]), str(evidence.get("kind") or "evidence"), evidence)

    # Bind findings to operations by exact normalized host and path containment.
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        host = _host(finding.get("host"))
        matched = str(finding.get("matched_at") or "")
        if not host:
            continue
        finding_key = finding.get("id") or {"rule": finding.get("rule_id"), "host": host}
        fid = _id("finding", finding_key)
        for operation in operations:
            if not isinstance(operation, Mapping) or _host(operation.get("host")) != host:
                continue
            path = str(operation.get("path") or "/")
            if matched and path not in matched:
                continue
            method = str(operation.get("method") or "GET").upper()
            key = {"method": method, "host": host, "path": path,
                   "query_parameter_names": sorted(str(x) for x in (operation.get("query_parameter_names") or []))}
            oid = _id("operation", key)
            refs = [finding.get("source_evidence")] if finding.get("source_evidence") else []
            edge(oid, fid, "may_indicate", refs, "medium")

    graph = {
        "schema": SCHEMA,
        "version": VERSION,
        "nodes": sorted(nodes_by_id.values(), key=lambda x: x["id"]),
        "edges": sorted(edges_by_id.values(), key=lambda x: x["id"]),
        "governance": {"offline": True, "network_contact": False, "compromise_claim": False, "edge_provenance_required": True},
    }
    graph["digest"] = hashlib.sha256(_canon(graph).encode("utf-8")).hexdigest()
    return graph


def paths(graph: Mapping[str, Any], minimum_confidence: str = "medium") -> list[dict[str, Any]]:
    rank = {"low": 0, "medium": 1, "high": 2}
    threshold = rank.get(minimum_confidence, 1)
    adjacency: dict[str, list[Mapping[str, Any]]] = {}
    for edge_row in graph.get("edges", []):
        if rank.get(str(edge_row.get("confidence", "low")), 0) >= threshold:
            adjacency.setdefault(str(edge_row["source"]), []).append(edge_row)
    starts = {str(n["id"]) for n in graph.get("nodes", []) if n.get("kind") in {"asset", "service"}}
    goals = {str(n["id"]) for n in graph.get("nodes", []) if n.get("kind") == "finding"}
    found: list[list[Mapping[str, Any]]] = []

    def dfs(current: str, trail: list[Mapping[str, Any]], seen: set[str]) -> None:
        if current in goals and trail:
            found.append(trail)
            return
        if len(trail) >= MAX_PATH_EDGES:
            return
        for edge_row in adjacency.get(current, []):
            target = str(edge_row["target"])
            if target in seen:
                continue
            dfs(target, trail + [edge_row], seen | {target})

    for start in sorted(starts):
        dfs(start, [], {start})

    result = []
    for edge_rows in found:
        score = sum({"low": 1, "medium": 2, "high": 3}.get(str(e.get("confidence")), 1) for e in edge_rows) / len(edge_rows)
        ids = [str(e["id"]) for e in edge_rows]
        result.append({"path_id": _id("path", ids), "edges": ids, "confidence_score": round(score, 4),
                       "interpretation": "evidence-linked assessment path, not proof of compromise"})
    return sorted(result, key=lambda x: (-x["confidence_score"], x["path_id"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ersec-attack-graph")
    parser.add_argument("workspace")
    parser.add_argument("--output")
    parser.add_argument("--paths", action="store_true")
    parser.add_argument("--min-confidence", choices=["low", "medium", "high"], default="medium")
    args = parser.parse_args(argv)
    workspace = json.loads(Path(args.workspace).read_text(encoding="utf-8"))
    graph = build(workspace)
    result = {"graph": graph, "paths": paths(graph, args.min_confidence)} if args.paths else graph
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

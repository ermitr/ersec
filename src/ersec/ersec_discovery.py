"""ERSEC 29.1.1 Discovery Fabric.

Deterministic, evidence-linked normalization of workspace observations into a
small security-behavior graph. This module is intentionally passive: it does
not contact targets or perform active exploitation.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping
from urllib.parse import urlsplit

VERSION = "29.1.1"
SCHEMA = "ersec-discovery-fabric/1"


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def node_id(kind: str, identity: Any) -> str:
    return f"{kind}-{hashlib.sha256(_canon(identity).encode()).hexdigest()[:24]}"


def _refs(row: Mapping[str, Any]) -> list[str]:
    values = row.get("evidence_refs") or row.get("source_evidence") or []
    if isinstance(values, str):
        values = [values]
    return sorted({str(x) for x in values if x})


def _add(nodes: dict[str, dict[str, Any]], kind: str, identity: Any, attrs: Mapping[str, Any], evidence: list[str]) -> str:
    nid = node_id(kind, identity)
    current = nodes.setdefault(nid, {"id": nid, "kind": kind, "evidence_refs": []})
    current.update({k: v for k, v in attrs.items() if v is not None})
    current["evidence_refs"] = sorted(set(current.get("evidence_refs", [])) | set(evidence))
    return nid


def build(workspace: Mapping[str, Any]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    def edge(kind: str, source: str, target: str, evidence: list[str]) -> None:
        eid = node_id("edge", {"kind": kind, "source": source, "target": target})
        row = edges.setdefault(eid, {"id": eid, "kind": kind, "source": source, "target": target, "evidence_refs": []})
        row["evidence_refs"] = sorted(set(row["evidence_refs"]) | set(evidence))

    for asset in workspace.get("assets", []):
        host = str(asset.get("host", "")).lower().rstrip(".")
        if not host:
            continue
        _add(nodes, "asset", {"host": host}, {"host": host, "confidence": asset.get("confidence")}, _refs(asset))

    service_nodes: dict[tuple[str, Any, Any], str] = {}
    for service in workspace.get("services", []):
        host = str(service.get("host", "")).lower().rstrip(".")
        key = (host, service.get("port"), service.get("scheme"))
        sid = _add(nodes, "service", {"host": host, "port": service.get("port"), "scheme": service.get("scheme")},
                   {"host": host, "port": service.get("port"), "scheme": service.get("scheme"), "technology": service.get("technology")}, _refs(service))
        service_nodes[key] = sid
        aid = node_id("asset", {"host": host})
        if aid in nodes:
            edge("hosts_service", aid, sid, _refs(service))

    for op in workspace.get("operations", []):
        method = str(op.get("method", "GET")).upper()
        url = str(op.get("url", ""))
        parsed = urlsplit(url)
        host = (parsed.hostname or op.get("host") or "").lower().rstrip(".")
        path = str(op.get("path") or parsed.path or "/")
        qnames = sorted(op.get("query_parameter_names") or [])
        oid = _add(nodes, "operation",
                   {"method": method, "host": host, "path": path, "query_names": qnames},
                   {"method": method, "host": host, "path": path, "query_parameter_names": qnames,
                    "operation_name": op.get("operation_name"), "auth": op.get("auth"),
                    "url_variants": sorted(op.get("url_variants") or ([url] if url else []))}, _refs(op))
        # Connect to the best-known service without inventing a port. Scheme is
        # enough to select a canonical service when the imported data contains it.
        scheme = parsed.scheme.lower() or None
        candidates = [sid for (h, _port, s), sid in service_nodes.items() if h == host and (s == scheme or scheme is None)]
        for sid in sorted(candidates)[:1]:
            edge("serves_operation", sid, oid, _refs(op))
        aid = node_id("asset", {"host": host})
        if host and aid in nodes:
            edge("exposes_operation", aid, oid, _refs(op))

    for finding in workspace.get("findings", []):
        fid = str(finding.get("id") or node_id("finding", finding))
        _add(nodes, "finding", {"id": fid}, {"finding_id": fid, "rule_id": finding.get("rule_id"),
             "severity": finding.get("severity") or finding.get("level"), "host": finding.get("host"),
             "matched_at": finding.get("matched_at"), "message": finding.get("message")}, _refs(finding))
        host = str(finding.get("host") or "").lower().rstrip(".")
        aid = node_id("asset", {"host": host})
        if host and aid in nodes:
            edge("affects_asset", fid, aid, _refs(finding))

    # Preserve explicit identity records if/when richer identity ingestion is added.
    for identity in workspace.get("identities", []):
        label = identity.get("id") or identity.get("name") or identity.get("subject")
        if label is None:
            continue
        iid = _add(nodes, "identity", {"label": str(label)}, {"name": identity.get("name"), "subject": identity.get("subject"),
             "role": identity.get("role"), "tenant": identity.get("tenant")}, _refs(identity))
        for target in identity.get("operation_ids", []) or []:
            if str(target) in nodes:
                edge("identity_can_reach", iid, str(target), _refs(identity))

    node_list = sorted(nodes.values(), key=lambda x: (x["kind"], x["id"]))
    edge_list = sorted(edges.values(), key=lambda x: (x["kind"], x["source"], x["target"]))
    counts: dict[str, int] = {}
    for n in node_list:
        counts[n["kind"]] = counts.get(n["kind"], 0) + 1
    return {"schema": SCHEMA, "version": VERSION, "nodes": node_list, "edges": edge_list,
            "statistics": {"nodes": len(node_list), "edges": len(edge_list), "by_kind": counts}}

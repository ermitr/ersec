"""ERSEC 29.1.1 Identity/Application Understanding Fabric.

Passive normalization only: turns observed identity metadata and API contract
security/resource information into deterministic, evidence-linked records.
Credentials/tokens are never stored in this layer.
"""
from __future__ import annotations
import hashlib, json
from typing import Any, Mapping
from urllib.parse import urlsplit

VERSION = "29.1.1"
SCHEMA = "ersec-identity-fabric/1"


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def identity_id(identity: Mapping[str, Any]) -> str:
    key = {
        "name": str(identity.get("name") or identity.get("subject") or identity.get("id") or "").strip().lower(),
        "role": str(identity.get("role") or "").strip().lower(),
        "tenant": str(identity.get("tenant") or "").strip().lower(),
    }
    return "identity-" + hashlib.sha256(_canon(key).encode()).hexdigest()[:24]


def application_id(host: str, base_path: str = "") -> str:
    key = {"host": host.lower().rstrip("."), "base_path": base_path or "/"}
    return "application-" + hashlib.sha256(_canon(key).encode()).hexdigest()[:24]


def resource_id(host: str, path: str) -> str:
    return "resource-" + hashlib.sha256(_canon({"host": host.lower().rstrip("."), "path": path or "/"}).encode()).hexdigest()[:24]


def build(workspace: Mapping[str, Any]) -> dict[str, Any]:
    identities = {}
    applications = {}
    resources = {}
    edges = {}

    def add_edge(kind, source, target, refs):
        key = (kind, source, target)
        eid = "edge-" + hashlib.sha256(_canon(key).encode()).hexdigest()[:24]
        row = edges.setdefault(eid, {"id": eid, "kind": kind, "source": source, "target": target, "evidence_refs": []})
        row["evidence_refs"] = sorted(set(row["evidence_refs"]) | set(refs or []))

    for raw in workspace.get("identities", []) or []:
        if not isinstance(raw, Mapping):
            continue
        iid = identity_id(raw)
        row = identities.setdefault(iid, {"id": iid, "kind": "identity", "evidence_refs": []})
        for k in ("name", "subject", "role", "tenant", "type", "source"):
            if raw.get(k) is not None:
                row[k] = raw[k]
        refs = raw.get("evidence_refs") or raw.get("source_evidence") or []
        row["evidence_refs"] = sorted(set(row["evidence_refs"]) | ({refs} if isinstance(refs, str) else set(refs)))
        for oid in raw.get("operation_ids", []) or []:
            if str(oid) in {str(x.get("id")) for x in workspace.get("operations", [])}:
                add_edge("identity_observed_on", iid, str(oid), row["evidence_refs"])

    for app in workspace.get("applications", []) or []:
        if not isinstance(app, Mapping):
            continue
        host = str(app.get("host") or "").lower().rstrip(".")
        if not host:
            continue
        aid = str(app.get("id") or application_id(host, str(app.get("base_path") or "/")))
        row = applications.setdefault(aid, {"id": aid, "kind": "application", "host": host, "base_path": app.get("base_path") or "/", "evidence_refs": []})
        row.update({k: app[k] for k in ("name", "framework", "environment") if app.get(k) is not None})
        refs = app.get("evidence_refs") or []
        row["evidence_refs"] = sorted(set(row["evidence_refs"]) | ({refs} if isinstance(refs, str) else set(refs)))

    for op in workspace.get("operations", []) or []:
        if not isinstance(op, Mapping):
            continue
        u = str(op.get("url") or "")
        p = urlsplit(u)
        host = str(op.get("host") or p.hostname or "").lower().rstrip(".")
        path = str(op.get("path") or p.path or "/")
        if not host:
            continue
        aid = application_id(host, "/")
        applications.setdefault(aid, {"id": aid, "kind": "application", "host": host, "base_path": "/", "evidence_refs": []})
        rid = resource_id(host, path)
        rr = resources.setdefault(rid, {"id": rid, "kind": "resource", "host": host, "path": path, "methods": [], "evidence_refs": []})
        method = str(op.get("method") or "GET").upper()
        if method not in rr["methods"]: rr["methods"].append(method)
        refs = op.get("evidence_refs") or []
        rr["evidence_refs"] = sorted(set(rr["evidence_refs"]) | ({refs} if isinstance(refs, str) else set(refs)))
        add_edge("application_contains_resource", aid, rid, rr["evidence_refs"])
        if op.get("auth"):
            rr["auth_observed"] = True

    return {"schema": SCHEMA, "version": VERSION,
            "identities": sorted(identities.values(), key=lambda x: x["id"]),
            "applications": sorted(applications.values(), key=lambda x: x["id"]),
            "resources": sorted(resources.values(), key=lambda x: x["id"]),
            "edges": sorted(edges.values(), key=lambda x: (x["kind"], x["source"], x["target"]))}

"""ERSEC 29.1.1 disposable multi-principal assurance fixtures.

Deterministic, offline fixture planning for security-behavior policies. It creates
synthetic identities/resources and expected authorization truth without storing
credentials or contacting a target. The artifact is designed to be consumed by
an authorized test harness that owns the actual lifecycle.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Dict, List, Mapping

VERSION = "29.1.1"
SCHEMA = "ersec-disposable-assurance-fixture/1"


def _canon(x: Any) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(x: Any) -> str:
    return hashlib.sha256(_canon(x).encode("utf-8")).hexdigest()


def load(path: str) -> Dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("fixture specification must be a JSON object")
    return value


def save(path: str, value: Mapping[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_fixture(spec: Mapping[str, Any]) -> Dict[str, Any]:
    """Compile a safe fixture manifest and deterministic oracle truth.

    Spec shape:
      identities: [{id, tenant, role}]
      resources: [{id, owner, tenant, type}]
      operations: [{id, action, resource, allow: [identity ids]}]

    No secret/token values are accepted or emitted.
    """
    identities = spec.get("identities", [])
    resources = spec.get("resources", [])
    operations = spec.get("operations", [])
    if not isinstance(identities, list) or not isinstance(resources, list) or not isinstance(operations, list):
        raise ValueError("identities, resources and operations must be lists")

    ids: Dict[str, Dict[str, Any]] = {}
    for item in identities:
        if not isinstance(item, Mapping):
            raise ValueError("identity entries must be objects")
        iid = str(item.get("id", "")).strip()
        if not iid or iid in ids:
            raise ValueError("identity ids must be non-empty and unique")
        if any(k in item for k in ("token", "bearer_token", "password", "secret", "credential")):
            raise ValueError("fixture specs must not contain credential material")
        ids[iid] = {"id": iid, "tenant": str(item.get("tenant", "")), "role": str(item.get("role", ""))}

    rs: Dict[str, Dict[str, Any]] = {}
    for item in resources:
        if not isinstance(item, Mapping):
            raise ValueError("resource entries must be objects")
        rid = str(item.get("id", "")).strip()
        if not rid or rid in rs:
            raise ValueError("resource ids must be non-empty and unique")
        owner = str(item.get("owner", ""))
        if owner and owner not in ids:
            raise ValueError(f"resource {rid} references unknown owner {owner}")
        tenant = str(item.get("tenant", ids.get(owner, {}).get("tenant", "")))
        rs[rid] = {"id": rid, "owner": owner, "tenant": tenant, "type": str(item.get("type", "resource"))}

    rows: List[Dict[str, Any]] = []
    for op in operations:
        if not isinstance(op, Mapping):
            raise ValueError("operation entries must be objects")
        oid = str(op.get("id", "")).strip()
        resource = str(op.get("resource", "")).strip()
        if not oid or resource not in rs:
            raise ValueError(f"operation {oid or '<missing>'} references an unknown resource")
        allowed = op.get("allow", [])
        if not isinstance(allowed, list) or any(str(x) not in ids for x in allowed):
            raise ValueError(f"operation {oid} has invalid allow identities")
        allowed_set = {str(x) for x in allowed}
        for iid, identity in sorted(ids.items()):
            expected = iid in allowed_set
            rows.append({
                "operation_id": oid,
                "action": str(op.get("action", "read")),
                "resource_id": resource,
                "identity_id": iid,
                "expected": "allow" if expected else "deny",
                "reason": "declared_allowlist" if expected else "not_in_declared_allowlist",
                "tenant": identity["tenant"],
                "role": identity["role"],
            })

    base = {
        "schema": SCHEMA,
        "version": VERSION,
        "safety": {
            "network_access": False,
            "destructive_actions": False,
            "credential_material": False,
            "requires_authorized_harness": True,
        },
        "identities": [ids[k] for k in sorted(ids)],
        "resources": [rs[k] for k in sorted(rs)],
        "oracle_truth": rows,
        "lifecycle": ["provision", "execute", "observe", "cleanup"],
        "cleanup_contract": "Every provisioned fixture must be disposable and cleanup must be reported explicitly; cleanup absence is not PASS.",
    }
    base["fixture_digest"] = _digest(base)
    return base


def compile_file(path: str, output: str) -> Dict[str, Any]:
    result = build_fixture(load(path))
    save(output, result)
    return result

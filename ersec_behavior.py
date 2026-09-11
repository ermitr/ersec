from __future__ import annotations

import hashlib
import json
import re
import urllib.parse


def _response_field_paths(text: str, max_fields: int = 200) -> List[str]:
    try:
        obj = json.loads(text)
    except Exception:
        return []
    out: List[str] = []
    def walk(value: Any, prefix: str = "", depth: int = 0) -> None:
        if depth > 5 or len(out) >= max_fields:
            return
        if isinstance(value, dict):
            for k, v in value.items():
                path = f"{prefix}.{k}" if prefix else str(k)
                out.append(path)
                walk(v, path, depth + 1)
                if len(out) >= max_fields:
                    return
        elif isinstance(value, list):
            for v in value[:10]:
                walk(v, prefix + "[]" if prefix else "[]", depth + 1)
                if len(out) >= max_fields:
                    return
    walk(obj)
    return sorted(set(out))[:max_fields]
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

SCHEMA = "ersec-security-behavior-model/1"
GRAPH_SCHEMA = "ersec-security-behavior-graph/2"
VERIFICATION_SCHEMA = "ersec-security-behavior-verification/1"
STATE_SCHEMA = "ersec-security-behavior-state/1"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _norm_url(value: str) -> str:
    """Canonicalize a behavior-model URL without discarding security-relevant identity.

    Preserve explicit non-default ports, query strings, IPv6 brackets, and path percent-encoding;
    always discard fragments because they are client-only and never sent in HTTP requests.
    """
    raw = str(value).strip()
    p = urllib.parse.urlsplit(raw)
    scheme = (p.scheme or "").lower()
    host = (p.hostname or "").lower()
    try:
        port = p.port
    except ValueError as exc:
        raise ValueError(f"invalid URL port: {raw!r}") from exc
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urllib.parse.urlunsplit((scheme, netloc, p.path or "/", p.query, ""))


def _slug(value: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return s or "item"


def _fingerprint(value: Any, length: int = 16) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:length]


@dataclass(frozen=True)
class ModelIdentity:
    name: str
    role: str = "user"
    tenant: str = ""
    privilege_rank: int = 1


@dataclass(frozen=True)
class ModelResource:
    resource_id: str
    url: str
    owner: str = ""
    tenant: str = ""
    classification: str = "normal"
    methods: Tuple[str, ...] = ("GET",)
    expected: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelInvariant:
    invariant_id: str
    type: str
    statement: str
    subject: str = ""
    resource: str = ""
    expected: Dict[str, Any] = field(default_factory=dict)
    severity: str = "HIGH"


@dataclass(frozen=True)
class ModelTransition:
    transition_id: str
    source: str
    destination: str
    method: str = "GET"
    path: str = ""
    allowed_roles: Tuple[str, ...] = ()


class SecurityBehaviorModel:
    """Strict declarative model for authorized application-security verification.

    It intentionally contains no credential material. Tokens stay in ERSEC's runtime
    configuration and are referenced by identity name only.
    """

    def __init__(self, data: Dict[str, Any]):
        if not isinstance(data, dict):
            raise ValueError("security model must be a JSON object")
        schema = str(data.get("schema", SCHEMA))
        if schema != SCHEMA:
            raise ValueError(f"unsupported security model schema: {schema!r}")
        self.schema = schema
        self.version = int(data.get("version", 1))
        self.name = str(data.get("name", "ERSEC Security Model"))
        self.identities = self._identities(data.get("identities", []))
        self.resources = self._resources(data.get("resources", []))
        self.invariants = self._invariants(data.get("invariants", []))
        self.transitions = self._transitions(data.get("workflows", data.get("transitions", [])))
        self._validate_references()

    @staticmethod
    def _identities(raw: Any) -> List[ModelIdentity]:
        if not isinstance(raw, list):
            raise ValueError("identities must be a list")
        out: List[ModelIdentity] = []
        seen = set()
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("each identity must be an object")
            name = str(item.get("name", "")).strip()
            if not name:
                raise ValueError("identity.name is required")
            key = name.lower()
            if key in seen:
                raise ValueError(f"duplicate identity: {name}")
            seen.add(key)
            rank = int(item.get("privilege_rank", 1))
            if rank < 0:
                raise ValueError(f"identity {name}: privilege_rank must be >= 0")
            out.append(ModelIdentity(name, str(item.get("role", "user")), str(item.get("tenant", "")), rank))
        return out

    @staticmethod
    def _resources(raw: Any) -> List[ModelResource]:
        if not isinstance(raw, list):
            raise ValueError("resources must be a list")
        out: List[ModelResource] = []
        seen = set()
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("each resource must be an object")
            rid = str(item.get("id", item.get("resource_id", ""))).strip()
            url = str(item.get("url", "")).strip()
            if not rid or not url:
                raise ValueError("resource.id and resource.url are required")
            if rid in seen:
                raise ValueError(f"duplicate resource id: {rid}")
            seen.add(rid)
            methods = tuple(sorted({str(x).upper() for x in item.get("methods", ["GET"])}))
            if not methods or not set(methods).issubset(SAFE_METHODS):
                raise ValueError(f"resource {rid}: only GET/HEAD/OPTIONS are allowed by the safe model verifier")
            expected = item.get("expected", {})
            if expected is None:
                expected = {}
            if not isinstance(expected, dict):
                raise ValueError(f"resource {rid}: expected must be an object")
            out.append(ModelResource(rid, url, str(item.get("owner", "")), str(item.get("tenant", "")),
                                     str(item.get("classification", "normal")), methods, expected))
        return out

    @staticmethod
    def _invariants(raw: Any) -> List[ModelInvariant]:
        if not isinstance(raw, list):
            raise ValueError("invariants must be a list")
        out: List[ModelInvariant] = []
        seen = set()
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("each invariant must be an object")
            statement = str(item.get("statement", "")).strip()
            iid = str(item.get("id", item.get("invariant_id", ""))).strip() or "SBG-" + _fingerprint(statement)
            if not statement:
                raise ValueError("invariant.statement is required")
            if iid in seen:
                raise ValueError(f"duplicate invariant id: {iid}")
            seen.add(iid)
            expected = item.get("expected", {}) or {}
            if not isinstance(expected, dict):
                raise ValueError(f"invariant {iid}: expected must be an object")
            out.append(ModelInvariant(iid, str(item.get("type", "authorization")), statement,
                                      str(item.get("subject", "")), str(item.get("resource", "")),
                                      expected, str(item.get("severity", "HIGH")).upper()))
        return out

    @staticmethod
    def _transitions(raw: Any) -> List[ModelTransition]:
        if not isinstance(raw, list):
            raise ValueError("workflows/transitions must be a list")
        out: List[ModelTransition] = []
        seen = set()
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("each workflow transition must be an object")
            tid = str(item.get("id", item.get("transition_id", ""))).strip()
            source = str(item.get("from", item.get("source", ""))).strip()
            dest = str(item.get("to", item.get("destination", ""))).strip()
            if not tid:
                tid = "TR-" + _fingerprint({"from": source, "to": dest, "path": item.get("path", "")})
            if tid in seen:
                raise ValueError(f"duplicate transition id: {tid}")
            if not source or not dest:
                raise ValueError(f"transition {tid}: source and destination are required")
            method = str(item.get("method", "GET")).upper()
            if method not in SAFE_METHODS:
                raise ValueError(f"transition {tid}: state-changing methods are not permitted in the safe model verifier")
            allowed_roles = tuple(sorted({str(x) for x in item.get("allowed_roles", []) if str(x).strip()}))
            seen.add(tid)
            out.append(ModelTransition(tid, source, dest, method, str(item.get("path", "")), allowed_roles))
        return out

    def _validate_references(self) -> None:
        identity_names = {x.name for x in self.identities}
        resource_ids = {x.resource_id for x in self.resources}
        for r in self.resources:
            if r.owner and r.owner not in identity_names:
                raise ValueError(f"resource {r.resource_id}: unknown owner identity {r.owner!r}")
            if r.expected:
                unknown = [k for k in r.expected if k not in identity_names]
                if unknown:
                    raise ValueError(f"resource {r.resource_id}: expected contains unknown identities: {unknown}")
        for inv in self.invariants:
            if inv.subject and inv.subject not in identity_names:
                raise ValueError(f"invariant {inv.invariant_id}: unknown subject identity {inv.subject!r}")
            if inv.resource and inv.resource not in resource_ids:
                raise ValueError(f"invariant {inv.invariant_id}: unknown resource {inv.resource!r}")

    @classmethod
    def load(cls, path: str) -> "SecurityBehaviorModel":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def contracts(self) -> List[Dict[str, Any]]:
        """Create reviewable, stable contracts from explicit security policy."""
        out: List[Dict[str, Any]] = []
        for resource in self.resources:
            expected = resource.expected or {}
            for identity in self.identities:
                exp = self._expected_for_resource(resource, identity)
                cid = "SMCON-" + _fingerprint({"resource": resource.resource_id, "identity": identity.name, "expected": exp}, 16)
                out.append({
                    "contract_id": cid,
                    "type": "model-authorization",
                    "model_resource_id": resource.resource_id,
                    "identity": identity.name,
                    "given": {"method": list(resource.methods), "url": _norm_url(resource.url), "tenant": identity.tenant, "role": identity.role},
                    "then": {"allowed_status_codes": exp["status"]},
                    "statement": f"Identity {identity.name} must receive one of {exp['status']} for resource {resource.resource_id}.",
                    "automation": {"safe_by_default": True, "stateful": False, "status": "draft", "human_approval_required": True},
                })
        for invariant in self.invariants:
            cid = "SMINV-" + _fingerprint({"id": invariant.invariant_id, "statement": invariant.statement}, 16)
            out.append({
                "contract_id": cid,
                "type": "model-invariant",
                "invariant_id": invariant.invariant_id,
                "statement": invariant.statement,
                "severity": invariant.severity,
                "automation": {"safe_by_default": True, "stateful": False, "status": "draft", "human_approval_required": True},
            })
        return out

    @staticmethod
    def _expected_for_resource(resource: ModelResource, identity: ModelIdentity) -> Dict[str, List[int]]:
        raw = resource.expected.get(identity.name, {}) if isinstance(resource.expected, dict) else {}
        if not isinstance(raw, dict):
            raw = {}
        status = raw.get("status")
        if status is None:
            status = [200] if resource.owner == identity.name or (resource.tenant and resource.tenant == identity.tenant) else [403, 404]
        if isinstance(status, int):
            status = [status]
        forbidden = raw.get("forbidden_fields", []) if isinstance(raw.get("forbidden_fields", []), list) else []
        required = raw.get("required_fields", []) if isinstance(raw.get("required_fields", []), list) else []
        return {"status": sorted({int(x) for x in status}),
                "forbidden_fields": sorted({str(x) for x in forbidden if str(x).strip()}),
                "required_fields": sorted({str(x) for x in required if str(x).strip()})}

    def validate(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "version": self.version,
            "name": self.name,
            "identities": len(self.identities),
            "resources": len(self.resources),
            "invariants": len(self.invariants),
            "transitions": len(self.transitions),
            "fingerprint": _fingerprint({
                "identities": [asdict(x) for x in self.identities],
                "resources": [asdict(x) for x in self.resources],
                "invariants": [asdict(x) for x in self.invariants],
                "transitions": [asdict(x) for x in self.transitions],
            }),
            "stateful_methods_allowed": False,
        }


class SecurityBehaviorGraphV2:
    """Graph with explicit entity relationships and authorization decisions."""

    def build(self, model: SecurityBehaviorModel, observed: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        observed = observed or {}
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, str]] = []
        seen = set()

        def node(kind: str, key: str, **extra: Any) -> str:
            nid = f"{kind}:{key}"
            if nid not in seen:
                seen.add(nid)
                nodes.append({"id": nid, "kind": kind, "key": key, **extra})
            return nid

        for ident in model.identities:
            i = node("identity", ident.name, role=ident.role, tenant=ident.tenant, privilege_rank=ident.privilege_rank)
            if ident.role:
                r = node("role", ident.role)
                edges.append({"from": i, "to": r, "relation": "has-role"})
            if ident.tenant:
                t = node("tenant", ident.tenant)
                edges.append({"from": i, "to": t, "relation": "member-of"})

        for resource in model.resources:
            r = node("resource", resource.resource_id, url=_norm_url(resource.url), classification=resource.classification,
                     owner=resource.owner, tenant=resource.tenant, methods=list(resource.methods))
            if resource.owner:
                edges.append({"from": r, "to": node("identity", resource.owner), "relation": "owned-by"})
            if resource.tenant:
                edges.append({"from": r, "to": node("tenant", resource.tenant), "relation": "scoped-to"})

        for transition in model.transitions:
            src = node("workflow-state", transition.source)
            dst = node("workflow-state", transition.destination)
            tid = node("transition", transition.transition_id, method=transition.method, path=transition.path,
                       allowed_roles=list(transition.allowed_roles))
            edges.append({"from": src, "to": tid, "relation": "permits-transition"})
            edges.append({"from": tid, "to": dst, "relation": "reaches-state"})

        verifications = observed.get("verifications", []) if isinstance(observed, dict) else []
        for v in verifications[:500]:
            did = node("authorization-decision", _fingerprint(v, 20), identity=v.get("identity"),
                       resource=v.get("resource_id"), method=v.get("method"), status=v.get("status"),
                       expected=v.get("expected"), verdict=v.get("verdict"))
            if v.get("identity"):
                edges.append({"from": node("identity", str(v["identity"])), "to": did, "relation": "made-decision"})
            if v.get("resource_id"):
                edges.append({"from": node("resource", str(v["resource_id"])), "to": did, "relation": "evaluated-by"})

        for invariant in model.invariants:
            inv = node("invariant", invariant.invariant_id, type=invariant.type, statement=invariant.statement,
                       severity=invariant.severity)
            if invariant.subject:
                edges.append({"from": inv, "to": node("identity", invariant.subject), "relation": "applies-to"})
            if invariant.resource:
                edges.append({"from": inv, "to": node("resource", invariant.resource), "relation": "protects"})

        edge_key = lambda e: (e["from"], e["relation"], e["to"])
        edges = sorted({(e["from"], e["relation"], e["to"]): e for e in edges}.values(), key=edge_key)
        graph = {
            "schema": GRAPH_SCHEMA,
            "generated_at": observed.get("generated_at"),
            "model_fingerprint": model.validate()["fingerprint"],
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges,
            "verifications": verifications[:500],
            "invariants": [asdict(x) for x in model.invariants],
            "interpretation": "Explicit security model plus observed read-only decisions; graph structure is not by itself proof of exploitability.",
        }
        fingerprint_material = {k: v for k, v in graph.items() if k not in {"generated_at", "graph_fingerprint"}}
        graph["graph_fingerprint"] = _fingerprint(fingerprint_material)
        return graph


class SecurityBehaviorVerifier:
    """Execute only explicitly modeled, read-only authorization checks."""

    def __init__(self, model: SecurityBehaviorModel):
        self.model = model

    @staticmethod
    def _expected_for(resource: ModelResource, identity: ModelIdentity) -> Dict[str, Any]:
        raw = resource.expected.get(identity.name, {}) if isinstance(resource.expected, dict) else {}
        if not isinstance(raw, dict):
            raw = {}
        status = raw.get("status")
        if status is None:
            status = [200] if resource.owner == identity.name or (resource.tenant and resource.tenant == identity.tenant) else [403, 404]
        if isinstance(status, int):
            status = [status]
        forbidden = raw.get("forbidden_fields", []) if isinstance(raw.get("forbidden_fields", []), list) else []
        required = raw.get("required_fields", []) if isinstance(raw.get("required_fields", []), list) else []
        return {"status": sorted({int(x) for x in status}),
                "forbidden_fields": sorted({str(x) for x in forbidden if str(x).strip()}),
                "required_fields": sorted({str(x) for x in required if str(x).strip()})}

    def verify(self, identities: Sequence[ModelIdentity], request: Callable[[str, str, str], Any], scope_check: Callable[[str, str], Tuple[bool, str]]) -> Dict[str, Any]:
        verifications: List[Dict[str, Any]] = []
        failures: List[Dict[str, Any]] = []
        for resource in self.model.resources:
            url = resource.url
            for identity in identities:
                for method in resource.methods:
                    if method not in SAFE_METHODS:
                        continue
                    ok, reason = scope_check(method, url)
                    if not ok:
                        verifications.append({"resource_id": resource.resource_id, "identity": identity.name, "method": method,
                                              "url": _norm_url(url), "verdict": "not_tested", "reason": reason})
                        continue
                    expected = self._expected_for(resource, identity)
                    try:
                        resp = request(identity.name, method, url)
                        status = int(getattr(resp, "status_code", 0) or 0)
                        body = getattr(resp, "text", "") or ""
                        headers = getattr(resp, "headers", {}) or {}
                        v = "pass" if status in expected["status"] else "violation"
                        record = {
                            "resource_id": resource.resource_id, "identity": identity.name, "method": method,
                            "url": _norm_url(url), "status": status, "expected": expected,
                            "body_length": len(body),
                            "body_fingerprint": hashlib.sha256(body[:5000].encode("utf-8", "ignore")).hexdigest()[:16],
                            "content_type": str(headers.get("Content-Type", "")).split(";", 1)[0].lower(),
                            "observed_fields": _response_field_paths(body),
                            "body_observable": bool(body),
                            "verdict": v,
                        }
                        verifications.append(record)
                        if v == "violation":
                            failures.append(record)
                    except Exception as exc:
                        verifications.append({"resource_id": resource.resource_id, "identity": identity.name, "method": method,
                                              "url": _norm_url(url), "verdict": "inconclusive", "error": str(exc)[:240]})
        invariant_results = []
        for invariant in self.model.invariants:
            related = [v for v in verifications if v.get("resource_id") == invariant.resource and (not invariant.subject or v.get("identity") == invariant.subject)]
            if not related:
                state = "not_tested"
            elif any(v.get("verdict") == "violation" for v in related):
                state = "violated"
            elif all(v.get("verdict") == "pass" for v in related):
                state = "pass"
            else:
                state = "inconclusive"
            invariant_results.append({"invariant_id": invariant.invariant_id, "status": state, "statement": invariant.statement})
        return {
            "schema": VERIFICATION_SCHEMA,
            "model_fingerprint": self.model.validate()["fingerprint"],
            "verifications": verifications,
            "failure_count": len(failures),
            "failures": failures,
            "invariant_results": invariant_results,
            "status": "fail" if failures else "pass",
            "safe_methods": sorted(SAFE_METHODS),
            "statement": "Only explicitly modeled read-only authorization checks were executed. No state-changing methods are used.",
        }



GRAPH_V3_SCHEMA = "ersec-security-behavior-graph/3"
ASSURANCE_SCHEMA = "ersec-security-behavior-assurance/1"


def _compact_json_shape(text: str) -> Dict[str, Any]:
    try:
        obj = json.loads(text or "")
    except Exception:
        return {"kind": "text", "length": len(text or "")}
    def shape(x: Any, depth: int = 0) -> Any:
        if depth > 3:
            return "..."
        if isinstance(x, dict):
            return {str(k): shape(v, depth + 1) for k, v in list(x.items())[:50]}
        if isinstance(x, list):
            return [shape(v, depth + 1) for v in x[:10]]
        if x is None or isinstance(x, (bool, int, float)):
            return type(x).__name__
        return "string"
    return {"kind": "json", "shape": shape(obj)}


class SecurityInvariantEngine:
    """Evaluate explicit security invariants against read-only verification evidence."""

    def __init__(self, model: SecurityBehaviorModel):
        self.model = model

    def evaluate(self, verification: Dict[str, Any]) -> Dict[str, Any]:
        rows = verification.get("verifications", []) if isinstance(verification, dict) else []
        results: List[Dict[str, Any]] = []
        by_resource: Dict[str, List[Dict[str, Any]]] = {}
        for row in rows:
            by_resource.setdefault(str(row.get("resource_id", "")), []).append(row)
        for inv in self.model.invariants:
            related = by_resource.get(inv.resource, []) if inv.resource else rows
            if inv.subject:
                related = [r for r in related if str(r.get("identity", "")) == inv.subject]
            status = "not_tested"
            reasons: List[str] = []
            counterexamples: List[Dict[str, Any]] = []
            typ = inv.type.lower().strip()
            if not related:
                status = "not_tested"
            elif typ in {"tenant_isolation", "tenant-isolation"}:
                violations = [r for r in related if r.get("verdict") == "violation"]
                if violations:
                    status = "violated"
                    reasons.append("A modeled cross-tenant authorization expectation was violated.")
                    counterexamples = violations[:5]
                elif all(r.get("verdict") == "pass" for r in related):
                    status = "pass"
                else:
                    status = "inconclusive"
            elif typ in {"privilege_boundary", "role_boundary", "authorization"}:
                violations = [r for r in related if r.get("verdict") == "violation"]
                status = "violated" if violations else ("pass" if all(r.get("verdict") == "pass" for r in related) else "inconclusive")
                if violations:
                    reasons.append("A modeled authorization boundary did not match the expected decision.")
                    counterexamples = violations[:5]
            elif typ in {"method_consistency", "representation_consistency"}:
                verdicts = {str(r.get("verdict")) for r in related if r.get("verdict")}
                if "violation" in verdicts:
                    status = "violated"
                    reasons.append("Equivalent modeled representations produced inconsistent authorization outcomes.")
                    counterexamples = [r for r in related if r.get("verdict") == "violation"][:5]
                elif verdicts == {"pass"}:
                    status = "pass"
                else:
                    status = "inconclusive"
            else:
                violations = [r for r in related if r.get("verdict") == "violation"]
                status = "violated" if violations else ("pass" if all(r.get("verdict") == "pass" for r in related) else "inconclusive")
                if violations:
                    reasons.append("Observed authorization behavior conflicts with the explicit invariant.")
                    counterexamples = violations[:5]
            results.append({"invariant_id": inv.invariant_id, "type": inv.type, "severity": inv.severity,
                            "status": status, "statement": inv.statement, "reasons": reasons,
                            "counterexamples": counterexamples})
        counts = {k: sum(1 for r in results if r["status"] == k) for k in ("pass", "violated", "inconclusive", "not_tested")}
        return {"schema": ASSURANCE_SCHEMA, "invariants": results, "counts": counts,
                "status": "fail" if counts["violated"] else ("inconclusive" if counts["inconclusive"] or counts["not_tested"] else "pass"),
                "statement": "Assurance is evidence-based; untested invariants are not treated as secure."}


class CounterexamplePathEngine:
    """Create minimal explainable paths for violated authorization invariants."""

    def build(self, model: SecurityBehaviorModel, assurance: Dict[str, Any]) -> Dict[str, Any]:
        paths: List[Dict[str, Any]] = []
        by_id = {x.invariant_id: x for x in model.invariants}
        for inv in assurance.get("invariants", []):
            if inv.get("status") != "violated":
                continue
            policy = by_id.get(str(inv.get("invariant_id")))
            for ex in (inv.get("counterexamples") or [])[:5]:
                identity = str(ex.get("identity", policy.subject if policy else ""))
                resource = str(ex.get("resource_id", policy.resource if policy else ""))
                resource_obj = next((r for r in model.resources if r.resource_id == resource), None)
                tenant = resource_obj.tenant if resource_obj else ""
                role = next((i.role for i in model.identities if i.name == identity), "")
                path_nodes = [
                    {"kind": "identity", "key": identity},
                    {"kind": "role", "key": role},
                    {"kind": "authorization-decision", "key": f"{identity}:{resource}:{ex.get('method','GET')}"},
                    {"kind": "resource", "key": resource},
                ]
                if tenant:
                    path_nodes.append({"kind": "tenant", "key": tenant})
                paths.append({"invariant_id": inv.get("invariant_id"), "severity": inv.get("severity", "HIGH"),
                              "identity": identity, "resource": resource, "method": ex.get("method", "GET"),
                              "observed_status": ex.get("status"), "expected_status": ex.get("expected", {}).get("status", []),
                              "path": path_nodes,
                              "summary": f"{identity} -> {resource} -> HTTP {ex.get('status')} (expected {ex.get('expected', {}).get('status', [])})"})
        return {"schema": "ersec-counterexample-path/1", "paths": paths, "count": len(paths),
                "statement": "Paths are minimal explanatory evidence chains, not exploit instructions."}




class SecurityAuthorizationMatrix:
    """Build an auditable identity x resource x method authorization matrix."""
    SCHEMA = "ersec-authorization-matrix/1"

    def build(self, model: SecurityBehaviorModel, verification: Dict[str, Any]) -> Dict[str, Any]:
        observed = {}
        for row in verification.get("verifications", []) if isinstance(verification, dict) else []:
            key = (str(row.get("identity","")), str(row.get("resource_id","")), str(row.get("method","GET")).upper())
            observed[key] = row
        rows: List[Dict[str, Any]] = []
        for ident in model.identities:
            for resource in model.resources:
                exp = model._expected_for_resource(resource, ident)
                for method in resource.methods:
                    key = (ident.name, resource.resource_id, method)
                    row = observed.get(key)
                    rows.append({
                        "identity": ident.name, "role": ident.role, "tenant": ident.tenant,
                        "resource_id": resource.resource_id, "resource_tenant": resource.tenant,
                        "owner": resource.owner, "method": method,
                        "expected_status": exp["status"],
                        "observed_status": row.get("status") if row else None,
                        "verdict": row.get("verdict", "not_tested") if row else "not_tested",
                        "coverage": "tested" if row and row.get("verdict") in {"pass", "violation"} else "not_tested",
                    })
        counts={k:sum(1 for r in rows if r["verdict"]==k) for k in ("pass","violation","inconclusive","not_tested")}
        tested=counts["pass"]+counts["violation"]
        coverage=(tested/len(rows)) if rows else 0.0
        violations=[r for r in rows if r["verdict"]=="violation"]
        return {"schema": self.SCHEMA, "identity_count": len(model.identities), "resource_count": len(model.resources),
                "row_count": len(rows), "coverage_ratio": round(coverage,4), "counts": counts,
                "violation_count": len(violations), "violations": violations[:200], "rows": rows[:2000],
                "status": "fail" if violations else ("inconclusive" if counts["inconclusive"] or counts["not_tested"] else "pass"),
                "statement": "Authorization matrix reports observed read-only decisions against explicit model expectations; untested cells are not treated as secure."}


class SecurityBehaviorGraphV3:
    """Evidence-linked graph for identities, roles, tenants, resources, decisions, invariants and counterexamples."""

    def build(self, model: SecurityBehaviorModel, verification: Dict[str, Any], assurance: Dict[str, Any]) -> Dict[str, Any]:
        v2 = SecurityBehaviorGraphV2().build(model, verification)
        nodes = list(v2.get("nodes", []))
        edges = list(v2.get("edges", []))
        seen = {n.get("id") for n in nodes}
        def add_node(kind: str, key: str, **extra: Any) -> str:
            nid = f"{kind}:{key}"
            if nid not in seen:
                seen.add(nid)
                nodes.append({"id": nid, "kind": kind, "key": key, **extra})
            return nid
        for inv in assurance.get("invariants", []):
            iid = str(inv.get("invariant_id"))
            add_node("invariant-result", iid, status=inv.get("status"), severity=inv.get("severity"))
            edges.append({"from": add_node("invariant", iid), "to": f"invariant-result:{iid}", "relation": "evaluates-to"})
        for path in CounterexamplePathEngine().build(model, assurance).get("paths", [])[:200]:
            prev = None
            pid = add_node("counterexample", str(_fingerprint(path, 20)), invariant_id=path.get("invariant_id"), summary=path.get("summary"))
            for step in path.get("path", []):
                sid = add_node(step.get("kind", "node"), str(step.get("key", "")))
                if prev:
                    edges.append({"from": prev, "to": sid, "relation": "counterexample-step"})
                prev = sid
            if prev:
                edges.append({"from": pid, "to": prev, "relation": "ends-at"})
        edges = sorted({(e.get("from"), e.get("relation"), e.get("to")): e for e in edges}.values(), key=lambda e: (e.get("from",""), e.get("relation",""), e.get("to","")))
        graph = {"schema": GRAPH_V3_SCHEMA, "model_fingerprint": model.validate()["fingerprint"],
                 "node_count": len(nodes), "edge_count": len(edges), "nodes": nodes, "edges": edges,
                 "verification_count": len(verification.get("verifications", [])),
                 "assurance_status": assurance.get("status"),
                 "invariant_results": assurance.get("invariants", []),
                 "interpretation": "Operational security-behavior graph linking policy, observed decisions and minimal counterexamples. Presence is evidence, not proof of exploitability."}
        graph["graph_fingerprint"] = _fingerprint({k:v for k,v in graph.items() if k != "graph_fingerprint"})
        return graph


class SecurityBehaviorStateStore:
    """Persists graph fingerprints and highlights authorization-model drift."""

    def __init__(self, path: Optional[str]):
        self.path = path

    def compare_and_save(self, graph: Dict[str, Any]) -> Dict[str, Any]:
        if not self.path:
            return {"status": "disabled", "regressed": False}
        path = Path(self.path)
        previous = None
        if path.exists():
            try:
                previous = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                previous = None
        current_nodes = {str(x.get("id")) for x in graph.get("nodes", []) if isinstance(x, dict)}
        current_edges = {f'{x.get("from")}|{x.get("relation")}|{x.get("to")}' for x in graph.get("edges", []) if isinstance(x, dict)}
        prior_nodes = {str(x.get("id")) for x in (previous or {}).get("nodes", []) if isinstance(x, dict)}
        prior_edges = {f'{x.get("from")}|{x.get("relation")}|{x.get("to")}' for x in (previous or {}).get("edges", []) if isinstance(x, dict)}
        diff = {
            "status": "baseline" if previous is None else "compared",
            "regressed": False,
            "new_nodes": sorted(current_nodes - prior_nodes)[:500],
            "removed_nodes": sorted(prior_nodes - current_nodes)[:500],
            "new_edges": sorted(current_edges - prior_edges)[:500],
            "removed_edges": sorted(prior_edges - current_edges)[:500],
            "previous_fingerprint": (previous or {}).get("graph_fingerprint"),
            "current_fingerprint": graph.get("graph_fingerprint"),
        }
        # Removal of an identity/tenant/resource relationship is treated as drift,
        # not automatically a vulnerability. Surface it for human review.
        diff["security_boundary_drift"] = bool(diff["removed_edges"] or diff["removed_nodes"])
        tmp = Path(str(path) + ".tmp")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(graph, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
        return diff

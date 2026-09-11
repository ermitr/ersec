"""ERSEC 29.1.0 Security Reality Fabric.

A deterministic, evidence-first layer that turns a scan into a living security
model rather than a flat finding list.  It does not exploit targets or infer
security from absence of evidence.  Its job is to answer four harder questions:

* What security-relevant assets and claims do we actually know about?
* Which claims are supported, contradicted, or still unobserved?
* What is the smallest next assurance action that would reduce uncertainty?
* What changed in the application's security reality between two runs?

The module is deliberately transport/report agnostic so it can be used against
existing ERSEC JSON artifacts, CI reports, or future telemetry adapters.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import urlparse

VERSION = "29.1.0"
SCHEMA = "ersec-reality/1"


@dataclass(frozen=True)
class RealityNode:
    node_id: str
    kind: str
    label: str
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RealityEdge:
    source: str
    relation: str
    target: str
    weight: float = 1.0
    evidence: Tuple[str, ...] = ()


@dataclass(frozen=True)
class SecurityClaim:
    claim_id: str
    dimension: str
    subject: str
    statement: str
    verdict: str
    evidence_level: str
    impact: float
    uncertainty: float
    sources: Tuple[str, ...] = ()
    limitations: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AssuranceAction:
    action_id: str
    priority: float
    dimension: str
    action: str
    reason: str
    expected_uncertainty_reduction: float
    prerequisites: Tuple[str, ...] = ()


def _stable(prefix: str, *parts: Any) -> str:
    material = "|".join(str(x).strip() for x in parts)
    return prefix + "-" + hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()[:16]


def _bounded(value: Any, default: float = 0.0) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return default


def _severity_impact(value: Any) -> float:
    text = str(value or "").lower()
    return {"critical": 1.0, "high": 0.82, "medium": 0.58, "low": 0.28, "info": 0.10}.get(text, 0.40)


def _evidence_level(item: Mapping[str, Any]) -> str:
    explicit = str(item.get("evidence_level") or item.get("evidence") or "").lower()
    if any(x in explicit for x in ("authoritative", "confirmed", "proof")):
        return "high"
    if any(x in explicit for x in ("likely", "strong", "observed")):
        return "medium"
    return "low"


def _uncertainty(verdict: str, evidence: str) -> float:
    if verdict in {"violated", "fail", "confirmed"}:
        return {"high": 0.05, "medium": 0.18, "low": 0.32}.get(evidence, 0.30)
    if verdict in {"pass", "verified"}:
        return {"high": 0.05, "medium": 0.15, "low": 0.28}.get(evidence, 0.25)
    if verdict in {"not_tested", "unavailable", "inconclusive", "unknown"}:
        return 0.90
    return 0.55


def _dimension_for_finding(finding: Mapping[str, Any]) -> str:
    category = str(finding.get("category") or finding.get("title") or "").lower()
    if any(x in category for x in ("authorization", "idor", "access", "privilege", "tenant", "oauth")):
        return "authorization"
    if any(x in category for x in ("sql", "nosql", "ldap", "xpath", "template", "command", "injection", "traversal", "xss", "xxe")):
        return "input-safety"
    if any(x in category for x in ("cookie", "session", "csrf", "header", "tls", "cors", "cache")):
        return "transport-and-browser"
    if any(x in category for x in ("api", "graphql", "grpc", "contract", "schema")):
        return "api-contract"
    if any(x in category for x in ("secret", "credential", "dependency", "library", "sbom")):
        return "supply-chain"
    if any(x in category for x in ("cloud", "docker", "kubernetes", "terraform", "iam")):
        return "cloud-native"
    return "application-behavior"


class SecurityRealityFabric:
    """Compile ERSEC observations into a deterministic security reality model."""

    DIMENSIONS = (
        "discovery",
        "authorization",
        "application-behavior",
        "api-contract",
        "input-safety",
        "transport-and-browser",
        "cloud-native",
        "supply-chain",
        "governance",
    )

    def compile(self, report: Mapping[str, Any]) -> Dict[str, Any]:
        nodes: Dict[str, RealityNode] = {}
        edges: List[RealityEdge] = []
        claims: List[SecurityClaim] = []
        endpoints = self._endpoints(report)
        findings = self._findings(report)
        graph = report.get("security_behavior_graph") or report.get("behavior_graph") or {}

        # The application itself is an anchor.  Everything else gets connected to it.
        target = str(report.get("target") or report.get("scan", {}).get("target") or "application")
        app_id = _stable("app", target)
        nodes[app_id] = RealityNode(app_id, "application", target)

        for endpoint in endpoints:
            eid = _stable("endpoint", endpoint)
            p = urlparse(endpoint)
            nodes[eid] = RealityNode(eid, "endpoint", endpoint, {
                "path": p.path or "/", "host": p.netloc, "scheme": p.scheme,
            })
            edges.append(RealityEdge(app_id, "exposes", eid, 0.80))
            dimension = "api-contract" if "/api" in (p.path or "").lower() else "discovery"
            claims.append(SecurityClaim(
                _stable("claim", dimension, endpoint, "discovered"), dimension, eid,
                "This endpoint is part of the observed application surface.",
                "observed", "medium", 0.35, 0.20, (eid,),
            ))

        for finding in findings:
            fid = str(finding.get("finding_id") or finding.get("id") or _stable("finding", json.dumps(finding, sort_keys=True)))
            node_id = _stable("finding", fid)
            dimension = _dimension_for_finding(finding)
            verdict = self._finding_verdict(finding)
            evidence = _evidence_level(finding)
            impact = _severity_impact(finding.get("severity"))
            uncertainty = _uncertainty(verdict, evidence)
            label = str(finding.get("title") or finding.get("description") or fid)[:240]
            nodes[node_id] = RealityNode(node_id, "finding", label, {
                "finding_id": fid,
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "category": finding.get("category"),
            })
            edges.append(RealityEdge(app_id, "contains-finding", node_id, max(0.2, impact)))
            url = str(finding.get("url") or finding.get("endpoint") or "")
            if url:
                endpoint_id = _stable("endpoint", url)
                if endpoint_id in nodes:
                    edges.append(RealityEdge(endpoint_id, "has-finding", node_id, impact))
            claims.append(SecurityClaim(
                _stable("claim", dimension, fid), dimension, node_id,
                str(finding.get("description") or label), verdict, evidence, impact, uncertainty,
                (node_id,), tuple(self._limitations(finding)),
            ))

        self._ingest_behavior_graph(graph, nodes, edges, claims, app_id)
        self._add_governance_claims(report, nodes, edges, claims, app_id)
        frontier = self.assurance_frontier(nodes, edges, claims)
        posture = self._posture(claims)
        critical_path = self._critical_path(nodes, edges, claims)
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "target": target,
            "reality_digest": self.digest(nodes, edges, claims),
            "nodes": [asdict(x) for x in nodes.values()],
            "edges": [asdict(x) for x in edges],
            "claims": [asdict(x) for x in claims],
            "posture": posture,
            "assurance_frontier": [asdict(x) for x in frontier],
            "critical_security_reality": critical_path,
            "principles": [
                "absence_of_evidence_is_not_evidence_of_pass",
                "uncertainty_is_first_class",
                "all_priority_scores_are_explainable",
                "no_exploit_execution",
            ],
        }

    def assurance_frontier(
        self,
        nodes: Mapping[str, RealityNode],
        edges: Sequence[RealityEdge],
        claims: Sequence[SecurityClaim],
    ) -> List[AssuranceAction]:
        degree: Dict[str, int] = {}
        for edge in edges:
            degree[edge.source] = degree.get(edge.source, 0) + 1
            degree[edge.target] = degree.get(edge.target, 0) + 1
        actions: List[AssuranceAction] = []
        for claim in claims:
            if claim.verdict not in {"not_tested", "inconclusive", "unavailable", "unknown"} and claim.uncertainty < 0.60:
                continue
            connectivity = min(1.0, degree.get(claim.subject, 0) / 8.0)
            priority = round(min(100.0, 100.0 * (
                0.45 * claim.impact + 0.40 * claim.uncertainty + 0.15 * connectivity
            )), 2)
            action, reduction, prereq = self._next_action(claim)
            actions.append(AssuranceAction(
                _stable("action", claim.claim_id), priority, claim.dimension, action,
                f"Claim uncertainty={claim.uncertainty:.2f}; impact={claim.impact:.2f}; connectivity={connectivity:.2f}.",
                reduction, tuple(prereq),
            ))
        actions.sort(key=lambda x: (-x.priority, x.action_id))
        return actions[:50]

    @staticmethod
    def digest(nodes: Mapping[str, RealityNode], edges: Sequence[RealityEdge], claims: Sequence[SecurityClaim]) -> str:
        payload = {
            "nodes": sorted((asdict(x) for x in nodes.values()), key=lambda x: x["node_id"]),
            "edges": sorted((asdict(x) for x in edges), key=lambda x: (x["source"], x["relation"], x["target"])),
            "claims": sorted((asdict(x) for x in claims), key=lambda x: x["claim_id"]),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def diff(self, before: Mapping[str, Any], after: Mapping[str, Any]) -> Dict[str, Any]:
        b = {str(x.get("claim_id")): x for x in before.get("claims", []) if isinstance(x, Mapping)}
        a = {str(x.get("claim_id")): x for x in after.get("claims", []) if isinstance(x, Mapping)}
        changed = []
        for cid in sorted(set(b) | set(a)):
            old, new = b.get(cid), a.get(cid)
            if old is None:
                changed.append({"claim_id": cid, "change": "new", "after": new})
                continue
            if new is None:
                changed.append({"claim_id": cid, "change": "removed", "before": old})
                continue
            fields = [k for k in ("verdict", "evidence_level", "uncertainty", "impact") if old.get(k) != new.get(k)]
            if fields:
                regression = self._is_regression(old, new)
                changed.append({"claim_id": cid, "change": "changed", "fields": fields,
                                "regression": regression, "before": old, "after": new})
        regressions = [x for x in changed if x.get("regression")]
        resolved = [x for x in changed if self._is_resolved(x)]
        uncertainty_delta = self._mean_uncertainty(after) - self._mean_uncertainty(before)
        status = "regression" if regressions else ("improved" if resolved else ("changed" if changed else "unchanged"))
        return {
            "schema": "ersec-reality-diff/1",
            "before_digest": before.get("reality_digest"),
            "after_digest": after.get("reality_digest"),
            "changed_claims": changed,
            "regression_count": len(regressions),
            "resolved_count": len(resolved),
            "mean_uncertainty_delta": round(uncertainty_delta, 4),
            "status": status,
        }

    @staticmethod
    def _finding_verdict(finding: Mapping[str, Any]) -> str:
        status = str(finding.get("status") or "").lower()
        if status in {"resolved", "pass", "verified"}:
            return "pass"
        if status in {"inconclusive", "not_tested", "unavailable"}:
            return status
        if str(finding.get("confidence") or "").lower() == "confirmed":
            return "violated"
        if finding.get("severity"):
            return "violated"
        return "unknown"

    @staticmethod
    def _limitations(finding: Mapping[str, Any]) -> List[str]:
        raw = finding.get("limitations")
        if isinstance(raw, list):
            return [str(x) for x in raw[:8]]
        return ["Finding semantics depend on the evidence available in the source report."]

    @staticmethod
    def _endpoints(report: Mapping[str, Any]) -> List[str]:
        candidates: List[str] = []
        for key in ("endpoints", "discovered_endpoints", "urls"):
            value = report.get(key)
            if isinstance(value, list):
                candidates.extend(str(x) for x in value if isinstance(x, (str, int, float)))
        for finding in report.get("findings", []) if isinstance(report.get("findings"), list) else []:
            if isinstance(finding, Mapping) and finding.get("url"):
                candidates.append(str(finding["url"]))
        return sorted(set(x for x in candidates if x))[:2000]

    @staticmethod
    def _findings(report: Mapping[str, Any]) -> List[Mapping[str, Any]]:
        value = report.get("findings", [])
        return [x for x in value if isinstance(x, Mapping)] if isinstance(value, list) else []

    def _ingest_behavior_graph(self, graph: Mapping[str, Any], nodes: Dict[str, RealityNode], edges: List[RealityEdge], claims: List[SecurityClaim], app_id: str) -> None:
        if not isinstance(graph, Mapping):
            return
        raw_nodes = graph.get("nodes", [])
        raw_edges = graph.get("edges", [])
        if isinstance(raw_nodes, list):
            for item in raw_nodes[:1500]:
                if not isinstance(item, Mapping):
                    continue
                label = str(item.get("label") or item.get("name") or item.get("id") or "behavior-node")
                nid = _stable("behavior", item.get("id") or label)
                nodes.setdefault(nid, RealityNode(nid, "behavior", label, dict(item)))
                edges.append(RealityEdge(app_id, "models", nid, 0.75))
        if isinstance(raw_edges, list):
            for item in raw_edges[:3000]:
                if not isinstance(item, Mapping):
                    continue
                src = _stable("behavior", item.get("source"))
                dst = _stable("behavior", item.get("target"))
                if src in nodes and dst in nodes:
                    edges.append(RealityEdge(src, str(item.get("relation") or item.get("label") or "transitions"), dst, _bounded(item.get("weight"), 0.6)))

        invariants = graph.get("invariants", [])
        if isinstance(invariants, list):
            for inv in invariants[:500]:
                if not isinstance(inv, Mapping):
                    continue
                statement = str(inv.get("statement") or inv.get("description") or inv.get("name") or "security invariant")
                verdict = str(inv.get("verdict") or inv.get("status") or "unknown").lower()
                if verdict not in {"pass", "violated", "inconclusive", "not_tested", "unavailable"}:
                    verdict = "unknown"
                evidence = _evidence_level(inv)
                iid = _stable("invariant", statement)
                nodes[iid] = RealityNode(iid, "invariant", statement, dict(inv))
                edges.append(RealityEdge(app_id, "governed-by", iid, 0.9))
                claims.append(SecurityClaim(
                    _stable("claim", "authorization", iid), "authorization", iid, statement,
                    verdict, evidence, _bounded(inv.get("impact"), 0.8), _uncertainty(verdict, evidence),
                    (iid,), tuple(inv.get("limitations", []) if isinstance(inv.get("limitations"), list) else ()),
                ))

    @staticmethod
    def _add_governance_claims(report: Mapping[str, Any], nodes: Dict[str, RealityNode], edges: List[RealityEdge], claims: List[SecurityClaim], app_id: str) -> None:
        contracts = report.get("security_contracts") or report.get("contracts")
        if contracts is not None:
            count = len(contracts) if isinstance(contracts, list) else len(contracts.get("contracts", [])) if isinstance(contracts, Mapping) else 0
            nid = _stable("governance", "contracts")
            nodes[nid] = RealityNode(nid, "governance", "Security contracts", {"count": count})
            edges.append(RealityEdge(app_id, "governed-by", nid, 0.85))
            verdict = "observed" if count else "not_tested"
            claims.append(SecurityClaim(_stable("claim", "governance", "contracts"), "governance", nid,
                "The application has explicit security contracts represented in the assurance artifacts.", verdict,
                "medium" if count else "low", 0.65, 0.25 if count else 0.90, (nid,), ()))

    @staticmethod
    def _posture(claims: Sequence[SecurityClaim]) -> Dict[str, Any]:
        by_dimension: Dict[str, List[SecurityClaim]] = {}
        for claim in claims:
            by_dimension.setdefault(claim.dimension, []).append(claim)
        result: Dict[str, Any] = {}
        for dimension in SecurityRealityFabric.DIMENSIONS:
            group = by_dimension.get(dimension, [])
            if not group:
                result[dimension] = {"state": "unobserved", "score": None, "claims": 0}
                continue
            weighted = sum(c.impact * (1.0 - c.uncertainty) for c in group)
            weight = sum(max(0.1, c.impact) for c in group)
            violations = sum(1 for c in group if c.verdict in {"violated", "fail", "confirmed"})
            unknown = sum(1 for c in group if c.verdict in {"unknown", "not_tested", "inconclusive", "unavailable"})
            score = round(100.0 * max(0.0, min(1.0, 1.0 - weighted / max(weight, 0.1) * 0.65 - violations / max(len(group), 1) * 0.35)), 2)
            state = "risk" if violations else "uncertain" if unknown else "observed"
            result[dimension] = {"state": state, "score": score, "claims": len(group), "violations": violations, "unknown": unknown}
        observed = [v["score"] for v in result.values() if v["score"] is not None]
        result["overall"] = {
            "state": "risk" if any(v.get("violations", 0) for v in result.values() if isinstance(v, dict)) else "uncertain" if any(v.get("state") == "uncertain" for v in result.values() if isinstance(v, dict)) else "observed",
            "score": round(sum(observed) / len(observed), 2) if observed else None,
        }
        return result

    @staticmethod
    def _next_action(claim: SecurityClaim) -> Tuple[str, float, List[str]]:
        mapping = {
            "authorization": ("Compare the affected resource across two explicitly authorized identities and record the postcondition.", 0.55, ["two authorized identities", "stable target state"]),
            "api-contract": ("Re-run the observed contract case and compare status, shape, and security-relevant fields against the baseline.", 0.50, ["previous contract observation"]),
            "application-behavior": ("Replay the smallest safe workflow observation that establishes the claimed state transition.", 0.45, ["replayable workflow"]),
            "input-safety": ("Reverify the existing finding with a bounded, non-destructive probe and capture deterministic evidence.", 0.40, ["authorized target", "bounded probe"]),
            "transport-and-browser": ("Reobserve the affected browser/transport control and capture the exact response metadata.", 0.45, ["reachable endpoint"]),
            "supply-chain": ("Resolve the component identity to an authoritative package/version source and attach provenance evidence.", 0.60, ["package inventory"]),
            "cloud-native": ("Validate the affected policy/configuration against the declared deployment state without changing it.", 0.50, ["declared configuration"]),
            "governance": ("Create or review an explicit security contract for the unobserved property before gating CI.", 0.65, ["operator review"]),
            "discovery": ("Run a bounded discovery pass focused on the unobserved application surface.", 0.45, ["authorized scope"]),
        }
        return mapping.get(claim.dimension, ("Collect a stronger deterministic observation for this claim.", 0.30, []))

    @staticmethod
    def _critical_path(nodes: Mapping[str, RealityNode], edges: Sequence[RealityEdge], claims: Sequence[SecurityClaim]) -> List[Dict[str, Any]]:
        # A lightweight risk spine: findings with high impact plus graph connectivity.
        degree: Dict[str, int] = {}
        for edge in edges:
            degree[edge.source] = degree.get(edge.source, 0) + 1
            degree[edge.target] = degree.get(edge.target, 0) + 1
        rows = []
        for claim in claims:
            if claim.impact < 0.58:
                continue
            rows.append({
                "claim_id": claim.claim_id,
                "dimension": claim.dimension,
                "impact": claim.impact,
                "uncertainty": claim.uncertainty,
                "connectivity": degree.get(claim.subject, 0),
                "risk_attention": round(100 * claim.impact * (1 - 0.35 * claim.uncertainty) * min(1.0, 0.5 + degree.get(claim.subject, 0) / 10), 2),
                "statement": claim.statement,
            })
        return sorted(rows, key=lambda x: (-x["risk_attention"], x["claim_id"]))[:25]

    @staticmethod
    def _is_regression(old: Mapping[str, Any], new: Mapping[str, Any]) -> bool:
        ov, nv = str(old.get("verdict")), str(new.get("verdict"))
        if nv in {"violated", "fail", "confirmed"} and ov in {"pass", "verified", "observed"}:
            return True
        try:
            if float(new.get("uncertainty", 0)) > float(old.get("uncertainty", 0)) + 0.20:
                return True
        except (TypeError, ValueError):
            pass
        return False

    @staticmethod
    def _is_resolved(change: Mapping[str, Any]) -> bool:
        old = change.get("before", {})
        new = change.get("after", {})
        return str(old.get("verdict")) in {"violated", "fail", "confirmed"} and str(new.get("verdict")) in {"pass", "verified"}

    @staticmethod
    def _mean_uncertainty(report: Mapping[str, Any]) -> float:
        claims = [x for x in report.get("claims", []) if isinstance(x, Mapping)]
        if not claims:
            return 1.0
        return sum(_bounded(x.get("uncertainty"), 1.0) for x in claims) / len(claims)


def compile_report(path: str, output: Optional[str] = None) -> Dict[str, Any]:
    source = json.loads(Path(path).read_text(encoding="utf-8"))
    result = SecurityRealityFabric().compile(source)
    if output:
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def diff_reports(before_path: str, after_path: str) -> Dict[str, Any]:
    before = json.loads(Path(before_path).read_text(encoding="utf-8"))
    after = json.loads(Path(after_path).read_text(encoding="utf-8"))
    # Accept either raw ERSEC reports or already compiled reality artifacts.
    fabric = SecurityRealityFabric()
    if before.get("schema") != SCHEMA:
        before = fabric.compile(before)
    if after.get("schema") != SCHEMA:
        after = fabric.compile(after)
    return fabric.diff(before, after)

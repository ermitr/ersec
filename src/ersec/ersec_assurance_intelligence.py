"""ERSEC 29.1.1 Assurance Intelligence.

A deterministic layer for reasoning about *proof freshness*, *reality gaps*,
*assurance debt*, and *bounded next-best observations*.

This module deliberately does not claim exploit probability or autonomous
compromise. It turns heterogeneous security evidence into reviewable assurance
state and safe, prioritized observation plans.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

VERSION = "29.1.1"
SCHEMA = "ersec-assurance-intelligence/1"


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(v: Any) -> str:
    return hashlib.sha256(_canon(v).encode("utf-8")).hexdigest()


def _norm(v: Any) -> str:
    return str(v or "").strip().lower()


def _rank(v: Any) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3, "authoritative": 4}.get(_norm(v), 0)


def _verdict(v: Any) -> str:
    return _norm(v).replace("_", "-")

def _number(v: Any, default: float = 0.5) -> float:
    try:
        n = float(v)
        if n != n or n in (float("inf"), float("-inf")):
            return default
        return n
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class AssuranceGap:
    gap_id: str
    kind: str
    subject: str
    dimension: str
    severity: str
    reason: str
    suggested_observation: str
    confidence: float


@dataclass(frozen=True)
class ProofDebtItem:
    claim_id: str
    dimension: str
    subject: str
    debt: float
    reason: str
    evidence_age_days: Optional[float]
    evidence_level: str


@dataclass(frozen=True)
class ObservationAction:
    action_id: str
    kind: str
    target: str
    expected_uncertainty_reduction: float
    cost: float
    safety_risk: float
    priority: float
    prerequisites: Tuple[str, ...] = ()


class AssuranceIntelligence:
    """Compile a reality artifact into a deterministic assurance-intelligence model."""

    def __init__(self, now: Optional[datetime] = None) -> None:
        self.now = now or datetime.now(timezone.utc)

    def analyze(self, reality: Mapping[str, Any], declared: Optional[Mapping[str, Any]] = None,
                budget: float = 10.0) -> Dict[str, Any]:
        budget = _number(budget, 10.0)
        if budget < 0:
            budget = 0.0
        claims = [x for x in reality.get("claims", []) if isinstance(x, Mapping)]
        nodes = [x for x in reality.get("nodes", []) if isinstance(x, Mapping)]
        declared = declared or {}
        gaps = self._reality_gaps(claims, nodes, declared)
        debt = self._proof_debt(claims)
        actions = self._actions(gaps, debt, reality)
        selected, spent = self._select(actions, max(0.0, float(budget)))
        impact_cone = self._impact_cone(claims, reality)
        result = {
            "schema": SCHEMA,
            "version": VERSION,
            "reality_digest": str(reality.get("reality_digest") or _hash(reality)),
            "assurance_intelligence_digest": "",
            "analysis_time": self.now.isoformat(),
            "reality_gaps": [asdict(x) for x in gaps],
            "proof_debt": [asdict(x) for x in debt],
            "proof_debt_total": round(sum(x.debt for x in debt), 6),
            "observation_budget": {"requested": float(budget), "selected_cost": round(spent, 6), "remaining": round(max(0.0, float(budget) - spent), 6)},
            "next_best_observations": [asdict(x) for x in selected],
            "security_impact_cone": impact_cone,
            "governance": {
                "deterministic": True,
                "absence_of_evidence_is_not_pass": True,
                "actions_are_non_destructive": True,
                "ai_is_not_a_trust_boundary": True,
            },
        }
        result["assurance_intelligence_digest"] = _hash({k: v for k, v in result.items() if k not in {"assurance_intelligence_digest", "analysis_time"}})
        return result

    def diff(self, before: Mapping[str, Any], after: Mapping[str, Any]) -> Dict[str, Any]:
        b = self.analyze(before)
        a = self.analyze(after)
        bmap = {x["claim_id"]: x for x in before.get("claims", []) if isinstance(x, Mapping) and x.get("claim_id")}
        amap = {x["claim_id"]: x for x in after.get("claims", []) if isinstance(x, Mapping) and x.get("claim_id")}
        changes: List[Dict[str, Any]] = []
        for cid in sorted(set(bmap) | set(amap)):
            if cid not in bmap:
                changes.append({"claim_id": cid, "change": "added", "after": amap[cid]})
                continue
            if cid not in amap:
                changes.append({"claim_id": cid, "change": "removed", "before": bmap[cid], "interpretation": "observation disappeared; not a remediation"})
                continue
            if _canon(bmap[cid]) != _canon(amap[cid]):
                bv, av = _verdict(bmap[cid].get("verdict")), _verdict(amap[cid].get("verdict"))
                changes.append({"claim_id": cid, "change": "changed", "before": bmap[cid], "after": amap[cid],
                                "regression": self._regression(bmap[cid], amap[cid]),
                                "resolution": bv in {"violated", "failed"} and av in {"pass", "passed", "verified"}})
        status = "unchanged" if not changes else "changed"
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "status": status,
            "before_digest": b.get("assurance_intelligence_digest"),
            "after_digest": a.get("assurance_intelligence_digest"),
            "claim_changes": changes,
            "proof_debt_delta": round(a["proof_debt_total"] - b["proof_debt_total"], 6),
            "gap_count_delta": len(a["reality_gaps"]) - len(b["reality_gaps"]),
            "absence_is_not_resolution": True,
        }

    def _reality_gaps(self, claims: Sequence[Mapping[str, Any]], nodes: Sequence[Mapping[str, Any]], declared: Mapping[str, Any]) -> List[AssuranceGap]:
        out: List[AssuranceGap] = []
        declared_items = declared.get("endpoints", declared.get("surface", [])) if isinstance(declared, Mapping) else []
        observed = set()
        for n in nodes:
            label = str(n.get("label") or n.get("subject") or n.get("url") or "").strip()
            if label:
                observed.add(label)
        for c in claims:
            subject = str(c.get("subject") or c.get("statement") or "")
            if subject:
                observed.add(subject)
        if isinstance(declared_items, list):
            for item in declared_items:
                s = str(item).strip()
                if s and not any(s == o or s in o or o in s for o in observed):
                    out.append(AssuranceGap(_hash(("declared-unobserved", s))[:20], "declared-but-unobserved", s, "discovery", "high",
                                            "Declared surface has no matching positive observation.", "Observe the declared route/contract using an authorized read-only probe.", 0.9))
        declared_claims = declared.get("claims", []) if isinstance(declared, Mapping) else []
        if isinstance(declared_claims, list):
            observed_ids = {str(c.get("claim_id")) for c in claims}
            for item in declared_claims:
                if not isinstance(item, Mapping):
                    continue
                cid = str(item.get("claim_id") or "")
                if cid and cid not in observed_ids:
                    out.append(AssuranceGap(_hash(("claim-unobserved", cid))[:20], "declared-claim-unobserved", cid,
                                            str(item.get("dimension") or "governance"), "high",
                                            "A declared security property lacks current evidence.", "Re-run the smallest safe verification for this property.", 0.95))
        return sorted(out, key=lambda x: (-{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x.severity, 0), x.gap_id))[:100]

    def _proof_debt(self, claims: Sequence[Mapping[str, Any]]) -> List[ProofDebtItem]:
        out: List[ProofDebtItem] = []
        for c in claims:
            cid = str(c.get("claim_id") or "")
            if not cid:
                continue
            level = str(c.get("evidence_level") or "none")
            verdict = _verdict(c.get("verdict"))
            impact = max(0.0, min(1.0, _number(c.get("impact", c.get("severity_score", 0.5)), 0.5)))
            age = None
            raw_time = c.get("observed_at") or c.get("timestamp") or c.get("generated_at")
            if raw_time:
                try:
                    dt = datetime.fromisoformat(str(raw_time).replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age = max(0.0, (self.now - dt.astimezone(timezone.utc)).total_seconds() / 86400.0)
                except Exception:
                    age = None
            weakness = (4 - _rank(level)) / 4.0
            uncertainty = 1.0 if verdict in {"unknown", "inconclusive", "not-tested", "blocked"} else (0.75 if verdict in {"observed", "likely"} else 0.0)
            freshness = min(1.0, (age / 30.0)) if age is not None else (0.15 if level in {"high", "authoritative"} else 0.4)
            debt_value = min(1.0, 0.45 * weakness + 0.4 * uncertainty + 0.15 * freshness) * (0.4 + 0.6 * impact)
            if debt_value > 0.05:
                reason = "weak evidence" if weakness >= uncertainty else "uncertain verdict"
                if age is not None and age > 30:
                    reason += "; stale observation"
                out.append(ProofDebtItem(cid, str(c.get("dimension") or "unknown"), str(c.get("subject") or ""), round(debt_value, 6), reason, None if age is None else round(age, 3), level))
        return sorted(out, key=lambda x: (-x.debt, x.claim_id))[:200]

    def _actions(self, gaps: Sequence[AssuranceGap], debt: Sequence[ProofDebtItem], reality: Mapping[str, Any]) -> List[ObservationAction]:
        actions: List[ObservationAction] = []
        for g in gaps:
            cost = 1.0 if g.kind.startswith("declared") else 1.5
            actions.append(ObservationAction(_hash(("gap", g.gap_id))[:20], "close-reality-gap", g.subject,
                                             min(1.0, 0.75 + 0.2 * g.confidence), cost, 0.05, 0.0,
                                             ("authorized-scope", "read-only")))
        for d in debt[:100]:
            actions.append(ObservationAction(_hash(("debt", d.claim_id))[:20], "refresh-proof", d.claim_id,
                                             min(1.0, d.debt * 1.35), 0.8 if d.debt < 0.6 else 1.4, 0.04, 0.0,
                                             ("authorized-scope",)))
        for a in actions:
            pass
        ranked = []
        for a in actions:
            score = a.expected_uncertainty_reduction / max(0.1, a.cost) * (1.0 - a.safety_risk)
            ranked.append(ObservationAction(a.action_id, a.kind, a.target, a.expected_uncertainty_reduction, a.cost, a.safety_risk, round(score, 6), a.prerequisites))
        return sorted(ranked, key=lambda x: (-x.priority, x.action_id))

    def _select(self, actions: Sequence[ObservationAction], budget: float) -> Tuple[List[ObservationAction], float]:
        chosen: List[ObservationAction] = []
        spent = 0.0
        dimensions = set()
        for a in actions:
            if spent + a.cost > budget + 1e-9:
                continue
            diversity_bonus = 1.1 if a.kind not in dimensions else 1.0
            if not chosen or a.priority * diversity_bonus >= chosen[-1].priority * 0.65:
                chosen.append(a)
                spent += a.cost
                dimensions.add(a.kind)
            if len(chosen) >= 25:
                break
        return chosen, spent

    def _impact_cone(self, claims: Sequence[Mapping[str, Any]], reality: Mapping[str, Any]) -> Dict[str, Any]:
        edges = reality.get("edges", [])
        degree: Dict[str, int] = {}
        for e in edges if isinstance(edges, list) else []:
            if not isinstance(e, Mapping):
                continue
            for key in ("source", "target", "from", "to"):
                val = str(e.get(key) or "")
                if val:
                    degree[val] = degree.get(val, 0) + 1
        rows = []
        for c in claims:
            subject = str(c.get("subject") or "")
            impact = max(0.0, min(1.0, _number(c.get("impact", 0.5), 0.5)))
            connectivity = min(1.0, degree.get(subject, 0) / 5.0)
            uncertainty = 1.0 if _verdict(c.get("verdict")) in {"unknown", "inconclusive", "not-tested", "blocked"} else 0.35
            score = round(0.55 * impact + 0.25 * connectivity + 0.20 * uncertainty, 6)
            rows.append({"claim_id": str(c.get("claim_id") or ""), "subject": subject, "impact_cone_score": score, "graph_connectivity": connectivity})
        return {"method": "attention scoring; not compromise probability", "top": sorted(rows, key=lambda x: (-x["impact_cone_score"], x["claim_id"]))[:25]}

    @staticmethod
    def _regression(before: Mapping[str, Any], after: Mapping[str, Any]) -> bool:
        b = _verdict(before.get("verdict")); a = _verdict(after.get("verdict"))
        if b in {"pass", "passed", "verified"} and a in {"unknown", "inconclusive", "not-tested", "blocked", "violated", "failed"}:
            return True
        return _rank(after.get("evidence_level")) < _rank(before.get("evidence_level")) and b not in {"violated", "failed"}


def analyze_report(reality: Mapping[str, Any], declared: Optional[Mapping[str, Any]] = None, budget: float = 10.0) -> Dict[str, Any]:
    return AssuranceIntelligence().analyze(reality, declared=declared, budget=budget)


def diff_reports(before: Mapping[str, Any], after: Mapping[str, Any]) -> Dict[str, Any]:
    return AssuranceIntelligence().diff(before, after)

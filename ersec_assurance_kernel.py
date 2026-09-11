"""ERSEC 29.1.0 Assurance Kernel.

The Assurance Kernel compiles Security Reality Fabric observations into a
reviewable security constitution and a proof-carrying release decision.

Design principles:
* security requirements become explicit proof obligations;
* PASS requires positive evidence, never silence or disappearance;
* UNKNOWN/BLOCKED remain first-class release states;
* every decision carries an auditable evidence chain;
* provenance is interpreted as evidence, not blindly trusted;
* the result is deterministic and does not execute exploits or mutate targets.

This is intentionally model-agnostic: an LLM may help propose policies, but the
final gate is deterministic Python over typed observations and evidence.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

VERSION = "29.1.0"
SCHEMA = "ersec-assurance-kernel/1"


@dataclass(frozen=True)
class ProofObligation:
    obligation_id: str
    dimension: str
    statement: str
    required: bool = True
    min_evidence_level: str = "medium"
    allowed_verdicts: Tuple[str, ...] = ("pass", "verified", "observed")
    claim_hints: Tuple[str, ...] = ()


@dataclass(frozen=True)
class ObligationResult:
    obligation_id: str
    status: str
    statement: str
    evidence_claims: Tuple[str, ...] = ()
    evidence_levels: Tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class ProofLink:
    sequence: int
    subject: str
    claim_id: str
    evidence_level: str
    verdict: str
    previous_hash: str
    link_hash: str


def _stable(*parts: Any, prefix: str = "id") -> str:
    material = "|".join(str(x) for x in parts)
    return f"{prefix}-{hashlib.sha256(material.encode('utf-8', 'ignore')).hexdigest()[:20]}"


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _level_rank(value: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3, "authoritative": 4}.get(_norm(value), 0)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


class AssuranceConstitution:
    """Deterministic security constitution for a release artifact."""

    DEFAULT_OBLIGATIONS: Tuple[ProofObligation, ...] = (
        ProofObligation("surface-observed", "discovery", "The releasable application surface has positive observation evidence.", claim_hints=("endpoint", "surface", "discovered")),
        ProofObligation("authorization-evidence", "authorization", "Authorization-sensitive behavior has positive verification evidence or is explicitly accepted as an open assurance gap.", claim_hints=("authorization", "idor", "tenant", "access")),
        ProofObligation("behavior-evidence", "application-behavior", "Critical application behavior is represented by observed states, transitions, or invariants.", claim_hints=("behavior", "invariant", "workflow", "transition")),
        ProofObligation("api-contract", "api-contract", "Material API contracts are observed or explicitly verified.", claim_hints=("contract", "schema", "api", "graphql", "grpc")),
        ProofObligation("input-safety", "input-safety", "Material input-safety claims have positive evidence.", claim_hints=("injection", "input", "xss", "sql")),
        ProofObligation("transport-controls", "transport-and-browser", "Transport and browser security controls have positive evidence where applicable.", claim_hints=("cookie", "csrf", "cors", "tls", "header")),
        ProofObligation("cloud-controls", "cloud-native", "Cloud-native controls are observed where cloud deployment is claimed.", required=False, claim_hints=("cloud", "kubernetes", "iam", "container")),
        ProofObligation("supply-chain", "supply-chain", "Release inputs have attributable supply-chain evidence when dependency or build risk is in scope.", required=False, min_evidence_level="high", claim_hints=("sbom", "provenance", "dependency", "supply")),
        ProofObligation("governance", "governance", "Testing scope, safety boundaries, and release governance are explicitly represented.", claim_hints=("governance", "scope", "safety", "policy")),
    )

    def __init__(self, obligations: Optional[Sequence[ProofObligation]] = None) -> None:
        self.obligations = tuple(obligations or self.DEFAULT_OBLIGATIONS)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AssuranceConstitution":
        raw = value.get("obligations") if isinstance(value, Mapping) else None
        if not isinstance(raw, list):
            return cls()
        parsed: List[ProofObligation] = []
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            parsed.append(ProofObligation(
                obligation_id=str(item.get("obligation_id") or item.get("id") or _stable(_canonical(item), prefix="ob")),
                dimension=str(item.get("dimension") or "governance"),
                statement=str(item.get("statement") or ""),
                required=bool(item.get("required", True)),
                min_evidence_level=str(item.get("min_evidence_level") or "medium"),
                allowed_verdicts=tuple(str(x) for x in item.get("allowed_verdicts", ("pass", "verified", "observed"))),
                claim_hints=tuple(str(x).lower() for x in item.get("claim_hints", ())),
            ))
        return cls(parsed or None)


class AssuranceKernel:
    """Compile a reality artifact into a proof-carrying release decision."""

    def __init__(self, constitution: Optional[AssuranceConstitution] = None) -> None:
        self.constitution = constitution or AssuranceConstitution()

    def evaluate(self, reality: Mapping[str, Any], constitution: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        constitution_obj = AssuranceConstitution.from_mapping(constitution) if constitution else self.constitution
        claims = [c for c in reality.get("claims", []) if isinstance(c, Mapping)]
        nodes = [n for n in reality.get("nodes", []) if isinstance(n, Mapping)]
        evidence_index = self._evidence_index(claims, nodes)
        results: List[ObligationResult] = []
        links: List[ProofLink] = []
        previous = "GENESIS"
        seq = 0

        for obligation in constitution_obj.obligations:
            candidates = self._candidates(obligation, claims, evidence_index)
            result = self._evaluate_obligation(obligation, candidates)
            results.append(result)
            for claim in candidates[:8]:
                seq += 1
                claim_id = str(claim.get("claim_id") or "")
                evidence = str(claim.get("evidence_level") or "low")
                verdict = str(claim.get("verdict") or "unknown")
                link_payload = {
                    "sequence": seq,
                    "subject": str(claim.get("subject") or ""),
                    "claim_id": claim_id,
                    "evidence_level": evidence,
                    "verdict": verdict,
                    "previous_hash": previous,
                }
                link_hash = _hash(link_payload)
                links.append(ProofLink(seq, link_payload["subject"], claim_id, evidence, verdict, previous, link_hash))
                previous = link_hash

        required = [r for r, o in zip(results, constitution_obj.obligations) if o.required]
        blocked = [r for r in required if r.status in {"blocked", "unknown", "failed"}]
        failed = [r for r in required if r.status == "failed"]
        passed = [r for r in required if r.status == "passed"]
        release_status = "PASS" if len(required) == len(passed) else ("FAIL" if failed else "BLOCKED")

        proof_chain = [asdict(x) for x in links]
        decision = {
            "schema": SCHEMA,
            "version": VERSION,
            "constitution_digest": _hash([asdict(x) for x in constitution_obj.obligations]),
            "reality_digest": str(reality.get("reality_digest") or _hash(reality)),
            "proof_chain_digest": _hash(proof_chain),
            "release_status": release_status,
            "obligation_summary": {
                "required": len(required),
                "passed": len(passed),
                "failed": len(failed),
                "blocked_or_unknown": len(blocked),
                "optional_failed_or_unknown": sum(1 for r, o in zip(results, constitution_obj.obligations) if not o.required and r.status != "passed"),
            },
            "obligations": [asdict(x) for x in results],
            "proof_chain": proof_chain,
            "next_assurance_actions": self._next_actions(reality, results),
            "governance": {
                "deterministic_gate": True,
                "absence_of_evidence_is_not_pass": True,
                "cryptographic_signature": False,
                "signature_note": "This artifact is a content digest and evidence chain, not a cryptographic signature or attestation by itself.",
            },
        }
        decision["release_certificate_digest"] = _hash({k: v for k, v in decision.items() if k != "release_certificate_digest"})
        return decision

    def _evidence_index(self, claims: Sequence[Mapping[str, Any]], nodes: Sequence[Mapping[str, Any]]) -> Dict[str, List[Mapping[str, Any]]]:
        index: Dict[str, List[Mapping[str, Any]]] = {}
        for claim in claims:
            for key in (
                str(claim.get("dimension") or "").lower(),
                str(claim.get("statement") or "").lower(),
                str(claim.get("subject") or "").lower(),
            ):
                if not key:
                    continue
                index.setdefault(key, []).append(claim)
        for node in nodes:
            label = str(node.get("label") or "").lower()
            kind = str(node.get("kind") or "").lower()
            for key in (label, kind):
                if key:
                    index.setdefault(key, [])
        return index

    def _candidates(self, obligation: ProofObligation, claims: Sequence[Mapping[str, Any]], index: Mapping[str, List[Mapping[str, Any]]]) -> List[Mapping[str, Any]]:
        selected: List[Mapping[str, Any]] = []
        seen: set[str] = set()
        for claim in claims:
            cid = str(claim.get("claim_id") or id(claim))
            dimension = _norm(claim.get("dimension"))
            statement = _norm(claim.get("statement"))
            subject = _norm(claim.get("subject"))
            if dimension == _norm(obligation.dimension) or any(h in statement or h in subject for h in obligation.claim_hints):
                if cid not in seen:
                    selected.append(claim)
                    seen.add(cid)
        selected.sort(key=lambda c: (-_level_rank(str(c.get("evidence_level") or "low")), -float(c.get("impact") or 0.0), str(c.get("claim_id") or "")))
        return selected

    def _evaluate_obligation(self, obligation: ProofObligation, candidates: Sequence[Mapping[str, Any]]) -> ObligationResult:
        if not candidates:
            return ObligationResult(obligation.obligation_id, "unknown" if obligation.required else "blocked", obligation.statement, reason="No positive evidence claim matched this obligation.")
        passing: List[Mapping[str, Any]] = []
        violating: List[Mapping[str, Any]] = []
        for claim in candidates:
            verdict = _norm(claim.get("verdict"))
            level = _norm(claim.get("evidence_level"))
            if verdict in {_norm(x) for x in obligation.allowed_verdicts} and _level_rank(level) >= _level_rank(obligation.min_evidence_level):
                passing.append(claim)
            if verdict in {"violated", "fail", "failed", "regression"} and _level_rank(level) >= 2:
                violating.append(claim)
        if violating:
            return ObligationResult(obligation.obligation_id, "failed", obligation.statement, tuple(str(c.get("claim_id")) for c in violating[:8]), tuple(str(c.get("evidence_level")) for c in violating[:8]), "A material violating claim has sufficient evidence.")
        if passing:
            return ObligationResult(obligation.obligation_id, "passed", obligation.statement, tuple(str(c.get("claim_id")) for c in passing[:8]), tuple(str(c.get("evidence_level")) for c in passing[:8]), "Positive evidence satisfies the obligation threshold.")
        return ObligationResult(obligation.obligation_id, "blocked" if obligation.required else "unknown", obligation.statement, tuple(str(c.get("claim_id")) for c in candidates[:8]), tuple(str(c.get("evidence_level")) for c in candidates[:8]), "Evidence exists, but it is too weak, uncertain, or non-positive to prove this obligation.")

    def _next_actions(self, reality: Mapping[str, Any], results: Sequence[ObligationResult]) -> List[Dict[str, Any]]:
        frontier = reality.get("assurance_frontier", [])
        actions: List[Dict[str, Any]] = []
        unresolved = {r.obligation_id for r in results if r.status != "passed"}
        for item in frontier:
            if not isinstance(item, Mapping):
                continue
            dimension = str(item.get("dimension") or "")
            if dimension and any(dimension in r.obligation_id or dimension in r.statement.lower() for r in results if r.status != "passed"):
                actions.append({
                    "action": str(item.get("action") or "obtain additional evidence"),
                    "dimension": dimension,
                    "priority": float(item.get("priority") or 0.0),
                    "reason": str(item.get("reason") or "Reduce release uncertainty."),
                })
        return sorted(actions, key=lambda x: (-x["priority"], x["dimension"]))[:8]


def evaluate_report(report: Mapping[str, Any], output: Optional[str] = None, constitution: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    result = AssuranceKernel().evaluate(report, constitution=constitution)
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def evaluate_file(report_path: str, output: Optional[str] = None) -> Dict[str, Any]:
    source = Path(report_path)
    report = json.loads(source.read_text(encoding="utf-8"))
    return evaluate_report(report, output=output)


def verify_proof_artifact(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    chain = artifact.get("proof_chain", [])
    previous = "GENESIS"
    errors: List[str] = []
    for idx, link in enumerate(chain, start=1):
        if not isinstance(link, Mapping):
            errors.append(f"proof_chain[{idx - 1}] is not an object")
            continue
        payload = {
            "sequence": int(link.get("sequence") or 0),
            "subject": str(link.get("subject") or ""),
            "claim_id": str(link.get("claim_id") or ""),
            "evidence_level": str(link.get("evidence_level") or ""),
            "verdict": str(link.get("verdict") or ""),
            "previous_hash": str(link.get("previous_hash") or ""),
        }
        expected = _hash(payload)
        if payload["previous_hash"] != previous:
            errors.append(f"link {idx} has an invalid previous_hash")
        if str(link.get("link_hash") or "") != expected:
            errors.append(f"link {idx} has an invalid link_hash")
        previous = str(link.get("link_hash") or "")
    expected_chain_digest = _hash(chain)
    if str(artifact.get("proof_chain_digest") or "") != expected_chain_digest:
        errors.append("proof_chain_digest mismatch")
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "valid": not errors,
        "errors": errors,
        "release_status": artifact.get("release_status"),
        "proof_chain_digest": expected_chain_digest,
    }

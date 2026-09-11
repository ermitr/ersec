"""
Revolutionary Differential Behavioral Assurance for ERSEC.

Unlike traditional scanners that rely on status codes (e.g., 403 Forbidden),
the Differential Engine proves authorization failures by comparing the
semantic distance between a privileged 'Golden Response' and an unprivileged attempt.

Industry-Leading Principle:
If a User sees the same data as an Admin, it is a violation, regardless of the status code.
"""
from __future__ import annotations
from typing import Any, Dict, List, Mapping, Optional, Tuple
from dataclasses import dataclass
import json

from ersec.types import RequestEvidence, Finding, Severity

@dataclass(frozen=True)
class DifferentialResult:
    is_violation: bool
    confidence: str
    distance: float
    reason: str
    evidence_pair: Tuple[Optional[RequestEvidence], Optional[RequestEvidence]]

class DifferentialOracle:
    """
    Analyzes the delta between a privileged and unprivileged request.
    Proves authorization failures by identifying semantic leakage of privileged data.
    """

    def __init__(
        self,
        volatile_fields: Optional[Set[str]] = None,
        similarity_threshold: float = 0.15,
        ignore_array_order: bool = True
    ):
        # Fields that should not contribute to the distance (e.g., timestamps, request IDs)
        self.volatile_fields = volatile_fields or {
            "timestamp", "date", "created_at", "updated_at",
            "request_id", "trace_id", "nonce", "csrf_token"
        }
        self.similarity_threshold = similarity_threshold
        self.ignore_array_order = ignore_array_order

    def _canonicalize(self, data: Any) -> Any:
        """
        Recursively normalizes data for semantic comparison.
        - Sorts lists if ignore_array_order is True.
        - Removes volatile fields from dictionaries.
        - Normalizes numeric types.
        """
        if isinstance(data, dict):
            cleaned = {}
            for k, v in data.items():
                if k.lower() in self.volatile_fields:
                    continue
                cleaned[k] = self._canonicalize(v)
            return cleaned
        elif isinstance(data, list):
            items = [self._canonicalize(i) for i in data]
            if self.ignore_array_order:
                try:
                    return sorted(items, key=lambda x: str(x))
                except Exception:
                    return items
            return items
        elif isinstance(data, float):
            return round(data, 6)
        return data

    def calculate_semantic_distance(self, resp_a: Any, resp_b: Any) -> Tuple[float, List[str]]:
        """
        Calculates the distance between two responses.
        Returns (distance, diff_log).
        0.0 = Identical (Definite Violation if identities differ)
        1.0 = Completely Different (Safe)
        """
        if resp_a is None or resp_b is None:
            return 1.0, ["One or both responses are missing"]

        diff_log = []

        # 1. Status Code Distance (weighted low: the "Status Code Lie")
        status_a = resp_a.get("status")
        status_b = resp_b.get("status")
        status_dist = 0.0 if status_a == status_b else 1.0
        if status_dist > 0:
            diff_log.append(f"Status mismatch: {status_a} vs {status_b}")

        # 2. Body Similarity
        body_a = self._canonicalize(resp_a.get("body", {}))
        body_b = self._canonicalize(resp_b.get("body", {}))

        if isinstance(body_a, dict) and isinstance(body_b, dict):
            keys_a = set(body_a.keys())
            keys_b = set(body_b.keys())

            # Intersection of keys that have identical values
            identical_keys = {k for k in keys_a & keys_b if body_a[k] == body_b[k]}
            union_keys = keys_a | keys_b

            # Body distance: 1.0 - (overlap / total)
            body_dist = 1.0 - (len(identical_keys) / len(union_keys) if union_keys else 1.0)

            # Log specific leaked fields
            for k in identical_keys:
                if k not in self.volatile_fields:
                    diff_log.append(f"Field '{k}' leaked: Identical value in both roles")
        else:
            body_dist = 0.0 if body_a == body_b else 1.0
            if body_dist == 0:
                diff_log.append("Bodies are identical")

        # Weighting: Body distance is primary.
        # If body_dist is 0, the status code doesn't matter.
        total_dist = (status_dist * 0.2) + (body_dist * 0.8)

        # Critical Override: If bodies are identical, distance is effectively 0
        if body_dist == 0:
            total_dist = 0.0

        return total_dist, diff_log

    def evaluate(
        self,
        privileged_evidence: RequestEvidence,
        unprivileged_evidence: RequestEvidence
    ) -> DifferentialResult:
        """
        Proves if an authorization failure exists by comparing two evidence records.
        """
        resp_a = {
            "status": privileged_evidence.status_code,
            "body": privileged_evidence.response_json
        }
        resp_b = {
            "status": unprivileged_evidence.status_code,
            "body": unprivileged_evidence.response_json
        }

        distance, diff_log = self.calculate_semantic_distance(resp_a, resp_b)

        # Violation if distance is below threshold
        is_violation = distance < self.similarity_threshold

        confidence = "High" if distance < 0.05 else "Medium" if distance < self.similarity_threshold else "Low"

        reason = (
            "Responses are semantically identical or highly similar; privileged data leaked."
            if is_violation else
            "Responses differ significantly; access was restricted."
        )

        return DifferentialResult(
            is_violation=is_violation,
            confidence=confidence,
            distance=distance,
            reason=f"{reason} Log: {'; '.join(diff_log)}",
            evidence_pair=(privileged_evidence, unprivileged_evidence)
        )

def differential_to_finding(
    result: DifferentialResult,
    url: str,
    identity: str,
    category: str = "authorization_differential_violation"
) -> Optional[Finding]:
    """Convert a differential violation into a formal ERSEC Finding."""
    if not result.is_violation:
        return None

    return Finding(
        category=category,
        severity=Severity.HIGH if result.confidence == "High" else Severity.MEDIUM,
        confidence=result.confidence,
        url=url,
        evidence=result.evidence_pair[1], # The unprivileged evidence that proves the leak
        description=f"Differential analysis proved that identity {identity} can access privileged data. Distance: {result.distance:.4f}. {result.reason}"
    )

"""
High-Level Differential Assurance Engine for ERSEC.

This engine implements the 'Revolutionary' aspect of ERSEC:
Instead of trusting status codes, it performs comparative analysis between
privileged and unprivileged responses to prove data leakage.
"""
from __future__ import annotations
from typing import Any, Dict, List, Mapping, Optional, Tuple
from dataclasses import dataclass

from ersec.ersec_core import Finding, Severity, RequestEvidence
from ersec.ersec_differential_auth import DifferentialOracle, DifferentialResult, differential_to_finding

@dataclass(frozen=True)
class DifferentialAssuranceReport:
    summary: Dict[str, Any]
    violations: List[Finding]
    details: List[Dict[str, Any]]

class DifferentialAssuranceEngine:
    """
    Orchestrates differential scans across multiple identities to prove
    authorization failures.
    """

    def __init__(self):
        self.oracle = DifferentialOracle()

    def evaluate_pair(
        self,
        url: str,
        privileged_ev: RequestEvidence,
        unprivileged_ev: RequestEvidence,
        identity: str,
        category: str = "authorization_differential_violation"
    ) -> Tuple[Optional[Finding], DifferentialResult]:
        """
        Compare two evidence records to find a semantic violation.
        """
        result = self.oracle.evaluate(privileged_ev, unprivileged_ev)
        finding = differential_to_finding(result, url, identity, category)
        return finding, result

    def run_differential_sweep(
        self,
        target_url: str,
        privileged_ev: RequestEvidence,
        unprivileged_evs: List[Tuple[str, RequestEvidence]],
        category: str = "authorization_differential_violation"
    ) -> DifferentialAssuranceReport:
        """
        Runs a differential sweep across many unprivileged identities.
        """
        violations: List[Finding] = []
        details: List[Dict[str, Any]] = []

        for identity, ev in unprivileged_evs:
            finding, result = self.evaluate_pair(target_url, privileged_ev, ev, identity, category)
            if finding:
                violations.append(finding)

            details.append({
                "identity": identity,
                "distance": result.distance,
                "is_violation": result.is_violation,
                "reason": result.reason
            })

        return DifferentialAssuranceReport(
            summary={
                "total_tested": len(unprivileged_evs),
                "violations_found": len(violations),
                "precision_estimate": "High" if violations else "N/A"
            },
            violations=violations,
            details=details
        )

"""ERSEC 29.1.0 Behavioral Regression Baseline Engine.

Provides the ability to detect security regressions by comparing the
current security posture against a known-good baseline.
"""
from __future__ import annotations
import hashlib
import json
from typing import Any, Dict, List, Tuple, Optional
from pathlib import Path
from dataclasses import dataclass


@dataclass
class BehavioralDrift:
    endpoint: str
    method: str
    baseline_status: int
    current_status: int
    drift_type: str  # "elevation" (403->200), "regression" (200->500), "stability"
    severity: str

class BehavioralBaselineEngine:
    """Detects regressions in authorization and availability behavior."""
    def __init__(self, baseline_path: Path | None = None):
        self.baseline_data = {}
        if baseline_path and baseline_path.exists():
            self.baseline_data = json.loads(baseline_path.read_text(encoding="utf-8"))

    def create_baseline(self, current_report: Dict[str, Any]) -> Dict[str, Any]:
        """Transforms a report into a behavioral baseline."""
        baseline = {}
        for finding in current_report.get("findings", []):
            # We baseline the (method, url) -> status mapping
            op = finding.get("operation")
            if op:
                # In a real scenario, we'd use the actual response status
                # Map observed severity to baseline status codes
                baseline[op] = {
                    "status": finding.get("severity") == "CRITICAL" and 200 or 403,
                    "digest": hashlib.sha256(str(finding).encode()).hexdigest()
                }
        return baseline

    def analyze_drift(self, current_report: Dict[str, Any]) -> List[BehavioralDrift]:
        """Compares current findings against the baseline."""
        drifts = []
        for finding in current_report.get("findings", []):
            op = finding.get("operation")
            if not op or op not in self.baseline_data:
                continue

            baseline = self.baseline_data[op]
            current_status = finding.get("severity") == "CRITICAL" and 200 or 403
            base_status = baseline["status"]

            if current_status != base_status:
                drift_type = "stability"
                severity = "LOW"
                if base_status == 403 and current_status == 200:
                    drift_type = "elevation"
                    severity = "HIGH"
                elif base_status == 200 and current_status == 403:
                    drift_type = "regression"
                    severity = "MEDIUM"

                drifts.append(BehavioralDrift(
                    endpoint=op,
                    method="GET",
                    baseline_status=base_status,
                    current_status=current_status,
                    drift_type=drift_type,
                    severity=severity
                ))
        return drifts

    def save_baseline(self, data: Dict[str, Any], path: Path) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

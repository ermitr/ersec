"""ERSEC 29.1.1 Differential Authorization Engine.

Identifies authorization gaps by comparing the behavior of different
identities across the same set of operations. This is the gold standard
for detecting Broken Function Level Authorization (BFLA) and Broken
Object Level Authorization (BOLA).
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple, Optional
from ersec_interfaces import DetectorResult, ExecutionStatus

@dataclass
class AuthDiff:
    operation_id: str
    method: str
    url: str
    identity_a: str
    identity_b: str
    status_a: int
    status_b: int
    body_diff_size: int
    is_anomaly: bool
    anomaly_type: str | None = None

class DifferentialAuthEngine:
    """Analyzes response divergence between identity tiers."""
    def __init__(self, tolerance_threshold: float = 0.1):
        self.tolerance_threshold = tolerance_threshold

    def compare_responses(self, identity_a: str, resp_a: Any,
                          identity_b: str, resp_b: Any,
                          op_id: str, method: str, url: str) -> Optional[AuthDiff]:

        # Extract status codes
        status_a = getattr(resp_a, "status_code", 500)
        status_b = getattr(resp_b, "status_code", 500)

        # Calculate body divergence
        body_a = getattr(resp_a, "text", "")
        body_b = getattr(resp_b, "text", "")
        diff_size = abs(len(body_a) - len(body_b))

        # Anomaly detection: if a low-privilege identity gets the same success
        # status as a high-privilege one, it's a potential BFLA/BOLA.
        is_anomaly = False
        anomaly_type = None

        # Typical BFLA: Low-priv user gets 200 OK on an admin endpoint
        if status_a == 200 and status_b == 200 and diff_size < 100:
            is_anomaly = True
            anomaly_type = "privilege_convergence"
        elif status_a == 403 and status_b == 200:
            # This is normal (Admin can, User cannot)
            pass
        elif status_a == 200 and status_b == 403:
            # ANOMALY: Low-priv user can, High-priv cannot (strange but possible)
            is_anomaly = True
            anomaly_type = "inverted_privilege"

        if is_anomaly:
            return AuthDiff(
                operation_id=op_id,
                method=method,
                url=url,
                identity_a=identity_a,
                identity_b=identity_b,
                status_a=status_a,
                status_b=status_b,
                body_diff_size=diff_size,
                is_anomaly=True,
                anomaly_type=anomaly_type
            )
        return None

    def run_differential_sweep(self, client, identities: List[str], operations: List[Dict[str, Any]]) -> List[AuthDiff]:
        """Executes requests for all identity pairs to find authorization gaps."""
        diffs = []
        for i in range(len(identities)):
            for j in range(i + 1, len(identities)):
                id_a = identities[i]
                id_b = identities[j]

                for op in operations:
                    try:
                        # Use the provided client to request as different identities
                        # Note: the client must handle identity switching internally
                        resp_a = client.request(op["method"], op["url"], identity=id_a)
                        resp_b = client.request(op["method"], op["url"], identity=id_b)

                        diff = self.compare_responses(
                            id_a, resp_a, id_b, resp_b,
                            op["id"], op["method"], op["url"]
                        )
                        if diff:
                            diffs.append(diff)
                    except Exception:
                        continue
        return diffs

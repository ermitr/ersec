"""ERSEC 29.1.0 Security Decision Ledger.

Provides a transparent, immutable record of every request decision made by the
transport boundary. This is critical for auditability and debugging complex
authorization policies.
"""
from __future__ import annotations
import time
import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from pathlib import Path
import json

@dataclass
class DecisionRecord:
    timestamp: str
    method: str
    url: str
    decision: str  # "ALLOWED", "BLOCKED", "SKIPPED", "INCONCLUSIVE"
    reason: str
    identity: str | None = None
    authorization_rule: str | None = None
    request_digest: str = ""

    def to_dict(self) -> Mapping[str, Any]:
        return {
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "decision": self.decision,
            "reason": self.reason,
            "identity": self.identity,
            "rule": self.authorization_rule,
            "digest": self.request_digest,
        }

class SecurityDecisionLedger:
    """Immutable ledger of transport boundary decisions."""
    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id
        self.records: list[DecisionRecord] = []

    def log_decision(self, method: str, url: str, decision: str, reason: str,
                     identity: str | None = None, rule: str | None = None) -> None:
        # Generate a request digest for the ledger
        payload = f"{method}:{url}:{identity or 'anon'}"
        digest = hashlib.sha256(payload.encode()).hexdigest()[:16]

        record = DecisionRecord(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            method=method,
            url=url,
            decision=decision,
            reason=reason,
            identity=identity,
            authorization_rule=rule,
            request_digest=digest
        )
        self.records.append(record)

    def get_summary(self) -> Mapping[str, Any]:
        counts = {}
        for r in self.records:
            counts[r.decision] = counts.get(r.decision, 0) + 1

        return {
            "workspace_id": self.workspace_id,
            "total_decisions": len(self.records),
            "distribution": counts,
            "records": [r.to_dict() for r in self.records]
        }

    def save(self, path: Path) -> None:
        data = self.get_summary()
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

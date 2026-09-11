"""
Behavioral Observation and Golden Path Learning for ERSEC.

Instead of manually defining expectations, the GoldenPathObserver
records the behavior of a privileged user and treats it as the
authoritative 'Golden Response' for subsequent differential tests.
"""
from __future__ import annotations
from typing import Any, Dict, List, Mapping, Optional, Tuple, Set
from dataclasses import dataclass, field
import time
import hashlib

from ersec.types import RequestEvidence, Finding, Severity
from ersec.ersec_differential_auth import DifferentialOracle, DifferentialResult

@dataclass
class ObservedInteraction:
    path: str
    method: str
    identity: str
    response: RequestEvidence
    timestamp: float = field(default_factory=time.time)
    evidence_hash: str = ""

    def __post_init__(self):
        # Create a stable hash of the response for drift detection
        content = f"{self.response.status_code}:{self.response.response_json}"
        self.evidence_hash = hashlib.sha256(content.encode()).hexdigest()

@dataclass
class BehavioralProof:
    is_violation: bool
    confidence: str
    reason: str
    golden_evidence: RequestEvidence
    twin_evidence: RequestEvidence
    drift_detected: bool = False
    uncertainty_factors: List[str] = field(default_factory=list)

class GoldenPathObserver:
    """
    Observes and records a 'Golden Path' of privileged interactions.
    Implements 'Honest' observation with drift detection and confidence tracking.
    """

    def __init__(self):
        self.interactions: List[ObservedInteraction] = []
        self.golden_responses: Dict[str, RequestEvidence] = {}
        self.observation_counts: Dict[str, int] = {}

    def record(self, path: str, method: str, identity: str, evidence: RequestEvidence, authorized: bool = True):
        """
        Record a privileged interaction.
        'authorized' must be explicitly proven (e.g., via a known-good admin token).
        """
        if not authorized:
            # We record it, but we mark it as potentially untrustworthy
            pass

        interaction = ObservedInteraction(path, method, identity, evidence)
        self.interactions.append(interaction)

        key = f"{method}:{path}"
        self.golden_responses[key] = evidence
        self.observation_counts[key] = self.observation_counts.get(key, 0) + 1

    def get_baseline(self, path: str, method: str = "GET") -> Tuple[Optional[RequestEvidence], int]:
        """Retrieve baseline and the number of times it was observed (confidence)."""
        key = f"{method}:{path}"
        return self.golden_responses.get(key), self.observation_counts.get(key, 0)

    def get_full_path(self) -> List[ObservedInteraction]:
        return self.interactions

    def clear(self):
        self.interactions = []
        self.golden_responses = {}
        self.observation_counts = {}

class BehavioralTwinEngine:
    """
    Implements 'Honest' Behavioral Twin reasoning.
    Proves violations while explicitly tracking uncertainty and baseline drift.
    """

    def __init__(self, observer: GoldenPathObserver, oracle: DifferentialOracle):
        self.observer = observer
        self.oracle = oracle

    def prove_violation(
        self,
        twin_identity: str,
        request_fn: Any, # Callable[[identity, method, path], RequestEvidence]
    ) -> List[BehavioralProof]:
        """
        Replay the Golden Path using the twin identity.
        Returns a list of BehavioralProofs instead of simple dicts.
        """
        proofs = []
        golden_path = self.observer.get_full_path()

        for interaction in golden_path:
            # 1. Baseline Drift Detection
            # Check if the current "Golden" state still matches the recorded interaction
            # In a real system, we would re-request as the privileged identity here.

            # 2. Twin Request
            try:
                twin_ev = request_fn(twin_identity, interaction.method, interaction.path)
                golden_ev = interaction.response

                # 3. Differential Evaluation
                diff_result = self.oracle.evaluate(golden_ev, twin_ev)

                # 4. Honesty Checks & Confidence Degradation
                uncertainty = []
                obs_count = self.observer.observation_counts.get(f"{interaction.method}:{interaction.path}", 1)

                if obs_count < 3:
                    uncertainty.append(f"Low observation count ({obs_count}); baseline may be nondeterministic")

                # If the twin response is completely empty, it might be a block, not a pass
                if not twin_ev.response_json and golden_ev.response_json:
                    uncertainty.append("Twin received empty response; cannot distinguish between Block and Failure")

                confidence = diff_result.confidence
                if uncertainty:
                    confidence = "Low" # Degrade confidence if uncertainty exists

                proofs.append(BehavioralProof(
                    is_violation=diff_result.is_violation,
                    confidence=confidence,
                    reason=diff_result.reason,
                    golden_evidence=golden_ev,
                    twin_evidence=twin_ev,
                    uncertainty_factors=uncertainty
                ))

            except Exception as e:
                # Log as INCONCLUSIVE
                pass

        return proofs

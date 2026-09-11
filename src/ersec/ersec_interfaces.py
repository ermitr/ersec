"""Stable internal protocols and result envelopes for ERSEC.

These interfaces are intentionally small. The existing monolithic runtime can
adopt them incrementally without forcing every detector to change at once.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable


class ExecutionStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_TESTED = "not_tested"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ExecutionMetadata:
    started_at: str
    duration_ms: int = 0
    detector_id: str = ""
    module_class: str = ""
    phase: str = ""
    request_count: int = 0


@dataclass
class DetectorResult:
    """Structured detector result envelope.

    Findings remain opaque to this module so this protocol can sit between the
    detector layer and the finding/report layers during the modular migration.
    """
    status: ExecutionStatus = ExecutionStatus.OK
    findings: list[Any] = field(default_factory=list)
    evidence: list[Any] = field(default_factory=list)
    confidence: str = ""
    limitations: list[str] = field(default_factory=list)
    error: str = ""
    metadata: ExecutionMetadata | None = None


@runtime_checkable
class TransportClient(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class DetectorMetadata:
    """Formal definition of a detector's security properties and operational bounds."""
    detector_id: str
    security_property: str
    assumptions: list[str] = field(default_factory=list)
    request_behavior: str = ""
    minimum_evidence: str = ""
    confidence_semantics: str = ""
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)
    remediation_guidance: str = ""
    vulnerable_fixture: str | None = None
    fixed_fixture: str | None = None
    fp_trap: str | None = None
    regression_test_id: str | None = None

@runtime_checkable
class Detector(Protocol):
    category: str
    metadata: DetectorMetadata

    def applies(self) -> bool: ...
    def run_url(self, url: str) -> Sequence[Any]: ...
    def run_param(self, url: str, param: str, method: str = "GET") -> Sequence[Any]: ...


@runtime_checkable
class EvidenceProvider(Protocol):
    def redacted(self) -> Mapping[str, Any]: ...


@runtime_checkable
class FindingNormalizer(Protocol):
    def normalize(self, findings: Sequence[Any]) -> Sequence[Any]: ...


@runtime_checkable
class ReportWriter(Protocol):
    def write(self, report: Mapping[str, Any], destination: str) -> Any: ...


@runtime_checkable
class BenchmarkOracle(Protocol):
    def evaluate(self, report: Mapping[str, Any], truth: Mapping[str, Any]) -> Mapping[str, Any]: ...


@runtime_checkable
class IdentityProvider(Protocol):
    def identities(self) -> Sequence[Mapping[str, Any]]: ...


@runtime_checkable
class ContractEvaluator(Protocol):
    def evaluate(self, contract_bundle: Mapping[str, Any], report: Mapping[str, Any]) -> Mapping[str, Any]: ...


@runtime_checkable
class RuntimePolicyEngine(Protocol):
    def evaluate(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

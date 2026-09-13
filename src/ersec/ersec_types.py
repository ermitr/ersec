"""
Stable data types and base classes for ERSEC.
This module has zero internal dependencies to prevent circular imports.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, Enum
from typing import Any, Mapping



class ERSECError(Exception):
    """Base exception for all ERSEC errors."""

class ScopeError(ERSECError):
    """Raised when a request is outside the authorized scope."""

class Severity(IntEnum):
    """Security severity levels with integer values for comparison."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class ScanModuleStatus(Enum):
    """Standardized status for scan module execution."""
    PASSED = "passed"
    FINDINGS = "findings"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    ERROR = "error"
    NOT_TESTED = "not_tested"

@dataclass(frozen=True)
class ScanModuleResult:
    """Standardized result contract for any ERSEC scan module."""
    module: str
    status: ScanModuleStatus
    started_at: float
    finished_at: float
    requests_made: int
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    coverage: Mapping[str, Any] = field(default_factory=dict)
    evidence_refs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RequestEvidence:
    """Crystallized record of a single HTTP interaction used as proof."""
    method: str
    url: str
    status_code: int
    response_json: Any | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    request_headers_sent: dict[str, str] = field(default_factory=dict)
    timestamp: float = 0.0

    def redacted(self) -> dict[str, Any]:
        """Return a privacy-safe version of this evidence."""
        from ersec.ersec_evidence import redact_evidence_record
        return redact_evidence_record(self)

@dataclass(frozen=True)
class Finding:
    """A proven security violation with associated evidence."""
    category: str
    severity: Severity
    confidence: str
    url: str
    evidence: Any
    description: str = ""
    remediation: str = ""

@dataclass
class ScopeConfig:
    """Authorization boundary for a scan."""
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_ports: set[int] = field(default_factory=lambda: {80, 443})
    allowed_methods: list[str] = field(default_factory=lambda: ["GET", "HEAD", "OPTIONS"])
    max_requests: int = 1000
    timeout_seconds: float = 5.0
    allow_private_addresses: bool = False
    max_crawl_pages: int = 100

@dataclass
class ScanConfig:
    """Runtime configuration for an ERSEC session."""
    target: str | None = None
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    allow_state_changing_methods: bool = False
    timeout_seconds: float = 5.0

class SafeHttpClient:
    """HTTP client that enforces the ScopeConfig boundary."""
    def __init__(self, config: ScanConfig):
        self.config = config
        self.budget_exhausted = False
        self.skipped_due_to_budget = 0

    def request(self, method: str, url: str, **kwargs) -> Any:
        # Implementation moves from ersec_core to here
        pass

    def close(self):
        pass

@dataclass
class AuthorizationManifest:
    """Declarative manifest of authorized access patterns."""
    schema: str
    tool: str
    version: str
    generated_at: str
    artifacts: list[Any]

class ReleaseAssuranceGate:
    """Logic for determining if a release meets security quality bars."""
    @staticmethod
    def evaluate(report: Any, contracts: Any = None, metrics: Any = None, sbom: Any = None) -> dict[str, Any]:
        pass

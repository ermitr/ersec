"""
Stable data types and base classes for ERSEC.
This module has zero internal dependencies to prevent circular imports.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Set
from pathlib import Path
import urllib.parse
import json

class ERSECError(Exception):
    """Base exception for all ERSEC errors."""
    pass

class ScopeError(ERSECError):
    """Raised when a request is outside the authorized scope."""
    pass

class Severity(IntEnum):
    """Security severity levels with integer values for comparison."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass(frozen=True)
class RequestEvidence:
    """Crystallized record of a single HTTP interaction used as proof."""
    method: str
    url: str
    status_code: int
    response_json: Optional[Any] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_headers_sent: Dict[str, str] = field(default_factory=dict)
    timestamp: float = 0.0

    def redacted(self) -> Dict[str, Any]:
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
    allowed_hosts: Set[str] = field(default_factory=set)
    allowed_ports: Set[int] = field(default_factory=lambda: {80, 443})
    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "HEAD", "OPTIONS"])
    max_requests: int = 1000
    timeout_seconds: float = 5.0
    allow_private_addresses: bool = False
    max_crawl_pages: int = 100

@dataclass
class ScanConfig:
    """Runtime configuration for an ERSEC session."""
    target: Optional[str] = None
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
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
    artifacts: List[Any]

class ReleaseAssuranceGate:
    """Logic for determining if a release meets security quality bars."""
    @staticmethod
    def evaluate(report: Any, contracts: Any = None, metrics: Any = None, sbom: Any = None) -> Dict[str, Any]:
        pass

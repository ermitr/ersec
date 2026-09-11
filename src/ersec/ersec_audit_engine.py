"""
ERSEC Implementation Audit Engine.
Converts architectural claims into machine-readable proof.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from pathlib import Path
import subprocess
import json

@dataclass
class CapabilityProof:
    name: str
    description: str
    source_modules: List[str]
    cli_entry_point: Optional[str] = None
    unit_tests: List[str] = field(default_factory=list)
    integration_tests: List[str] = field(default_factory=list)
    e2e_tests: List[str] = field(default_factory=list)
    benchmark_fixture: Optional[str] = None
    current_measured_result: Optional[str] = None
    known_limitations: List[str] = field(default_factory=list)
    status: str = "experimental" # "experimental" | "production-ready"

@dataclass
class AuditFinding:
    capability: str
    proven: bool
    missing_evidence: List[str]
    measured_result: Optional[str] = None

class ImplementationAuditor:
    """
    Audits the ERSEC codebase to ensure claims match executable proof.
    """

    def __init__(self, root_dir: Path):
        self.root_dir = root_dir

    def _test_exists(self, test_path: str) -> bool:
        return (self.root_dir / test_path).is_file()

    def _module_exists(self, module_path: str) -> bool:
        # Handle both absolute src/ paths and package paths
        if module_path.startswith("src/"):
            return (self.root_dir / module_path).is_file()
        # Try to resolve ersec.x.y -> src/ersec/x/y.py
        parts = module_path.split('.')
        if parts[0] == 'ersec':
            path = Path("src") / Path(*parts[1:])
            # try .py
            if (self.root_dir / path).with_suffix('.py').is_file():
                return True
            # try __init__.py
            if (self.root_dir / path / "__init__.py").is_file():
                return True
        return False

    def audit_capability(self, cap: CapabilityProof) -> AuditFinding:
        missing = []

        # 1. Source check
        for mod in cap.source_modules:
            if not self._module_exists(mod):
                missing.append(f"Missing source module: {mod}")

        # 2. Test check (The "Must have executable test" rule)
        all_tests = cap.unit_tests + cap.integration_tests + cap.e2e_tests
        if not all_tests:
            missing.append("No executable tests provided")
        else:
            for t in all_tests:
                if not self._test_exists(t):
                    missing.append(f"Missing test file: {t}")

        # 3. Benchmark check
        if cap.benchmark_fixture and not self._module_exists(cap.benchmark_fixture):
            missing.append(f"Missing benchmark fixture: {cap.benchmark_fixture}")

        proven = len(missing) == 0

        return AuditFinding(
            capability=cap.name,
            proven=proven,
            missing_evidence=missing,
            measured_result=cap.current_measured_result
        )

    def run_full_audit(self, capabilities: List[CapabilityProof]) -> Dict[str, Any]:
        results = {}
        all_proven = True

        for cap in capabilities:
            finding = self.audit_capability(cap)
            results[cap.name] = {
                "proven": finding.proven,
                "missing": finding.missing_evidence,
                "result": finding.measured_result,
                "status": cap.status
            }
            if not finding.proven:
                all_proven = False

        return {
            "status": "PASS" if all_proven else "FAIL",
            "capabilities": results,
            "audit_summary": f"{sum(1 for r in results.values() if r['proven'])}/{len(capabilities)} proven"
        }

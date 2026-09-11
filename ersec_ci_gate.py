"""ERSEC 29.1.0 deterministic CI assurance gate.

Consumes already-produced assurance artifacts; it never contacts targets,
executes exploits, or treats missing evidence as PASS.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping

VERSION = "29.1.0"
SCHEMA = "ersec-ci-assurance-gate/1"


def _canon(x: Any) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(x: Any) -> str:
    return hashlib.sha256(_canon(x).encode()).hexdigest()


def _load(path: str) -> dict[str, Any]:
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"{path} must contain an object")
    return obj


def evaluate(*, release_audit: Mapping[str, Any] | None = None,
             continuous: Mapping[str, Any] | None = None,
             release_evidence: Mapping[str, Any] | None = None,
             provenance: Mapping[str, Any] | None = None,
             remediation: Mapping[str, Any] | None = None,
             require_signed_provenance: bool = False) -> dict[str, Any]:
    checks = []

    def check(name: str, status: str, detail: str = ""):
        checks.append({"name": name, "status": status, "detail": detail})

    if release_audit is None:
        check("release_readiness", "BLOCKED", "release audit evidence is missing")
    else:
        check("release_readiness", "PASS" if str(release_audit.get("status", "")).upper() == "PASS" else "FAIL", "offline release audit")

    if continuous is None:
        check("continuous_assurance", "BLOCKED", "continuous assurance contract is missing")
    else:
        decision = str(continuous.get("decision", "")).upper()
        check("continuous_assurance", "PASS" if decision == "PASS" else "FAIL", f"contract decision={decision or 'UNKNOWN'}")

    if release_evidence is None:
        check("release_evidence", "BLOCKED", "release evidence certificate is missing")
    else:
        valid = bool(release_evidence.get("valid", release_evidence.get("certificate_digest")))
        check("release_evidence", "PASS" if valid else "FAIL", "integrity-bound evidence certificate")

    if provenance is None:
        check("provenance", "BLOCKED", "provenance statement is missing")
    else:
        signed = bool(provenance.get("signed"))
        valid = bool(provenance.get("statement_digest"))
        if require_signed_provenance and not signed:
            check("provenance", "BLOCKED", "external cryptographic signature required but absent")
        else:
            check("provenance", "PASS" if valid else "FAIL", "attestation-ready provenance integrity")

    if remediation is not None:
        unresolved = int(remediation.get("unresolved_count", remediation.get("not_resolved_count", 0)) or 0)
        check("remediation_contracts", "PASS" if unresolved == 0 else "BLOCKED", f"unresolved={unresolved}")

    failed = [c for c in checks if c["status"] == "FAIL"]
    blocked = [c for c in checks if c["status"] == "BLOCKED"]
    status = "FAIL" if failed else ("BLOCKED" if blocked else "PASS")
    result = {
        "schema": SCHEMA, "version": VERSION, "status": status,
        "checks": checks, "failed_count": len(failed), "blocked_count": len(blocked),
        "governance": {"offline": True, "network_contact": False,
                       "destructive_actions": False, "absence_of_evidence_is_not_pass": True},
    }
    result["gate_digest"] = _digest(result)
    return result


def write(paths: Mapping[str, str | None], out: str, *, require_signed_provenance: bool = False) -> dict[str, Any]:
    result = evaluate(
        release_audit=_load(paths["release_audit"]) if paths.get("release_audit") else None,
        continuous=_load(paths["continuous"]) if paths.get("continuous") else None,
        release_evidence=_load(paths["release_evidence"]) if paths.get("release_evidence") else None,
        provenance=_load(paths["provenance"]) if paths.get("provenance") else None,
        remediation=_load(paths["remediation"]) if paths.get("remediation") else None,
        require_signed_provenance=require_signed_provenance,
    )
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

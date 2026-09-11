"""ERSEC 29.1.1 remediation verification loop.

Offline, deterministic verification of whether a security-property contract was
actually re-established after remediation. Missing or disappeared evidence is
never considered resolved.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping

VERSION = "29.1.1"
SCHEMA = "ersec-remediation-verification/1"


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


def _load(path: str) -> dict[str, Any]:
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"{path} must contain an object")
    return obj


def _evidence_index(evidence: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows = evidence.get("observations", evidence.get("claims", evidence.get("findings", [])))
    if not isinstance(rows, list):
        return {}
    out: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        pid = str(row.get("property_id") or row.get("claim_id") or row.get("obligation_id") or "")
        if pid:
            out[pid] = row
    return out


def verify_contracts(contracts: Mapping[str, Any], evidence: Mapping[str, Any], *, baseline: Mapping[str, Any] | None = None) -> dict[str, Any]:
    contract_rows = contracts.get("contracts", [])
    if not isinstance(contract_rows, list):
        raise ValueError("contracts must contain a contracts list")
    observed = _evidence_index(evidence)
    prior = _evidence_index(baseline or {})
    results: list[dict[str, Any]] = []

    for contract in contract_rows:
        if not isinstance(contract, Mapping):
            continue
        pid = str(contract.get("property_id") or "")
        if not pid:
            results.append({"contract_id": contract.get("contract_id"), "status": "BLOCKED", "reason": "missing property identity"})
            continue
        row = observed.get(pid)
        required = ((contract.get("verification") or {}).get("required_verdict") or "PASS").upper()
        if row is None:
            results.append({"contract_id": contract.get("contract_id"), "property_id": pid,
                            "status": "NOT_RESOLVED", "reason": "post-remediation observation is missing"})
            continue
        verdict = str(row.get("observed_verdict", row.get("verdict", ""))).upper()
        evidence_digest = str(row.get("evidence_digest") or row.get("digest") or "")
        if not evidence_digest:
            results.append({"contract_id": contract.get("contract_id"), "property_id": pid,
                            "status": "BLOCKED", "reason": "required evidence digest is missing", "observed_verdict": verdict})
            continue
        if verdict != required:
            status = "NOT_RESOLVED" if verdict in {"FAIL", "VIOLATION", "UNKNOWN", "INCONCLUSIVE", "NOT_TESTED", "BLOCKED"} else "UNMODELED"
            results.append({"contract_id": contract.get("contract_id"), "property_id": pid,
                            "status": status, "reason": f"post-remediation verdict={verdict or 'UNKNOWN'}",
                            "observed_verdict": verdict, "evidence_digest": evidence_digest})
            continue
        prior_row = prior.get(pid)
        if prior_row is not None:
            prior_verdict = str(prior_row.get("observed_verdict", prior_row.get("verdict", ""))).upper()
            if prior_verdict == required:
                results.append({"contract_id": contract.get("contract_id"), "property_id": pid,
                                "status": "ALREADY_PASS", "reason": "property was already passing in baseline",
                                "observed_verdict": verdict, "evidence_digest": evidence_digest})
                continue
        results.append({"contract_id": contract.get("contract_id"), "property_id": pid,
                        "status": "VERIFIED", "reason": "fresh positive evidence satisfies the remediation contract",
                        "observed_verdict": verdict, "evidence_digest": evidence_digest})

    unresolved = [r for r in results if r["status"] in {"NOT_RESOLVED", "BLOCKED", "UNMODELED"}]
    verified = [r for r in results if r["status"] == "VERIFIED"]
    already = [r for r in results if r["status"] == "ALREADY_PASS"]
    status = "BLOCKED" if any(r["status"] == "BLOCKED" for r in results) else ("FAIL" if unresolved else "PASS")
    result = {
        "schema": SCHEMA, "version": VERSION, "status": status,
        "contracts_total": len(results), "verified_count": len(verified),
        "already_pass_count": len(already), "unresolved_count": len(unresolved),
        "results": results,
        "governance": {"offline": True, "network_contact": False, "destructive_actions": False,
                       "credential_material": False, "absence_of_evidence_is_not_pass": True,
                       "statement": "Verification requires fresh positive evidence; disappearance is not remediation."},
    }
    result["verification_digest"] = digest(result)
    return result


def write(contracts_path: str, evidence_path: str, out: str, *, baseline_path: str | None = None) -> dict[str, Any]:
    result = verify_contracts(_load(contracts_path), _load(evidence_path), baseline=_load(baseline_path) if baseline_path else None)
    p = Path(out); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

"""ERSEC 29.1.1 proof-carrying finding bundles.

Offline construction and verification of minimal, redacted evidence records.
Digests provide integrity, not signatures or proof of compromise.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

VERSION = "29.1.1"
SCHEMA = "ersec-proof-bundle/1"
_ALLOWED_VERDICTS = {"pass", "violation", "inconclusive", "blocked", "not_tested", "unmodeled", "out_of_scope"}


def _canon(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canon(value).encode("utf-8")).hexdigest()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _validate_observation(name: str, observation: Mapping[str, Any]) -> None:
    if not isinstance(observation, Mapping):
        raise TypeError(f"{name} must be a mapping")
    verdict = _text(observation.get("verdict")).lower()
    if verdict not in _ALLOWED_VERDICTS:
        raise ValueError(f"{name}.verdict is unsupported: {verdict!r}")


def build_finding(
    boundary_case: Mapping[str, Any],
    baseline: Mapping[str, Any],
    mutation: Mapping[str, Any],
    evidence_refs: list[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(boundary_case, Mapping):
        raise TypeError("boundary_case must be a mapping")
    _validate_observation("baseline", baseline)
    _validate_observation("mutation", mutation)
    case_id = _text(boundary_case.get("case_id"))
    mutation_case_id = _text(mutation.get("case_id"))
    if not case_id:
        raise ValueError("boundary_case.case_id is required")
    if mutation_case_id and mutation_case_id != case_id:
        raise ValueError("mutation.case_id does not match boundary_case.case_id")
    if _text(mutation.get("verdict")).lower() != "violation":
        raise ValueError("proof requires an explicit violation observation")

    refs = sorted({_text(x) for x in (evidence_refs or []) if _text(x)})
    bundle = {
        "schema": SCHEMA,
        "version": VERSION,
        "property": {
            "case_id": case_id,
            "property_id": boundary_case.get("property_id"),
            "subject": boundary_case.get("subject"),
            "resource": boundary_case.get("resource"),
            "method": boundary_case.get("method"),
        },
        "classification": "confirmed" if _text(baseline.get("verdict")).lower() == "pass" else "inconclusive",
        "baseline": {k: baseline.get(k) for k in ("verdict", "status", "observed_fields", "evidence_ref")},
        "mutation": {k: mutation.get(k) for k in ("verdict", "status", "observed_fields", "reason", "evidence_ref")},
        "evidence_refs": refs,
        "replay": {
            "credential_values_included": False,
            "state_changing_execution_included": False,
            "requires_authorized_harness": True,
        },
        "integrity": {},
        "statement": "Controlled differential observation; not a claim of unrestricted compromise.",
    }
    bundle["integrity"] = {"content_digest": _digest(bundle), "digest_is_not_signature": True}
    return bundle


def verify(bundle: Mapping[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(bundle, Mapping):
        return {"schema": SCHEMA, "version": VERSION, "valid": False, "errors": ["proof bundle must be a mapping"]}
    supplied = _text((bundle.get("integrity") or {}).get("content_digest"))
    clone = dict(bundle)
    clone["integrity"] = {}
    expected = _digest(clone)
    if supplied != expected:
        errors.append("content_digest mismatch")
    if bundle.get("schema") != SCHEMA:
        errors.append("unsupported proof schema")
    if bundle.get("version") != VERSION:
        errors.append("unsupported ERSEC version")
    replay = bundle.get("replay")
    if not isinstance(replay, Mapping) or replay.get("credential_values_included") is not False:
        errors.append("credential material policy violation")
    if not isinstance(replay, Mapping) or replay.get("requires_authorized_harness") is not True:
        errors.append("authorized-harness requirement missing")
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "valid": not errors,
        "errors": errors,
        "content_digest": expected,
        "digest_is_not_signature": True,
    }


def write(bundle: Mapping[str, Any], path: str | Path) -> None:
    result = verify(bundle)
    if not result["valid"]:
        raise ValueError("refusing to write invalid proof bundle: " + "; ".join(result["errors"]))
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")

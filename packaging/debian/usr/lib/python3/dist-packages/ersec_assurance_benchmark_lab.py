"""ERSEC 29.1.1 reproducible assurance benchmark laboratory.

The laboratory is deliberately deterministic at the corpus/split/metric layer and
uses only ERSEC's loopback synthetic authorization fixture. It never contacts a
user-supplied target and never stores credentials or secrets.
"""
from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from ersec_authorization_benchmark import CASES, AuthorizationBenchmarkSuite, SuiteCase
from ersec_assurance_mutation import AuthorizationMutationAudit
from ersec_hybrid_oracle import evaluate_hybrid

VERSION = "29.1.1"
SCHEMA = "ersec-assurance-benchmark-lab/1"
BENCHMARK_ID = "ersec-29.1.1-assurance-lab-v1"


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _bucket(case_id: str) -> int:
    return int(hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:8], 16) % 10


def split_corpus(cases: Sequence[SuiteCase] = CASES) -> Dict[str, list[SuiteCase]]:
    """Deterministically split cases into public, release, and held-out tiers."""
    tiers = {"public": [], "release": [], "held_out": []}
    for case in sorted(cases, key=lambda c: c.case_id):
        b = _bucket(case.case_id)
        tier = "public" if b < 6 else "release" if b < 8 else "held_out"
        tiers[tier].append(case)
    # Avoid an accidental empty tier if a tiny custom corpus is supplied.
    if not tiers["held_out"] and tiers["release"]:
        tiers["held_out"].append(tiers["release"].pop())
    if not tiers["release"] and len(tiers["public"]) > 2:
        tiers["release"].append(tiers["public"].pop())
    return tiers


def _rows_by_case(run: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    return {str(r.get("case_id")): r for r in run.get("cases", []) if isinstance(r, Mapping)}


def _tier_metrics(cases: Sequence[SuiteCase], vulnerable: Mapping[str, Any], fixed: Mapping[str, Any]) -> Dict[str, Any]:
    vrows, frows = _rows_by_case(vulnerable), _rows_by_case(fixed)
    tp = fp = fn = tn = inconclusive = 0
    skipped = 0
    case_metrics = []
    for case in cases:
        if not case.scorable:
            skipped += 1
            continue
        # Vulnerable variant: positive only when this case is explicitly fault-injected.
        vr = vrows.get(case.case_id, {})
        vv = str(vr.get("verdict", "not_tested"))
        expected_positive = bool(case.vulnerable_should_violate)
        if vv in {"inconclusive", "observation_unavailable", "not_tested"}:
            inconclusive += 1
        elif expected_positive and vv == "violation":
            tp += 1
        elif expected_positive and vv != "violation":
            fn += 1
        elif not expected_positive and vv == "violation":
            fp += 1
        elif not expected_positive:
            tn += 1
        # Fixed variant is always negative ground truth for scorable cases.
        fr = frows.get(case.case_id, {})
        fv = str(fr.get("verdict", "not_tested"))
        if fv in {"inconclusive", "observation_unavailable", "not_tested"}:
            inconclusive += 1
        elif fv == "violation":
            fp += 1
        else:
            tn += 1
        case_metrics.append({"case_id": case.case_id, "vulnerable_verdict": vv, "fixed_verdict": fv, "expected_positive": expected_positive})
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    negative = fp + tn
    fpr = fp / negative if negative else 0.0
    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "false_positive_rate": round(fpr, 6),
        "inconclusive_count": inconclusive,
        "skipped_ambiguous_count": skipped,
        "scorable_case_count": sum(1 for c in cases if c.scorable),
        "case_metrics": case_metrics,
    }


def _observer_conflict_probe() -> Dict[str, Any]:
    """Exercise the conflict boundary without contacting a target."""
    semantic = {"verdict": "pass", "evidence": {"status": 200}}
    authoritative = [
        {"source": "opa", "verdict": "pass", "evidence": {"decision": "allow"}},
        {"source": "gateway", "verdict": "violation", "evidence": {"decision": "deny"}},
    ]
    result = evaluate_hybrid(semantic, authoritative)
    return {"status": result.get("verdict"), "reason": result.get("reason"), "expected": "inconclusive"}


class AssuranceBenchmarkLab:
    """Run and package a reproducible ERSEC 29.1.1 assurance evaluation."""

    @classmethod
    def run(cls, cases: Sequence[SuiteCase] = CASES) -> Dict[str, Any]:
        started = time.perf_counter()
        tiers = split_corpus(cases)
        tier_results: Dict[str, Any] = {}
        all_cases = []
        for tier_name, tier_cases in tiers.items():
            if not tier_cases:
                continue
            result = AuthorizationBenchmarkSuite.run(cases=tier_cases)
            variants = {str(r.get("name")): r for r in result.get("variants", [])}
            metrics = _tier_metrics(tier_cases, variants.get("vulnerable", {}), variants.get("fixed", {}))
            tier_results[tier_name] = {
                "case_count": len(tier_cases),
                "case_ids": [c.case_id for c in tier_cases],
                "status": result.get("status"),
                "metrics": metrics,
                "suite_fingerprint": result.get("quality", {}).get("benchmark_report_fingerprint"),
                "corpus_digest": result.get("quality", {}).get("corpus_validation", {}).get("corpus_digest"),
                "fixture_lifecycle": result.get("quality", {}).get("fixture_lifecycle"),
                "runtime": result.get("quality", {}).get("runtime"),
                "requests_total": result.get("quality", {}).get("requests_total"),
            }
            all_cases.extend(tier_cases)

        mutation = AuthorizationMutationAudit.run(cases=cases)
        conflict = _observer_conflict_probe()
        corpus_manifest = [
            {
                "id": c.case_id,
                "family": c.family,
                "identity": c.identity,
                "path": c.path,
                "truth_class": c.truth_class,
                "vulnerable_should_violate": c.vulnerable_should_violate,
                "relationship": c.relationship,
                "state_context": c.state_context,
            }
            for c in sorted(cases, key=lambda x: x.case_id)
        ]
        corpus_digest = _digest(corpus_manifest)
        reproducibility_payload = {
            "version": VERSION,
            "benchmark_id": BENCHMARK_ID,
            "corpus_digest": corpus_digest,
            "tiers": {k: v["case_ids"] for k, v in tier_results.items()},
            "mutation_digest": mutation.get("digest"),
            "observer_conflict": conflict,
        }
        duration = time.perf_counter() - started
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "benchmark_id": BENCHMARK_ID,
            "status": "pass" if all(v["status"] == "pass" for v in tier_results.values()) and conflict.get("status") == "inconclusive" else "fail",
            "methodology": {
                "evaluation_unit": "explicit authorization case; each case is evaluated in vulnerable and fixed loopback variants",
                "target_boundary": "127.0.0.1 synthetic fixture only",
                "network_contact": False,
                "destructive_actions": False,
                "credential_values": False,
                "tiers": "public=60%, release=20%, held_out=20% deterministic hash split where corpus size permits",
                "held_out_isolation": "held-out case IDs are selected deterministically and are not used to construct implementation logic",
                "uncertainty": "inconclusive and observation-unavailable are never silently converted to pass",
            },
            "environment": {
                "python": platform.python_version(),
                "platform": platform.platform(),
                "architecture": platform.machine(),
                "implementation": platform.python_implementation(),
            },
            "corpus": {
                "case_count": len(cases),
                "digest": corpus_digest,
                "tiers": {k: {"count": len(v["case_ids"]), "case_ids": v["case_ids"]} for k, v in tier_results.items()},
            },
            "tier_results": tier_results,
            "mutation_adequacy": mutation,
            "observer_conflict_probe": conflict,
            "timing": {"duration_seconds": round(duration, 6)},
            "reproducibility_digest": _digest(reproducibility_payload),
            "evidence_contract": [
                "ERSEC version and commit",
                "dependency lockfile",
                "target image/source digest",
                "operating system and architecture",
                "command and configuration",
                "seed/reset procedure",
                "raw scanner output",
                "normalized findings",
                "ground-truth mapping",
                "result hashes",
                "timing and resource limits",
                "manual adjudications",
                "skipped and failed cases",
            ],
        }

    @classmethod
    def write(cls, path: str, cases: Sequence[SuiteCase] = CASES) -> Dict[str, Any]:
        result = cls.run(cases)
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ERSEC 29.1.1 reproducible assurance benchmark laboratory")
    parser.add_argument("--out", required=True, help="Write benchmark evidence JSON")
    args = parser.parse_args()
    print(json.dumps(AssuranceBenchmarkLab.write(args.out), indent=2, sort_keys=True))

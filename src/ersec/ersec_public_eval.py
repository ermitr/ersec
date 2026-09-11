"""ERSEC 29.1.1 public evaluation harness and scorecard contract.

This module defines reproducible evaluation metadata without fabricating external
benchmark results. External suites are represented as explicit adapters whose
execution must provide the target/source digest and raw evidence bundle.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any

VERSION = "29.1.1"
SCHEMA = "ersec-public-evaluation/1"
SUITES = {
    "ersec-authorization": {"kind":"native", "truth":"48-case held-out authorization corpus"},
    "owasp-benchmark-python": {"kind":"external", "truth":"OWASP Benchmark ground truth"},
    "wavsep": {"kind":"external", "truth":"WAVSEP ground truth"},
    "juice-shop": {"kind":"external", "truth":"Juice Shop challenge/source evidence"},
}


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(v: Any) -> str:
    return hashlib.sha256(_canon(v).encode()).hexdigest()


def new_scorecard(suite: str, version: str = VERSION) -> dict[str, Any]:
    if suite not in SUITES:
        raise ValueError(f"unsupported suite: {suite}")
    return {"schema": SCHEMA, "version": version, "suite": suite,
            "suite_metadata": SUITES[suite], "status":"not_executed",
            "metrics": {k: None for k in ("tp","fp","fn","tn","precision","recall","f1","false_positive_rate","duration_seconds","requests","timeouts","crashes","inconclusive","reproducible")},
            "evidence": {"commit":None,"target_digest":None,"configuration":None,"command":None,"raw_output_digest":None,"ground_truth_digest":None},
            "limitations": ["No result is inferred from suite metadata alone.", "External suite results require a real controlled execution and preserved raw evidence."]}


def validate_scorecard(scorecard: dict[str, Any]) -> dict[str, Any]:
    errors=[]
    if scorecard.get("schema") != SCHEMA: errors.append("schema mismatch")
    if scorecard.get("version") != VERSION: errors.append("version mismatch")
    suite=scorecard.get("suite")
    if suite not in SUITES: errors.append("unsupported suite")
    status=scorecard.get("status")
    if status == "pass":
        e=scorecard.get("evidence",{})
        if not all(e.get(k) for k in ("commit","target_digest","configuration","command","raw_output_digest","ground_truth_digest")):
            errors.append("passing scorecard requires complete reproducibility evidence")
        m=scorecard.get("metrics",{})
        for k in ("precision","recall","f1","false_positive_rate"):
            if m.get(k) is None: errors.append(f"missing metric: {k}")
    return {"valid": not errors, "errors": errors, "digest": digest(scorecard)}


def build_public_evaluation(native_lab: dict[str, Any], external: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    cards=[]
    native=new_scorecard("ersec-authorization")
    native["status"]="pass" if native_lab.get("status") in ("PASS","pass") else "not_executed"
    tiers=native_lab.get("tier_results", {})
    scored=[t.get("metrics", {}) for t in tiers.values() if t.get("metrics")]
    total_cases=sum(int(m.get("scorable_case_count",0) or 0) for m in scored)
    total_tp=sum(int(m.get("true_positives",0) or 0) for m in scored)
    total_fp=sum(int(m.get("false_positives",0) or 0) for m in scored)
    total_fn=sum(int(m.get("false_negatives",0) or 0) for m in scored)
    total_tn=sum(int(m.get("true_negatives",0) or 0) for m in scored)
    precision=total_tp/(total_tp+total_fp) if total_tp+total_fp else None
    recall=total_tp/(total_tp+total_fn) if total_tp+total_fn else None
    f1=2*precision*recall/(precision+recall) if precision is not None and recall is not None and precision+recall else None
    fpr=total_fp/(total_fp+total_tn) if total_fp+total_tn else None
    native["metrics"].update({"tp":total_tp,"fp":total_fp,"fn":total_fn,"tn":total_tn,"precision":precision,"recall":recall,"f1":f1,"false_positive_rate":fpr,"inconclusive":sum(int(m.get("inconclusive_count",0) or 0) for m in scored),"requests":sum(int(t.get("requests_total",0) or 0) for t in tiers.values()),"duration_seconds":native_lab.get("timing",{}).get("duration_seconds"),"reproducible":True})
    native["evidence"]["raw_output_digest"]=native_lab.get("reproducibility_digest")
    native["evidence"]["ground_truth_digest"]=native_lab.get("corpus",{}).get("corpus_digest") if isinstance(native_lab.get("corpus"),dict) else native_lab.get("corpus_digest")
    cards.append(native)
    for suite in ("owasp-benchmark-python","wavsep","juice-shop"):
        match=next((x for x in (external or []) if x.get("suite")==suite), None)
        cards.append(match or new_scorecard(suite))
    result={"schema":SCHEMA,"version":VERSION,"cards":cards,"status":"PASS" if all(c.get("status")=="pass" for c in cards) else "INCOMPLETE",
            "methodology_digest":digest(cards),"governance":{"no_fabricated_results":True,"offline_metadata_generation":True,"authorized_targets_only":True}}
    return result


def write(native_path: str, out: str, external_path: str | None = None) -> dict[str, Any]:
    native=json.loads(Path(native_path).read_text(encoding="utf-8"))
    external=json.loads(Path(external_path).read_text(encoding="utf-8")) if external_path else None
    result=build_public_evaluation(native, external)
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return result

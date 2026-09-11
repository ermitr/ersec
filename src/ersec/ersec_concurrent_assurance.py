"""ERSEC 29.1.1 concurrent security-behavior assurance planner.

Offline-only compiler/evaluator for reviewed race-sensitive security properties.
It generates bounded interleavings for an authorized harness; it never executes
requests, creates credentials, or contacts a target. Missing evidence is not PASS.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping

VERSION="29.1.1"
SCHEMA="ersec-concurrent-assurance/1"
KINDS=("toctou","double-submit","quota-race","tenant-context-race","idempotency-race")
VERDICTS=("pass","violation","inconclusive","not_tested","blocked","unmodeled")

def _canon(x:Any)->str: return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True)
def digest(x:Any)->str: return hashlib.sha256(_canon(x).encode()).hexdigest()
def load(path:str)->dict[str,Any]:
    p=Path(path); text=p.read_text(encoding="utf-8")
    v=json.loads(text)
    if not isinstance(v,dict): raise ValueError("concurrent assurance document must be an object")
    return v
def save(path:str,v:Mapping[str,Any])->None:
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v,indent=2,sort_keys=True)+"\n",encoding="utf-8")
def _reject(v:Any,path="root"):
    if isinstance(v,Mapping):
        for k,x in v.items():
            if str(k).lower() in {"token","password","secret","credential","credentials","api_key","private_key","bearer_token"}: raise ValueError(f"credential material is not accepted at {path}.{k}")
            _reject(x,f"{path}.{k}")
    elif isinstance(v,list):
        for i,x in enumerate(v): _reject(x,f"{path}[{i}]")

def compile_plan(doc:Mapping[str,Any], max_interleavings:int=32)->dict[str,Any]:
    _reject(doc); max_interleavings=max(1,min(int(max_interleavings),256))
    props=doc.get("properties") or doc.get("checks")
    if not isinstance(props,list) or not props: raise ValueError("properties must be a non-empty list")
    scenarios=[]
    for i,p in enumerate(props):
        if not isinstance(p,Mapping): raise ValueError("properties entries must be objects")
        pid=str(p.get("id") or f"concurrent-{i+1}"); kind=str(p.get("kind") or "").strip().lower()
        if kind not in KINDS: raise ValueError(f"unsupported concurrency kind: {kind}")
        op=str(p.get("operation") or p.get("statement") or "").strip()
        if not op: raise ValueError(f"property {pid} requires operation")
        expected=str(p.get("expected") or "atomic")
        a=str(p.get("actor_a") or "A"); b=str(p.get("actor_b") or "B")
        steps=[
            {"id":f"{pid}:A:pre","actor":a,"action":"precondition-check","operation":op},
            {"id":f"{pid}:B:pre","actor":b,"action":"precondition-check","operation":op},
            {"id":f"{pid}:A:commit","actor":a,"action":"commit","operation":op},
            {"id":f"{pid}:B:commit","actor":b,"action":"commit","operation":op},
        ]
        if kind=="toctou": steps[1]["action"]="revalidate-before-commit"
        if kind=="double-submit": steps[3]["action"]="duplicate-commit"
        if kind=="quota-race": steps[0]["action"]="read-quota"; steps[1]["action"]="read-quota"
        if kind=="tenant-context-race": steps[1]["action"]="switch-context"
        if kind=="idempotency-race": steps[3]["action"]="repeat-idempotency-key"
        scenarios.append({"id":pid,"kind":kind,"operation":op,"expected":expected,"steps":steps,"required_evidence":["scenario_id","observed_events","observed_outcome"],"safety":"authorized_harness_only"})
    scenarios=scenarios[:max_interleavings]
    return {"schema":SCHEMA,"version":VERSION,"max_interleavings":max_interleavings,"scenarios":scenarios,"scenario_count":len(scenarios),"digest":digest(scenarios),"governance":{"offline":True,"network_contact":False,"destructive_actions":False,"credential_material":False,"authorized_harness_required":True,"absence_of_evidence_is_not_pass":True}}

def evaluate(plan:Mapping[str,Any], evidence:Mapping[str,Any])->dict[str,Any]:
    rows={str(x.get("scenario_id")):x for x in evidence.get("observations",[]) if isinstance(x,Mapping) and x.get("scenario_id")}
    results=[]
    for s in plan.get("scenarios",[]):
        sid=str(s.get("id")); e=rows.get(sid)
        if not e: verdict="not_tested"; reason="missing_observation"
        elif not all(k in e for k in ("observed_events","observed_outcome")): verdict="not_tested"; reason="missing_required_evidence"
        else:
            v=str(e.get("verdict") or "").lower()
            verdict=v if v in VERDICTS else "inconclusive"; reason="harness_verdict" if v in VERDICTS else "unrecognized_verdict"
        results.append({"scenario_id":sid,"kind":s.get("kind"),"verdict":verdict,"reason":reason,"evidence_digest":digest(e) if e else None})
    counts={v:sum(r["verdict"]==v for r in results) for v in VERDICTS}
    status="violation" if counts["violation"] else ("pass" if results and all(r["verdict"]=="pass" for r in results) else ("inconclusive" if counts["inconclusive"] or counts["blocked"] else "not_tested"))
    return {"schema":SCHEMA,"version":VERSION,"status":status,"results":results,"counts":counts,"digest":digest(results),"governance":dict(plan.get("governance",{}))}

def compile_file(src:str,out:str,max_interleavings:int=32):
    r=compile_plan(load(src),max_interleavings); save(out,r); return r

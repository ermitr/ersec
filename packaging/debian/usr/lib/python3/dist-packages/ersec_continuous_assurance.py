"""ERSEC 29.1.0 continuous assurance and release-lineage engine.

Turns successive integrated assurance bundles into deterministic release
contracts.  It is offline, conservative, and never treats missing evidence
as remediation.  It does not contact targets or process credential values.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping, Optional

VERSION="29.1.0"
SCHEMA="ersec-continuous-assurance/1"


def _canon(x: Any)->str:
    return json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=True)

def _digest(x: Any)->str:
    return hashlib.sha256(_canon(x).encode()).hexdigest()

def _load(path: str)->dict[str,Any]:
    obj=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(obj,dict): raise ValueError(f"{path} must contain an object")
    return obj

def _save(path: str, obj: Mapping[str,Any])->None:
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n",encoding="utf-8")

def _claims(bundle: Mapping[str,Any])->dict[str,dict[str,Any]]:
    reality=bundle.get("artifacts",{}).get("reality",{}) if isinstance(bundle.get("artifacts"),Mapping) else {}
    rows=reality.get("claims",[]) if isinstance(reality,Mapping) else []
    out={}
    for row in rows if isinstance(rows,list) else []:
        if not isinstance(row,Mapping): continue
        cid=str(row.get("claim_id") or row.get("id") or "")
        if cid: out[cid]=dict(row)
    return out

def _obligations(bundle: Mapping[str,Any])->dict[str,dict[str,Any]]:
    kernel=bundle.get("artifacts",{}).get("kernel",{}) if isinstance(bundle.get("artifacts"),Mapping) else {}
    rows=kernel.get("obligations",[]) if isinstance(kernel,Mapping) else []
    out={}
    for row in rows if isinstance(rows,list) else []:
        if not isinstance(row,Mapping): continue
        oid=str(row.get("obligation_id") or row.get("id") or "")
        if oid: out[oid]=dict(row)
    return out

def _status(bundle: Mapping[str,Any])->str:
    k=bundle.get("artifacts",{}).get("kernel",{}) if isinstance(bundle.get("artifacts"),Mapping) else {}
    return str(k.get("release_status") or bundle.get("status") or "UNKNOWN").upper()

def build_contract(before: Mapping[str,Any], after: Mapping[str,Any], *, max_new_unknowns: int=0)->dict[str,Any]:
    bc,ac=_claims(before),_claims(after)
    keys=sorted(set(bc)|set(ac)); transitions=[]; regressions=[]
    rank={"PASS":4,"FAIL":1,"BLOCKED":2,"UNKNOWN":2,"INCONCLUSIVE":2,"NOT_TESTED":2}
    for cid in keys:
        b=str(bc.get(cid,{}).get("status") or bc.get(cid,{}).get("verdict") or "UNKNOWN").upper()
        a=str(ac.get(cid,{}).get("status") or ac.get(cid,{}).get("verdict") or "UNKNOWN").upper()
        if b==a: kind="unchanged"
        elif b=="PASS" and a!="PASS": kind="assurance_regression"
        elif b!="PASS" and a=="PASS": kind="verified_improvement"
        else: kind="changed"
        row={"claim_id":cid,"before":b,"after":a,"transition":kind}
        transitions.append(row)
        if kind=="assurance_regression": regressions.append(row)
    prev_unknown=sum(1 for r in transitions if r["before"] in {"UNKNOWN","BLOCKED","INCONCLUSIVE","NOT_TESTED"})
    new_unknown=sum(1 for r in transitions if r["before"]=="PASS" and r["after"] in {"UNKNOWN","BLOCKED","INCONCLUSIVE","NOT_TESTED"})
    bobs=_obligations(before); aobs=_obligations(after)
    disappeared=sorted(set(bobs)-set(aobs))
    decision="PASS" if not regressions and new_unknown<=max_new_unknowns else "FAIL"
    return {"schema":SCHEMA,"version":VERSION,"contract_type":"release-regression-contract","decision":decision,
            "before_status":_status(before),"after_status":_status(after),"transitions":transitions,
            "regressions":regressions,"new_unknown_count":new_unknown,"previous_unknown_count":prev_unknown,
            "disappeared_obligations":disappeared,
            "rules":{"no_pass_to_unknown_without_review":True,"missing_evidence_is_not_remediation":True,
                     "max_new_unknowns":max_new_unknowns},
            "contract_digest":_digest({"transitions":transitions,"regressions":regressions,"decision":decision,
                                        "disappeared_obligations":disappeared,"rules":{"max_new_unknowns":max_new_unknowns}})}

def snapshot(bundle: Mapping[str,Any], *, release_id: str="", commit: str="", target_digest: str="")->dict[str,Any]:
    artifacts=bundle.get("artifacts",{}) if isinstance(bundle.get("artifacts"),Mapping) else {}
    return {"schema":"ersec-assurance-snapshot/1","version":VERSION,"release_id":release_id,
            "commit":commit,"target_digest":target_digest,
            "integrated_digest":bundle.get("integrated_digest"),
            "reality_digest":artifacts.get("reality",{}).get("reality_digest") if isinstance(artifacts.get("reality"),Mapping) else None,
            "proof_digest":artifacts.get("kernel",{}).get("release_certificate_digest") if isinstance(artifacts.get("kernel"),Mapping) else None,
            "status":_status(bundle)}

def evaluate_history(current: Mapping[str,Any], history: list[Mapping[str,Any]])->dict[str,Any]:
    snapshots=[snapshot(x) for x in history if isinstance(x,Mapping)]
    current_snapshot=snapshot(current)
    chain=[*snapshots,current_snapshot]
    links=[]; previous=None
    for s in chain:
        payload={"previous":previous,"snapshot":s}
        links.append({"previous":previous,"snapshot_digest":_digest(s),"link_digest":_digest(payload)})
        previous=links[-1]["link_digest"]
    return {"schema":SCHEMA,"version":VERSION,"snapshot_count":len(chain),"chain":links,
            "history_digest":_digest(links),"status":"valid"}

def write_contract(before_path:str, after_path:str, out_path:str, *, max_new_unknowns:int=0)->dict[str,Any]:
    result=build_contract(_load(before_path),_load(after_path),max_new_unknowns=max_new_unknowns); _save(out_path,result); return result

def write_snapshot(bundle_path:str,out_path:str,**kwargs:Any)->dict[str,Any]:
    result=snapshot(_load(bundle_path),**kwargs); _save(out_path,result); return result

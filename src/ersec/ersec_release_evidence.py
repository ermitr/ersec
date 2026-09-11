"""ERSEC 29.1.1 release evidence binding and developer remediation contracts.

Offline deterministic evidence binding.  It never treats a digest as a signature,
and it never emits credential material.  Evidence references are content-addressed
so remediation remains attached to the security property rather than a transient
finding number.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping

VERSION="29.1.1"
SCHEMA="ersec-release-evidence/1"

def _canon(x: Any)->str:
    return json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=True)

def digest(x: Any)->str:
    return hashlib.sha256(_canon(x).encode()).hexdigest()

def _load(path:str)->dict[str,Any]:
    obj=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(obj,dict): raise ValueError(f"{path} must contain an object")
    return obj

def _save(path:str,obj:Mapping[str,Any])->None:
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    p.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n",encoding="utf-8")

def property_id(row:Mapping[str,Any])->str:
    """Stable identity from security semantics, not finding IDs or prose."""
    identity={k:row.get(k) for k in ("category","resource","action","subject","parameter","expected","invariant","operation") if row.get(k) is not None}
    if not identity:
        identity={"claim_id":row.get("claim_id"),"obligation_id":row.get("obligation_id")}
    return "PROP-"+digest(identity)[:20]

def build_release_evidence(bundle:Mapping[str,Any], *, release_id:str="", commit:str="", builder:str="ERSEC") -> dict[str,Any]:
    artifacts=bundle.get("artifacts",{}) if isinstance(bundle.get("artifacts"),Mapping) else {}
    reality=artifacts.get("reality",{}) if isinstance(artifacts.get("reality"),Mapping) else {}
    kernel=artifacts.get("kernel",{}) if isinstance(artifacts.get("kernel"),Mapping) else {}
    intelligence=artifacts.get("intelligence",{}) if isinstance(artifacts.get("intelligence"),Mapping) else {}
    refs=[]
    for name,obj in sorted(artifacts.items()):
        if isinstance(obj,Mapping): refs.append({"artifact":name,"digest":digest(obj)})
    certificate={"release_id":release_id,"commit":commit,"builder":builder,"version":VERSION,
                 "integrated_digest":bundle.get("integrated_digest"),"reality_digest":reality.get("reality_digest"),
                 "proof_digest":kernel.get("release_certificate_digest"),"artifact_refs":refs,
                 "statement":"Content-addressed release evidence; digest is not a cryptographic signature."}
    return {"schema":SCHEMA,"version":VERSION,"release_id":release_id,"commit":commit,
            "status":str(kernel.get("release_status") or bundle.get("status") or "UNKNOWN").upper(),
            "artifact_refs":refs,"certificate":certificate,"certificate_digest":digest(certificate),
            "proof_debt":int(intelligence.get("proof_debt",0) or 0),
            "cryptographic_signature":None}

def verify_release_evidence(evidence:Mapping[str,Any])->dict[str,Any]:
    cert=evidence.get("certificate") if isinstance(evidence.get("certificate"),Mapping) else {}
    expected=digest(cert)
    actual=str(evidence.get("certificate_digest") or "")
    return {"schema":SCHEMA,"version":VERSION,"valid":bool(cert) and expected==actual,
            "certificate_digest":actual,"recomputed_digest":expected,
            "signature_verified":False,"statement":"Digest integrity verified only; no signature is implied."}

def build_remediation_contract(row:Mapping[str,Any], *, contract_version:int=1)->dict[str,Any]:
    pid=property_id(row)
    severity=str(row.get("severity") or "MEDIUM").upper()
    expected=row.get("expected") if isinstance(row.get("expected"),Mapping) else {}
    remediation=row.get("remediation") or row.get("recommendation") or "Review and correct the server-side security property, then re-run the governed assurance contract."
    contract={"contract_id":"RGC-"+digest({"property_id":pid,"version":contract_version})[:20],
              "contract_version":contract_version,"property_id":pid,"version":VERSION,
              "security_property":{"category":row.get("category"),"resource":row.get("resource"),"action":row.get("action"),"subject":row.get("subject"),"expected":expected},
              "severity":severity,"remediation":str(remediation),
              "verification":{"required_verdict":"PASS","missing_evidence":"BLOCKED","disappeared_observation":"NOT_RESOLVED",
                              "authoritative_observers":list(row.get("authoritative_observers",[]) or []),
                              "required_evidence":["property_id","observed_verdict","evidence_digest"]},
              "lineage":{"finding_id":row.get("finding_id"),"source_evidence_digest":row.get("evidence_digest")},
              "status":"active"}
    contract["contract_digest"]=digest({k:v for k,v in contract.items() if k!="contract_digest"})
    return contract

def build_remediation_bundle(rows:list[Mapping[str,Any]])->dict[str,Any]:
    contracts=[]; seen=set()
    for row in rows:
        c=build_remediation_contract(row)
        if c["property_id"] in seen: continue
        seen.add(c["property_id"]); contracts.append(c)
    contracts.sort(key=lambda x:x["contract_id"])
    return {"schema":"ersec-remediation-contracts/1","version":VERSION,"contracts":contracts,
            "digest":digest(contracts),"statement":"Contracts are verification obligations, not exploit instructions."}

def write_evidence(bundle_path:str,out_path:str,**kwargs:Any)->dict[str,Any]:
    r=build_release_evidence(_load(bundle_path),**kwargs); _save(out_path,r); return r

def write_remediation(rows_path:str,out_path:str)->dict[str,Any]:
    obj=_load(rows_path); rows=obj.get("findings",obj.get("claims",[]))
    if not isinstance(rows,list): raise ValueError("input must contain findings or claims list")
    r=build_remediation_bundle([x for x in rows if isinstance(x,Mapping)]); _save(out_path,r); return r

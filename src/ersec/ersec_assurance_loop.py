"""ERSEC 29.1.1 integrated security-behavior assurance loop.

Offline orchestration layer: policy/inventory -> assurance plan -> fixture truth ->
stateful plan -> metamorphic evidence -> counterfactual evidence -> Reality Fabric
-> Assurance Kernel -> Assurance Intelligence. It never contacts a target.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from ersec.ersec_assurance_compiler import load_document, compile_policy, normalize_inventory
from ersec.ersec_assurance_fixtures import build_fixture
from ersec.ersec_stateful_assurance import compile_plan as compile_stateful_plan
from ersec.ersec_metamorphic import evaluate as evaluate_metamorphic
from ersec.ersec_counterfactual import build_counterfactual
from ersec.ersec_reality import SecurityRealityFabric
from ersec.ersec_assurance_kernel import AssuranceKernel
from ersec.ersec_assurance_intelligence import AssuranceIntelligence

VERSION="29.1.1"; SCHEMA="ersec-integrated-assurance-loop/1"

def _canon(x: Any)->str: return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True)
def _digest(x: Any)->str: return hashlib.sha256(_canon(x).encode()).hexdigest()
def _load(path:str)->Dict[str,Any]:
    x=load_document(path)
    if not isinstance(x,dict): raise ValueError(f"{path} must contain an object")
    return x
def _save(path:str,x:Mapping[str,Any])->None:
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(x,indent=2,sort_keys=True)+"\n",encoding="utf-8")

def _fixture_spec(policy:Mapping[str,Any])->Dict[str,Any]:
    identities=policy.get("identities",[]); resources=policy.get("resources",[]); rules=policy.get("rules",[])
    ops=[]
    for r in rules if isinstance(rules,list) else []:
        if not isinstance(r,Mapping): continue
        subject=str(r.get("subject") or "")
        resource=str(r.get("resource") or "")
        allow=[subject] if str(r.get("expect") or "deny").lower()=="allow" and subject else []
        ops.append({"id":str(r.get("id") or resource or "operation"),"action":str(r.get("action") or "read"),"resource":resource,"allow":allow})
    return {"identities":identities,"resources":resources,"operations":ops}

def _report(plan:Mapping[str,Any], fixture:Mapping[str,Any], stateful:Mapping[str,Any], metamorphic:Mapping[str,Any], counterfactual:Mapping[str,Any])->Dict[str,Any]:
    endpoints=[]
    inv=plan.get("inventory",{}) if isinstance(plan.get("inventory"),Mapping) else {}
    for op in inv.get("operations",[]) if isinstance(inv.get("operations"),list) else []:
        if isinstance(op,Mapping): endpoints.append(str(op.get("path") or op.get("url") or op.get("operation_id") or ""))
    findings=[]
    for row in fixture.get("oracle_truth",[]) if isinstance(fixture.get("oracle_truth"),list) else []:
        if row.get("expected")=="deny":
            findings.append({"finding_id":"auth-"+_digest(row)[:12],"title":"Authorization assurance obligation","description":"Declared deny relationship requires positive verification.","category":"authorization","severity":"high","status":"not_tested","confidence":"unconfirmed"})
    if counterfactual.get("status")=="pass":
        findings.append({"finding_id":"counterfactual-pass","title":"Controlled policy differential verified","description":"Authorized baseline and controlled mutation produced the expected differential.","category":"authorization","severity":"info","status":"verified","confidence":"confirmed"})
    return {"schema":"ersec-report/1","version":VERSION,"target":"offline-assurance-harness","endpoints":sorted(set(x for x in endpoints if x)),"findings":findings,"assurance_inputs":{"plan":plan,"fixture":fixture,"stateful":stateful,"metamorphic":metamorphic,"counterfactual":counterfactual}}

class IntegratedAssuranceLoop:
    @classmethod
    def run(cls, policy_path:str, inventory_path:Optional[str]=None, stateful_path:Optional[str]=None,
            metamorphic_path:Optional[str]=None, baseline_path:Optional[str]=None, counterfactual_path:Optional[str]=None,
            declared_path:Optional[str]=None, budget:float=10.0)->Dict[str,Any]:
        policy=_load(policy_path)
        plan=compile_policy(policy, normalize_inventory(_load(inventory_path)) if inventory_path else {})
        fixture=build_fixture(_fixture_spec(policy))
        stateful=compile_stateful_plan(_load(stateful_path)) if stateful_path else {"schema":"ersec-stateful-assurance/1","version":VERSION,"workflows":[],"invariants":[]}
        metamorphic=evaluate_metamorphic(_load(metamorphic_path)) if metamorphic_path else {"schema":"ersec-metamorphic-assurance/1","version":VERSION,"relations":[],"counts":{}}
        if baseline_path and counterfactual_path:
            baseline=_load(baseline_path); mutated=_load(counterfactual_path)
            counterfactual=build_counterfactual(baseline,mutated,[])
        else:
            counterfactual={"schema":"ersec-counterfactual-evidence/1","version":VERSION,"status":"not_tested","reason":"separate baseline and mutated evidence were not supplied"}
        report=_report(plan,fixture,stateful,metamorphic,counterfactual)
        reality=SecurityRealityFabric().compile(report)
        kernel=AssuranceKernel().evaluate(reality)
        intelligence=AssuranceIntelligence().analyze(reality, _load(declared_path) if declared_path else {}, budget)
        payload={"schema":SCHEMA,"version":VERSION,"status":kernel.get("release_status","BLOCKED").lower(),"inputs":{"policy":policy_path,"inventory":inventory_path,"stateful":stateful_path,"metamorphic":metamorphic_path,"counterfactual_baseline":baseline_path,"counterfactual_mutated":counterfactual_path,"declared":declared_path},"artifacts":{"assurance_plan":plan,"fixture":fixture,"stateful_plan":stateful,"metamorphic":metamorphic,"counterfactual":counterfactual,"reality":reality,"kernel":kernel,"intelligence":intelligence},"governance":{"offline":True,"network_contact":False,"destructive_actions":False,"credential_material":False,"absence_of_evidence_is_not_pass":True,"ai_outside_trust_boundary":True}}
        payload["integrated_digest"]=_digest({k:v for k,v in payload.items() if k!="integrated_digest"})
        return payload

    @classmethod
    def write(cls,out:str,**kwargs:Any)->Dict[str,Any]:
        result=cls.run(**kwargs); _save(out,result); return result

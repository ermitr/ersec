"""ERSEC 29.1.1 Metamorphic Security Assurance.
Offline evaluation of declared metamorphic relations over authorized test evidence.
A relation describes what security-relevant output must remain invariant (or must
change) when a controlled input transformation is applied. Unknown evidence never
becomes PASS.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Dict, List, Mapping
VERSION="29.1.1"; SCHEMA="ersec-metamorphic-assurance/1"
VALID={"pass","violation","inconclusive","not_tested","blocked","observation_unavailable","unmodeled"}
def canon(x:Any)->str:return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=True)
def digest(x:Any)->str:return hashlib.sha256(canon(x).encode()).hexdigest()
def load(path:str)->Dict[str,Any]:
 p=Path(path); x=json.loads(p.read_text(encoding="utf-8"));
 if not isinstance(x,dict): raise ValueError("metamorphic input must be a JSON object")
 return x
def save(path:str,x:Mapping[str,Any])->None:
 p=Path(path);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2,sort_keys=True)+"\n",encoding="utf-8")
def evaluate(doc:Mapping[str,Any])->Dict[str,Any]:
 rels=doc.get("relations",[]); obs=doc.get("observations",{})
 if not isinstance(rels,list): raise ValueError("relations must be a list")
 if not isinstance(obs,Mapping): obs={}
 rows=[]
 for i,r in enumerate(rels):
  if not isinstance(r,Mapping): continue
  rid=str(r.get("id") or f"mr-{i+1}"); typ=str(r.get("type") or "equal")
  left=obs.get(str(r.get("baseline"))); right=obs.get(str(r.get("transformed")))
  if left is None or right is None: status="not_tested"; reason="required observation missing"
  elif typ=="equal": status="pass" if left==right else "violation"; reason="invariance relation"
  elif typ=="different": status="pass" if left!=right else "violation"; reason="required difference relation"
  elif typ=="subset":
   try: status="pass" if set(right).issubset(set(left)) else "violation"; reason="subset relation"
   except TypeError: status="inconclusive"; reason="non-set-like observations"
  else: status="unmodeled"; reason="unknown relation type"
  rows.append({"id":rid,"type":typ,"status":status,"reason":reason,"baseline":r.get("baseline"),"transformed":r.get("transformed"),"safety":r.get("safety","offline_evidence")})
 counts={s:sum(x["status"]==s for x in rows) for s in sorted(VALID)}
 out={"schema":SCHEMA,"version":VERSION,"relations":rows,"counts":counts,"statement":"Metamorphic PASS applies only to the declared relation and observed evidence; it is not a blanket security proof."}
 out["digest"]=digest(out); return out

"""ERSEC 29.1.0 provenance and attestation-ready release statement.

Produces a deterministic SLSA-inspired provenance predicate from local release
evidence. Environment metadata is explicit input so identical builds do not silently
produce different statement digests on different hosts.  It deliberately does not claim a signature: signing is an external
trust operation and can consume this statement with a project's signer.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from typing import Any, Mapping

VERSION="29.1.0"
SCHEMA="ersec-provenance-attestation/1"

def _canon(x: Any)->str:
    return json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=True)

def digest(x: Any)->str:
    return hashlib.sha256(_canon(x).encode()).hexdigest()

def load(path:str)->dict[str,Any]:
    obj=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(obj,dict): raise ValueError(f"{path} must contain an object")
    return obj

def build(evidence: Mapping[str,Any], *, source_uri:str="", builder_id:str="ERSEC/29.1.0", invocation_id:str="", environment: Mapping[str,Any] | None = None)->dict[str,Any]:
    cert=evidence.get("certificate",{}) if isinstance(evidence.get("certificate"),Mapping) else {}
    refs=evidence.get("artifact_refs",[]) if isinstance(evidence.get("artifact_refs"),list) else []
    subject=[{"name":str(x.get("artifact")),"digest":{"sha256":str(x.get("digest"))}} for x in refs if isinstance(x,Mapping) and x.get("artifact") and x.get("digest")]
    predicate={"buildType":"https://ersec.dev/provenance/29.1.0","builder":{"id":builder_id},
               "invocation":{"id":invocation_id,"source_uri":source_uri},
               "metadata":{"version":VERSION, **({str(k): v for k, v in sorted(environment.items())} if isinstance(environment, Mapping) else {})},
               "materials":[],"release_evidence_digest":evidence.get("certificate_digest"),
               "release_id":evidence.get("release_id") or cert.get("release_id"),
               "commit":evidence.get("commit") or cert.get("commit"),
               "statement":"Provenance statement is integrity-bound but unsigned unless a separate signer attests it."}
    statement={"_type":"https://in-toto.io/Statement/v1","subject":subject,"predicateType":"https://slsa.dev/provenance/v1","predicate":predicate}
    return {"schema":SCHEMA,"version":VERSION,"statement":statement,"statement_digest":digest(statement),"signed":False,
            "signature":None,"verification":{"digest_algorithm":"sha256","signature_required_for_trust":True}}

def verify(attestation: Mapping[str,Any])->dict[str,Any]:
    st=attestation.get("statement") if isinstance(attestation.get("statement"),Mapping) else {}
    expected=digest(st); actual=str(attestation.get("statement_digest") or "")
    return {"schema":SCHEMA,"version":VERSION,"valid":bool(st) and expected==actual,"digest":actual,"recomputed_digest":expected,
            "signed":bool(attestation.get("signed")),"signature_verified":False if not attestation.get("signed") else None,
            "statement":"Digest integrity is verified separately from signature trust."}

def write(evidence_path:str,out_path:str,**kwargs:Any)->dict[str,Any]:
    r=build(load(evidence_path),**kwargs); Path(out_path).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n",encoding="utf-8"); return r

"""ERSEC 29.1.0 authoritative observer adapters.

Normalizes OTel-like spans, OPA decisions, and gateway decisions into the
small evidence contract consumed by the hybrid oracle.  This module is
offline-only: it parses supplied telemetry and never contacts an observer.
"""
from __future__ import annotations
import hashlib, json
from typing import Any, Mapping, Iterable

VERSION="29.1.0"
SCHEMA="ersec-authoritative-observer-adapters/1"


def _canon(x: Any)->str:
    return json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=True)

def digest(x: Any)->str:
    return hashlib.sha256(_canon(x).encode()).hexdigest()

def _status(v: Any)->str:
    s=str(v or "").strip().lower()
    if s in {"allow","allowed","pass","permit","permitted","true","success"}: return "pass"
    if s in {"deny","denied","fail","violation","forbidden","false","error"}: return "violation"
    if s in {"inconclusive","unknown","blocked","not_tested"}: return s
    return "unknown"

def _base(row: Mapping[str,Any], source: str, index: int)->dict[str,Any]:
    attrs=row.get("attributes",{}) if isinstance(row.get("attributes"),Mapping) else {}
    trace_id=row.get("trace_id") or row.get("traceId") or attrs.get("trace_id") or attrs.get("trace.id")
    span_id=row.get("span_id") or row.get("spanId") or attrs.get("span_id") or attrs.get("span.id")
    service_revision=(row.get("service_revision") or row.get("serviceRevision") or attrs.get("service_revision") or attrs.get("service.version") or attrs.get("deployment.version"))
    return {"observer_id":f"{source}:{index}","observer_type":source,"trace_id":trace_id,"span_id":span_id,
            "service_revision":service_revision,"property_id":row.get("property_id") or attrs.get("ersec.property_id"),
            "verdict":_status(row.get("verdict") or row.get("decision") or row.get("status") or attrs.get("decision") or attrs.get("http.status_code")),
            "evidence_digest":digest(row)}

def adapt_otel(spans: Iterable[Mapping[str,Any]])->list[dict[str,Any]]:
    out=[]
    for i,row in enumerate(spans):
        if not isinstance(row,Mapping): continue
        r=_base(row,"otel",i)
        attrs=row.get("attributes",{}) if isinstance(row.get("attributes"),Mapping) else {}
        r.update({"route":row.get("route") or attrs.get("http.route"),"method":row.get("method") or attrs.get("http.request.method") or attrs.get("http.method"),
                  "http_status":row.get("http_status") or attrs.get("http.response.status_code") or attrs.get("http.status_code"),
                  "security_decision_id":row.get("security_decision_id") or attrs.get("security.decision_id")})
        out.append(r)
    return out

def adapt_opa(decisions: Iterable[Mapping[str,Any]])->list[dict[str,Any]]:
    out=[]
    for i,row in enumerate(decisions):
        if not isinstance(row,Mapping): continue
        r=_base(row,"opa",i)
        r.update({"policy_decision_id":row.get("policy_decision_id") or row.get("decision_id") or row.get("decisionId"),
                  "policy_id":row.get("policy_id") or row.get("policy")})
        out.append(r)
    return out

def adapt_gateway(decisions: Iterable[Mapping[str,Any]])->list[dict[str,Any]]:
    out=[]
    for i,row in enumerate(decisions):
        if not isinstance(row,Mapping): continue
        r=_base(row,"gateway",i)
        r.update({"policy_decision_id":row.get("policy_decision_id") or row.get("decision_id"),
                  "route":row.get("route"),"method":row.get("method")})
        out.append(r)
    return out

def merge_observers(*streams: Iterable[Mapping[str,Any]])->dict[str,Any]:
    observations=[]
    for stream in streams:
        for row in stream:
            if isinstance(row,Mapping): observations.append(dict(row))
    observations.sort(key=lambda x:(str(x.get("trace_id") or ""),str(x.get("observer_type") or ""),str(x.get("observer_id") or "")))
    return {"schema":SCHEMA,"version":VERSION,"observations":observations,"count":len(observations),"digest":digest(observations),
            "governance":{"offline":True,"network_contact":False,"credential_material":False,"authoritative_observation_only":True}}

def correlate_trace(observations: Iterable[Mapping[str,Any]], *, expected_revision: str|None=None)->dict[str,Any]:
    rows=[dict(x) for x in observations if isinstance(x,Mapping)]
    eligible=[]; rejected=[]
    for row in rows:
        if expected_revision and row.get("service_revision") and str(row.get("service_revision")) != str(expected_revision):
            rejected.append({"observer_id":row.get("observer_id"),"reason":"service_revision_mismatch"}); continue
        if expected_revision and not row.get("service_revision"):
            rejected.append({"observer_id":row.get("observer_id"),"reason":"missing_service_revision"}); continue
        if not row.get("trace_id"):
            rejected.append({"observer_id":row.get("observer_id"),"reason":"missing_trace_id"}); continue
        eligible.append(row)
    by_trace={}
    for row in eligible: by_trace.setdefault(str(row["trace_id"]),[]).append(row)
    traces=[]
    for tid,group in sorted(by_trace.items()):
        verdicts={str(x.get("verdict")) for x in group}
        if verdicts=={"pass"}: verdict="pass"
        elif verdicts=={"violation"}: verdict="violation"
        elif len(verdicts)>1: verdict="inconclusive"
        else: verdict="unknown"
        traces.append({"trace_id":tid,"verdict":verdict,"observer_count":len(group),"observers":[x.get("observer_id") for x in group],"evidence_digest":digest(group)})
    return {"schema":SCHEMA,"version":VERSION,"expected_revision":expected_revision,"traces":traces,"rejected":rejected,
            "status":"pass" if traces and all(x["verdict"]=="pass" for x in traces) and not rejected else ("violation" if any(x["verdict"]=="violation" for x in traces) else "inconclusive"),"digest":digest({"traces":traces,"rejected":rejected})}

# Extended downstream observers: supplied evidence only, no network access.
def _adapt_downstream(rows: Iterable[Mapping[str, Any]], source: str) -> list[dict[str, Any]]:
    out=[]
    for i,row in enumerate(rows):
        if not isinstance(row, Mapping): continue
        r=_base(row, source, i)
        r.update({"resource": row.get("resource") or row.get("resource_id"),
                  "action": row.get("action"), "event_type": row.get("event_type") or row.get("type"),
                  "decision_id": row.get("decision_id") or row.get("event_id"),
                  "tenant_id": row.get("tenant_id"), "object_id": row.get("object_id")})
        out.append(r)
    return out

def adapt_database(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return _adapt_downstream(records, "database")

def adapt_audit_log(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return _adapt_downstream(records, "audit_log")

def adapt_queue(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return _adapt_downstream(records, "queue")

def adapt_object_store(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return _adapt_downstream(records, "object_store")

def adapt_payment_sandbox(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return _adapt_downstream(records, "payment_sandbox")

def adapt_identity_provider(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return _adapt_downstream(records, "identity_provider")

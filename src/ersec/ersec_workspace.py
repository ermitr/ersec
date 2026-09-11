"""ERSEC 29.1.1 Universal Assessment Workspace.

Local-first, deterministic evidence correlation for common Kali/AppSec artifacts.
The workspace never contacts imported targets and preserves source digests plus
normalized provenance. It is an ingestion/correlation layer, not an exploitation
engine.
"""
from __future__ import annotations
import argparse, hashlib, json, re, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping
from ersec.ersec_discovery import build as build_discovery_fabric
from ersec.ersec_identity_fabric import build as build_identity_fabric, identity_id
from urllib.parse import parse_qsl, urlsplit, urlunsplit
from defusedxml import ElementTree as ET
from ersec.ersec_input_safety import bounded_bytes, loads_json, redact, safe_read_bytes, validate_structure, MAX_LINES

VERSION = "29.1.1"
SCHEMA = "ersec-assessment-workspace/1"


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_id(kind: str, value: Any) -> str:
    return f"{kind}-{hashlib.sha256(_canon(value).encode()).hexdigest()[:24]}"


def normalize_url(url: str) -> str:
    url = str(url).strip()
    if not url:
        return ""
    p = urlsplit(url if "://" in url else "https://" + url)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    if not host:
        return url
    port = p.port
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    netloc = host if not port or default else f"{host}:{port}"
    path = p.path or "/"
    pairs = sorted(parse_qsl(p.query, keep_blank_values=True))
    query = "&".join(f"{k}={v}" for k, v in pairs)
    return urlunsplit((scheme, netloc, path, query, ""))


def _source(path: Path, data: bytes) -> dict[str, Any]:
    return {
        "path": str(path),
        "digest": digest_bytes(data),
        "parser": "ersec_workspace/1",
        "imported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


@dataclass
class AssessmentWorkspace:
    root: Path
    data: dict[str, Any]

    @classmethod
    def create(cls, root: str | Path, target: str | None = None, scope: Mapping[str, Any] | None = None) -> "AssessmentWorkspace":
        p = Path(root)
        p.mkdir(parents=True, exist_ok=True)
        data = {"schema": SCHEMA, "version": VERSION, "workspace": {"id": stable_id("workspace", str(p.resolve())), "target": target, "scope": dict(scope or {})}, "assets": [], "services": [], "operations": [], "identities": [], "applications": [], "findings": [], "evidence": [], "tool_runs": []}
        return cls(p, data)

    @classmethod
    def load(cls, root: str | Path) -> "AssessmentWorkspace":
        p = Path(root)
        f = p / "workspace.json"
        if not f.exists():
            raise FileNotFoundError(f"workspace not initialized: {p}")
        data = json.loads(f.read_text(encoding="utf-8"))
        if data.get("schema") != SCHEMA or data.get("version") != VERSION:
            raise ValueError("unsupported ERSEC workspace schema/version")
        return cls(p, data)

    def save(self) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.root / "workspace.json.tmp"
        out = self.root / "workspace.json"
        tmp.write_text(json.dumps(self.data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        tmp.replace(out)
        return out

    def _upsert(self, bucket: str, obj: Mapping[str, Any], identity: str) -> None:
        items = self.data.setdefault(bucket, [])
        for i, existing in enumerate(items):
            if existing.get("id") == identity:
                merged = dict(existing); merged.update(obj); items[i] = merged; return
        items.append(dict(obj))

    def add_evidence(self, kind: str, source: Path, raw: bytes, parsed: Mapping[str, Any] | None = None) -> str:
        src = _source(source, raw)
        eid = stable_id("evidence", {"kind": kind, "source_digest": src["digest"]})
        self._upsert("evidence", {"id": eid, "kind": kind, "source": src, "parsed_summary": dict(parsed or {})}, eid)
        return eid

    def add_asset(self, host: str, source_id: str, confidence: str = "medium") -> None:
        host = host.lower().rstrip(".")
        aid = stable_id("asset", host)
        self._upsert("assets", {"id": aid, "host": host, "confidence": confidence, "evidence_refs": [source_id]}, aid)

    def add_service(self, host: str, port: int | None, scheme: str | None, source_id: str, technology: str | None = None) -> None:
        key = {"host": host.lower(), "port": port, "scheme": scheme}
        sid = stable_id("service", key)
        self._upsert("services", {"id": sid, **key, "technology": technology, "evidence_refs": [source_id]}, sid)
        self.add_asset(host, source_id)

    def add_identity(self, name: str, source_id: str, role: str | None = None, tenant: str | None = None, subject: str | None = None, identity_type: str | None = None, operation_ids: Iterable[str] | None = None) -> str:
        obj = {"name": name, "role": role, "tenant": tenant, "subject": subject, "type": identity_type, "evidence_refs": [source_id], "operation_ids": sorted({str(x) for x in (operation_ids or [])})}
        iid = identity_id(obj)
        obj["id"] = iid
        self._upsert("identities", obj, iid)
        return iid

    def add_operation(self, method: str, url: str, source_id: str, auth: Any = None, operation_name: str | None = None) -> None:
        nurl = normalize_url(url)
        p = urlsplit(nurl)
        # Canonical identity is method + host + path + query parameter names.
        # Query values are observations, not operation identity, so browser/HAR
        # variants and reordered parameters converge on one operation.
        query_names = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
        key = {"method": method.upper(), "host": (p.hostname or "").lower(), "path": p.path or "/", "query_names": query_names}
        oid = stable_id("operation", key)
        existing = next((x for x in self.data.setdefault("operations", []) if x.get("id") == oid), None)
        variants = list((existing or {}).get("url_variants", []))
        if nurl and nurl not in variants:
            variants.append(nurl)
        obj = {"id": oid, "method": method.upper(), "url": nurl, "host": p.hostname, "path": p.path or "/", "query_parameter_names": query_names, "url_variants": sorted(variants), "operation_name": operation_name, "auth": redact(auth), "evidence_refs": sorted(set((existing or {}).get("evidence_refs", [])) | {source_id})}
        self._upsert("operations", obj, oid)
        if p.hostname:
            self.add_asset(p.hostname, source_id)

    def import_file(self, filename: str | Path, kind: str | None = None) -> dict[str, Any]:
        path = Path(filename); raw = safe_read_bytes(path, label=f"workspace artifact {path.name}")
        detected = (kind or detect_kind(path, raw)).lower()
        if detected == "nmap": return ingest_nmap(self, path, raw)
        if detected in {"masscan", "domains", "subfinder"}: return ingest_lines(self, path, raw, detected)
        if detected in {"httpx"}: return ingest_httpx(self, path, raw)
        if detected == "har": return ingest_har(self, path, raw)
        if detected in {"openapi", "swagger", "graphql", "postman", "asyncapi", "grpc"}: return ingest_contract(self, path, raw, detected)
        if detected in {"sarif", "nuclei"}: return ingest_findings(self, path, raw, detected)
        raise ValueError(f"unsupported or ambiguous artifact format: {path}")


def detect_kind(path: Path, raw: bytes) -> str:
    name = path.name.lower()
    if name.endswith(".xml"):
        try:
            root = ET.fromstring(raw)
            if root.tag == "nmaprun": return "nmap"
        except ET.ParseError: pass
    if name.endswith(".har") or b'"log"' in raw[:1000] and b'"entries"' in raw[:5000]: return "har"
    try:
        doc = loads_json(raw, label=f"{path.name} JSON")
    except Exception:
        text = raw.decode("utf-8", errors="replace")
        return "subfinder" if "subfinder" in name else "domains"
    if isinstance(doc, dict):
        if "$schema" in doc and "sarif" in str(doc.get("$schema", "")).lower(): return "sarif"
        if "openapi" in doc: return "openapi"
        if "swagger" in doc: return "swagger"
        if "asyncapi" in doc: return "asyncapi"
        if "item" in doc and "info" in doc: return "postman"
        if "paths" in doc and isinstance(doc.get("paths"), dict): return "openapi"
        if "entries" in doc and "log" in doc: return "har"
    if name.endswith(".jsonl") or name.endswith(".ndjson"):
        lines = [loads_json(x, label=f"{path.name} JSONL record") for x in raw.decode().splitlines() if x.strip()][:3]
        if any(isinstance(x, dict) and ("template-id" in x or "template" in x) for x in lines): return "nuclei"
        if any(isinstance(x, dict) and ("url" in x or "host" in x) for x in lines): return "httpx"
    return "domains"


def ingest_nmap(ws: AssessmentWorkspace, path: Path, raw: bytes) -> dict[str, Any]:
    bounded_bytes(raw, label="Nmap XML"); root = ET.fromstring(raw); eid = ws.add_evidence("nmap_xml", path, raw, {"hosts": 0, "services": 0}); hosts=services=0
    for h in root.findall("host"):
        addr = h.find("address"); host = addr.get("addr") if addr is not None else None
        if not host: continue
        hosts += 1; ws.add_asset(host, eid, "high")
        ports = h.find("ports")
        if ports is not None:
            for pe in ports.findall("port"):
                state = pe.find("state")
                if state is None or state.get("state") != "open": continue
                services += 1; svc = pe.find("service"); scheme = None; tech = svc.get("name") if svc is not None else None
                if svc is not None and svc.get("name") in {"http", "https"}: scheme = svc.get("name")
                ws.add_service(host, int(pe.get("portid")), scheme, eid, tech)
    for e in ws.data["evidence"]:
        if e["id"] == eid: e["parsed_summary"]={"hosts":hosts,"services":services}
    return {"kind":"nmap","evidence_id":eid,"hosts":hosts,"services":services}


def ingest_lines(ws, path, raw, kind):
    eid=ws.add_evidence(kind, path, raw); count=0
    for line_no, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
        if line_no > MAX_LINES: raise ValueError(f"{kind} exceeds maximum line count of {MAX_LINES}")
        value=line.strip().split()[0] if line.strip() else ""
        if not value or value.startswith("#"): continue
        if kind == "masscan" and "/" in value:
            host, port = value.rsplit("/",1); ws.add_service(host, int(port) if port.isdigit() else None, None, eid); count+=1
        else:
            host=value.split("://")[-1].split("/")[0].split(":")[0]
            if host: ws.add_asset(host, eid, "medium"); count+=1
    return {"kind":kind,"evidence_id":eid,"count":count}


def ingest_httpx(ws,path,raw):
    eid=ws.add_evidence("httpx",path,raw); count=0
    text=raw.decode("utf-8",errors="replace")
    docs=[]
    try:
        d=loads_json(text, label="httpx JSON"); docs=d if isinstance(d,list) else [d]
    except Exception:
        for line in text.splitlines():
            try: docs.append(loads_json(line, label="httpx JSONL record"))
            except Exception: continue
    for d in docs:
        if not isinstance(d,dict): continue
        url=d.get("url") or d.get("input")
        if url:
            p=urlsplit(normalize_url(url)); ws.add_service(p.hostname or "", p.port, p.scheme, eid, d.get("tech") or d.get("webserver")); ws.add_operation("GET",url,eid); count+=1
    return {"kind":"httpx","evidence_id":eid,"count":count}


def ingest_har(ws,path,raw):
    doc=loads_json(raw, label="HAR JSON"); eid=ws.add_evidence("har",path,raw,{"entries":len(doc.get("log",{}).get("entries",[]))}); count=0
    for e in doc.get("log",{}).get("entries",[]):
        req=e.get("request",{}); url=req.get("url"); method=req.get("method","GET")
        if url: ws.add_operation(method,url,eid); count+=1
    return {"kind":"har","evidence_id":eid,"count":count}


def _walk_openapi(ws, doc, eid):
    count=0; servers=doc.get("servers",[])
    base=servers[0].get("url","") if servers and isinstance(servers[0],dict) else ""
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item,dict): continue
        for method, op in item.items():
            if method.lower() not in {"get","post","put","patch","delete","head","options"}: continue
            url=(base.rstrip("/")+"/"+path.lstrip("/")) if base else path
            ws.add_operation(method,url,eid,op.get("security") or doc.get("security"),op.get("operationId")); count+=1
    return count


def ingest_contract(ws,path,raw,kind):
    doc=loads_json(raw, label=f"{kind} JSON"); eid=ws.add_evidence(kind,path,raw); count=0
    if kind in {"openapi","swagger"}: count=_walk_openapi(ws,doc,eid)
    elif kind == "postman":
        def walk(items):
            nonlocal count
            for it in items or []:
                if "request" in it and isinstance(it["request"],dict):
                    r=it["request"]; u=r.get("url")
                    if isinstance(u,dict): u=u.get("raw")
                    if u: ws.add_operation(r.get("method","GET"),u,eid,it.get("auth"),it.get("name")); count+=1
                walk(it.get("item",[]))
        walk(doc.get("item",[]))
    elif kind == "asyncapi":
        count=len(doc.get("channels",{}));
        for ch in doc.get("channels",{}): ws.add_operation("EVENT",ch,eid)
    elif kind in {"graphql","grpc"}:
        count=len(doc.get("operations",[])) if isinstance(doc.get("operations"),list) else 0
    return {"kind":kind,"evidence_id":eid,"count":count}


def ingest_findings(ws,path,raw,kind):
    eid=ws.add_evidence(kind,path,raw); count=0
    if kind=="sarif":
        doc=loads_json(raw, label="SARIF JSON")
        for run in doc.get("runs",[]):
            for r in run.get("results",[]):
                rid=r.get("ruleId") or "unknown"; fid=stable_id("finding",{"rule":rid,"message":r.get("message",{}).get("text","")})
                ws._upsert("findings",{"id":fid,"rule_id":rid,"message":r.get("message",{}).get("text"),"level":r.get("level"),"source_evidence":eid},fid); count+=1
    else:
        for line in raw.decode("utf-8",errors="replace").splitlines():
            try: r=loads_json(line, label="Nuclei JSONL record")
            except Exception: continue
            rid=r.get("template-id") or r.get("template") or "unknown"; fid=stable_id("finding",{"rule":rid,"host":r.get("host"),"matched":r.get("matched-at")})
            ws._upsert("findings",{"id":fid,"rule_id":rid,"host":r.get("host"),"matched_at":r.get("matched-at"),"severity":r.get("info",{}).get("severity"),"source_evidence":eid},fid); count+=1
    return {"kind":kind,"evidence_id":eid,"count":count}


def export_workspace(ws: AssessmentWorkspace) -> dict[str,Any]:
    payload=dict(ws.data)
    payload["discovery_fabric"] = build_discovery_fabric(payload)
    payload["identity_fabric"] = build_identity_fabric(payload)
    payload["statistics"]={k:len(payload.get(k,[])) for k in ("assets","services","operations","identities","applications","findings","evidence","tool_runs")}
    payload["statistics"]["discovery_nodes"] = payload["discovery_fabric"]["statistics"]["nodes"]
    payload["statistics"]["discovery_edges"] = payload["discovery_fabric"]["statistics"]["edges"]
    payload["statistics"]["identity_fabric_identities"] = len(payload["identity_fabric"]["identities"])
    payload["statistics"]["identity_fabric_applications"] = len(payload["identity_fabric"]["applications"])
    payload["statistics"]["identity_fabric_resources"] = len(payload["identity_fabric"]["resources"])
    # Timestamps are provenance metadata, not semantic workspace identity.
    stable={k:v for k,v in payload.items() if k not in {"digest"}}
    stable["evidence"]=[{**e, "source": {k:v for k,v in e.get("source",{}).items() if k != "imported_at"}} for e in stable.get("evidence",[])]
    payload["digest"]=hashlib.sha256(_canon(stable).encode()).hexdigest()
    return payload


def main(argv=None):
    p=argparse.ArgumentParser(prog="ersec-workspace")
    sub=p.add_subparsers(dest="cmd",required=True)
    i=sub.add_parser("init"); i.add_argument("workspace"); i.add_argument("--target")
    g=sub.add_parser("ingest"); g.add_argument("workspace"); g.add_argument("files",nargs="+"); g.add_argument("--kind")
    e=sub.add_parser("export"); e.add_argument("workspace"); e.add_argument("--output",required=True)
    a=p.parse_args(argv)
    if a.cmd=="init": ws=AssessmentWorkspace.create(a.workspace,a.target); ws.save(); print(json.dumps({"status":"ok","version":VERSION,"workspace":str(ws.root)})); return 0
    ws=AssessmentWorkspace.load(a.workspace)
    if a.cmd=="ingest":
        results=[ws.import_file(f,a.kind) for f in a.files]; ws.save(); print(json.dumps({"status":"ok","version":VERSION,"results":results,"statistics":{k:len(ws.data.get(k,[])) for k in ("assets","services","operations","findings","evidence")}},indent=2)); return 0
    if a.cmd=="export": Path(a.output).write_text(json.dumps(export_workspace(ws),indent=2,sort_keys=True)+"\n",encoding="utf-8"); return 0

if __name__=="__main__": raise SystemExit(main())

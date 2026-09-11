"""Evidence capture and privacy boundary for ERSEC.

Pure helpers live here so evidence handling can be tested without starting a scan.
"""
from __future__ import annotations
import re
import urllib.parse
from dataclasses import asdict
from typing import Any, Mapping

SECRET_HEADER_NAMES = {
    "authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key",
    "api-key", "x-auth-token", "x-access-token", "x-csrf-token", "x-api-token",
}
SECRET_FIELD_NAMES = {
    "password", "passwd", "pwd", "token", "access_token", "refresh_token",
    "id_token", "api_key", "apikey", "secret", "client_secret", "private_key",
    "authorization", "cookie", "session", "sessionid", "csrf", "csrf_token",
}

def redact_sensitive_text(text: str) -> str:
    if not text:
        return text
    out = str(text)
    field_re = r'(?i)(["\']?(?:' + "|".join(map(re.escape, sorted(SECRET_FIELD_NAMES, key=len, reverse=True))) + r')["\']?\s*[:=]\s*)(["\'])(.*?)(\2)'
    out = re.sub(field_re, lambda m: m.group(1) + m.group(2) + "REDACTED" + m.group(4), out)
    out = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*', 'Bearer REDACTED', out)
    out = re.sub(r'(?i)\bBasic\s+[A-Za-z0-9+/=]+', 'Basic REDACTED', out)
    out = re.sub(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])', 'REDACTED-JWT', out)
    out = re.sub(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----(?:.|\n)*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----', 'REDACTED-PRIVATE-KEY', out, flags=re.S)
    return out

def redact_sensitive_url(url: str) -> str:
    try:
        p = urllib.parse.urlsplit(str(url))
        q = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
        if not q:
            return str(url)
        clean = []
        for k, v in q:
            lk = k.lower()
            clean.append((k, "REDACTED" if lk in SECRET_FIELD_NAMES or "token" in lk or "secret" in lk or "key" in lk else v))
        return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(clean), p.fragment))
    except Exception:
        return str(url)

def redact_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(value)
    for k in list(out):
        lk = str(k).lower()
        if lk in SECRET_FIELD_NAMES or lk in SECRET_HEADER_NAMES or "token" in lk or "secret" in lk or "api_key" in lk:
            out[k] = "REDACTED"
        elif isinstance(out[k], str):
            out[k] = redact_sensitive_text(out[k])
    return out

def redact_evidence_record(record: Any) -> dict[str, Any]:
    if hasattr(record, "__dataclass_fields__"):
        out = asdict(record)
    elif isinstance(record, Mapping):
        out = dict(record)
    else:
        raise TypeError("evidence record must be a mapping or dataclass")
    if isinstance(out.get("response_headers"), Mapping):
        out["response_headers"] = redact_mapping(out["response_headers"])
    if isinstance(out.get("request_headers_sent"), Mapping):
        out["request_headers_sent"] = redact_mapping(out["request_headers_sent"])
    if "url" in out:
        out["url"] = redact_sensitive_url(str(out["url"]))
    if "response_excerpt" in out:
        out["response_excerpt"] = redact_sensitive_text(str(out["response_excerpt"])[:2000])[:300]
    return out

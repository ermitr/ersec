"""Scope and URL boundary helpers for ERSEC.

These helpers are deliberately side-effect free and conservative.
"""
from __future__ import annotations
import ipaddress
import urllib.parse

INELIGIBLE_DNS_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".test")

def canonical_url(url: str) -> str:
    raw = str(url).strip()
    p = urllib.parse.urlsplit(raw)
    if p.scheme.lower() not in {"http", "https"} or not p.netloc:
        return raw
    host = p.hostname or ""
    try:
        port = p.port
    except ValueError:
        return raw
    host_part = host.lower()
    if ":" in host and not host_part.startswith("["):
        host_part = f"[{host_part}]"
    default = (p.scheme.lower() == "http" and port == 80) or (p.scheme.lower() == "https" and port == 443)
    netloc = host_part if port is None or default else f"{host_part}:{port}"
    return urllib.parse.urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))

def dns_is_eligible_host(host: str) -> bool:
    value = str(host or "").strip().rstrip(".").lower()
    if not value or value == "localhost" or value.endswith(INELIGIBLE_DNS_SUFFIXES):
        return False
    try:
        ipaddress.ip_address(value)
        return False
    except ValueError:
        pass
    return "." in value and not value.startswith(".") and not value.endswith(".")

def host_port(url: str) -> tuple[str, int | None]:
    p = urllib.parse.urlsplit(str(url))
    return p.hostname or "", p.port

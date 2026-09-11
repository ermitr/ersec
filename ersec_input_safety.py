"""ERSEC 29.1.0 input/output safety boundaries.

Bounded parsers and deterministic secret redaction. This module is deliberately
small and dependency-light: it sits before parsers and before report writers.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from typing import Any, Mapping

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_TEXT_CHARS = 8 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 100_000
MAX_JSON_STRING = 1_000_000
MAX_JSON_CONTAINER = 50_000
MAX_YAML_EVENTS = 200_000
MAX_LINES = 100_000

SENSITIVE_KEYS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "access-token", "refresh-token",
    "id-token", "token", "bearer", "password", "passwd", "secret",
    "client-secret", "client_secret", "private-key", "private_key",
    "credential", "credentials", "session", "sessionid", "session_id",
}
SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(basic\s+)[A-Za-z0-9+/=]{12,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(-----BEGIN [^-]*PRIVATE KEY-----).*?(-----END [^-]*PRIVATE KEY-----)"), r"\1[REDACTED]\2"),
    (re.compile(r"(?i)((?:api[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|password)\s*[=:]\s*)[^\s&;,\"']+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([?&](?:token|api[_-]?key|password|secret|access[_-]?token|client[_-]?secret)=)[^&\s]+"), r"\1[REDACTED]"),
    # Cloud & Provider tokens
    (re.compile(r"(?i)(aws_access_key_id\s*[:=]\s*)[A-Z0-9]{20}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(aws_secret_access_key\s*[:=]\s*)[A-Za-z0-9/+=]{40}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(ghp_[a-zA-Z0-9]{36})"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"(?i)(xox[baprs]-[0-9a-zA-Z]{10,48})"), "[REDACTED_SLACK_TOKEN]"),
]

class InputSafetyError(ValueError):
    pass


def bounded_bytes(raw: bytes, *, label: str = "input", limit: int = MAX_INPUT_BYTES) -> bytes:
    if len(raw) > limit:
        raise InputSafetyError(f"{label} exceeds maximum input size of {limit} bytes")
    return raw


def bounded_text(text: str, *, label: str = "input", limit: int = MAX_TEXT_CHARS) -> str:
    if len(text) > limit:
        raise InputSafetyError(f"{label} exceeds maximum text size of {limit} characters")
    return text


def validate_structure(value: Any, *, max_depth: int = MAX_JSON_DEPTH, max_nodes: int = MAX_JSON_NODES,
                      max_string: int = MAX_JSON_STRING, max_container: int = MAX_JSON_CONTAINER) -> None:
    nodes = 0
    def walk(v: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            raise InputSafetyError(f"structured input exceeds maximum node count of {max_nodes}")
        if depth > max_depth:
            raise InputSafetyError(f"structured input exceeds maximum depth of {max_depth}")
        if isinstance(v, str):
            if len(v) > max_string:
                raise InputSafetyError(f"structured input contains a string exceeding {max_string} characters")
        elif isinstance(v, Mapping):
            if len(v) > max_container:
                raise InputSafetyError(f"structured input object exceeds maximum member count of {max_container}")
            for k, x in v.items(): walk(k, depth + 1); walk(x, depth + 1)
        elif isinstance(v, (list, tuple)):
            if len(v) > max_container:
                raise InputSafetyError(f"structured input array exceeds maximum item count of {max_container}")
            for x in v: walk(x, depth + 1)
    walk(value, 0)


def _preflight_json_depth(text: str, max_depth: int = MAX_JSON_DEPTH, label: str = "JSON") -> None:
    depth = 0; in_string = False; escaped = False
    for ch in text:
        if in_string:
            if escaped: escaped = False
            elif ch == "\\": escaped = True
            elif ch == '"': in_string = False
            continue
        if ch == '"': in_string = True
        elif ch in '[{':
            depth += 1
            if depth > max_depth:
                raise InputSafetyError(f"{label} exceeds maximum depth of {max_depth}")
        elif ch in ']}':
            depth = max(0, depth - 1)

def loads_json(raw: bytes | str, *, label: str = "JSON") -> Any:
    if isinstance(raw, bytes): bounded_bytes(raw, label=label)
    text = raw.decode("utf-8") if isinstance(raw, bytes) else bounded_text(raw, label=label)
    _preflight_json_depth(text, MAX_JSON_DEPTH, label)
    value = json.loads(text)
    validate_structure(value)
    return value


def load_yaml(text: str, *, label: str = "YAML") -> Any:
    bounded_text(text, label=label)
    try:
        import yaml
        events = 0
        for _ in yaml.parse(text, Loader=yaml.SafeLoader):
            events += 1
            if events > MAX_YAML_EVENTS:
                raise InputSafetyError(f"{label} exceeds maximum YAML event count of {MAX_YAML_EVENTS}")
        value = yaml.safe_load(text)
    except ImportError as exc:
        raise InputSafetyError("YAML input requires PyYAML") from exc
    validate_structure(value)
    return value


def redact_text(value: Any) -> str:
    text = str(value)
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: Any, *, _key: str = "") -> Any:
    if isinstance(value, Mapping):
        out = {}
        for k, v in value.items():
            key = str(k)
            if key.lower().replace("-", "_") in {x.replace("-", "_") for x in SENSITIVE_KEYS}:
                out[key] = "[REDACTED]"
            else:
                out[key] = redact(v, _key=key)
        return out
    if isinstance(value, list):
        return [redact(v, _key=_key) for v in value]
    if isinstance(value, tuple):
        return tuple(redact(v, _key=_key) for v in value)
    if isinstance(value, str):
        return redact_text(value)
    return value


def safe_read_bytes(path: str | Path, *, limit: int = MAX_INPUT_BYTES, label: str = "input") -> bytes:
    p = Path(path)
    if not p.is_file():
        raise InputSafetyError(f"not a regular file: {p}")
    size = p.stat().st_size
    if size > limit:
        raise InputSafetyError(f"{label} exceeds maximum input size of {limit} bytes")
    return bounded_bytes(p.read_bytes(), label=label, limit=limit)

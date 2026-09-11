"""ERSEC 29.1.1 reproducible build and distribution assurance.

Offline, deterministic checks for source/package parity and reproducibility.
Container construction is represented as an explicit, digest-pinned input;
ERSEC never invents a base-image digest and never contacts registries here.
"""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from typing import Any

VERSION = "29.1.1"
SCHEMA = "ersec-build-assurance/1"


def _canon(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def source_manifest(root: str | Path) -> dict[str, Any]:
    root = Path(root).resolve()
    files = []
    for p in sorted(root.glob("*.py")):
        if p.name.startswith("__"):
            continue
        files.append({"path": p.name, "sha256": _sha(p), "bytes": p.stat().st_size})
    for rel in ("pyproject.toml", "requirements.txt", "requirements-dev.txt"):
        p = root / rel
        if p.is_file():
            files.append({"path": rel, "sha256": _sha(p), "bytes": p.stat().st_size})
    manifest = {"schema": "ersec-source-manifest/1", "version": VERSION, "files": files}
    manifest["digest"] = hashlib.sha256(_canon(manifest).encode()).hexdigest()
    return manifest


def package_parity(root: str | Path) -> dict[str, Any]:
    root = Path(root).resolve()
    payload = root / "packaging" / "debian" / "usr" / "lib" / "python3" / "dist-packages"
    source = {p.name: _sha(p) for p in root.glob("*.py") if not p.name.startswith("__") and p.name != "setup.py"}
    packaged = {p.name: _sha(p) for p in payload.glob("*.py") if p.name != "setup.py"} if payload.is_dir() else {}
    missing = sorted(set(source) - set(packaged))
    extra = sorted(set(packaged) - set(source))
    mismatched = sorted(k for k in source.keys() & packaged.keys() if source[k] != packaged[k])
    status = "MATCH" if not (missing or extra or mismatched) else "MISMATCH"
    return {"status": status, "source_modules": len(source), "packaged_modules": len(packaged),
            "missing": missing, "extra": extra, "mismatched": mismatched,
            "source_digest": hashlib.sha256(_canon(source).encode()).hexdigest(),
            "package_digest": hashlib.sha256(_canon(packaged).encode()).hexdigest()}


def container_contract(root: str | Path, base_image: str | None = None) -> dict[str, Any]:
    root = Path(root).resolve()
    cf = root / "Containerfile"
    image = base_image or ""
    pinned = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", image))
    exists = cf.is_file()
    status = "MATCH" if exists and pinned else "BLOCKED"
    return {"status": status, "containerfile": exists, "base_image": image,
            "base_image_digest_pinned": pinned,
            "reason": None if status == "MATCH" else "A real registry image digest must be supplied explicitly; offline assurance never invents one.",
            "containerfile_sha256": _sha(cf) if exists else None}


def compare_manifests(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    bd = before.get("digest")
    ad = after.get("digest")
    if not bd or not ad:
        return {"status": "BLOCKED", "reason": "both manifests require deterministic digests"}
    return {"status": "MATCH" if bd == ad else "MISMATCH", "before_digest": bd, "after_digest": ad,
            "changed": bd != ad}


def audit(root: str | Path, base_image: str | None = None) -> dict[str, Any]:
    sm = source_manifest(root)
    parity = package_parity(root)
    container = container_contract(root, base_image)
    result = {"schema": SCHEMA, "version": VERSION, "source": sm, "package_parity": parity,
              "container_contract": container,
              "integrity_digest": hashlib.sha256(_canon({"source": sm, "package_parity": parity, "container": container}).encode()).hexdigest(),
              "governance": {"offline": True, "network_contact": False, "credential_material": False,
                             "digest_is_not_signature": True}}
    result["status"] = "PASS" if parity["status"] == "MATCH" else "FAIL"
    return result


def write(root: str, out: str, base_image: str | None = None) -> dict[str, Any]:
    result = audit(root, base_image)
    p = Path(out); p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result

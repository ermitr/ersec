from pathlib import Path
from ersec_build_assurance import audit, container_contract, compare_manifests, source_manifest

ROOT = Path(__file__).resolve().parents[1]

def test_source_manifest_deterministic_and_unique():
    manifest = source_manifest(ROOT)
    assert manifest["digest"] == source_manifest(ROOT)["digest"]
    paths = [item["path"] for item in manifest["files"]]
    assert len(paths) == len(set(paths))

def test_package_parity_matches():
    assert audit(ROOT)["package_parity"]["status"] == "MATCH"

def test_container_requires_digest():
    assert container_contract(ROOT)["status"] == "BLOCKED"
    assert container_contract(ROOT, "python:3.12-slim@sha256:" + "a" * 64)["status"] == "MATCH"

def test_manifest_compare():
    m = source_manifest(ROOT)
    assert compare_manifests(m, m)["status"] == "MATCH"
    n = dict(m); n["digest"] = "b" * 64
    assert compare_manifests(m, n)["status"] == "MISMATCH"

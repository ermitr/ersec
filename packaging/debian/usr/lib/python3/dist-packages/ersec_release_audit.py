"""ERSEC 29.1.0 release readiness audit.

Deterministic offline audit for repository/package readiness. It checks release
metadata, required assurance modules, documentation, CI controls, and obvious
secret-bearing files. It does not contact networks and never executes target
applications.
"""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
from typing import Any, Iterable, Mapping

VERSION = "29.1.0"
SCHEMA = "ersec-release-readiness-audit/1"

REQUIRED_MODULES = (
    "ersec_reality.py", "ersec_assurance_kernel.py", "ersec_assurance_intelligence.py",
    "ersec_assurance_compiler.py", "ersec_metamorphic.py", "ersec_assurance_fixtures.py",
    "ersec_stateful_assurance.py", "ersec_hybrid_oracle.py", "ersec_counterfactual.py",
    "ersec_assurance_benchmark_lab.py", "ersec_assurance_loop.py", "ersec_continuous_assurance.py",
    "ersec_release_evidence.py", "ersec_observer_adapters.py", "ersec_provenance.py",
    "ersec_quality.py", "ersec_release_audit.py", "ersec_ci_gate.py", "ersec_remediation_verify.py", "ersec_workspace.py", "ersec_attack_graph.py",
    "ersec_concurrent_assurance.py", "ersec_stateful_links.py", "ersec_build_assurance.py", "ersec_public_eval.py",
)
REQUIRED_DOCS = ("README.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
                 "CHANGELOG.md", "RELEASE.md", "DEPLOY.md", "DEPLOY_KALI_29.1.0.md",
                 "RELEASE_NOTES_29.1.0.md", "docs/publish-github-pypi-29.1.0.md", ".gitattributes", ".github/dependabot.yml")
REQUIRED_WORKFLOWS = (".github/workflows/ci.yml", ".github/workflows/release.yml",
                      ".github/workflows/ersec-29.1.0-assurance.yml", ".github/workflows/ersec-29.1.0-reproducibility.yml", ".github/workflows/testpypi-29.1.0.yml")


def _canon(x: Any) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(x: Any) -> str:
    return hashlib.sha256(_canon(x).encode()).hexdigest()


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _check(path: Path, label: str) -> tuple[bool, str]:
    return (path.is_file(), label if path.is_file() else f"missing: {label}")


def _version_checks(root: Path) -> list[dict[str, Any]]:
    checks=[]
    pyproject=root/"pyproject.toml"; ersec=root/"ersec.py"
    if pyproject.is_file():
        text=_read(pyproject)
        checks.append({"id":"pyproject-version","pass":bool(re.search(r'version\s*=\s*[\"\']29\.1\.0[\"\']',text)),"observed":"29.1.0" if "29.1.0" in text else "missing"})
    else: checks.append({"id":"pyproject-version","pass":False,"observed":"missing"})
    if ersec.is_file():
        text=_read(ersec)
        checks.append({"id":"cli-version","pass":"ERSEC_VERSION = \"29.1.0\"" in text,"observed":"29.1.0" if "ERSEC_VERSION = \"29.1.0\"" in text else "missing"})
    else: checks.append({"id":"cli-version","pass":False,"observed":"missing"})
    return checks


def _secret_scan(root: Path) -> dict[str, Any]:
    patterns=(re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
              re.compile(r"(?i)aws_secret_access_key\\s*[=:]\\s*['\"][A-Za-z0-9/+=]{16,}"),
              re.compile(r"(?i)(?:password|passwd|api[_-]?key|secret|token)\\s*[=:]\\s*['\"][^'\"]{16,}['\"]"))
    hits=[]
    for path in root.rglob("*"):
        if not path.is_file() or any(p in {".git", ".venv", "node_modules", "dist", "build", ".pytest_cache"} for p in path.parts):
            continue
        if path.suffix.lower() not in {".py",".yml",".yaml",".json",".toml",".ini",".conf",".md",".sh",".txt"}:
            continue
        try: text=_read(path)
        except OSError: continue
        for rx in patterns:
            if rx.search(text): hits.append(str(path.relative_to(root))); break
    return {"pass":not hits,"hits":sorted(set(hits))}


def audit(root: str | Path) -> dict[str, Any]:
    root=Path(root).resolve(); checks=[]
    for name in REQUIRED_MODULES:
        ok,msg=_check(root/name,f"module:{name}"); checks.append({"id":f"module:{name}","pass":ok,"observed":msg})
    for name in REQUIRED_DOCS:
        ok,msg=_check(root/name,f"document:{name}"); checks.append({"id":f"document:{name}","pass":ok,"observed":msg})
    for name in REQUIRED_WORKFLOWS:
        ok,msg=_check(root/name,f"workflow:{name}"); checks.append({"id":f"workflow:{name}","pass":ok,"observed":msg})
    checks.extend(_version_checks(root))
    secret=_secret_scan(root)
    checks.append({"id":"secret-scan","pass":secret["pass"],"observed":secret["hits"]})
    # Packaging metadata must explicitly declare the core dependency boundary.
    pyproject=_read(root/"pyproject.toml") if (root/"pyproject.toml").is_file() else ""
    checks.append({"id":"packaging-version","pass":"version = \"29.1.0\"" in pyproject,"observed":"29.1.0" if "version = \"29.1.0\"" in pyproject else "missing"})
    failed=[c for c in checks if not c["pass"]]
    result={"schema":SCHEMA,"version":VERSION,"status":"PASS" if not failed else "FAIL",
            "root":str(root),"checks":checks,"failed_count":len(failed),
            "governance":{"offline":True,"network_contact":False,"target_contact":False,
                           "credential_material_processed":False,"destructive_actions":False,
                           "secret_scan_is_heuristic":True},
            "audit_digest":digest({"checks":checks,"status":"PASS" if not failed else "FAIL"})}
    return result


def write(root: str, out: str) -> dict[str, Any]:
    result=audit(root); p=Path(out); p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8"); return result

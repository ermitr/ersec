# ERSEC 29.1.0 — Release Readiness Audit

The release-readiness audit is a deterministic, offline repository-quality gate.
It checks that the 29.1.0 assurance modules, release documentation, CI workflows,
version metadata, and packaging metadata are present and internally aligned.

It also performs a heuristic scan for obvious private-key and hard-coded secret
patterns. This is a safety check, not a complete secret scanner.

## CLI

```bash
python ersec.py --release-audit . --release-audit-out release-readiness-29.1.0.json
```

A non-zero exit code means the repository did not satisfy the readiness audit.

The audit never contacts an application, observer, registry, or external service.
A PASS from this audit means release structure is coherent; it does not mean the
application being assessed is secure.

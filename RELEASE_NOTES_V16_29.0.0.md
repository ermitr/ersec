# ERSEC 29.0.0 — V16

## Roadmap Coverage Audit

V16 adds a deterministic roadmap coverage auditor that maps the ten 29.0.0 Security Behavior Assurance features to implementation modules, regression tests, documentation/evidence, and explicit remaining gaps.

The audit intentionally returns `PARTIAL` while product/validation gaps remain. It does not convert missing evidence into completion.

## CI Output Hardening

- SARIF driver version now follows `ERSEC_VERSION` and therefore remains `29.0.0`.
- The roadmap audit is exposed through the CLI and packaging metadata.
- Debian payload is synchronized with all current `ersec_*.py` modules.

## Validation

- Focused roadmap/assurance suite: 75/75 passed.
- Built-in ERSEC self-test: 66/66 passed.
- Roadmap audit: 10/10 core feature anchors covered; 6 explicit remaining gaps surfaced.

All changes remain evidence-first, offline where assurance artifacts are compiled, authorized-harness oriented, and non-destructive.

## V16 continuation — concurrent security assurance

Added `ersec_concurrent_assurance.py`, an offline planner/evaluator for bounded TOCTOU, double-submit, quota-race, tenant-context-race, and idempotency-race scenarios. It produces harness-ready interleavings without contacting targets or accepting credentials. Missing evidence remains `not_tested`.

# ERSEC 28.3 — Assurance Execution & Release Hardening

ERSEC 28.3 continues the Security Behavior Assurance direction by making the shipped artifact itself part of the assurance boundary.

## Priorities

- **Artifact parity:** source distributions, wheels, Debian payloads, tests, and documentation stay synchronized.
- **Version integrity:** package metadata and runtime CLI identity must agree.
- **Failure visibility:** fixture, schema, lifecycle, and packaging failures must be explicit.
- **Assurance continuity:** property lineage, oracle trust, conservative remediation deltas, and the Assurance Frontier remain first-class.
- **Developer-first output:** evidence, replay, remediation, and policy artifacts stay machine-readable and reviewable.

A release is healthy only after compilation, the complete regression suite, the ERSEC self-test, distribution builds, and clean-environment CLI checks. This is a release-quality boundary, not a claim that any scanner can prove the absence of vulnerabilities.

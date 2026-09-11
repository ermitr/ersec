# ERSEC 29.0.0 — V15

## Remediation Verification Loop

V15 adds property-level remediation verification. A security property is considered remediated only when fresh positive evidence satisfies its stable remediation contract. Missing evidence, disappeared observations, and non-positive verdicts are never silently converted into resolution.

## Reproducible Provenance

Provenance environment metadata is now explicit input rather than silently capturing host Python/platform values. This permits identical inputs and explicit environment metadata to produce identical provenance statement digests across build hosts.

## Release Hardening

- Debian payload synchronized with the current 29.0.0 source modules.
- Release-readiness audit now requires the CI gate and remediation verifier.
- CI assurance workflow exercises remediation verification and provenance reproducibility tests.
- Built-in self-test remains 66/66.

All changes remain offline, authorized-harness oriented, non-destructive, and evidence-first.

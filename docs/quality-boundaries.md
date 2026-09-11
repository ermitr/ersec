# ERSEC quality boundaries

ERSEC 29.1.1 adds a dependency-free quality boundary for stable artifact contracts.

## What it checks

- `ersec-quality-manifest/1` validates the shape and uniqueness of golden fixtures.
- `validate_report_semantics()` checks report structure, evidence schema compatibility, and duplicate finding identities.
- `cross_format_identity_check()` verifies that independent output representations contain the same finding identities.

These checks do **not** determine whether an application is secure. They protect the integrity of ERSEC's own assurance artifacts.

## Golden fixture principle

The initial corpus deliberately includes positive, negative, ambiguous, and unmodeled cases. An ambiguous oracle is represented as `observation_unavailable`; it is never silently converted into a pass or violation.

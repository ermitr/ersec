# Authorization Benchmark v4

ERSEC 29.1.0 expands the local authorization corpus to 33 explicit cases. The corpus adds ownership, role/tenant, revoked-session, version-drift, and relationship ambiguity dimensions while retaining deterministic vulnerable/fixed execution.

## Truth classes

- `vulnerable`: controlled defect expected to violate the approved property.
- `safe`: controlled behavior expected to satisfy the property.
- `ambiguous`: the test executes, but the authoritative observation is intentionally unavailable; these cases are reported but excluded from precision/recall.

## Measurement

The benchmark reports precision, recall, F1, scorable-case coverage, per-family coverage, relationship-dimension coverage, request cost, runtime, replayability, and fixture lifecycle status.

Relationship metadata describes the intended security relationship (for example `owner`, `cross_tenant`, `revoked_session`) and is part of the corpus digest. It does not by itself change a verdict.

This is a controlled research fixture, not a competitor benchmark and not evidence of general-world perfect detection.

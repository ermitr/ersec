# ERSEC Authorization Benchmark v3

ERSEC 29.1.0 treats the authorization benchmark as evidence infrastructure rather than a marketing score.

## Quality dimensions

The benchmark reports precision, recall, F1, scorable-case coverage, per-family coverage, request cost, runtime, replayability, corpus validation, and fixture lifecycle state.

## Coverage denominator

Coverage is based on explicitly declared benchmark cases. A case is observed only when the fixture execution produced a case result. Missing or unavailable observations do not increase the coverage ratio and are never treated as PASS.

## Lifecycle safety

The current laboratory uses loopback-only synthetic fixtures, GET-only requests, no external credentials, and no intended state changes. Fixture shutdown and residual-object state are recorded. A benchmark run cannot be successful unless cleanup is verified.

## Reproducibility

The corpus is fingerprinted with SHA-256 over canonical case metadata. Repeated vulnerable/fixed runs compare case verdict signatures. Runtime is recorded as a measurement, not a correctness claim.

## Interpretation

Benchmark numbers describe only the declared, operator-reviewed corpus. They do not establish arbitrary-application accuracy or competitor superiority. Public comparative claims require independently reviewed corpus construction and matched execution conditions.

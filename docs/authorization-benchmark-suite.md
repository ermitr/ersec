# ERSEC Authorization Benchmark Suite v1

The suite is the first reproducible benchmark boundary for the security-behavior assurance wedge.

## Safety

The default suite is loopback-only, synthetic, GET-only, and state-preserving. It does not require customer credentials and does not contact external targets.

## Cases

The v1 corpus contains ten explicit cases spanning horizontal BOLA, vertical privilege boundaries, field-level authorization, anonymous access, revoked sessions, API-version drift, and safe positive controls.

## Metrics

The runner reports precision, recall, F1, false positives, false negatives, per-family counts, request cost, runtime, and coverage. Coverage is the fraction of explicit cases that were actually executed. It is not a security score.

## Ground truth

The vulnerable fixture is a controlled fault-injection target. A case is a benchmark true positive when ERSEC observes the modeled secure property being violated on the vulnerable variant. The fixed variant must contain zero violations.

A benchmark result is not general evidence about arbitrary applications or competitors.

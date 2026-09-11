# ERSEC engineering interfaces

ERSEC 29.1.1 establishes small typed protocols at the boundaries between the
legacy runtime and the future modular architecture.

The initial interfaces are defined in `ersec_interfaces.py`:

- `TransportClient` — bounded HTTP transport boundary.
- `Detector` — detector capability boundary.
- `EvidenceProvider` — redacted evidence boundary.
- `FindingNormalizer` — detector-to-finding normalization boundary.
- `ReportWriter` — report serialization boundary.
- `BenchmarkOracle` — benchmark truth/evaluation boundary.
- `IdentityProvider` — identity source boundary.
- `ContractEvaluator` — regression-contract evaluation boundary.
- `RuntimePolicyEngine` — deterministic runtime policy boundary.

Legacy detectors continue to expose `run_url()` and `run_param()` for
compatibility. `InstrumentedDetector.execute_url()` and `execute_param()` now
provide `DetectorResult`, giving migration code an explicit status, findings,
limitations, error, and execution metadata envelope.

This is deliberately incremental: the next extraction stages should move
transport/scope, evidence/redaction, finding normalization, and benchmark
execution behind these contracts without changing the public CLI behavior.

### 29.1.1 report and test boundaries

`ersec_reports.py` now owns report serialization. JSON scan reports are validated
before replacement and written through a temporary file followed by flush,
`fsync`, and atomic replacement. This prevents interrupted output from silently
turning a previously valid artifact into a truncated report.

`ersec_testing.py` provides a loopback-only controlled HTTP fixture for
integration tests. The fixture is deterministic and harmless and is not a
production probing mechanism.

The next migration boundary is to replace direct output and transport calls in
legacy paths with these interfaces one boundary at a time, retaining the same
public CLI and stable artifact schemas.

### 29.1.1 execution and oracle boundaries

`DetectorExecutionRunner` makes detector status accounting explicit. The
runner aggregates structured `DetectorResult` objects, records failures, and
marks the aggregate incomplete when execution is skipped, inconclusive, not
tested, or failed.

`ersec_oracles.py` adds small deterministic oracle primitives. The key rule is
that missing authoritative observation is never converted into a security
pass.

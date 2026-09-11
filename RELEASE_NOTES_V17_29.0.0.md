# ERSEC 29.0.0 — V17

## Concurrent Security Assurance

V17 closes a major roadmap gap with a deterministic offline concurrency assurance boundary.

### Added
- `ersec_concurrent_assurance.py`
- bounded TOCTOU scenarios
- double-submit/race scenarios
- quota/resource race scenarios
- tenant-context race scenarios
- idempotency race scenarios
- explicit authorized-harness evidence contract
- fail-closed missing-evidence semantics
- CLI compile/evaluate operations
- 29.0.0 capability registration
- Debian payload parity

### Safety
- no network contact
- no destructive actions
- no credential material
- target-side concurrent execution remains outside the offline trust boundary

### Validation
- focused concurrent/roadmap/CI/remediation tests: 17/17 passed
- built-in ERSEC self-test: 66/66 passed
- local example compilation: PASS

### Packaging note
The offline build environment does not contain the required setuptools build dependency cache, so a newly rebuilt wheel is not claimed for V17. The V16 wheel remains available separately; the V17 source archive contains the complete updated source tree.

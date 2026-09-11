# ERSEC 29.0.0 V13

V13 extends the 29.0.0 assurance boundary with authoritative observer normalization and provenance/attestation-ready release statements.

## Added
- `ersec_observer_adapters.py`
- OTel-like span normalization
- OPA decision normalization
- API gateway decision normalization
- Trace-bound authoritative observer correlation
- Service-revision mismatch/missing-evidence rejection
- Explicit observer conflict → `inconclusive` behavior
- `ersec_provenance.py`
- in-toto/SLSA-shaped provenance statement generation from release evidence
- SHA-256 statement integrity verification
- Explicit unsigned-attestation boundary; no digest is presented as a signature
- CI coverage for observer normalization, trace verification, provenance generation, and provenance verification

## Validation
- Observer/provenance/release/continuity/integrated focused tests: 13/13 passed
- ERSEC built-in self-tests: 66/66 passed
- Observer CLI smoke test: passed
- Trace verification smoke test: passed
- Provenance generation and digest verification: passed
- Debian payload updated with new 29.0.0 modules

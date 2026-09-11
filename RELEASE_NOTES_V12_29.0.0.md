# ERSEC 29.0.0 V12

V12 advances the release-assurance boundary with deterministic release evidence binding and developer-first remediation contracts.

## Added
- `ersec_release_evidence.py`
- Content-addressed release artifact certificate
- Certificate integrity verification
- Explicit distinction between digest integrity and cryptographic signatures
- Stable remediation property identities independent of transient finding IDs
- Remediation verification contract with conservative BLOCKED / NOT_RESOLVED semantics
- CLI release-evidence and remediation-contract workflows
- Documentation and deterministic examples

## Validation
- Focused assurance/release-evidence suite: 12/12 passed
- ERSEC built-in self-tests: 66/66 passed
- CLI release-evidence generation: passed
- CLI certificate verification: passed
- CLI remediation-contract generation: passed

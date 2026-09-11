# ERSEC Phase 0 Audit Report

## 1. Repository Status
- **Structure**: The repository is well-structured, containing source code, documentation, examples, and Debian packaging.
- **Git Status**: Not currently a Git repository (unzipped from `ERSEC_29.1.1_PHASE2_FINAL.zip`).
- **Version**: 29.1.1 (declared in `pyproject.toml`).
- **Conflict Markers**: No unresolved merge-conflict markers found.
- **Compilation**: All Python files compile cleanly (`python -m compileall`).
- **Test Status**: 213 tests passed. Note: `pytest` failed initially due to missing `PyYAML`, which is declared in `pyproject.toml` but missing from `requirements.txt`.

## 2. Engineering Baseline
- **Dependencies**: 
    - `pyproject.toml` is the primary source of truth.
    - `requirements.txt` is inconsistent (missing `PyYAML`).
- **Build/Install**: `pyproject.toml` is present. Standard `setuptools` build path is supported.
- **Traceability**: Strong mapping between source files and the `tool.setuptools.py-modules` list.

## 3. Security & Safety Audit
- **Network Request Entry Points**: 
    - Centralized through `ersec_transport.ScopedTransportClient`.
    - Default methods are read-only (`GET`, `HEAD`).
    - Scope checks are performed before every request.
- **Input Parsing**:
    - `ersec_input_safety.py` provides a robust boundary layer.
    - YAML: Uses `yaml.safe_load` and implements an event-count limit to prevent decompression bombs/entity expansion.
    - JSON: Implements depth and node limits (`_preflight_json_depth` and `validate_structure`).
    - General: Implements `bounded_text` and `bounded_bytes` limits.
- **Credential Handling**:
    - `ersec_input_safety.redact` provides key-based and pattern-based redaction.
    - Covers common headers (Authorization, Cookie) and patterns (Bearer tokens, Private Keys).
- **Security Controls**: 
    - Request timeouts and concurrency limits are referenced in the roadmap, but specific implementation in `ersec_transport.py` is minimal (relies on the underlying `client`).

## 4. Packaging & Documentation
- **Debian/Kali**:
    - `debian/` and `packaging/debian/` directories are populated.
    - `debian/control` lists standard dependencies.
    - `ersec.1` manpage is provided.
- **Documentation**:
    - Extensive research and architecture documentation in `docs/`.
    - `RELEASE_NOTES` and `CHANGELOG.md` are maintained.

## 5. Top 10 Priority Blockers
1. **Dependency Inconsistency**: `requirements.txt` must match `pyproject.toml` to ensure clean environment setup.
2. **Git Provenance**: Transition from zip-archive to a proper Git repository with tagged releases.
3. **Authorization Manifest**: The "authorization manifest" for state-changing requests (Phase 2) needs formal implementation and adversarial testing.
4. **Redaction Coverage**: Verification that redaction is applied consistently across all output formats (HTML, JSON, etc.).
5. **Kali Offline Testing**: Verification of the "no network downloads" requirement for Debian installation.
6. **Default Request Limits**: Hardening of timeouts and rate limits in the transport layer.
7. **Private Address Controls**: Implementation of strict checks for loopback/private IP ranges to prevent SSRF.
8. **Credential Rotation Audit**: Ensuring no legacy secrets exist in `examples/` or `tests/fixtures/`.
9. **Benchmarking Evidence**: Transition from sample reports to raw evidence and digests (Phase 6).
10. **SBOM Generation**: Integration of a formal SBOM (Software Bill of Materials) in the release pipeline.

## 6. Phased Implementation Plan

### Phase 1: Restore Engineering Baseline
- Synchronize `requirements.txt` and `pyproject.toml`.
- Initialize Git repository and establish version tags.
- Ensure `python -m build` and `twine check` pass.
- Validate that the installed wheel passes all tests in an isolated environment.

### Phase 2: Safe Default Network Behavior
- Implement strict authorization manifests for non-read-only methods.
- Add private-address/loopback blocking in `ersec_transport.py`.
- Add request/response limits (timeouts, wall-clock).
- Implement dry-run and scope preview functionality.

### Phase 3: Harden Inputs and Outputs
- Verify `defusedxml` usage for all XML parsing.
- Extend `ersec_input_safety.py` to cover all report formats.
- Adversarial testing of YAML/JSON parsers against "bombs".

### Phase 4: Improve Detector Quality
- Define formal security properties and confidence semantics for every detector.
- Create "vulnerable" and "fixed" fixtures for regression testing.

### Phase 5: Meaningful Innovation
- Implement the Authorization Graph and Scope Compiler.
- Develop Differential Authorization testing.

### Phase 6: Honest Benchmarking
- Generate F1 scores and precision/recall metrics using the Benchmark Lab.
- Store raw output digests for reproducibility.

### Phase 7: Reproducible Releases
- Set up GitHub Actions with OIDC for PyPI Trusted Publishing.
- Integrate SBOM generation into the CI pipeline.

### Phase 8: Debian and Kali Readiness
- Finalize `docs/KALI_READINESS.md`.
- Verify offline autopkgtest results.
- Submit for maintainer review.

## 7. Acceptance Criteria
- **Phase 1**: `ersec --self-test` passes on a clean machine.
- **Phase 2**: Any state-changing request without an authorization manifest is blocked.
- **Phase 3**: No credentials appear in any generated report or log.
- **Phase 4**: Every High/Critical finding is backed by evidence and a regression test.
- **Phase 6**: Benchmarks include ground-truth digests.
- **Phase 8**: `validate_kali_29.1.1.sh` passes without network access.

# ERSEC 29.1.0 — Runtime, Performance and Kali UX

## Major changes

- **Detector concurrency is now real:** independent URL-level detectors execute concurrently using the configured concurrency limit instead of serializing every detector call.
- **Rate limiting no longer blocks the worker pool:** ERSEC reserves request slots under a short lock and sleeps outside the critical section, preserving minimum request spacing while allowing slow network responses to overlap.
- **Thread-safe HTTP sessions:** worker threads use isolated `requests.Session` objects while sharing the scan-wide request budget, scope checks, adaptive backoff and evidence accounting.
- **Runtime split:** the public `ersec.py` entry point is now a lightweight lazy facade; `ersec_cli.py` owns CLI bootstrapping; the assessment engine is isolated in `ersec_core.py`.
- **Fast version path:** `ersec --version` no longer imports the full assessment engine. In this build, the cold version-path benchmark is about 0.65 seconds in the development environment, versus about 0.97 seconds for the previous monolithic 29.0.0 entry point in the same environment.
- **Compatibility:** `from ersec import ...` remains supported through lazy symbol forwarding.
- **Dashboard redesign:** the offline HTML report now uses a modern security-operations cockpit layout, stronger typography, KPI telemetry, responsive breakpoints, improved finding cards, search/filter controls, and reduced-motion support. No external font or CDN is required.
- **Packaging:** Python and Debian packaging now include the split runtime modules and identify the release as 29.1.0.

## Security invariants

The performance/UI work does not relax scope enforcement, authorization controls, evidence integrity, deterministic assurance, or the authorized/non-destructive testing boundary.


## Continued roadmap build — disposable assurance fixtures

ERSEC 29.1.0 now includes a deterministic disposable multi-principal fixture compiler.

- Generates synthetic identities, tenants, roles, resources and explicit authorization truth.
- Produces one oracle case per identity/operation combination.
- Rejects credential/token/secret material in fixture specifications.
- Declares a four-stage lifecycle: provision, execute, observe, cleanup.
- Records cleanup as an explicit contract; missing cleanup evidence is not treated as PASS.
- Performs no network access and no destructive actions during compilation.

This is a fixture-planning boundary for an authorized harness, not an autonomous exploitation engine.

## Continued 29.1.0 roadmap build

- Added bounded Stateful Security Behavior Assurance compiler/evaluator.
- Added reviewed business-flow scenario generation with safe negative-path categories.
- Added explicit stateful evidence verdicts and authoritative-oracle availability handling.
- Added credential-material rejection and offline-only execution boundary.
- Added 29.1.0 stateful workflow examples and regression tests.

## Assurance expansion — Hybrid Oracle & Runtime Control Correlation

- Added `ersec_hybrid_oracle.py` for conservative semantic + authoritative evidence fusion.
- Added explicit `observer_conflict` handling: disagreement becomes `inconclusive`, never PASS.
- Added runtime control correlation for OTel/OPA/gateway-style normalized telemetry.
- Added explicit `observed_enforced`, `observed_gap`, `configured_only`, and `insufficient_telemetry` outcomes at the correlation boundary.
- Added offline examples, documentation, and regression tests.

## 29.1.0 — Reproducible Assurance Benchmark Laboratory

- Added `ersec_assurance_benchmark_lab.py`.
- Added deterministic public/release/held-out corpus partitioning.
- Added TP/FP/FN/TN, precision/recall/F1, false-positive rate, inconclusive rate, runtime/request cost, fixture lifecycle, and reproducibility digest reporting.
- Integrated mutation adequacy and observer-conflict boundary checks.
- Added GitHub Actions assurance workflow and Kali validation script.
- The laboratory is loopback-only and does not contact user-supplied targets.

### Integrated assurance loop
- Added `ersec_assurance_loop.py` to compose reviewed policy, inventory, fixture truth, stateful assurance, metamorphic evidence, counterfactual evidence, Security Reality Fabric, Assurance Kernel, and Assurance Intelligence into one reproducible 29.1.0 bundle.
- Added explicit offline/safety governance and integrated digest semantics.
- Added `docs/integrated-assurance-loop-29.1.0.md` and an integrated example policy.


## ERSEC 29.1.0 — Continuous Assurance

29.1.0 now includes deterministic release-lineage snapshots and continuous assurance contracts that compare successive assurance bundles. A PASS claim that becomes unknown, blocked, inconclusive, or not-tested is surfaced as a release regression; missing evidence is never treated as remediation.

## 29.1.0 Maturity Closure — V19

The original 29.1.0 roadmap engineering scope is now closed at the implementation level.

### Build and distribution assurance
- Added `ersec_build_assurance.py` for deterministic source manifests, Debian payload parity, and explicit digest-pinned container contracts.
- Added a reproducible `Containerfile` with an explicit Python 3.12 slim Bookworm manifest digest.
- Added a real Debian source-packaging skeleton under `debian/`, including changelog, control metadata, manpage, shell completions, and autopkgtest smoke coverage.
- Added CI coverage for Debian builds, digest-pinned container builds, offline container self-tests, and reproducibility evidence.
- Added `MANIFEST.in` so source distributions retain the Containerfile, Debian packaging, completions, fixtures, docs and examples.

### Public evaluation boundary
- Added `ersec_public_eval.py`, a scorecard contract for the ERSEC authorization corpus plus OWASP Benchmark Python, WAVSEP, and Juice Shop adapters.
- External results are never inferred from metadata. A PASS scorecard requires version, commit, target/source digest, configuration, command, raw-output digest and ground-truth digest.
- The current local public evaluation proves the ERSEC held-out authorization laboratory; external suite execution remains an explicit environment validation gate rather than an invented claim.

### Roadmap closure
- Roadmap audit: 10/10 feature anchors covered.
- Explicit remaining implementation gaps: none.
- Environment validation gates remain explicitly recorded for container execution, independent clean rebuild, and external public benchmark execution.

### Validation
- Built-in ERSEC self-test: 66/66 passed.
- Focused 29.1.0 assurance/release suite: 90/90 passed.
- Release readiness audit: PASS, failed_count=0.
- Build assurance: PASS, source/package parity MATCH.
- Debian package built with `dpkg-deb --root-owner-group` and installed self-test: 66/66 passed.
- Wheel and sdist built successfully; sdist retains Debian/Containerfile/completion assets.

This release remains authorized, bounded, evidence-first, offline-capable for its assurance compilers, and conservative about uncertainty. A digest is an integrity value, not a cryptographic signature.

## V19 maturity and next-roadmap foundation

- Closed the 29.1.0 roadmap coverage audit at 10/10 feature anchors covered.
- Hardened HTTP client and loopback fixture lifecycle handling.
- Added reproducible source/package parity validation and digest-pinned container contract assets.
- Added the first P0 capability from the next roadmap: Universal Assessment Workspace.
- Workspace supports local/offline normalization of Nmap, Masscan-style output, domain lists, httpx, HAR, OpenAPI/Swagger, Postman, AsyncAPI, supplied GraphQL/gRPC operation documents, SARIF, and Nuclei JSONL.
- Workspace objects preserve source digests and stable canonical identities; import never contacts targets.

## Publication hardening

ERSEC 29.1.0 now includes an explicit GitHub/PyPI publication procedure, a manual TestPyPI Trusted Publishing workflow, Debian `watch` metadata, stricter release-version consistency tests, and CI package-manifest checks for the newest assurance boundaries.

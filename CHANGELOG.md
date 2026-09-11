# Changelog

All notable changes to this project will be documented in this file.

## [29.1.0] - 2026-09-11
**The Assurance Release**

### 🚀 Major Features
- **Assurance Kernel**: Introduced a deterministic engine to compile a "Security Constitution" (policy-as-data) into explicit proof obligations.
- **Security Reality Fabric**: A deterministic claim graph connecting assets, endpoints, findings, invariants, and governance, with a canonical reality digest for longitudinal comparison.
- **Authorization Benchmark Lab**: A revolutionary, loopback-only laboratory that separates policy truth from observed verdicts, providing industry-standard Precision, Recall, and F1 metrics.
- **Deterministic Build Assurance**: Integrated source-to-wheel parity verification, SBOM generation, and provenance tracking for reproducible releases.

### 🛡️ Trust & Safety
- **Fail-Closed Transport**: Hardened the `ScopedTransportClient` to deny all requests by default unless explicitly authorized by a manifest.
- **Input Safety Layer**: Implemented bounded parsers for JSON, YAML, and XML to eliminate XXE and DoS vectors.
- **Recursive Redaction**: Expanded sensitive-data redaction across all output boundaries (JSON, HTML, SARIF, SBOM).
- **Private-Address Policy**: Strict blocking of internal/loopback IP ranges to prevent SSRF.

### ⚙️ Engineering & Performance
- **Modular Runtime**: Split the architecture into a lazy compatibility facade (`ersec.py`), a bootstrap CLI (`ersec_cli.py`), and a high-performance engine (`ersec_core.py`).
- **Adaptive Concurrency**: Optimized the `BoundedScheduler` and `SafeHttpClient` to allow overlapping network I/O while maintaining strict rate-limiting.
- **Adaptive Backoff**: Added automatic 429/503 response handling with exponential backoff.
- **Debian Integration**: Fully synchronized source distribution with Debian packaging assets for Kali Linux readiness.

### 🔬 Research & Assurance
- **Security Behavior Graphs**: Semantic mapping of identities $\rightarrow$ roles $\rightarrow$ resources to identify privilege escalation paths.
- **Differential Authorization**: Divergence analysis between identity tiers to detect BFLA and BOLA.
- **Concurrent Assurance**: Bounded race-sensitive scenario planning for TOCTOU and tenant-context races.
- **Metamorphic Relations**: Deterministic verification of security properties across transformed input variants.

---

## [29.1.0] - 2026-09-06
- Introduced the initial Security Behavior Graph and machine-readable Security Contracts.
- Implemented the first version of the Authorization Manifest for explicit scope control.
- Added the basic Risk Budget Scheduler for information-gain-based planning.
- Introduced the ERSEC Shield application-layer enforcement point.

## [Older Versions]
Historical entries preserved in `RELEASE_NOTES_*.md` and previous project archives.

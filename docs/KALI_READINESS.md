# ERSEC Kali Linux Readiness Document

## 1. The Paradigm Shift: From Detection to Assurance
ERSEC represents a fundamental shift in application security testing. Traditional DAST tools are **detectors**—they search for known-bad patterns and anomalies. ERSEC is an **Assurance Platform**. It treats security as a provable engineering property.

Instead of reporting "I didn't find any BOLA," ERSEC reports: *"I have proven that for the following 48 identities and 12 resources, the defined Security Constitution is strictly enforced. The following 3 paths remain 'Proof Debt' and require manual observation."*

This transition from **vulnerability scanning** to **security behavior assurance** provides the deterministic evidence required for high-assurance release gates.

## 2. Technical Architecture & Safety
ERSEC is designed as a defensive tool for authorized environments.

### Fail-Closed Transport Boundary
The core of ERSEC's safety is the `ScopedTransportClient`. It implements a strict "fail-closed" model:
- **Default Deny**: All requests are denied unless explicitly allowed by an `AuthorizationManifest`.
- **Boundary Enforcement**: Host, port, path, and method validation happen at the transport layer, preventing accidental out-of-scope requests.
- **SSRF Protection**: Private/loopback IP ranges are blocked by default.
- **Input Safety**: All external ingestion (Nmap, OpenAPI, HAR) is processed through bounded parsers to eliminate XXE and DoS vectors.

### Security Behavior Graphs
ERSEC maps identities $\rightarrow$ roles $\rightarrow$ resources. This semantic mapping allows it to identify privilege escalation paths that traditional scanners miss by understanding the *relationship* between principals.

## 3. Reproducibility and Provenance
To be industry-leading, security tools must be as reproducible as the code they test.
- **Source-to-Package Parity**: Every release is verified for parity between source code and the distributed wheel.
- **SBOM**: Every release includes a JSON-formatted Software Bill of Materials.
- **Deterministic Benchmarks**: ERSEC includes a loopback laboratory that allows maintainers to verify the tool's precision, recall, and F1 scores against reviewed ground-truth fixtures.

## 4. Installation and Deployment
### Debian Packaging
ERSEC is packaged as a standard Debian package for seamless integration into Kali Linux.
- **Dependencies**: `python3-requests`, `python3-urllib3`, `python3-bs4`, `python3-yaml`.
- **Zero-Network Install**: The package is self-contained; no network calls are made during installation.

## 5. Maintainer Review Priorities
For Kali maintainers, we recommend prioritizing the audit of the following "Trust Anchors":
1. **`ersec_transport.py`**: The fail-closed logic and boundary enforcement.
2. **`ersec_input_safety.py`**: The bounded parsing and redaction logic.
3. **`ersec_scope_compiler.py`**: The transformation of manifests into runtime rules.

## 6. Limitations
ERSEC is a semantic analyzer, not a fuzzer. It assumes the operator has some knowledge of the target (or uses the discovery phase) to build a behavior model. It does not automate destructive state changes or credential theft.

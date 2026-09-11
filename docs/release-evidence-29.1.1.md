# ERSEC 29.1.1 Release Evidence Binding

`--release-evidence` creates a deterministic certificate over the integrated assurance bundle and every structured artifact it contains. `--verify-release-evidence` recomputes the certificate digest and detects tampering.

The digest is an integrity mechanism, **not a cryptographic signature**. External signing/provenance systems can sign the resulting certificate without changing ERSEC's deterministic trust boundary.

`--remediation-contracts` creates stable developer contracts from security properties. Contract identity is derived from semantic fields rather than transient finding IDs. Missing evidence remains `BLOCKED`; a disappeared observation is `NOT_RESOLVED`.

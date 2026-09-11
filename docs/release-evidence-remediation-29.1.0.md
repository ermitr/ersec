# ERSEC 29.1.0 Release Evidence and Remediation Contracts

ERSEC 29.1.0 binds release artifacts by deterministic SHA-256 content digests and creates stable remediation/regression contracts from the security property being verified. Finding IDs are lineage metadata only; they are not the identity of the property.

A release evidence certificate digest proves integrity of the certificate payload. **It is not a cryptographic signature.** Signature/provenance systems may wrap the certificate externally.

Missing evidence is `BLOCKED`; a disappeared observation is `NOT_RESOLVED`. A remediation is verified only by fresh positive evidence satisfying the contract.

The engine is offline and emits no credential material or exploit instructions.

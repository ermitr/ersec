# ERSEC 29.1.1 — Assurance Intelligence Research Direction

## Purpose

ERSEC 29.1.1 treats application security as an evidence problem, not a finding-count problem. This layer adds deterministic reasoning about **reality gaps, proof debt, evidence freshness, impact cones, and bounded next-best assurance actions**.

## Research basis

- OWASP ASVS 5.0.0 provides a structured basis for technical security verification and explicit requirements. ERSEC's constitution/proof model follows the same verification-first philosophy.
- NIST SP 800-218 defines secure software development practices that should be integrated into the SDLC; NIST's SP 800-218 Rev. 1 draft adds improved practices for modern software delivery. ERSEC therefore treats assurance as a lifecycle state rather than a one-time scan.
- OWASP API Security Top 10 emphasizes authorization, sensitive business flows, SSRF, inventory management and unsafe API consumption. ERSEC's reality-gap and authorization reasoning are designed to expose missing observation around these surfaces.
- OpenTelemetry semantic conventions provide common names for telemetry across traces, metrics, logs and resources. ERSEC's evidence model can correlate runtime observations without making telemetry itself a security verdict.
- in-toto and SLSA establish a foundation for provenance/attestation. ERSEC treats provenance as evidence with explicit trust strength rather than automatic truth.
- OWASP's 2026 Agentic Applications guidance emphasizes goal hijacking, tool misuse, identity/privilege abuse, supply-chain risk and the need for safe, auditable agent behavior. ERSEC deliberately keeps AI outside the deterministic security trust boundary.

## Novel ERSEC architecture

### 1. Reality Gap Engine

Compare what an application **claims or declares** with what ERSEC can positively observe. Gaps are classified as `declared-but-unobserved` or `declared-claim-unobserved`. A gap is an assurance problem, not automatically a vulnerability.

### 2. Proof Debt

Security claims accumulate debt when evidence is weak, uncertain, missing, or stale. This gives teams a deterministic way to identify security properties whose proof is decaying even when the vulnerability count is unchanged.

### 3. Next-Best Assurance

Candidate read-only observations are ranked by expected uncertainty reduction, cost and safety risk under an explicit budget. The result is a bounded plan rather than an unconstrained autonomous attack strategy.

### 4. Security Impact Cone

Claims receive an attention score from impact, graph connectivity and uncertainty. It is explicitly **not** exploit probability. Its purpose is to identify claims whose failure or uncertainty can affect more of the security reality model.

### 5. AI outside the trust boundary

AI may propose hypotheses or remediation ideas, but ERSEC's release decision remains deterministic over typed evidence. This prevents a language model from becoming the final authority on whether a release is secure.

## Safety boundaries

- Authorized targets only.
- No credential theft, persistence, destructive exploitation or arbitrary data extraction.
- Next-best observations are planning artifacts; operators remain responsible for authorization.
- Missing evidence never becomes PASS.
- Observation disappearance is not treated as remediation.
- Impact/cone scores are attention metrics, not compromise probabilities.

## Current limitations

ERSEC 29.1.1 does not claim scientific novelty merely because these mechanisms are combined. The defensible engineering contribution is the deterministic integration of evidence freshness, explicit uncertainty, reality gaps, proof obligations and bounded observation planning into one release-assurance workflow.

# ERSEC 29.1.0 Deep Research Memo — Assurance Kernel

Date: 2026-09-07

## Research question

How can an application-security platform move beyond scanner output into a deterministic, developer- and release-facing assurance system without allowing AI, absence of evidence, or unverified metadata to create false confidence?

## Findings

### 1. Verification should be explicit
OWASP ASVS describes a standardized basis for testing web-application security controls and giving developers security requirements. ERSEC 29.1.0 converts that general verification mindset into explicit per-release proof obligations.

Source: https://owasp.org/www-project-application-security-verification-standard/

### 2. Secure development is a lifecycle property
NIST SP 800-218 and its 2025/2026 revision work emphasize practices integrated into software development and delivery. ERSEC therefore keeps assurance stateful across runs instead of treating each scan as an isolated verdict.

Source: https://csrc.nist.gov/projects/ssdf

### 3. Provenance is evidence about how artifacts were produced
SLSA defines provenance as verifiable information that tracks an artifact through the moving parts of a supply chain. in-toto provides an extensible attestation framework. ERSEC can ingest those claims, but the Assurance Kernel deliberately keeps their evidence strength separate from the security verdict.

Sources:
- https://slsa.dev/spec/v1.2/provenance
- https://in-toto.io/

### 4. Autonomous security needs a hard safety boundary
The 2026 OWASP Autonomous Penetration Testing Standard identifies scope enforcement, safety controls, human oversight, graduated autonomy, auditability, manipulation resistance, supply-chain trust, and reporting as governance domains. This supports a design where intelligent planning is separated from deterministic authorization and release gating.

Source: https://owasp.org/APTS/

### 5. Agentic systems need deterministic runtime enforcement and evidence
Recent 2026 research argues that prompts are insufficient as an enforcement boundary and that safety should include runtime contracts and evidence chains. ERSEC's Assurance Kernel adopts the relevant architectural principle without depending on an LLM.

Sources:
- https://arxiv.org/abs/2608.11274
- https://arxiv.org/abs/2608.21423

## ERSEC design response

The resulting architecture is:

`observations -> Security Reality Fabric -> Security Constitution -> proof obligations -> evidence chain -> PASS / FAIL / BLOCKED -> next assurance action`

The key invariant is: **no positive evidence, no PASS**. A digest proves artifact identity/integrity of the generated record; it is not itself a signature, attestation, or proof that the underlying observation was truthful.

## Research limits

The cited standards and papers do not establish that ERSEC's composition is scientifically novel. The defensible claim is that ERSEC implements a distinct product architecture combining explicit security claims, uncertainty, evidence lineage, deterministic proof obligations, and longitudinal reality state.

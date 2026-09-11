# ERSEC 29.0 — Security Reality Fabric

ERSEC 29.0 advances the roadmap from a collection of scanners and assurance
artifacts into a deterministic **Security Reality Fabric**.

## The new idea

A conventional report answers: *what findings were produced?*

The Reality Fabric answers four harder questions:

1. **What security reality is actually observed?**
2. **Which security claims are supported, contradicted, or unknown?**
3. **Which unknown has the greatest impact and connectivity?**
4. **What is the smallest safe next observation that would reduce that uncertainty?**

The model is evidence-first. It never converts an untested property into PASS.

## Core mechanisms

### 1. Claim graph

Endpoints, findings, behavioral nodes, invariants, contracts, and governance
artifacts become stable nodes with typed relationships.

### 2. Security Reality Digest

The complete graph and claim state receive a canonical content digest. This
makes longitudinal comparisons deterministic and allows CI systems to detect
semantic change without comparing noisy raw request logs.

### 3. Assurance Frontier

The frontier ranks the highest-value unverified claims using impact,
uncertainty, and graph connectivity. It produces reviewable, bounded next
assurance actions rather than blindly increasing request volume.

### 4. Causal risk spine

High-impact claims are ranked by their relationship to the observed security
model. The score is an attention mechanism, not a probability of compromise.

### 5. Security Reality Diff

Two raw reports or two Reality artifacts can be compared. Regressions are
identified when a previously observed safe claim becomes violated or when
uncertainty increases materially. Resolutions require an explicit later PASS;
absence from the later report is not treated as proof of remediation.

## Why this is different

ERSEC 29.0 deliberately avoids claiming that authenticated scanning,
stateful workflows, access-control matrices, or graph visualization are new by
themselves. The differentiating engineering direction is the **closed loop
between evidence, claims, uncertainty, graph connectivity, and the next
assurance obligation**, with a deterministic artifact that can survive across
runs.

This is a research direction and an engineering mechanism, not a claim that
ERSEC can prove the absence of all vulnerabilities.

## Deep-research extension: Assurance Kernel

The next architectural step inside 29.1.1 is to turn the Reality Fabric into a deterministic assurance boundary. Current industry guidance supports several ingredients that ERSEC can combine without pretending they are novel standards of its own:

1. **OWASP ASVS** frames application security verification as a basis for testing technical controls and developer requirements. ERSEC uses the same idea at the property/claim layer, but binds each release obligation to concrete observed evidence.
2. **NIST SSDF** emphasizes secure development practices integrated into the SDLC. ERSEC treats the release as an assurance state transition rather than a single scanner result.
3. **SLSA and in-toto** provide provenance/attestation concepts for tracing how software artifacts were produced. ERSEC can consume provenance as one evidence source while preserving its trust level and limitations.
4. **OWASP APTS (2026)** explicitly calls out scope enforcement, safety controls, human oversight, graduated autonomy, auditability, manipulation resistance, and supply-chain trust for autonomous testing. ERSEC therefore keeps its execution authority deterministic and bounded instead of delegating safety to prompts.
5. Recent 2026 agent-security research argues that deterministic runtime enforcement and evidence-bearing trajectories are safer than trusting an agent's own policy interpretation. ERSEC applies the same separation: planning can be intelligent; the assurance gate remains deterministic.

### What is distinctive in ERSEC 29.1.1

ERSEC's defensible product contribution is the composition: a Security Reality graph becomes a **Security Constitution**, the constitution becomes explicit proof obligations, and each obligation is evaluated against typed claims and a tamper-evident evidence chain. The result is a machine-verifiable release state with first-class uncertainty and a bounded next-assurance path. This is an architectural/product claim, not a claim of scientific priority over the cited projects.

### Trust boundary

The Assurance Kernel intentionally does not treat a hash as a signature, a missing observation as a pass, a model-generated explanation as evidence, or provenance metadata as automatically trustworthy. A cryptographic signature/attestation layer can be added by an external signing system without changing the deterministic gate.

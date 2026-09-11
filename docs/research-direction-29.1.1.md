# ERSEC 29.1.1 — Security Behavior Assurance Roadmap

## Research basis

ERSEC 29.1.1 builds on the supplied roadmap's core claim: the product should verify whether deployed security behavior still matches reviewed authorization and business-flow intent, while showing exactly what was tested, observed, unavailable, and untested. This is a product integration opportunity rather than a claim that each underlying algorithm is novel.

Current primary guidance reinforces this direction:

- OWASP Authorization Testing Automation recommends maintaining an authorization matrix and automating integration tests because authorization regressions often appear as features evolve. ERSEC therefore treats authorization properties as versioned contracts rather than one-off scanner findings.
- NIST API protection guidance emphasizes layered API protection and risk-informed controls; ERSEC keeps gateway configuration separate from downstream enforcement evidence.
- NIST's metamorphic-testing work motivates security relations where a single expected response is unavailable; ERSEC records relation failures as hypotheses until policy or authoritative evidence supports a violation.
- OpenTelemetry semantic conventions provide a common correlation vocabulary across HTTP, database, messaging and RPC telemetry; ERSEC can consume correlation metadata without treating sampled telemetry as complete proof.
- SLSA 1.2 defines provenance as an evidence artifact with increasing authenticity and isolation guarantees; ERSEC treats provenance as typed evidence rather than automatic truth.
- OWASP's 2026 agentic-applications guidance reinforces deterministic scope, oversight and auditability for autonomous systems; ERSEC keeps AI outside the final security trust boundary.

## Implemented in 29.1.1

1. **Security Behavior Assurance Compiler** — reviewed YAML/JSON policy becomes deterministic assurance cells and regression contracts.
2. **Unified API/Behavior Inventory** — normalizes OpenAPI, GraphQL, HAR, browser, traffic, crawler, manual and runtime operation observations.
3. **Runtime Control Evidence** — five-state model: observed enforced, observed gap, configured only, insufficient telemetry, not applicable.
4. **Proof Debt / Reality Gap / Next-Best Assurance** — inherited from the Security Reality Fabric and Assurance Intelligence layers.
5. **Proof-Carrying Release** — inherited Assurance Kernel with tamper-evident evidence links and explicit PASS/FAIL/BLOCKED semantics.
6. **Evidence merge boundary** — observed evidence can update an assurance plan, while untouched cells remain `not_tested`.
7. **29.1.1 deterministic validation** — policy plans, inventory, controls and merged evidence all expose stable digests.

## Research guardrails

ERSEC does not claim that policy compilation, authorization matrices, stateful testing, metamorphic testing, telemetry correlation, or provenance are individually novel. The defensible product distinction is the integrated workflow: reviewed security intent → bounded multi-principal scenarios → semantic/downstream observation → explicit uncertainty → counterexample/evidence → regression contract → release assurance.

ERSEC should not build an unrestricted autonomous hacking agent, generic template ecosystem, arbitrary symbolic executor, or default production blocker. Those choices conflict with the roadmap's safety and evidence principles.

## Exit criteria

A 29.1.1 release is considered trustworthy only when the default scan, security-model path, assurance compiler, proof verification, package install, fixture suite, report schema, and regression tests complete without uncaught exceptions on the controlled test matrix. Combined-suite timeout behavior must be treated as an engineering issue rather than silently ignored.

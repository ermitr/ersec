# ERSEC 29.1.0 — Security Behavior Assurance Platform

ERSEC 29.1.0 is the current release identity. The product is built around one core loop: **reviewed security intent → bounded multi-principal assurance → semantic/downstream evidence → explicit uncertainty → regression contract → release decision**.

## 29.1.0 Assurance Compiler

Compile a reviewed YAML policy without contacting a target:

```bash
ersec --assurance-policy-compile examples/security-behavior-policy-29.1.0.yaml --assurance-policy-out assurance-plan-29.1.0.json
```

Normalize API and behavior inventory:

```bash
ersec --assurance-inventory examples/api-behavior-inventory-29.1.0.json --assurance-inventory-out inventory-29.1.0.json
```

Evaluate imported runtime-control evidence:

```bash
ersec --assurance-controls examples/runtime-control-evidence-29.1.0.json --assurance-controls-out controls-29.1.0.json
```

Validate the plan:

```bash
ersec --assurance-plan-validate assurance-plan-29.1.0.json
```

The compiler never turns missing evidence into PASS. `not_tested`, `blocked`, `inconclusive`, and `observation_unavailable` remain explicit. Runtime gateway configuration is not treated as proof of downstream authorization.

## 29.1.0 research direction

The 29.1.0 roadmap focuses on Security Behavior Assurance: a unified API/behavior inventory, reviewed authorization policy, disposable multi-principal fixtures, stateful business-flow verification, semantic and authoritative oracles, metamorphic relations, mutation adequacy, runtime-control evidence, counterfactual evidence bundles, safe CI integration, reproducible benchmarks, and proof-carrying release decisions.

The defensible novelty is the integrated assurance workflow—not a claim that individual components such as authorization matrices or metamorphic testing were invented by ERSEC.

## ERSEC 29.1.0 — Semantic Authorization Assurance

This release begins the focused authorization-assurance wedge. With an explicit Security Behavior Model, ERSEC can evaluate modeled identity/resource cells using expected status and bounded response-field semantics, calculate assurance coverage, and emit minimal counterexamples when a property is violated.

A deterministic loopback laboratory fixture is included for development and benchmark work. Export the starter ground-truth corpus with:

```bash
ersec --authorization-ground-truth authorization-ground-truth.json
```

Write semantic assurance during a modeled run with:

```bash
ersec --security-model model.json --authorization-assurance authorization-assurance.json -t https://authorized.example
```

Untested or unobservable cells are never counted as secure. Response values are not persisted by the semantic field observer; only bounded field paths are retained.


## Evidence-first application security and security-behavior verification

ERSEC is a defensive application-security platform for authorized web and API assessments. It combines broad bounded discovery and detection with a **Security Behavior Graph**, evidence/proof records, multi-identity and workflow reasoning, a **Security Control Plane**, reviewable security contracts, risk-budget planning, and the ERSEC Shield application-layer enforcement point.

The goal is not to advertise the largest detector count. The goal is to make important security behavior **observable, explainable, reproducible, and continuously testable**.

> **Current release:** 29.1.0  

## ERSEC 29.1.0 — Security Reality Fabric

29.1.0 introduces the Security Reality Fabric: a deterministic claim graph that connects observed application surface, security findings, behavioral invariants, contracts, and governance. It computes a canonical reality digest, an explainable causal risk spine, and an Assurance Frontier that recommends the smallest safe next observation for the highest-impact unknowns. It also provides a conservative semantic diff for longitudinal security regressions.

See `docs/research-direction-29.0.md`.

## ERSEC 29.1.0 — Assurance Kernel & Proof-Carrying Release

29.1.0 now has a deterministic **Assurance Kernel** on top of the Security Reality Fabric. Instead of asking only whether a scanner found something, ERSEC can compile an explicit security constitution into proof obligations and produce a release artifact that says exactly what is proven, what failed, and what remains unknown.

Key properties:

- **Security Constitution:** reviewable policy-as-data describing what must be proven.
- **Proof-Carrying Release:** release decisions carry the evidence chain that caused them.
- **Evidence-chain verification:** tampering or reordering of proof links is detectable.
- **Three-valued release truth:** `PASS`, `FAIL`, or `BLOCKED`; missing evidence never becomes PASS.
- **AI outside the trust boundary:** models may help generate hypotheses, but deterministic ERSEC policy/evidence checks decide the gate.
- **Research-aligned supply-chain semantics:** provenance is treated as evidence with explicit trust rather than an unconditional claim.

Example:

```bash
ersec --reality-model scan.json --reality-out reality.json
ersec --assurance-kernel reality.json --assurance-kernel-out release-assurance.json
ersec --verify-assurance-proof release-assurance.json
```

A `BLOCKED` result is intentionally a release stop: it means ERSEC cannot prove a required obligation from the evidence available. It is not a claim that the application is compromised. Likewise, `PASS` means the configured obligations were proven to the configured evidence thresholds; it is not a universal proof of security.

> **Testing model:** authorized, bounded, non-destructive by default  
> **AI model:** deterministic security analysis is the source of truth; optional local model assistance is not required for core operation

### ERSEC 29.1.0


## ERSEC 29.1.0 — Semantic Authorization Assurance

This release begins the focused authorization-assurance wedge. With an explicit Security Behavior Model, ERSEC can evaluate modeled identity/resource cells using expected status and bounded response-field semantics, calculate assurance coverage, and emit minimal counterexamples when a property is violated.

A deterministic loopback laboratory fixture is included for development and benchmark work. Export the starter ground-truth corpus with:

```bash
ersec --authorization-ground-truth authorization-ground-truth.json
```

Write semantic assurance during a modeled run with:

```bash
ersec --security-model model.json --authorization-assurance authorization-assurance.json -t https://authorized.example
```

Untested or unobservable cells are never counted as secure. Response values are not persisted by the semantic field observer; only bounded field paths are retained.


29.1.0 focuses on the engineering foundation: validated atomic report serialization, controlled loopback integration fixtures, and safe artifact handling while preserving the existing security-assurance interfaces.

This release completes the next trust-focused engineering step: model findings share the common finding pipeline, benchmark quality is explicit, incomplete scans are visible to CI, request-budget exhaustion is reported cleanly, and failure-injection coverage is expanded.

---

## What ERSEC is becoming

ERSEC 29.1.0 extends the platform from inferred behavior to an operator-declared security model when teams have explicit knowledge of their identities, tenants, resources and security policy.

A conventional scanner answers:

> “What suspicious responses did I observe?”

ERSEC 29.1.0 asks a wider set of security-behavior questions:

> “Which identities, resources, workflows and controls exist?”  
> “What security behavior is invariant?”  
> “Where does that behavior change?”  
> “What evidence proves the change?”  
> “Can the same property become a regression contract?”  
> “What changed since the previous run?”  
> “Can a narrowly scoped compensating control reduce exposure while the real fix is being developed?”

This direction is consistent with the industry's focus on authorization, sensitive business flows, resource consumption and API security rather than relying only on payload signatures. OWASP's API Security Top 10 emphasizes authorization heavily and explicitly includes unrestricted access to sensitive business flows and unrestricted resource consumption. [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) 

---

# Architecture

```text
                         ERSEC 29.1.0
                             │
            ┌────────────────┼─────────────────┐
            │                │                 │
            ▼                ▼                 ▼
       Discovery         Detection         Runtime Shield
            │                │                 │
            └────────────────┼─────────────────┘
                             ▼
                    Evidence / Proof
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        Behavior Graph   Risk / Causal   Control Plane
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    Security Contracts
                             │
                             ▼
                      CI / Release Gate
                             │
                             ▼
                       Next ERSEC run
```

---

# Core capabilities

## Discovery

ERSEC can discover application surface through:

- same-origin crawling;
- HTML links and forms;
- `robots.txt` and `sitemap.xml`;
- JavaScript references;
- SPA/browser traffic when Playwright is available;
- API-like route discovery;
- JSON schema hints;
- API contract mining;
- passive surface mining.

Missing optional browser tooling is handled as a fallback condition rather than being treated as proof of a clean application.

## Detection

The current release contains the established ERSEC detector registry plus deeper behavioral/differential engines covering areas such as authentication, authorization, injection signals, API exposure, caching, browser security, configuration, request normalization, and application-specific business-flow signals.

Detector count is deliberately not treated as the primary quality metric. A registered detector is not equivalent to a guaranteed true-positive rate or complete vulnerability coverage.

## Multi-identity authorization reasoning

ERSEC can compare explicitly supplied authorized identities across application resources and workflows.

Example identities:

```yaml
identities:
  user_a:
    bearer_token: ${USER_A_TOKEN}
    tenant: tenant_a
    role: user
  user_b:
    bearer_token: ${USER_B_TOKEN}
    tenant: tenant_b
    role: user
  administrator:
    bearer_token: ${ADMIN_TOKEN}
    tenant: global
    role: admin
```

Comparison dimensions include:

- HTTP status;
- response shape;
- sensitive fields;
- object identifiers;
- redirect behavior;
- caching behavior;
- observable side effects;
- supporting timing evidence.

Timing is treated as supporting evidence, not standalone proof.

---

# Security Behavior Graph

The flagship behavior-verification capability is a deterministic model of security-relevant application behavior.

The graph can represent:

- identities;
- resources and routes;
- findings;
- workflow states and transitions;
- learned security invariants.

The graph connects evidence to the resource or state where it was observed.

Conceptually:

```text
identity:user_a
       │
       │ accesses
       ▼
resource:/api/orders/123
       │
       │ affected by
       ▼
finding:F-123
       │
       │ may violate
       ▼
invariant:user-isolation
```

The graph is not decorative. Its purpose is to give security teams a stable representation that can be compared, exported and turned into regression contracts.

---

# Explicit Security Behavior Model

ERSEC 29.1.0 continues the strict, declarative model for teams that want to encode known authorization policy rather than relying only on inference. The model is intentionally separate from credentials: it contains identity names, roles, tenants, resources, expected read-only outcomes, invariants, and workflow transitions. Runtime tokens remain in the operator's environment.

Validate a model without contacting a target:

```bash
ersec --validate-security-model examples/security-model.example.json
```

Use a model during an authorized scan:

```bash
ersec -t https://example.com \
  --security-model security-model.json \
  --behavior-verify-out behavior-verification.json \
  --behavior-state .ersec-security-behavior-state.json \
  --contract-dir .ersec-contracts
```

A minimal model looks like:

```json
{
  "schema": "ersec-security-behavior-model/1",
  "identities": [
    {"name":"user_a","role":"user","tenant":"tenant_a","privilege_rank":1},
    {"name":"user_b","role":"user","tenant":"tenant_b","privilege_rank":1}
  ],
  "resources": [
    {
      "id":"order_a",
      "url":"https://example.com/api/orders/100",
      "owner":"user_a",
      "tenant":"tenant_a",
      "methods":["GET"],
      "expected": {
        "user_a":{"status":[200]},
        "user_b":{"status":[403,404]}
      }
    }
  ],
  "invariants": [
    {
      "id":"INV-TENANT-001",
      "type":"tenant_isolation",
      "subject":"user_b",
      "resource":"order_a",
      "statement":"A tenant B user must not read a tenant A order.",
      "severity":"CRITICAL"
    }
  ]
}
```

The built-in verifier is deliberately read-only: only `GET`, `HEAD`, and `OPTIONS` can be modeled for execution. A missing identity credential becomes `not_tested`, not an implicit authorization decision.

# Security invariants

ERSEC can represent statements such as:

```text
A user in tenant A must not read an object belonging to tenant B.

A lower-privilege identity must not access an administrative resource.

A workflow must not reach an approved state without the required transition.

An identity token intended for one audience must not be accepted as another audience.

Authorization should remain equivalent across equivalent resource representations.

A new API version should not silently weaken authorization semantics.
```

These are **security properties**, not generic vulnerability signatures.

---

# Proof-carrying findings

Every important finding can be represented as a structured proof capsule using the ERSEC proof schema.

The record includes:

1. observation;
2. baseline availability;
3. detector reasoning;
4. evidence score;
5. impact context;
6. limitations;
7. replay information;
8. remediation information;
9. integrity information.

Example shape:

```json
{
  "schema": "ersec-proof/2",
  "finding_id": "F-123",
  "category": "sql_injection_signal",
  "severity": "HIGH",
  "confidence": "Confirmed",
  "observation": {},
  "baseline": {},
  "detector_reasoning": {},
  "impact": {},
  "limitations": [],
  "replay": {
    "credentials_persisted": false
  },
  "remediation": {},
  "integrity": {
    "algorithm": "sha256"
  }
}
```

ERSEC intentionally does not persist authentication credentials inside proof capsules.

---

# Explicit result semantics

ERSEC distinguishes uncertainty rather than converting it into a larger vulnerability count.

| Classification | Meaning |
|---|---|
| `confirmed` | Controlled evidence established the stated behavior with strong evidence. |
| `likely` | Evidence strongly supports the behavior, but an important condition requires review. |
| `signal` / `possible` | Suspicious behavior was observed without sufficient proof. |
| `inconclusive` | Testing could not support a reliable determination. |
| `not_tested` | Required context was unavailable. |

A clean scan is therefore not equivalent to “secure.”

---

# Security contracts

ERSEC can compile observed findings and invariants into a machine-readable contract bundle.

```bash
python ersec.py \
  -t https://staging.example.com \
  --contract-dir .ersec-contracts
```

Generated artifacts include:

```text
.ersec-contracts/
├── ersec-contracts.json
├── pytest_contracts.py
├── playwright_contracts.md
├── postman.collection.json
└── openapi-security-assertions.json
```

Generated finding-regression tests are deliberately **drafts**. ERSEC does not invent an application-specific “safe response” predicate that the evidence never established.

Review and replace the draft predicate with the application's real security expectation before enabling it as a release gate.

This turns ERSEC from a point-in-time scanner into a source of repeatable security controls.

---

# Risk-budget scheduler

Security testing is not only about the number of requests. It is also about information gained per unit of cost and risk.

ERSEC 29.1.0 exposes a bounded risk-budget planner that considers signals such as:

- information gain;
- crown-jewel proximity;
- authorization relevance;
- contract relevance;
- request cost;
- state-change risk.

Run with:

```bash
python ersec.py -t https://staging.example.com --risk-budget 40
```

The report records selected and skipped candidates so incomplete coverage is visible instead of silently appearing complete.

---

# Authorization manifest

For higher-assurance engagements, create an explicit authorization manifest.

Example:

```json
{
  "schema": "ersec-authorization-manifest/1",
  "name": "example-staging-assessment",
  "owner": "security-team@example.com",
  "purpose": "Authorized application-security assessment of staging",
  "allowed_hosts": ["staging.example.com"],
  "allowed_ports": [443],
  "allowed_paths": ["/", "/api", "/account"],
  "allowed_methods": ["GET", "HEAD", "OPTIONS"],
  "window_start": "2026-09-06T08:00:00Z",
  "window_end": "2026-09-06T22:00:00Z",
  "private_address_policy": "deny",
  "stateful_tests": "deny",
  "approved_identities": ["anonymous", "user_a"]
}
```

Use it with:

```bash
python ersec.py \
  -t https://staging.example.com \
  --authorization-manifest examples/authorization-manifest.example.json
```

The manifest adds a second authorization layer above normal scanner scope.

With a supplied manifest, requests are denied when they fall outside its hosts, ports, paths, methods, or authorized testing window. A private-address deny policy also fails closed when a destination resolves to a private, loopback, link-local, multicast, or unspecified address.

This does not replace organizational authorization procedures. It is an additional technical guardrail.

---

# Stateful test simulator

State-changing operations require more care than read-only observation.

ERSEC can produce a dry-run preview of stateful forms without submitting them:

```json
{
  "method": "POST",
  "url": "/checkout",
  "predicted_state_change": "form submission may mutate server-side state",
  "rollback_plan": "application-specific rollback required",
  "enabled": false
}
```

The preview is not evidence that the state change occurred.

Safe automation should not invent rollback procedures for application-specific state transitions.

---

# ERSEC Shield

ERSEC Shield is an **application-layer reverse proxy / WAF-style enforcement point**. It is not a replacement for a network firewall.

OWASP describes virtual patching as a compensating enforcement layer for known vulnerabilities and recommends positive/allow-list models where the expected input characteristics can be established. It also emphasizes that virtual patching is risk reduction and does not replace fixing the application itself. [OWASP Virtual Patching Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html) 

Shield supports:

- `monitor` mode;
- `block` mode;
- `learn` mode;
- method restrictions;
- request body limits;
- URL-length limits;
- rate limiting;
- request-framing sanity checks;
- path normalization anomaly checks;
- narrow evidence-derived virtual patches;
- route learning;
- privacy-minimized telemetry.

Start it locally:

```bash
python ersec.py \
  --shield \
  --shield-upstream http://127.0.0.1:8000 \
  --shield-port 8080 \
  --shield-mode monitor \
  --shield-log .ersec-shield.jsonl
```

Compile a narrow virtual-patch policy from a report:

```bash
python ersec.py \
  --shield-compile ersec-report.json \
  --shield-policy ersec-shield-policy.json
```

Rules generated from evidence carry governance metadata including:

- source finding ID;
- owner;
- creation timestamp;
- expiration timestamp;
- rollback guidance;
- simulation/review status.

By default generated virtual patches have a finite review horizon rather than pretending that a temporary control is a permanent code fix.

---

# Positive security direction

The long-term Shield strategy is to move from mostly negative signatures toward selective positive-security envelopes where application behavior is stable enough to establish expected input and route characteristics.

That means learning statements such as:

```text
/api/orders/{id}
  allowed methods: GET
  id: integer-like
  identity required: user
  tenant boundary: caller-owned
```

rather than trying to maintain an ever-growing list of exploit strings.

This is intentionally incremental. A learned contract is only useful when its false-positive risk is understood.

---

# Security Control Plane

The Security Control Plane turns a scan into persistent application-security state.

It provides:

- application asset modeling;
- exposed-asset categorization;
- security hypotheses;
- exposure budget scoring;
- security SLO compilation;
- cross-run regression state.

Example SLO concepts:

```text
critical findings      → target 0
high findings          → target 0
coverage ratio         → target 0.80+
critical attack paths  → target 0
```

These are **operator policy examples**, not universal compliance requirements.

Persist the control-plane state:

```bash
python ersec.py \
  -t https://staging.example.com \
  --control-plane-memory .ersec-control-plane.json \
  --security-slo .ersec-security-slo.json
```

---

# Cross-run security state

ERSEC can compare current and previous application-security state.

The output can identify:

- new assets;
- removed assets;
- new findings;
- resolved findings;
- new risk chains;
- resolved risk chains;
- security regressions.

This is what lets ERSEC behave like a continuous security control rather than a report generator that starts from zero each time.

---

# Behavioral memory and drift

ERSEC maintains local behavioral memory and security behavior genome information where configured.

Longitudinal reasoning can help identify:

```text
stable behavior
      ↓
release change
      ↓
authorization drift
      ↓
new evidence
      ↓
regression contract
```

This complements rather than replaces code review and change management.

---

# API security

ERSEC includes API-oriented discovery and reasoning for REST, GraphQL and gRPC-like surfaces.

The API layer is designed around the kinds of problems highlighted by OWASP's API Security Top 10, including object/function authorization, property-level authorization, resource consumption, sensitive business flows, SSRF, inventory, and unsafe API consumption. [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) 

ERSEC can therefore reason about more than “did this payload generate an error?”

It can compare:

- API versions;
- methods;
- object identifiers;
- parameter shapes;
- content representations;
- identities;
- response schemas;
- workflow states.

---

# Business-flow security

Some of the hardest API security issues are business-specific.

ERSEC identifies review surfaces around things such as:

- checkout;
- orders;
- inventory;
- pricing;
- discount/coupon flows;
- account and identity operations;
- approval workflows.

The goal is to establish an invariant and test whether alternate endpoints or identities violate it, not to automate harmful transactions.

OWASP explicitly identifies sensitive business-flow protection as a distinct API security concern because abuse can cause business harm even when a classic technical vulnerability is not present. [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) 

---

# Evidence-based remediation

The built-in advisor is local and deterministic by default.

It can:

- explain the observed condition;
- select remediation guidance;
- use stack fingerprints;
- provide verification steps;
- account for risk chains.

Optional local GGUF model support can assist explanation/triage, but the model is not the source of truth.

ERSEC does not upload application evidence to a remote AI service as part of the default advisor path.

---

# Policy as code

ERSEC can export security-oriented policy artifacts for developer review, including Semgrep/OPA-oriented material.

The correct engineering pattern is:

```text
finding
  ↓
policy proposal
  ↓
review
  ↓
CI enforcement
```

not:

```text
scanner
  ↓
automatically rewrite production code
```

---

# Benchmark and quality measurement

ERSEC includes benchmark plumbing for local benchmark reports and operator-supplied truth data.

The quality layer can calculate:

- true positives;
- false positives;
- false negatives;
- precision;
- recall;
- F1.

The metric is only meaningful when the benchmark oracle is trustworthy and representative.

A serious benchmark program should include:

- OWASP Juice Shop;
- WebGoat;
- multi-tenant applications;
- GraphQL authorization labs;
- OAuth/session fixtures;
- commerce/approval workflows;
- false-positive trap applications;
- vulnerable/fixed application pairs;
- caching, redirect, proxy and TLS fixtures.

The project roadmap explicitly treats benchmarked detector quality as more meaningful than detector count. 

---

# Safety model

ERSEC is designed around bounded authorized testing.

The HTTP client enforces controls such as:

- allowed hosts;
- allowed ports;
- allowed paths;
- allowed methods;
- request budgets;
- rate limits;
- concurrency limits;
- connect/read timeouts;
- adaptive backoff.

ERSEC deliberately avoids general-purpose workflows for:

- data extraction;
- persistence;
- credential theft;
- destructive state changes;
- remote shell acquisition;
- malware deployment.

A finding is evidence for a security condition, not an invitation to weaponize it.

---

# Installation

## PyPI

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install ersec
```

Then:

```bash
ersec --version
ersec --self-test
```

## From source

```bash
git clone https://github.com/ermitr/ersec.git
cd ersec
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
```

---

# Basic usage

```bash
ersec -t https://example.com
```

Deep assessment:

```bash
ersec -t https://example.com --profile deep
```

Maximum bounded coverage:

```bash
ersec -t https://example.com -m
```

JSON/HTML report:

```bash
ersec \
  -t https://example.com \
  --profile deep \
  --output ersec.json \
  --html ersec.html
```

---

# High-assurance scan example

```bash
ersec \
  -t https://staging.example.com \
  --profile deep \
  --authorization-manifest examples/authorization-manifest.example.json \
  --control-plane-memory .ersec-control-plane.json \
  --security-slo .ersec-security-slo.json \
  --security-graph .ersec-security-behavior-graph.json \
  --contract-dir .ersec-contracts \
  --proof-dir .ersec-proof \
  --history-db .ersec-history.sqlite \
  --crown-jewel /admin \
  --crown-jewel /account \
  --crown-jewel /checkout \
  --output ersec.json \
  --html ersec.html \
  --sarif ersec.sarif \
  --markdown ersec.md \
  --junit ersec.xml
```

---

# CLI reference: assurance commands

```text
--authorization-manifest FILE
--stateful-tests
--risk-budget N
--contract-dir DIR
--security-graph FILE
--benchmark-quality FILE
--security-category-manifest
```

Existing ERSEC scanning, reporting, re-verification, memory, policy, IDE, benchmark, browser, workflow and Shield options remain available.

Inspect the installed CLI for the authoritative option set:

```bash
ersec --help
```

---

# Security category registry

The canonical registry is exposed so integrations can consume a consistent security vocabulary:

```bash
ersec --security-category-manifest
```

This registry associates supported categories with:

- canonical name;
- test family;
- Shield compatibility;
- minimum confidence requirement;
- remediation key.

This is an important architectural control: detector semantics and runtime enforcement should not maintain separate incompatible copies of the taxonomy.

---

# Re-verification

Re-run exact recorded evidence against an authorized target:

```bash
ersec \
  -t https://staging.example.com \
  --reverify ersec.json
```

Audit the verification history:

```bash
ersec --verify-audit-log verification-audit.json
```

---

# Release engineering

The GitHub repository includes CI intended to validate:

1. Python compatibility;
2. source compilation;
3. ERSEC self-tests;
4. pytest smoke tests;
5. build distribution validation;
6. installation of the actual built wheel;
7. release-version/tag consistency;
8. GitHub artifact provenance;
9. PyPI Trusted Publishing.

PyPI's current Trusted Publishing documentation recommends the PyPA publish action with job-level `id-token: write` permission and a dedicated environment. [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) 

The PyPI publishing action also generates and uploads PyPI attestations by default when configured with Trusted Publishing. [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/) 

GitHub artifact attestations provide an additional build-provenance mechanism for release artifacts. [GitHub Artifact Attestations](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) 

---

# Versioning

ERSEC follows a conventional major/minor/patch release model for the public project.

For every release, keep these aligned:

```text
pyproject.toml
ERSEC runtime version
CHANGELOG.md
Git tag
GitHub Release
Debian package
PyPI package
```

The CI release workflow checks the Git tag against the version declared in `pyproject.toml`.

---

# Project maturity rules

The project deliberately adopts the following rules:

### A capability is not complete because a class exists.

Its output must reach a supported workflow and be tested.

### A finding is not stronger because its severity is higher.

Evidence and confidence must justify the result.

### A virtual patch is not a source-code fix.

It is a compensating control with review and rollback metadata. OWASP explicitly frames virtual patching as risk reduction rather than a substitute for fixing the application. [OWASP Virtual Patching Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html) 

### A green scan is not proof of security.

Coverage limitations remain visible.

### More detector names do not automatically mean a better product.

Benchmark precision, reproducibility, evidence quality and regression value matter more.

---

# Limitations

ERSEC cannot guarantee absence of vulnerabilities.

Important limitations include:

- business logic can require deep domain understanding;
- authorization relationships may be impossible to infer without multiple authorized identities;
- browser-based behavior varies by application and runtime;
- some vulnerabilities require state changes that ERSEC intentionally does not automate;
- network/infrastructure weaknesses outside the application boundary may need other tooling;
- third-party dependency risk requires dedicated dependency analysis;
- false positives and false negatives remain possible.

The Security Behavior Graph and contracts improve continuity and evidence quality; they do not eliminate the need for human security engineering judgment.

---

# Legal and authorization notice

Only use ERSEC against systems you own or systems for which you have explicit permission to perform security testing.

An authorization manifest is a technical guardrail, not legal authorization.

Do not use ERSEC to:

- access unauthorized systems;
- steal credentials or private information;
- disrupt availability;
- deploy persistence;
- exfiltrate data;
- weaponize application vulnerabilities.

---

# Contributing

See `CONTRIBUTING.md`.

Security-related contributions should include tests, evidence semantics, safety considerations, and documentation of blind spots.

---

# Security reporting

See `SECURITY.md` for responsible disclosure guidance.

Do not place real secrets, credentials or private customer data in public issues or pull requests.

---

# License

ERSEC is distributed under the MIT License. See `LICENSE`.

---

# Research references

- NIST Special Publication 800-207, *Zero Trust Architecture*.
- OWASP Virtual Patching Cheat Sheet.
- OWASP API Security Top 10.
- PyPA packaging and publishing guidance.
- PyPI Trusted Publishing and digital attestations documentation.
- GitHub Artifact Attestations documentation.

The research direction for ERSEC is intentionally centered on evidence, authorization behavior, safe enforcement, reproducible controls, and release integrity rather than AI branding or detector-count inflation. 

## ERSEC 29.1.0 — Release focus

This release packages the Security Behavior Graph, explicit Security Behavior Model, read-only authorization verification, counterexample paths, authorization matrix, governed security contracts, release assurance, SBOM generation, benchmark scaffolding, and the application-layer Shield in one versioned distribution.

### Quality contract

ERSEC treats the following as first-class release requirements:

- deterministic evidence rather than unsupported guesses;
- explicit `pass`, `violated`, `inconclusive`, and `not_tested` semantics;
- human review before a generated security contract can gate CI;
- read-only authorization verification for modeled behavior;
- reproducible artifacts with version-consistent source and packaging metadata;
- transparent limitations and documented blind spots.

The public release is **29.1.0**.


### Authorization assurance (29.1.0)

Export a deterministic authorization matrix from a reviewed security model with `--authorization-matrix-v2`. Credential inputs are opaque references, never raw secret values. Remediation comparison requires an explicit later `pass` verdict before a previous violation is considered resolved.


## Research comparison benchmark

ERSEC 29.1.0 adds a comparison-ready authorization benchmark analysis that separates reviewed policy truth from observed verdicts, reports false positives/negatives and uncertainty, and fingerprints the corpus and comparison rules. Run it only against the included loopback laboratory.

```bash
ersec --authorization-research-benchmark research-result.json
```

See `docs/authorization-research-benchmark-v8.md`.

## Research benchmark starter

Run the deterministic local multi-tenant authorization benchmark with `ersec --authorization-benchmark RESULT.json`. The fixture is loopback-only, read-only, and uses operator-reviewed ground truth.

## Research review (2026-09)

ERSEC's current research position was reviewed against official documentation from ZAP, Burp Scanner, Schemathesis, Nuclei and OWASP API Security. See `docs/research-review-2026-09.md`. The review intentionally avoids claiming stateful scanning, authentication, workflows or access-control matrices as inventions; ERSEC focuses on semantic authorization properties, authoritative postconditions, coverage and longitudinal evidence.
## Security Behavior Assurance v1

ERSEC 29.1.0 adds property-level assurance lineage, an Oracle Trust Lattice, conservative remediation deltas, and an Assurance Frontier. These are research/assurance mechanisms: they distinguish strong evidence from weak or unavailable observation and never turn untested behavior into PASS.

```bash
ersec --assurance-lineage research-result.json
ersec --assurance-delta before.json after.json
```



## ERSEC 29.1.0 — Assurance Execution & Release Hardening

29.1.0 hardens the shipped assurance boundary: runtime/package versions are aligned, loopback fixture lifecycle handling is corrected, and regression fixtures are included in source distributions. The trust rules from 29.1.0 remain unchanged: untested or unobservable behavior is never treated as secure, and active testing remains bounded and authorized.

## ERSEC 29.1.0 — Assurance Intelligence

ERSEC 29.1.0 adds an additional deterministic assurance layer above the Security Reality Fabric and Assurance Kernel.

### Reality Gap Engine

Compare a 29.1.0 Reality artifact against an operator declaration and identify declared-but-unobserved application surface or security claims. A gap is never silently interpreted as a vulnerability, and disappearance of an observation is never interpreted as a fix.

### Proof Debt

Claims with missing, weak, uncertain, or stale evidence accumulate measurable proof debt. This lets teams prioritize assurance work even when the raw finding count has not changed.

### Next-Best Assurance

ERSEC 29.1.0 can rank bounded, non-destructive read-only observations by expected uncertainty reduction, cost, and safety risk under an explicit observation budget.

```bash
ersec --assurance-intelligence reality.json \
  --assurance-intelligence-declared examples/assurance-declaration.example.json \
  --assurance-intelligence-out assurance-intelligence.json \
  --assurance-intelligence-budget 10
```

### Security Impact Cone

The model highlights high-impact claims with strong graph connectivity and uncertainty. This is an attention score, not exploit probability.

### Compare assurance state

```bash
ersec --assurance-intelligence-diff before-reality.json after-reality.json
```

### Recommended 29.1.0 workflow

```text
scan → Reality Fabric → Assurance Intelligence → Assurance Kernel → proof verification → release gate
```

The deterministic gate remains authoritative. AI is optional and never becomes the final security trust boundary.

## ERSEC 29.1.0 reproducible assurance laboratory

ERSEC 29.1.0 now includes a loopback-only benchmark laboratory that separates public, release, and deterministic held-out authorization cases and records TP/FP/FN/TN, precision, recall, F1, false-positive rate, inconclusive results, request/runtime cost, fixture cleanup, mutation adequacy, and reproducibility digests.

Run it with:

```bash
python3 ersec.py --assurance-benchmark-run artifacts/assurance-benchmark-29.1.0.json
```

See `docs/assurance-benchmark-lab-29.1.0.md` for the methodology and evidence contract. The laboratory does not contact user-supplied targets.


## ERSEC 29.1.0 — Continuous Assurance

29.1.0 now includes deterministic release-lineage snapshots and continuous assurance contracts that compare successive assurance bundles. A PASS claim that becomes unknown, blocked, inconclusive, or not-tested is surfaced as a release regression; missing evidence is never treated as remediation.

### 29.1.0 roadmap coverage audit

Run `python ersec.py --roadmap-audit . --roadmap-audit-out roadmap-coverage-29.1.0.json` to generate a deterministic implementation/test/evidence map for the ten core 29.1.0 roadmap features. The auditor deliberately reports `PARTIAL` while explicit gaps remain.

## ERSEC 29.1.0 — concurrent security assurance

The 29.1.0 assurance boundary now includes `ersec_concurrent_assurance.py`, which compiles bounded race-sensitive security scenarios for an authorized harness. Supported families include TOCTOU, double-submit, quota races, tenant-context races, and idempotency races. The planner is offline-only and never contacts targets or accepts credential material; target-side concurrency remains an explicit harness responsibility.

Example:

```bash
python ersec.py --concurrent-assurance-compile examples/assurance-concurrency-29.1.0.json --concurrent-assurance-out concurrent-assurance-29.1.0.json
```

## ERSEC 29.1.0 V18

Added deterministic stateful producer/link learning for OpenAPI Links, Location values, producer fields, and authorized-harness derived relationships, plus broader downstream authoritative observer adapters.

## ERSEC 29.1.0 maturity closure

ERSEC 29.1.0 now includes deterministic build/package assurance, Debian source packaging assets, digest-pinned container construction, reproducibility manifests, and a public-evaluation scorecard that refuses to fabricate external benchmark results.

Useful validation commands:

```bash
python3 ersec.py --self-test
python3 ersec.py --roadmap-audit . --roadmap-audit-out roadmap-coverage-29.1.0.json
python3 ersec.py --build-assurance . --build-assurance-out build-assurance-29.1.0.json
python3 ersec.py --release-audit . --release-audit-out release-readiness-29.1.0.json
```

The 29.1.0 engineering roadmap is closed when these local gates pass. Environment-dependent validation (real container runtime, independent clean rebuild, and external public benchmark deployments) is explicitly represented as a validation gate rather than silently treated as completed.

### ERSEC 29.1.0 publication

The controlled publication procedure is documented in `docs/publish-github-pypi-29.1.0.md`. Production PyPI publication uses GitHub OIDC/Trusted Publishing rather than a long-lived API token.
# ERSEC 29.1.0 - Live

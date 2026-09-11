# ERSEC research direction — 2026-09

This note separates established techniques from ERSEC's proposed combinations.

## Research ground truth

Access-control policy mutation testing is an established research technique. Earlier work defines mutation operators, equivalent-mutant handling, and mutant-killing analysis for access-control policies. Recent work continues to study mutation-based security test quality. Therefore ERSEC must not claim that mutation testing itself is novel.

Current adjacent products also show that authorization matrices, authenticated scanning, stateful workflows, and sequence controls already exist. ZAP documents explicit users and access rules; Burp documents authenticated crawling and state-sensitive crawling; Schemathesis documents stateful testing and authentication; Nuclei documents workflows; Cloudflare documents sequence analytics and sequence mitigation.

## ERSEC proposals worth researching

### 1. Semantic Authorization Mutation Adequacy (implemented experimentally in 29.1.0)

Instead of using only vulnerability counts, seed bounded semantic faults into the *security-property model* and ask whether the corpus can distinguish them. Report survivors as explicit assurance gaps. The score measures test-suite strength, not product accuracy.

### 2. Assurance Frontier (first gap frontier emitted experimentally in 29.1.0)

Represent the next-best tests as an explicit frontier of uncovered relationships, oracle weaknesses, stale-state combinations, field policies, and API-version boundaries. The frontier should publish why each candidate matters and what evidence would make it observable. This turns “more testing” into a measurable optimization problem rather than a request-count race.

### 3. Counterfactual Security Lineage

For every important verdict, retain a compact lineage linking property → selected scenario → observed evidence → verdict → remediation verification. A future implementation could compare the pre-change and post-change executions and answer not merely whether a finding disappeared, but which security property changed and which evidence established the transition.

### 4. Oracle Trust Lattice

Treat oracles as an explicit hierarchy rather than a binary available/unavailable signal. Authoritative database state, audit events, queue observations, and gateway enforcement can provide stronger evidence than HTTP status alone. AI interpretation remains supporting evidence only.

### 5. Metamorphic Authorization Invariants

Define representation-level transformations that must preserve a security verdict when semantics are unchanged: query ordering, fragment insertion/removal, equivalent path encoding, header-order changes, and selected API-version aliases. Any unexplained verdict change becomes a measurement-system or target-behavior investigation.

### 6. Behavior-Preserving Comparator Protocol

When comparing ERSEC with another workflow, compare the *same policy obligations* and not the alert taxonomies. Each system gets a case-level matrix with matched truth labels, observed verdict, evidence completeness, request cost, and untested scope. This reduces the risk of “more alerts = better” conclusions.

### 7. Security Regression Kill Score

After a remediation, measure which previously failing security properties are actually re-established by an independent positive observation. A disappeared violation without a positive verification remains unresolved. This is stronger than simple alert-diffing.

## Claims discipline

These proposals are not, by themselves, proof of novelty. The research milestone is an externally reproducible corpus and a comparison showing that these mechanisms improve detection, maintainability, evidence quality, or release confidence under controlled conditions.

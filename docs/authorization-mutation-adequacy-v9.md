# ERSEC 29.1.1 — Semantic Authorization Mutation Adequacy

ERSEC 29.1.1 introduces a bounded, offline mutation audit for the authorization corpus.

## Why this exists

Mutation testing is an established way to evaluate whether a test suite can detect small, representative faults. Research has also applied mutation testing specifically to access-control policies. ERSEC does not claim to invent mutation testing. The goal is to specialize the fault model around security-behavior dimensions that ERSEC is designed to assure: authorization outcomes, sensitive fields, ownership relationships, revocation state, and API-version distinctions.

## What a mutant means

A mutant is a deterministic semantic change to a reviewed benchmark case. Examples include removing a field prohibition, changing a cross-tenant relationship, removing a revocation state, or erasing an API-version distinction.

The audit asks whether the current corpus contains a contrasting case capable of distinguishing the mutated security property.

## Important limitation

This audit is a **test-suite adequacy signal**, not a vulnerability-detection metric and not a substitute for executing a target application. A surviving mutant identifies a coverage weakness in the benchmark or policy corpus; it does not prove a production vulnerability.

## Safety

The mutation audit is offline and performs no network requests. It handles only benchmark metadata and security-property signatures, never credentials or application response bodies.

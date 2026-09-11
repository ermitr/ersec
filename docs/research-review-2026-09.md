# ERSEC Research Review — 2026-09

This note records a focused review of current official documentation for adjacent tools. It is used to refine ERSEC's research position; it is not a claim that competitors lack extensions or custom integrations.

## ZAP

ZAP documents an Access Control Testing add-on that uses explicitly configured access rules, users and site nodes, with results for allowed/denied/unknown behavior. ZAP also states that generic active scanning does not find logical vulnerabilities such as broken access control. ERSEC should therefore not claim that access-control matrices themselves are unique; the intended differentiator is semantic object/tenant/field policy, authoritative postconditions, coverage denominators and longitudinal evidence.

## Burp Scanner

Burp's current documentation describes state-aware crawling, authenticated scanning and recorded login sequences, including application-state changes during crawl. ERSEC therefore should not claim stateful execution or authenticated scanning as unique. Its narrower target is security-property verification across explicitly named principals, resources, relationships and postconditions.

## Schemathesis

Schemathesis documents OpenAPI-aware authentication, dynamic authentication, stateful testing, link discovery and checks such as authentication enforcement and use-after-free. ERSEC should treat schema-driven generation and stateful execution as complementary capabilities and focus its research contribution on reviewed authorization intent, relationship graphs, semantic verdicts and evidence lineage.

## Nuclei

ProjectDiscovery documents ordered and conditional template workflows with a shared execution context. ERSEC should not compete on workflow/template breadth. Its benchmark should instead compare property-level assurance outcomes and evidence quality on a fixed, reviewed corpus.

## OWASP API Security

OWASP's API Security Top 10 continues to identify Broken Object Level Authorization as a primary API risk. ERSEC's first benchmark wedge remains aligned with that problem, while adding field-level, tenant, relationship and evidence dimensions.

## Research implication

The defensible ERSEC research question is not whether ERSEC can send multi-step requests or test roles. The question is whether a reviewed security property can be expressed once and then verified across the relevant principals, tenants, resources, fields and state while making untested and unobservable scope explicit and preserving replayable evidence.

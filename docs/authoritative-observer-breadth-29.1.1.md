# ERSEC 29.1.1 — Authoritative Observer Breadth

ERSEC 29.1.1 extends the authoritative evidence boundary beyond OTel, OPA, and gateway records to supplied evidence from database/audit records, application audit logs, queues/webhooks, object stores, payment sandboxes, and identity providers.

These adapters are parsers, not connectors. They never contact those systems. Target-side collection remains the responsibility of an authorized harness.

Supported CLI inputs include `--observer-database`, `--observer-audit-log`, `--observer-queue`, `--observer-object-store`, `--observer-payment-sandbox`, and `--observer-identity-provider` alongside the existing observer inputs.

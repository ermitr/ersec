# ERSEC 29.1.1 — Concurrent Security Assurance

`ersec_concurrent_assurance.py` adds a deterministic, offline planning/evaluation boundary for race-sensitive security properties.

Supported reviewed families:

- TOCTOU / check-then-use
- double-submit
- quota/resource races
- tenant-context races
- idempotency races

The module **does not execute concurrent requests**. It compiles bounded scenarios for an authorized harness and evaluates supplied observations. Missing observations remain `not_tested`; an explicit harness violation is `violation`.

Safety is fail-closed: no network contact, no destructive actions, and no credential material.

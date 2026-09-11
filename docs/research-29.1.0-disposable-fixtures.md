# ERSEC 29.1.0 — Disposable Multi-Principal Assurance Fixtures

## Purpose

Security-behavior properties are difficult to verify reproducibly when every test depends on manually prepared accounts and data. ERSEC 29.1.0 introduces a deterministic fixture-planning boundary that turns a reviewed identity/resource/operation specification into a disposable test manifest and explicit oracle truth.

## Design

`reviewed specification → fixture manifest → authorized harness → observations → assurance evidence`

The compiler itself is offline. It does not create accounts, send requests, retrieve credentials, mutate production state, or infer secrets.

## Safety invariants

1. Credential material is rejected from the specification.
2. Network access is explicitly disabled in the generated manifest.
3. Destructive actions are explicitly disabled.
4. The harness must be authorized independently.
5. Cleanup is a first-class lifecycle obligation.
6. Oracle truth is derived only from the reviewed allowlist supplied to the compiler.
7. The fixture digest identifies the generated artifact; it is not a cryptographic signature or proof of runtime truth.

## Why this matters

The roadmap calls for disposable multi-principal fixtures and explicit ground truth before stateful security-behavior verification. This module supplies the deterministic substrate for that work without making the test system an unrestricted autonomous agent.

# Semantic Authorization Assurance

ERSEC 29.1.1 introduces a narrow authorization-assurance layer for explicit identity, tenant, resource, status, and response-field expectations.

## Verdicts

`pass` means the modeled status and semantic field expectations were observed. `violation` means an explicit expectation was contradicted. `not_tested`, `inconclusive`, `blocked`, and `observation_unavailable` are never collapsed into pass.

## Usage

```bash
ersec -t https://authorized.example --security-model model.json --authorization-assurance authorization-assurance.json
```

Export the deterministic starter corpus with:

```bash
ersec --authorization-ground-truth authorization-ground-truth.json
```

Response bodies are not copied into the semantic assurance artifact. The engine records bounded field paths so forbidden or required field expectations can be tested without persisting field values.

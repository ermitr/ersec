# ERSEC 29.1.1 — Stateful Producer/Link Learning

ERSEC 29.1.1 can compile producer/consumer relationships from a reviewed API inventory. Sources include OpenAPI `Link` relationships, `Location` values, declared producer fields, and authorized-harness response-derived relationships.

The output is a deterministic relationship graph plus replayable assurance obligations. It does not make network requests, execute target actions, accept credentials, or infer authorization truth from absence of evidence.

## CLI

```bash
python3 ersec.py --stateful-links-compile examples/stateful-producer-links-29.1.1.json --stateful-links-out producer-links-29.1.1.json
python3 ersec.py --stateful-links-evaluate producer-links-29.1.1.json evidence.json --stateful-links-out producer-links-result-29.1.1.json
```

Missing relationship evidence is `not_tested`; an overall result with missing evidence is not `pass`.

# ERSEC 29.1.1 CI Assurance Gate

The CI gate consumes existing release evidence and returns `PASS`, `FAIL`, or `BLOCKED`. It is deterministic and offline. Missing evidence never becomes PASS. A FAIL means supplied evidence demonstrates a release regression or failed quality condition; BLOCKED means required evidence is absent.

```bash
python ersec.py --ci-assurance-gate \
  --ci-release-audit release-readiness-29.1.1.json \
  --ci-continuous continuous-assurance-29.1.1.json \
  --ci-release-evidence release-evidence-29.1.1.json \
  --ci-provenance provenance-29.1.1.json
```

The optional `--ci-require-signed-provenance` switch requires an external cryptographic signature. ERSEC's provenance digest is an integrity check, not a signature.

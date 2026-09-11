# Contributing to ERSEC

ERSEC is security tooling. Contributions should optimize for evidence quality, safety, reproducibility, and maintainability rather than detector-count inflation.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pip install -e .
python ersec.py --self-test
python -m pytest -q
```

## Pull requests

Every security feature should include:

- deterministic unit/integration tests;
- explicit safety boundaries;
- evidence and confidence semantics;
- documentation of blind spots;
- no destructive exploitation workflow;
- integration into the final report or assurance artifacts.

A class existing in source code is not considered complete unless its output is reachable from a supported workflow and covered by tests.

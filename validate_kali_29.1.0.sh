#!/usr/bin/env bash
set -euo pipefail

python3 ersec.py --version
python3 ersec.py --self-test
python3 ersec.py --assurance-benchmark-run /tmp/ersec-assurance-benchmark-29.1.0.json
python3 - <<'PY'
import json
p='/tmp/ersec-assurance-benchmark-29.1.0.json'
d=json.load(open(p, encoding='utf-8'))
assert d['version'] == '29.1.0'
assert d['status'] == 'pass', d['status']
assert d['methodology']['network_contact'] is False
assert d['methodology']['destructive_actions'] is False
print('ERSEC 29.1.0 Kali validation: PASS')
PY

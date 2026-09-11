import os
from pathlib import Path

dirs = ['src/ersec/benchmarking', 'src/ersec/adapters', 'scripts']
for d in dirs:
    p = Path(d)
    if not p.exists():
        continue
    for f in p.iterdir():
        if f.name.endswith('`'):
            new_name = f.name.rstrip('`')
            print(f"Renaming {f.name} -> {new_name}")
            f.rename(p / new_name)

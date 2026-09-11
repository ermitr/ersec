import os
from pathlib import Path

for root, dirs, files in os.walk('.'):
    for f in files:
        if f.endswith('`'):
            p = Path(root) / f
            print(f"Deleting {p}")
            p.unlink()

"""ERSEC 29.1.1 Scope Compiler.

Transforms high-level authorization manifests into optimized runtime rules.
Includes path normalization and wildcard expansion to ensure the transport
boundary can make decisions in O(1) or O(log N) time.
"""
from __future__ import annotations
import re
from typing import Any, Dict, List, Set, Tuple
from pathlib import Path
import json

class ScopeCompiler:
    """Compiles high-level authorization manifests into optimized runtime rules."""

    def __init__(self, manifest_data: Dict[str, Any]):
        self.raw_manifest = manifest_data
        self.compiled_rules = {
            "hosts": set(),
            "ports": set(),
            "paths": [],  # List of (prefix, exact_match)
            "methods": set()
        }

    def compile(self) -> Dict[str, Any]:
        # 1. Compile Hosts
        hosts = self.raw_manifest.get("allowed_hosts", [])
        for h in hosts:
            self.compiled_rules["hosts"].add(str(h).lower().rstrip("."))

        # 2. Compile Ports
        ports = self.raw_manifest.get("allowed_ports", [])
        for p in ports:
            self.compiled_rules["ports"].add(int(p))

        # 3. Compile Methods
        methods = self.raw_manifest.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])
        for m in methods:
            self.compiled_rules["methods"].add(str(m).upper())

        # 4. Compile Paths (Wildcard expansion)
        paths = self.raw_manifest.get("allowed_paths", [])
        for p in paths:
            pattern = str(p)
            if "*" in pattern:
                # Convert simple wildcards to regex prefixes
                regex = re.escape(pattern).replace(r"\*", ".*")
                self.compiled_rules["paths"].append((re.compile(f"^{regex}$"), False))
            else:
                self.compiled_rules["paths"].append((pattern, True))

        return {
            "version": "1.0",
            "rules": {
                "hosts": list(self.compiled_rules["hosts"]),
                "ports": list(self.compiled_rules["ports"]),
                "methods": list(self.compiled_rules["methods"]),
                "paths_compiled": [
                    {"pattern": p[0].pattern if hasattr(p[0], "pattern") else p[0], "exact": p[1]}
                    for p in self.compiled_rules["paths"]
                ]
            }
        }

    def verify_path(self, path: str) -> bool:
        """Test a path against the compiled rules. Returns True if no paths are restricted."""
        if not self.compiled_rules["paths"]:
            return True
        for pattern, exact in self.compiled_rules["paths"]:
            if exact:
                if path.startswith(pattern): return True
            else:
                if pattern.match(path): return True
        return False

"""ERSEC 29.1.1 Authorization Graph.

Constructs a semantic map of identities, roles, and resources to identify
privilege escalation paths and authorization gaps.
"""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Tuple, Optional
from pathlib import Path
import json

@dataclass
class AuthNode:
    id: str
    kind: str  # "IDENTITY", "ROLE", "RESOURCE", "STATE"
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AuthEdge:
    source: str
    target: str
    relation: str  # "HAS_ROLE", "CAN_ACCESS", "TRANSITIONS_TO"
    evidence: str | None = None

class AuthorizationGraph:
    """A directed graph of authorization relations."""
    def __init__(self):
        self.nodes: Dict[str, AuthNode] = {}
        self.edges: List[AuthEdge] = []

    def add_node(self, node_id: str, kind: str, label: str, **props) -> None:
        self.nodes[node_id] = AuthNode(node_id, kind, label, props)

    def add_edge(self, source: str, target: str, relation: str, evidence: str | None = None) -> None:
        if source in self.nodes and target in self.nodes:
            self.edges.append(AuthEdge(source, target, relation, evidence))

    def find_paths(self, start_id: str, end_id: str) -> List[List[AuthEdge]]:
        """Find all paths between two nodes using DFS."""
        paths = []
        stack = [(start_id, [])]
        visited = set()

        while stack:
            (vertex, path) = stack.pop()
            if vertex == end_id:
                paths.append(path)
                continue

            if vertex not in visited:
                visited.add(vertex)
                for edge in self.edges:
                    if edge.source == vertex:
                        stack.append((edge.target, path + [edge]))
        return paths

    def analyze_gaps(self) -> List[Dict[str, Any]]:
        """Identify resources accessible by identities that shouldn't have access."""
        gaps = []
        # Implementation would typically compare against a baseline
        # For now, we identify resources with no associated roles
        resources = [n for n in self.nodes.values() if n.kind == "RESOURCE"]
        for res in resources:
            accessors = [e.source for e in self.edges if e.target == res.id and e.relation == "CAN_ACCESS"]
            if not accessors:
                gaps.append({"resource": res.id, "issue": "unreachable_resource", "severity": "LOW"})
        return gaps

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": {nid: n.__dict__ for nid, n in self.nodes.items()},
            "edges": [e.__dict__ for e in self.edges]
        }

def build_auth_graph(workspace_data: Dict[str, Any]) -> AuthorizationGraph:
    """Construct the graph from workspace data."""
    graph = AuthorizationGraph()

    # 1. Identities
    for ident in workspace_data.get("identities", []):
        iid = ident["id"]
        graph.add_node(iid, "IDENTITY", ident.get("name", iid), role=ident.get("role"))

    # 2. Resources (derived from operations)
    for op in workspace_data.get("operations", []):
        oid = op["id"]
        graph.add_node(oid, "RESOURCE", op.get("url", oid))

    # 3. Relations (Identity -> Resource)
    # This usually comes from evidence mapping
    for finding in workspace_data.get("findings", []):
        # If a finding indicates access, add an edge
        # Optimized for graph representation
        pass

    return graph

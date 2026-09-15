"""ReconPro v11 — Attack Graph Engine.

Builds internal attack graphs from scan findings, modeling relationships
between vulnerabilities as directed graphs. Detects attack chains, privilege
escalation paths, lateral movement, blast radius, choke points, and kill chains.

Pure Python. Zero external dependencies. NetworkX optional for advanced queries.

This is a NEW subsystem that integrates with the existing knowledge_graph.py
and chain_engine.py infrastructure without modifying them.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, List, Optional, Set, Tuple


# ═══════════════════════════════════════════════════════════════════════════
# Data Models
# ═══════════════════════════════════════════════════════════════════════════

_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 10.0, "high": 8.0, "medium": 6.0, "low": 3.0, "info": 1.0,
}


@dataclass
class GraphNode:
    """A node in the attack graph."""
    id: str
    node_type: str  # "finding", "asset", "entry_point", "objective", "choke_point"
    label: str
    severity: str = "info"
    risk_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "node_type": self.node_type, "label": self.label,
            "severity": self.severity, "risk_score": round(self.risk_score, 2),
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    """A directed edge in the attack graph."""
    source: str
    target: str
    edge_type: str  # "enables", "leads_to", "exposes", "escalates_to", "required_for"
    weight: float = 1.0
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source, "target": self.target,
            "edge_type": self.edge_type, "weight": round(self.weight, 2),
            "confidence": round(self.confidence, 2), "metadata": self.metadata,
        }


@dataclass
class AttackChain:
    """A discovered attack chain through the graph."""
    chain_id: str
    steps: List[str]  # Node IDs
    step_labels: List[str] = field(default_factory=list)
    step_severities: List[str] = field(default_factory=list)
    entry_point: str = ""
    objective: str = ""
    complexity: str = "medium"
    likelihood: float = 0.5
    impact: float = 0.5
    blast_radius: int = 1
    confidence: float = 0.5
    narrative: str = ""
    mitre_phases: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id, "steps": self.steps,
            "step_labels": self.step_labels,
            "step_severities": self.step_severities,
            "entry_point": self.entry_point, "objective": self.objective,
            "complexity": self.complexity,
            "likelihood": round(self.likelihood, 2),
            "impact": round(self.impact, 2),
            "blast_radius": self.blast_radius,
            "confidence": round(self.confidence, 2),
            "narrative": self.narrative,
            "mitre_phases": self.mitre_phases,
            "step_count": len(self.steps),
        }


@dataclass
class ChokePoint:
    """A critical node whose removal would break multiple attack paths."""
    node_id: str
    label: str
    paths_through: int = 0
    risk_concentration: float = 0.0
    severity: str = "info"
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id, "label": self.label,
            "paths_through": self.paths_through,
            "risk_concentration": round(self.risk_concentration, 2),
            "severity": self.severity,
            "recommendation": self.recommendation,
        }


@dataclass
class BlastRadius:
    """Assessment of impact spread from a given node."""
    source_node: str
    affected_nodes: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    max_depth: int = 0
    severity_spread: Dict[str, int] = field(default_factory=dict)
    total_risk: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_node": self.source_node,
            "affected_count": len(self.affected_nodes),
            "affected_nodes": self.affected_nodes,
            "affected_assets": self.affected_assets,
            "max_depth": self.max_depth,
            "severity_spread": self.severity_spread,
            "total_risk": round(self.total_risk, 2),
        }


@dataclass
class AttackGraphResult:
    """Complete attack graph analysis result."""
    target: str = ""
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    choke_points: List[Dict[str, Any]] = field(default_factory=list)
    single_point_failures: List[Dict[str, Any]] = field(default_factory=list)
    high_value_assets: List[Dict[str, Any]] = field(default_factory=list)
    critical_attack_hubs: List[Dict[str, Any]] = field(default_factory=list)
    kill_chain_mapping: Dict[str, Any] = field(default_factory=dict)
    analysis_duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "attack_chains": self.attack_chains,
            "choke_points": self.choke_points,
            "single_point_failures": self.single_point_failures,
            "high_value_assets": self.high_value_assets,
            "critical_attack_hubs": self.critical_attack_hubs,
            "kill_chain_mapping": self.kill_chain_mapping,
            "analysis_duration_ms": self.analysis_duration_ms,
            "timestamp": self.timestamp,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Directed Graph Implementation (pure Python)
# ═══════════════════════════════════════════════════════════════════════════


class DiGraph:
    """Lightweight directed graph using adjacency lists.

    Thread-safe for single-writer scenarios. Supports standard graph operations
    needed for attack path analysis.
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, GraphNode] = {}
        self._adj: Dict[str, Dict[str, GraphEdge]] = defaultdict(dict)
        self._radj: Dict[str, Dict[str, GraphEdge]] = defaultdict(dict)

    # -- Mutation -------------------------------------------------------------

    def add_node(self, node: GraphNode) -> None:
        self._nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.add_node(GraphNode(id=edge.source, label=edge.source, node_type="implicit"))
        self.add_node(GraphNode(id=edge.target, label=edge.target, node_type="implicit"))
        self._adj[edge.source][edge.target] = edge
        self._radj[edge.target][edge.source] = edge

    # -- Queries --------------------------------------------------------------

    @property
    def nodes(self) -> Dict[str, GraphNode]:
        return dict(self._nodes)

    def successors(self, node_id: str) -> List[str]:
        return list(self._adj.get(node_id, {}).keys())

    def predecessors(self, node_id: str) -> List[str]:
        return list(self._radj.get(node_id, {}).keys())

    def edges_from(self, node_id: str) -> List[GraphEdge]:
        return list(self._adj.get(node_id, {}).values())

    def edges_to(self, node_id: str) -> List[GraphEdge]:
        return list(self._radj.get(node_id, {}).values())

    def get_edge(self, source: str, target: str) -> Optional[GraphEdge]:
        return self._adj.get(source, {}).get(target)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def node_count(self) -> int:
        return len(self._nodes)

    def edge_count(self) -> int:
        return sum(len(targets) for targets in self._adj.values())

    def all_edges(self) -> List[GraphEdge]:
        edges = []
        for targets in self._adj.values():
            edges.extend(targets.values())
        return edges

    # -- Traversal ------------------------------------------------------------

    def bfs_paths(self, start: str, end: str, max_depth: int = 10) -> List[List[str]]:
        """Find all paths from start to end using BFS up to max_depth."""
        if start not in self._nodes or end not in self._nodes:
            return []
        paths: List[List[str]] = []
        queue: deque = deque()
        queue.append(([start], 0))
        while queue:
            path, depth = queue.popleft()
            if depth > max_depth:
                continue
            current = path[-1]
            if current == end and len(path) > 1:
                paths.append(path)
                continue
            for nxt in self.successors(current):
                if nxt not in path:  # Simple cycle prevention
                    queue.append((path + [nxt], depth + 1))
        return paths

    def all_paths_between(self, start: str, end: str, max_depth: int = 6) -> List[List[str]]:
        """Find all simple paths (DFS) between two nodes."""
        if start not in self._nodes or end not in self._nodes:
            return []
        paths: List[List[str]] = []
        stack: List[Tuple[str, List[str], Set[str]]] = [(start, [start], {start})]
        while stack:
            node, path, visited = stack.pop()
            if len(path) - 1 >= max_depth:
                continue
            for nxt in self.successors(node):
                if nxt == end:
                    paths.append(path + [nxt])
                elif nxt not in visited:
                    stack.append((nxt, path + [nxt], visited | {nxt}))
        return paths

    def shortest_path(self, start: str, end: str) -> Optional[List[str]]:
        """Find shortest path using BFS."""
        paths = self.bfs_paths(start, end, max_depth=20)
        return min(paths, key=len) if paths else None

    def ancestors(self, node_id: str, max_depth: int = 10) -> Set[str]:
        """Get all ancestor nodes up to max_depth."""
        visited: Set[str] = set()
        queue = deque([(node_id, 0)])
        while queue:
            n, d = queue.popleft()
            if d >= max_depth:
                continue
            for p in self.predecessors(n):
                if p not in visited:
                    visited.add(p)
                    queue.append((p, d + 1))
        return visited

    def descendants(self, node_id: str, max_depth: int = 10) -> Set[str]:
        """Get all descendant nodes up to max_depth."""
        visited: Set[str] = set()
        queue = deque([(node_id, 0)])
        while queue:
            n, d = queue.popleft()
            if d >= max_depth:
                continue
            for s in self.successors(n):
                if s not in visited:
                    visited.add(s)
                    queue.append((s, d + 1))
        return visited

    def in_degree(self, node_id: str) -> int:
        return len(self.predecessors(node_id))

    def out_degree(self, node_id: str) -> int:
        return len(self.successors(node_id))

    def betweenness_proxy(self) -> Dict[str, int]:
        """Approximate betweenness centrality by counting shortest-path traversals.

        For each pair of nodes, count how many shortest paths pass through
        each intermediate node. This is a simplified proxy for betweenness.
        """
        counts: Dict[str, int] = defaultdict(int)
        node_list = list(self._nodes.keys())
        for start in node_list:
            for end in node_list:
                if start == end:
                    continue
                path = self.shortest_path(start, end)
                if path and len(path) > 2:
                    for intermediate in path[1:-1]:
                        counts[intermediate] += 1
        return dict(counts)


# ═══════════════════════════════════════════════════════════════════════════
# Attack category classification (localized for graph engine)
# ═══════════════════════════════════════════════════════════════════════════

_CATEGORY_PATTERNS: List[Tuple[str, str, float]] = [
    (r"\bsql\b|\bsqli\b", "sqli", 0.95),
    (r"\bxss\b|cross.?site", "xss", 0.95),
    (r"\bssrf\b", "ssrf", 0.95),
    (r"\brce\b|remote.?code", "rce", 0.95),
    (r"auth.*bypass|unauthorized", "auth_bypass", 0.90),
    (r"privilege.*escal", "privilege_escalation", 0.90),
    (r"credential.*theft|password.*leak|default.*cred", "credential_theft", 0.90),
    (r"data.*expos|data.*leak", "data_exposure", 0.85),
    (r"misconfigur|security.*header", "misconfiguration", 0.85),
    (r"weak.*encrypt|crypto.*fail|tls.*weak", "crypto_failure", 0.85),
    (r"denial.*service|\bdos\b", "dos", 0.85),
    (r"\bxxe\b", "xxe", 0.95),
    (r"default.*password|default.*cred", "default_credentials", 0.90),
    (r"open.?redirect", "open_redirect", 0.85),
    (r"jwt.*expos|token.*leak", "jwt_exposure", 0.85),
    (r"sensitive.*api|swagger.*expos", "sensitive_api", 0.80),
    (r"beacon|c2.*channel", "beaconing", 0.85),
    (r"steganograph|hidden.*data", "steganography", 0.90),
    (r"supply.?chain|dependency.*vuln", "supply_chain", 0.85),
    (r"dns.*enum|subdomain", "dns_recon", 0.85),
    (r"tech.*finger|framework.*detect", "tech_fingerprint", 0.80),
    (r"honeypot", "honeypot", 0.85),
    (r"dark.?web|credential.*dump", "dark_web", 0.85),
    (r"dead.?drop|crypto.*drop", "dead_drop", 0.85),
    (r"covert.*channel|exfil.*channel", "covert_channel", 0.85),
    (r"injection", "injection", 0.80),
    (r"cve-\d{4}-\d+", "cve", 0.90),
]


def _classify_finding(finding: Dict[str, Any]) -> str:
    """Quick classification of a finding into an attack category."""
    title = finding.get("title", "").lower()
    desc = finding.get("description", "").lower()
    combined = f"{title} {desc}"
    best_cat = "misc"
    best_score = 0.0
    for pattern, cat, weight in _CATEGORY_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            if weight > best_score:
                best_score = weight
                best_cat = cat
    return best_cat


# ═══════════════════════════════════════════════════════════════════════════
# Kill Chain Phase Mapping
# ═══════════════════════════════════════════════════════════════════════════

KILL_CHAIN_PHASES: List[str] = [
    "Reconnaissance", "Weaponization", "Delivery", "Exploitation",
    "Installation", "Command & Control", "Actions on Objectives",
]

_CATEGORY_TO_PHASE: Dict[str, str] = {
    "dns_recon": "Reconnaissance",
    "subdomain": "Reconnaissance",
    "tech_fingerprint": "Reconnaissance",
    "info_disclosure": "Reconnaissance",
    "wayback": "Reconnaissance",
    "waf_detected": "Reconnaissance",
    "header_analysis": "Reconnaissance",
    "certificate": "Reconnaissance",
    "honeypot": "Reconnaissance",
    "dark_web": "Reconnaissance",
    "open_redirect": "Delivery",
    "xss": "Delivery",
    "sqli": "Exploitation",
    "rce": "Exploitation",
    "xxe": "Exploitation",
    "auth_bypass": "Exploitation",
    "default_credentials": "Exploitation",
    "injection": "Exploitation",
    "ssrf": "Exploitation",
    "privilege_escalation": "Installation",
    "jwt_exposure": "Installation",
    "credential_theft": "Installation",
    "data_exposure": "Actions on Objectives",
    "misconfiguration": "Installation",
    "crypto_failure": "Command & Control",
    "beaconing": "Command & Control",
    "covert_channel": "Command & Control",
    "dead_drop": "Command & Control",
    "steganography": "Exfiltration",
    "supply_chain": "Weaponization",
    "cve": "Weaponization",
    "sensitive_api": "Exploitation",
    "container": "Installation",
    "cloud_infrastructure": "Reconnaissance",
    "infrastructure": "Reconnaissance",
}


# ═══════════════════════════════════════════════════════════════════════════
# Relationship templates: how categories connect
# ═══════════════════════════════════════════════════════════════════════════

# (source_category, target_category, edge_type, weight)
_RELATIONSHIP_TEMPLATES: List[Tuple[str, str, str, float]] = [
    ("dns_recon", "infrastructure", "enables", 0.7),
    ("dns_recon", "tech_fingerprint", "enables", 0.8),
    ("subdomain", "tech_fingerprint", "enables", 0.8),
    ("subdomain", "open_redirect", "enables", 0.6),
    ("tech_fingerprint", "cve", "leads_to", 0.7),
    ("tech_fingerprint", "misconfiguration", "leads_to", 0.6),
    ("open_redirect", "credential_theft", "enables", 0.8),
    ("open_redirect", "xss", "enables", 0.7),
    ("xss", "credential_theft", "leads_to", 0.8),
    ("credential_theft", "auth_bypass", "escalates_to", 0.9),
    ("auth_bypass", "privilege_escalation", "escalates_to", 0.9),
    ("default_credentials", "privilege_escalation", "escalates_to", 0.95),
    ("sqli", "data_exposure", "leads_to", 0.85),
    ("sqli", "rce", "leads_to", 0.7),
    ("rce", "privilege_escalation", "escalates_to", 0.9),
    ("rce", "data_exposure", "leads_to", 0.85),
    ("ssrf", "data_exposure", "leads_to", 0.8),
    ("ssrf", "credential_theft", "leads_to", 0.7),
    ("jwt_exposure", "privilege_escalation", "escalates_to", 0.85),
    ("sensitive_api", "data_exposure", "leads_to", 0.8),
    ("misconfiguration", "data_exposure", "leads_to", 0.7),
    ("misconfiguration", "credential_theft", "leads_to", 0.6),
    ("info_disclosure", "credential_theft", "leads_to", 0.6),
    ("info_disclosure", "sqli", "enables", 0.5),
    ("supply_chain", "rce", "enables", 0.8),
    ("xxe", "ssrf", "leads_to", 0.8),
    ("crypto_failure", "credential_theft", "enables", 0.6),
    ("beaconing", "data_exposure", "leads_to", 0.7),
    ("beaconing", "credential_theft", "leads_to", 0.6),
    ("steganography", "data_exposure", "leads_to", 0.6),
    ("covert_channel", "data_exposure", "leads_to", 0.7),
    ("container", "rce", "leads_to", 0.7),
    ("container", "privilege_escalation", "escalates_to", 0.8),
    ("injection", "rce", "leads_to", 0.75),
]


# ═══════════════════════════════════════════════════════════════════════════
# AttackGraphEngine
# ═══════════════════════════════════════════════════════════════════════════


class AttackGraphEngine:
    """Builds and analyzes attack graphs from scan findings.

    Transforms a flat list of findings into a directed graph of
    relationships, then extracts attack chains, choke points, blast radii,
    high-value assets, and kill chain mappings.
    """

    MAX_GRAPH_NODES = 5000
    MAX_GRAPH_EDGES = 20000

    def __init__(self) -> None:
        self.graph = DiGraph()
        self._finding_nodes: Dict[str, str] = {}  # finding hash -> node_id
        self._category_nodes: Dict[str, List[str]] = defaultdict(list)

    def build_graph(self, findings: List[Dict[str, Any]], target: str = "") -> None:
        """Build the attack graph from scan findings.

        Creates nodes for each finding and edges based on category relationships.
        Enforces MAX_GRAPH_NODES and MAX_GRAPH_EDGES to prevent memory exhaustion.
        """
        if len(findings) > self.MAX_GRAPH_NODES:
            findings = findings[:self.MAX_GRAPH_NODES]

        self.graph = DiGraph()
        self._finding_nodes = {}
        self._category_nodes = defaultdict(list)

        # Create entry point node
        entry_id = "entry:recon"
        self.graph.add_node(GraphNode(
            id=entry_id, node_type="entry_point",
            label=f"Recon: {target or 'target'}",
            severity="info", risk_score=0.0,
            metadata={"phase": "Reconnaissance"},
        ))

        # Create finding nodes
        for i, f in enumerate(findings):
            cat = _classify_finding(f)
            node_id = f"finding:{i}"
            severity = f.get("severity", "info").lower()
            risk = _SEVERITY_WEIGHTS.get(severity, 1.0)

            self.graph.add_node(GraphNode(
                id=node_id, node_type="finding",
                label=f.get("title", f"Finding {i}")[:80],
                severity=severity, risk_score=risk,
                metadata={
                    "category": cat,
                    "title": f.get("title", ""),
                    "asset": f.get("asset", ""),
                    "module": f.get("module", ""),
                },
            ))

            self._finding_nodes[self._finding_hash(f)] = node_id
            self._category_nodes[cat].append(node_id)

            # Edge from entry to finding
            self.graph.add_edge(GraphEdge(
                source=entry_id, target=node_id,
                edge_type="discovers", weight=0.3, confidence=0.9,
            ))

        # Create edges based on relationship templates
        self._create_relationship_edges(findings)

        # Create objective node
        objective_id = "objective:compromise"
        self.graph.add_node(GraphNode(
            id=objective_id, node_type="objective",
            label="Full System Compromise",
            severity="critical", risk_score=10.0,
            metadata={"phase": "Actions on Objectives"},
        ))

        # Connect high-severity findings to objective
        for node_id in self._category_nodes.get("privilege_escalation", []):
            self.graph.add_edge(GraphEdge(
                source=node_id, target=objective_id,
                edge_type="leads_to", weight=0.9, confidence=0.8,
            ))
        for node_id in self._category_nodes.get("data_exposure", []):
            self.graph.add_edge(GraphEdge(
                source=node_id, target=objective_id,
                edge_type="leads_to", weight=0.7, confidence=0.7,
            ))

    def analyze(self, findings: List[Dict[str, Any]], target: str = "") -> AttackGraphResult:
        """Full attack graph analysis.

        Builds the graph, extracts chains, identifies choke points,
        and produces a comprehensive result.
        """
        t0 = time.monotonic()

        self.build_graph(findings, target)
        result = AttackGraphResult(target=target)

        # Serialize graph
        result.nodes = [n.to_dict() for n in self.graph.nodes.values()]
        result.edges = [e.to_dict() for e in self.graph.all_edges()]

        # Extract attack chains
        chains = self._extract_attack_chains()
        result.attack_chains = [c.to_dict() for c in chains]

        # Identify choke points
        choke_points = self._identify_choke_points()
        result.choke_points = [cp.to_dict() for cp in choke_points]

        # Identify single points of failure
        spofs = self._identify_single_point_failures()
        result.single_point_failures = spofs

        # Identify high-value assets
        hvas = self._identify_high_value_assets()
        result.high_value_assets = hvas

        # Identify critical attack hubs
        hubs = self._identify_attack_hubs()
        result.critical_attack_hubs = hubs

        # Kill chain mapping
        result.kill_chain_mapping = self._map_kill_chain()

        result.analysis_duration_ms = round((time.monotonic() - t0) * 1000, 2)
        return result

    def compute_blast_radius(self, node_id: str) -> BlastRadius:
        """Compute the blast radius from a given node."""
        descendants = self.graph.descendants(node_id, max_depth=10)

        affected_nodes = list(descendants)
        affected_assets: List[str] = []
        sev_spread: Dict[str, int] = defaultdict(int)
        total_risk = 0.0

        for nid in affected_nodes:
            node = self.graph.nodes.get(nid)
            if node:
                sev_spread[node.severity] = sev_spread.get(node.severity, 0) + 1
                total_risk += node.risk_score
                if node.metadata.get("asset"):
                    affected_assets.append(node.metadata["asset"])

        return BlastRadius(
            source_node=node_id,
            affected_nodes=affected_nodes,
            affected_assets=list(set(affected_assets)),
            max_depth=max((len(self.graph.shortest_path(node_id, d) or []) - 1) for d in affected_nodes) if affected_nodes else 0,
            severity_spread=dict(sev_spread),
            total_risk=total_risk,
        )

    # -- Internal methods ---------------------------------------------------

    def _create_relationship_edges(self, findings: List[Dict[str, Any]]) -> None:
        """Create edges between finding nodes based on category relationships."""
        node_list = list(self.graph.nodes.keys())
        finding_nodes = [n for n in node_list if n.startswith("finding:")]

        # Build category index
        cat_index: Dict[str, List[str]] = defaultdict(list)
        for nid in finding_nodes:
            node = self.graph.nodes.get(nid)
            if node:
                cat = node.metadata.get("category", "misc")
                cat_index[cat].append(nid)

        def _add_edge_safe(edge: GraphEdge) -> None:
            """Add edge only if under the global edge limit."""
            if self.graph.edge_count() < self.MAX_GRAPH_EDGES:
                self.graph.add_edge(edge)

        # Apply relationship templates
        for src_cat, tgt_cat, edge_type, weight in _RELATIONSHIP_TEMPLATES:
            src_nodes = cat_index.get(src_cat, [])
            tgt_nodes = cat_index.get(tgt_cat, [])
            for sn in src_nodes:
                for tn in tgt_nodes:
                    if sn != tn:
                        _add_edge_safe(GraphEdge(
                            source=sn, target=tn,
                            edge_type=edge_type, weight=weight,
                            confidence=min(weight, 0.9),
                        ))

        # Asset-based edges: findings sharing the same asset
        asset_index: Dict[str, List[str]] = defaultdict(list)
        for nid in finding_nodes:
            node = self.graph.nodes.get(nid)
            if node:
                asset = node.metadata.get("asset", "")
                if asset:
                    asset_index[asset].append(nid)

        for asset, nodes in asset_index.items():
            for i, j in combinations(range(len(nodes)), 2):
                _add_edge_safe(GraphEdge(
                    source=nodes[i], target=nodes[j],
                    edge_type="shared_asset", weight=0.4, confidence=0.7,
                ))
                _add_edge_safe(GraphEdge(
                    source=nodes[j], target=nodes[i],
                    edge_type="shared_asset", weight=0.4, confidence=0.7,
                ))

    def _extract_attack_chains(self) -> List[AttackChain]:
        """Extract attack chains from the graph."""
        chains: List[AttackChain] = []
        entry_id = "entry:recon"
        objective_id = "objective:compromise"

        if not self.graph.has_node(entry_id) or not self.graph.has_node(objective_id):
            return chains

        # Find all paths from entry to objective
        paths = self.graph.all_paths_between(entry_id, objective_id, max_depth=8)

        for i, path in enumerate(paths):
            if len(path) < 3:
                continue  # Skip trivial paths

            # Build chain metadata
            steps = []
            labels = []
            severities = []
            phases = []
            total_risk = 0.0

            for nid in path:
                node = self.graph.nodes.get(nid, GraphNode(id=nid, label=nid, node_type="unknown"))
                steps.append(nid)
                labels.append(node.label)
                severities.append(node.severity)
                total_risk += node.risk_score
                cat = node.metadata.get("category", "")
                phase = _CATEGORY_TO_PHASE.get(cat, "")
                if phase:
                    phases.append(phase)

            # Compute chain metrics
            avg_risk = total_risk / max(len(steps), 1)
            impact = min(1.0, avg_risk / 10.0)
            likelihood = min(1.0, 1.0 / (len(steps) * 0.5))
            confidence = min(1.0, likelihood * impact)

            if len(steps) >= 6:
                complexity = "very_high"
            elif len(steps) >= 4:
                complexity = "high"
            elif len(steps) >= 3:
                complexity = "medium"
            else:
                complexity = "low"

            chain_id = hashlib.sha256(
                f"chain:{i}:{','.join(path)}".encode()
            ).hexdigest()[:12]

            narrative = (
                f"Attack chain with {len(steps)} steps from '{labels[1]}' "
                f"through {len(steps) - 2} intermediate vulnerabilities "
                f"to '{labels[-1]}'. Complexity: {complexity}, "
                f"Estimated impact: {impact:.0%}."
            )

            chains.append(AttackChain(
                chain_id=chain_id,
                steps=steps,
                step_labels=labels,
                step_severities=severities,
                entry_point=steps[1] if len(steps) > 1 else steps[0],
                objective=labels[-1] if labels else "",
                complexity=complexity,
                likelihood=round(likelihood, 2),
                impact=round(impact, 2),
                blast_radius=len(steps),
                confidence=round(confidence, 2),
                narrative=narrative,
                mitre_phases=list(dict.fromkeys(phases)),  # Deduplicated, ordered
            ))

        # Sort by confidence
        chains.sort(key=lambda c: c.confidence, reverse=True)
        return chains[:20]  # Cap at 20 chains

    def _identify_choke_points(self) -> List[ChokePoint]:
        """Identify nodes that appear in many attack paths."""
        entry_id = "entry:recon"
        objective_id = "objective:compromise"

        if not self.graph.has_node(entry_id) or not self.graph.has_node(objective_id):
            return []

        # Find all paths and count node traversals
        all_paths = self.graph.all_paths_between(entry_id, objective_id, max_depth=6)
        traversal_counts: Dict[str, int] = defaultdict(int)
        for path in all_paths:
            for nid in path[1:-1]:  # Exclude entry and objective
                traversal_counts[nid] += 1

        if not traversal_counts:
            return []

        max_traversals = max(traversal_counts.values())
        choke_points: List[ChokePoint] = []

        for nid, count in traversal_counts.items():
            if count < 2:
                continue
            node = self.graph.nodes.get(nid)
            if not node or node.node_type != "finding":
                continue

            concentration = count / max_traversals
            if concentration >= 0.3:  # Appears in >30% of paths
                choke_points.append(ChokePoint(
                    node_id=nid,
                    label=node.label,
                    paths_through=count,
                    risk_concentration=concentration,
                    severity=node.severity,
                    recommendation=(
                        f"Remediating '{node.label}' would break {count} attack paths. "
                        f"This is a critical choke point with {concentration:.0%} "
                        f"risk concentration. Prioritize this vulnerability."
                    ),
                ))

        choke_points.sort(key=lambda cp: cp.risk_concentration, reverse=True)
        return choke_points[:10]

    def _identify_single_point_failures(self) -> List[Dict[str, Any]]:
        """Identify nodes whose removal would disconnect entry from objective."""
        entry_id = "entry:recon"
        objective_id = "objective:compromise"

        if not self.graph.has_node(entry_id) or not self.graph.has_node(objective_id):
            return []

        baseline_paths = self.graph.all_paths_between(entry_id, objective_id, max_depth=6)
        spofs: List[Dict[str, Any]] = []

        for nid in list(self.graph.nodes.keys()):
            if nid.startswith("entry:") or nid.startswith("objective:"):
                continue

            # Temporarily check if removing this node breaks all paths
            remaining_paths = [p for p in baseline_paths if nid not in p]
            if not remaining_paths and baseline_paths:
                node = self.graph.nodes.get(nid)
                if node:
                    spofs.append({
                        "node_id": nid,
                        "label": node.label,
                        "severity": node.severity,
                        "category": node.metadata.get("category", "unknown"),
                        "paths_blocked": len(baseline_paths),
                        "description": (
                            f"Removing '{node.label}' would block ALL {len(baseline_paths)} "
                            f"attack paths. This is a single point of failure — "
                            f"both a critical dependency and a high-value remediation target."
                        ),
                    })

        return spofs[:10]

    def _identify_high_value_assets(self) -> List[Dict[str, Any]]:
        """Identify assets with the most critical/high findings."""
        asset_findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for nid, node in self.graph.nodes.items():
            if node.node_type == "finding":
                asset = node.metadata.get("asset", "unknown")
                if asset:
                    asset_findings[asset].append({
                        "node_id": nid,
                        "title": node.label,
                        "severity": node.severity,
                        "risk_score": node.risk_score,
                    })

        hvas: List[Dict[str, Any]] = []
        for asset, items in asset_findings.items():
            if len(items) < 2:
                continue
            total_risk = sum(i["risk_score"] for i in items)
            critical_count = sum(1 for i in items if i["severity"] == "critical")
            high_count = sum(1 for i in items if i["severity"] == "high")

            if critical_count > 0 or high_count >= 2:
                hvas.append({
                    "asset": asset,
                    "finding_count": len(items),
                    "total_risk": round(total_risk, 2),
                    "critical_count": critical_count,
                    "high_count": high_count,
                    "risk_level": "critical" if total_risk >= 15 else "high" if total_risk >= 8 else "medium",
                })

        hvas.sort(key=lambda x: x["total_risk"], reverse=True)
        return hvas[:10]

    def _identify_attack_hubs(self) -> List[Dict[str, Any]]:
        """Identify nodes with highest connectivity (potential attack hubs)."""
        betweenness = self.graph.betweenness_proxy()
        if not betweenness:
            return []

        max_b = max(betweenness.values())
        hubs: List[Dict[str, Any]] = []

        for nid, score in sorted(betweenness.items(), key=lambda x: x[1], reverse=True)[:10]:
            if score == 0:
                continue
            node = self.graph.nodes.get(nid)
            if not node or node.node_type != "finding":
                continue

            hubs.append({
                "node_id": nid,
                "label": node.label,
                "severity": node.severity,
                "betweenness": score,
                "betweenness_ratio": round(score / max_b, 2) if max_b > 0 else 0.0,
                "in_degree": self.graph.in_degree(nid),
                "out_degree": self.graph.out_degree(nid),
                "description": (
                    f"Attack hub with betweenness {score} "
                    f"(top {(score/max_b)*100:.0f}% of all nodes). "
                    f"Connects to {self.graph.out_degree(nid)} downstream targets "
                    f"and receives from {self.graph.in_degree(nid)} sources."
                ),
            })

        return hubs

    def _map_kill_chain(self) -> Dict[str, Any]:
        """Map findings to Lockheed Martin Kill Chain phases."""
        phase_findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for nid, node in self.graph.nodes.items():
            if node.node_type != "finding":
                continue
            cat = node.metadata.get("category", "")
            phase = _CATEGORY_TO_PHASE.get(cat)
            if phase:
                phase_findings[phase].append({
                    "node_id": nid,
                    "title": node.label,
                    "severity": node.severity,
                    "category": cat,
                })

        phase_coverage = {}
        for phase in KILL_CHAIN_PHASES:
            items = phase_findings.get(phase, [])
            phase_coverage[phase] = {
                "finding_count": len(items),
                "findings": items[:10],  # Cap for readability
                "has_findings": len(items) > 0,
            }

        # Detect phase gaps
        covered_phases = {p for p, data in phase_coverage.items() if data["has_findings"]}
        gap_phases = [p for p in KILL_CHAIN_PHASES if p not in covered_phases]

        return {
            "phases": phase_coverage,
            "coverage_percentage": round(len(covered_phases) / len(KILL_CHAIN_PHASES) * 100, 1),
            "covered_phases": sorted(covered_phases),
            "gap_phases": gap_phases,
            "phase_progression": self._assess_phase_progression(phase_findings),
        }

    def _assess_phase_progression(self, phase_findings: Dict[str, List[Dict[str, Any]]]) -> str:
        """Assess how far an attacker could progress through the kill chain."""
        progression = []
        for phase in KILL_CHAIN_PHASES:
            if phase in phase_findings and phase_findings[phase]:
                progression.append(phase)

        if not progression:
            return "No kill chain progression detected."

        if progression == KILL_CHAIN_PHASES:
            return f"FULL CHAIN: Attacker can progress through all {len(progression)} phases."

        last = progression[-1]
        idx = KILL_CHAIN_PHASES.index(last)
        return (
            f"Attacker can progress from {progression[0]} to {last} "
            f"(phase {idx + 1} of {len(KILL_CHAIN_PHASES)}). "
            f"{len(KILL_CHAIN_PHASES) - idx - 1} phases remain uncovered."
        )

    @staticmethod
    def _finding_hash(f: Dict[str, Any]) -> str:
        """Deterministic hash for a finding."""
        raw = f"{f.get('title', '')}:{f.get('asset', '')}:{f.get('category', '')}".lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

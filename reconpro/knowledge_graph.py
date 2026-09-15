"""
ReconPro Knowledge Graph System

Builds and queries a directed knowledge graph from scan results,
enabling attack surface analysis, blast radius computation,
attack chain discovery, and cross-correlation of findings.

Dependencies:
    networkx (optional) – falls back to a pure-Python dict graph.
"""

from __future__ import annotations

import json
import os
import uuid
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Optional NetworkX import with pure-Python fallback
# ---------------------------------------------------------------------------
try:
    import networkx as nx

    HAS_NX = True
except ImportError:
    HAS_NX = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NODE_TYPES = {
    "target",
    "subdomain",
    "port",
    "service",
    "vulnerability",
    "finding",
    "cve",
    "asset",
    "endpoint",
    "technology",
    "certificate",
}

EDGE_TYPES = {
    "has_subdomain",
    "runs_on",
    "has_port",
    "has_vuln",
    "related_cve",
    "exposes",
    "uses_tech",
    "links_to",
    "has_cert",
}

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_GRAPH_DIR = Path.home() / ".reconpro" / "memory"


# ---------------------------------------------------------------------------
# Fallback dict-based directed graph (used when networkx is absent)
# ---------------------------------------------------------------------------

class _FallbackDiGraph:
    """Minimal directed-graph implementation backed by plain dicts."""

    def __init__(self) -> None:
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._succ: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
        self._pred: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)

    # -- mutation ---------------------------------------------------------
    def add_node(self, node: str, **attr: Any) -> None:
        if node not in self._nodes:
            self._nodes[node] = {}
        self._nodes[node].update(attr)

    def add_edge(self, u: str, v: str, **attr: Any) -> None:
        self.add_node(u)
        self.add_node(v)
        self._succ[u][v] = attr
        self._pred[v][u] = attr

    def remove_node(self, node: str) -> None:
        self._nodes.pop(node, None)
        for neighbour in list(self._succ.get(node, {})):
            self._pred[neighbour].pop(node, None)
        self._succ.pop(node, None)
        for neighbour in list(self._pred.get(node, {})):
            self._succ[neighbour].pop(node, None)
        self._pred.pop(node, None)

    # -- queries ----------------------------------------------------------
    def nodes(self, data: bool = False):
        if data:
            return list(self._nodes.items())
        return list(self._nodes.keys())

    def edges(self, data: bool = False):
        result = []
        for u, nbrs in self._succ.items():
            for v, attr in nbrs.items():
                if data:
                    result.append((u, v, attr))
                else:
                    result.append((u, v))
        return result

    def successors(self, node: str):
        return list(self._succ.get(node, {}).keys())

    def predecessors(self, node: str):
        return list(self._pred.get(node, {}).keys())

    def out_edges(self, node: str, data: bool = False):
        if data:
            return [(node, v, a) for v, a in self._succ.get(node, {}).items()]
        return [(node, v) for v in self._succ.get(node, {}).keys()]

    def in_edges(self, node: str, data: bool = False):
        if data:
            return [(u, node, a) for u, a in self._pred.get(node, {}).items()]
        return [(u, node) for u in self._pred.get(node, {}).keys()]

    def has_node(self, node: str) -> bool:
        return node in self._nodes

    def get_node_data(self, node: str) -> Dict[str, Any]:
        return dict(self._nodes.get(node, {}))

    def subgraph(self, nodes: Set[str]):
        g = _FallbackDiGraph()
        for n in nodes:
            if n in self._nodes:
                g.add_node(n, **self._nodes[n])
        for u, nbrs in self._succ.items():
            if u in nodes:
                for v, attr in nbrs.items():
                    if v in nodes:
                        g.add_edge(u, v, **attr)
        return g

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": dict(self._nodes),
            "edges": [
                {"source": u, "target": v, **a}
                for u, nbrs in self._succ.items()
                for v, a in nbrs.items()
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        g = cls()
        for node, attr in data.get("nodes", {}).items():
            g.add_node(node, **attr)
        for edge in data.get("edges", []):
            src = edge.pop("source")
            tgt = edge.pop("target")
            g.add_edge(src, tgt, **edge)
        return g


def _make_graph():
    """Return a NetworkX DiGraph if available, else the fallback."""
    if HAS_NX:
        return nx.DiGraph()
    return _FallbackDiGraph()


# ---------------------------------------------------------------------------
# SecurityKnowledgeGraph
# ---------------------------------------------------------------------------

class SecurityKnowledgeGraph:
    """Directed knowledge graph for security scan results.

    Wraps a NetworkX :class:`DiGraph` when *networkx* is installed;
    otherwise falls back to a lightweight pure-Python implementation.
    """

    def __init__(self) -> None:
        self._g = _make_graph()
        self._node_type_index: Dict[str, Set[str]] = defaultdict(set)
        self._edge_type_index: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _node_id(self, ntype: str, label: str) -> str:
        """Deterministic node id: ``<type>:<label>``."""
        return f"{ntype}:{label}"

    def _add_indexed_node(self, ntype: str, label: str, **attrs: Any) -> str:
        nid = self._node_id(ntype, label)
        self._g.add_node(nid, node_type=ntype, label=label, **attrs)
        self._node_type_index[ntype].add(nid)
        return nid

    def _add_indexed_edge(self, src: str, dst: str, etype: str, **attrs: Any) -> None:
        self._g.add_edge(src, dst, edge_type=etype, **attrs)
        self._edge_type_index[etype].append((src, dst))

    def _safe_sev(self, raw) -> str:
        """Normalise a severity value to lowercase string."""
        if raw is None:
            return "info"
        s = str(raw).strip().lower()
        if s in SEVERITY_ORDER:
            return s
        return "info"

    # ------------------------------------------------------------------
    # Public mutation API
    # ------------------------------------------------------------------

    def add_scan_result(self, result_dict: Dict[str, Any]) -> None:
        """Ingest a full ``ReconProResult.to_dict()`` payload.

        Creates nodes/edges for the target, every finding, associated
        technologies, and open ports.
        """
        target = result_dict.get("target") or result_dict.get("host", "unknown")
        self._add_indexed_node("target", target)

        # Subdomains
        for sub in result_dict.get("subdomains", []):
            self.add_subdomain(sub, target)

        # Ports & services
        for port_entry in result_dict.get("ports", []):
            if isinstance(port_entry, dict):
                port_num = port_entry.get("port", port_entry.get("number"))
                service = port_entry.get("service", port_entry.get("name", "unknown"))
                state = port_entry.get("state", "open")
            else:
                port_num = port_entry
                service = "unknown"
                state = "open"

            if port_num is None:
                continue

            port_id = self._add_indexed_node("port", f"{target}:{port_num}", port=int(port_num), state=state)
            target_id = self._node_id("target", target)
            self._add_indexed_edge(target_id, port_id, "has_port")

            svc_id = self._add_indexed_node("service", f"{target}:{port_num}:{service}", name=service, port=int(port_num))
            self._add_indexed_edge(port_id, svc_id, "runs_on")

        # Technologies
        for tech in result_dict.get("technologies", []):
            tech_name = tech if isinstance(tech, str) else tech.get("name", str(tech))
            tech_id = self._add_indexed_node("technology", tech_name)
            target_id = self._node_id("target", target)
            self._add_indexed_edge(target_id, tech_id, "uses_tech")

        # Findings
        for finding in result_dict.get("findings", []):
            self.add_finding(finding)

        # Certificates
        for cert in result_dict.get("certificates", []):
            if isinstance(cert, dict):
                cn = cert.get("common_name", cert.get("cn", "unknown"))
                issuer = cert.get("issuer", "")
                expires = cert.get("expires", "")
            else:
                cn = str(cert)
                issuer = ""
                expires = ""
            cert_id = self._add_indexed_node("certificate", f"{target}:{cn}", common_name=cn, issuer=issuer, expires=expires)
            target_id = self._node_id("target", target)
            self._add_indexed_edge(target_id, cert_id, "has_cert")

        # Endpoints
        for ep in result_dict.get("endpoints", []):
            if isinstance(ep, dict):
                path = ep.get("path", ep.get("url", str(ep)))
                method = ep.get("method", "GET")
            else:
                path = str(ep)
                method = "GET"
            ep_id = self._add_indexed_node("endpoint", f"{target}:{method}:{path}", path=path, method=method)
            target_id = self._node_id("target", target)
            self._add_indexed_edge(target_id, ep_id, "exposes")

    def add_finding(self, finding_dict: Dict[str, Any]) -> None:
        """Add a finding node and connect it to its parent target."""
        title = finding_dict.get("title", finding_dict.get("name", finding_dict.get("description", "unnamed")))
        severity = self._safe_sev(finding_dict.get("severity"))
        target = finding_dict.get("target", finding_dict.get("host", "unknown"))
        finding_type = finding_dict.get("type", finding_dict.get("category", "generic"))
        description = finding_dict.get("description", "")
        evidence = finding_dict.get("evidence", "")
        cvss_score = finding_dict.get("cvss_score", finding_dict.get("cvss", None))

        fid = self._add_indexed_node(
            "finding",
            f"{target}:{title}",
            title=title,
            severity=severity,
            finding_type=finding_type,
            description=description,
            evidence=evidence,
            cvss_score=cvss_score,
        )

        # Ensure target node exists
        self._add_indexed_node("target", target)
        target_id = self._node_id("target", target)
        self._add_indexed_edge(target_id, fid, "has_vuln")

        # Link to port if specified
        port_num = finding_dict.get("port")
        if port_num is not None:
            port_id = self._node_id("port", f"{target}:{port_num}")
            if self._g.has_node(port_id):
                self._add_indexed_edge(port_id, fid, "has_vuln")

        # Link related CVEs
        for cve_ref in finding_dict.get("cves", finding_dict.get("references", [])):
            if isinstance(cve_ref, dict):
                cve_id = cve_ref.get("id", cve_ref.get("cve_id", ""))
                cve_sev = cve_ref.get("severity", severity)
                cve_desc = cve_ref.get("description", "")
                affected = cve_ref.get("affected", "")
            else:
                cve_id = str(cve_ref)
                cve_sev = severity
                cve_desc = ""
                affected = ""
            if cve_id:
                self.add_cve(cve_id, cve_sev, cve_desc, affected)
                self._add_indexed_edge(fid, self._node_id("cve", cve_id), "related_cve")

        # Link related technologies
        for tech in finding_dict.get("technologies", []):
            tech_name = tech if isinstance(tech, str) else tech.get("name", str(tech))
            tech_id = self._add_indexed_node("technology", tech_name)
            self._add_indexed_edge(tech_id, fid, "exposes")

    def add_cve(
        self,
        cve_id: str,
        severity: str = "info",
        description: str = "",
        affected: str = "",
    ) -> None:
        """Add a CVE node (idempotent) and return its node id."""
        sev = self._safe_sev(severity)
        nid = self._add_indexed_node(
            "cve",
            cve_id,
            severity=sev,
            description=description,
            affected=affected,
        )
        return nid

    def add_subdomain(self, domain: str, parent: str) -> None:
        """Link *domain* as a subdomain of *parent*."""
        sub_id = self._add_indexed_node("subdomain", domain)
        parent_id = self._node_id("target", parent)
        # Parent might be a subdomain itself
        if not self._g.has_node(parent_id):
            parent_id = self._node_id("subdomain", parent)
            if not self._g.has_node(parent_id):
                self._add_indexed_node("target", parent)
                parent_id = self._node_id("target", parent)
        self._add_indexed_edge(parent_id, sub_id, "has_subdomain")

    # ------------------------------------------------------------------
    # Query / analysis API
    # ------------------------------------------------------------------

    def get_attack_surface(self, target: str) -> Dict[str, List[Dict[str, Any]]]:
        """Return all reachable endpoints, open ports, and vulns for *target*.

        Returns a dict with keys ``"endpoints"``, ``"ports"``,
        ``"vulnerabilities"``, and ``"technologies"``.
        """
        target_id = self._node_id("target", target)
        if not self._g.has_node(target_id):
            # Check subdomains
            target_id = self._node_id("subdomain", target)
            if not self._g.has_node(target_id):
                return {"endpoints": [], "ports": [], "vulnerabilities": [], "technologies": []}

        visited = self._bfs_collect(target_id, max_depth=3)
        result: Dict[str, List[Dict[str, Any]]] = {
            "endpoints": [],
            "ports": [],
            "vulnerabilities": [],
            "technologies": [],
        }

        for nid in visited:
            if HAS_NX:
                data = self._g.nodes[nid]
            else:
                data = self._g.get_node_data(nid)
            ntype = data.get("node_type", "")
            if ntype == "endpoint":
                result["endpoints"].append(data)
            elif ntype == "port":
                if data.get("state", "open") == "open":
                    result["ports"].append(data)
            elif ntype in ("vulnerability", "finding"):
                result["vulnerabilities"].append(data)
            elif ntype == "technology":
                result["technologies"].append(data)

        return result

    def get_blast_radius(self, asset: str) -> List[Dict[str, Any]]:
        """BFS from *asset* to find all connected vulnerabilities.

        *asset* can be a node label, an IP, or a partial node id.
        """
        start = self._resolve_node(asset)
        if start is None:
            return []

        visited = self._bfs_collect(start, max_depth=10)
        vulns: List[Dict[str, Any]] = []
        for nid in visited:
            if HAS_NX:
                data = self._g.nodes[nid]
            else:
                data = self._g.get_node_data(nid)
            if data.get("node_type") in ("vulnerability", "finding", "cve"):
                vulns.append(data)
        return vulns

    def find_chains(self, target: str) -> List[List[Dict[str, Any]]]:
        """Find multi-hop attack chains originating from *target*.

        Each chain follows a pattern like::

            target → port → service → vulnerability → CVE
        """
        target_id = self._resolve_node(target)
        if target_id is None:
            return []

        chains: List[List[Dict[str, Any]]] = []
        # DFS to find paths that end at CVE or finding nodes
        stack: List[Tuple[str, List[str]]] = [(target_id, [target_id])]
        seen_chains: Set[tuple] = set()

        while stack:
            current, path = stack.pop()
            succs = self._g.successors(current) if HAS_NX else self._g.successors(current)
            for nxt in succs:
                if nxt in path:
                    continue
                new_path = path + [nxt]
                if HAS_NX:
                    nd = self._g.nodes[nxt]
                else:
                    nd = self._g.get_node_data(nxt)
                ntype = nd.get("node_type", "")
                # A chain is complete if it reaches a CVE or high-sev finding
                if ntype == "cve" or (ntype == "finding" and SEVERITY_ORDER.get(self._safe_sev(nd.get("severity")), 0) >= 2):
                    chain_key = tuple(new_path)
                    if chain_key not in seen_chains:
                        seen_chains.add(chain_key)
                        chain_data = []
                        for nid in new_path:
                            if HAS_NX:
                                chain_data.append(dict(self._g.nodes[nid]))
                            else:
                                chain_data.append(self._g.get_node_data(nid))
                        chains.append(chain_data)
                elif len(new_path) < 8:
                    stack.append((nxt, new_path))

        # Sort by severity of the terminal node
        def _chain_sort_key(chain):
            last = chain[-1]
            return SEVERITY_ORDER.get(self._safe_sev(last.get("severity")), 0)

        chains.sort(key=_chain_sort_key, reverse=True)
        return chains

    def get_vulnerable_assets(self) -> List[Dict[str, Any]]:
        """Return all assets (targets/subdomains) with HIGH or CRITICAL findings."""
        vulnerable: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        for nid in self._node_type_index.get("finding", set()):
            if HAS_NX:
                data = self._g.nodes[nid]
            else:
                data = self._g.get_node_data(nid)
            sev = self._safe_sev(data.get("severity"))
            if SEVERITY_ORDER.get(sev, 0) < 3:
                continue
            # Walk predecessors to find the owning target/subdomain
            for pred in (self._g.predecessors(nid) if HAS_NX else self._g.predecessors(nid)):
                if HAS_NX:
                    pdata = self._g.nodes[pred]
                else:
                    pdata = self._g.get_node_data(pred)
                ptype = pdata.get("node_type", "")
                if ptype in ("target", "subdomain", "asset") and pred not in seen:
                    seen.add(pred)
                    vulnerable.append({"node_id": pred, **pdata, "critical_finding": data})
        return vulnerable

    def correlate(self) -> List[Dict[str, Any]]:
        """Cross-reference findings to suggest related vulnerabilities.

        Returns a list of correlation suggestions, each containing
        the two related node ids, the relationship type, and a
        confidence score.
        """
        suggestions: List[Dict[str, Any]] = []
        # Group findings by technology
        tech_findings: Dict[str, List[str]] = defaultdict(list)
        for nid in self._node_type_index.get("finding", set()):
            if HAS_NX:
                data = self._g.nodes[nid]
            else:
                data = self._g.get_node_data(nid)
            for pred in (self._g.predecessors(nid) if HAS_NX else self._g.predecessors(nid)):
                if HAS_NX:
                    pdata = self._g.nodes[pred]
                else:
                    pdata = self._g.get_node_data(pred)
                if pdata.get("node_type") == "technology":
                    tech_findings[pred].append(nid)

        for tech_id, finding_ids in tech_findings.items():
            if len(finding_ids) < 2:
                continue
            for i in range(len(finding_ids)):
                for j in range(i + 1, len(finding_ids)):
                    f1 = finding_ids[i]
                    f2 = finding_ids[j]
                    if HAS_NX:
                        d1 = self._g.nodes[f1]
                        d2 = self._g.nodes[f2]
                    else:
                        d1 = self._g.get_node_data(f1)
                        d2 = self._g.get_node_data(f2)
                    # If both share a technology, suggest they may be related
                    conf = 0.6
                    if d1.get("severity") == d2.get("severity"):
                        conf += 0.2
                    if d1.get("finding_type") == d2.get("finding_type"):
                        conf += 0.2
                    suggestions.append({
                        "source": f1,
                        "target": f2,
                        "relationship": "shared_technology",
                        "technology": tech_id,
                        "confidence": min(conf, 1.0),
                        "source_severity": d1.get("severity"),
                        "target_severity": d2.get("severity"),
                    })

        # Also correlate by port: findings on the same port may be related
        port_findings: Dict[str, List[str]] = defaultdict(list)
        for nid in self._node_type_index.get("finding", set()):
            for pred in (self._g.predecessors(nid) if HAS_NX else self._g.predecessors(nid)):
                if HAS_NX:
                    pdata = self._g.nodes[pred]
                else:
                    pdata = self._g.get_node_data(pred)
                if pdata.get("node_type") == "port":
                    port_findings[pred].append(nid)

        for port_id, fids in port_findings.items():
            if len(fids) < 2:
                continue
            for i in range(len(fids)):
                for j in range(i + 1, len(fids)):
                    f1, f2 = fids[i], fids[j]
                    suggestions.append({
                        "source": f1,
                        "target": f2,
                        "relationship": "shared_port",
                        "port": port_id,
                        "confidence": 0.7,
                    })

        suggestions.sort(key=lambda s: s["confidence"], reverse=True)
        return suggestions

    def to_cypher(self) -> str:
        """Export the graph as Cypher-like CREATE statements."""
        lines: List[str] = []
        # Nodes
        for nid in (self._g.nodes() if HAS_NX else self._g.nodes()):
            if HAS_NX:
                data = self._g.nodes[nid]
            else:
                data = self._g.get_node_data(nid)
            ntype = data.pop("node_type", "Unknown")
            label = data.pop("label", nid)
            props = json.dumps(data, default=str)
            safe_id = nid.replace(":", "__").replace("-", "_")
            lines.append(f'CREATE ({safe_id}:{ntype} {{label: "{label}", {props[1:-1]}}})')
            # Restore for edge generation below
            data["node_type"] = ntype
            data["label"] = label

        # Edges
        for u, v, attr in (self._g.edges(data=True) if HAS_NX else self._g.edges(data=True)):
            etype = attr.get("edge_type", "RELATED_TO")
            props = {k: v for k, v in attr.items() if k != "edge_type"}
            props_str = json.dumps(props, default=str)
            safe_u = u.replace(":", "__").replace("-", "_")
            safe_v = v.replace(":", "__").replace("-", "_")
            if props_str == "{}":
                lines.append(f'CREATE ({safe_u})-[:{etype}]->({safe_v})')
            else:
                lines.append(f'CREATE ({safe_u})-[:{etype} {{{props_str[1:-1]}}}]->({safe_v})')

        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        """Return a summary dict with node/edge counts broken down by type."""
        node_counts: Dict[str, int] = {}
        for ntype, nids in self._node_type_index.items():
            node_counts[ntype] = len(nids)

        edge_counts: Dict[str, int] = {}
        for etype, pairs in self._edge_type_index.items():
            edge_counts[etype] = len(pairs)

        total_nodes = len(self._g.nodes()) if HAS_NX else len(self._g.nodes())
        total_edges = len(self._g.edges()) if HAS_NX else len(self._g.edges())

        # Severity distribution
        sev_dist: Dict[str, int] = defaultdict(int)
        for nid in self._node_type_index.get("finding", set()).union(self._node_type_index.get("cve", set())):
            if HAS_NX:
                data = self._g.nodes[nid]
            else:
                data = self._g.get_node_data(nid)
            sev_dist[self._safe_sev(data.get("severity"))] += 1

        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "nodes_by_type": node_counts,
            "edges_by_type": edge_counts,
            "severity_distribution": dict(sev_dist),
            "backing_engine": "networkx" if HAS_NX else "fallback_dict",
        }

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Optional[str] = None) -> str:
        """Persist the graph to JSON.

        Parameters
        ----------
        path :
            Destination file path.  Defaults to
            ``~/.reconpro/memory/graph.json``.

        Returns
        -------
        str
            The path the graph was saved to.
        """
        if path is None:
            path = str(DEFAULT_GRAPH_DIR / "graph.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)

        if HAS_NX:
            from networkx.readwrite import json_graph
            data = json_graph.node_link_data(self._g)
        else:
            data = self._g.to_dict()

        payload = {
            "graph": data,
            "node_type_index": {k: list(v) for k, v in self._node_type_index.items()},
            "edge_type_index": dict(self._edge_type_index),
        }

        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        return path

    def load(self, path: Optional[str] = None) -> None:
        """Load a previously saved graph from JSON.

        Parameters
        ----------
        path :
            Source file path.  Defaults to
            ``~/.reconpro/memory/graph.json``.
        """
        if path is None:
            path = str(DEFAULT_GRAPH_DIR / "graph.json")

        with open(path, "r") as fh:
            payload = json.load(fh)

        if HAS_NX:
            from networkx.readwrite import json_graph
            self._g = json_graph.node_link_graph(payload["graph"], directed=True)
        else:
            self._g = _FallbackDiGraph.from_dict(payload["graph"])

        self._node_type_index = defaultdict(set)
        for k, v in payload.get("node_type_index", {}).items():
            self._node_type_index[k] = set(v)

        self._edge_type_index = defaultdict(list)
        for k, v in payload.get("edge_type_index", {}).items():
            self._edge_type_index[k] = [tuple(pair) for pair in v]

    # ------------------------------------------------------------------
    # Internal traversal helpers
    # ------------------------------------------------------------------

    def _resolve_node(self, label: str) -> Optional[str]:
        """Try to resolve a human-readable label to a full node id."""
        # Exact node id
        if self._g.has_node(label):
            return label
        # Try as target
        candidate = self._node_id("target", label)
        if self._g.has_node(candidate):
            return candidate
        # Try as subdomain
        candidate = self._node_id("subdomain", label)
        if self._g.has_node(candidate):
            return candidate
        # Try as asset
        candidate = self._node_id("asset", label)
        if self._g.has_node(candidate):
            return candidate
        # Fuzzy: search all node labels
        for nid in self._g.nodes():
            if HAS_NX:
                data = self._g.nodes[nid]
            else:
                data = self._g.get_node_data(nid)
            if data.get("label") == label or nid.endswith(f":{label}"):
                return nid
        return None

    def _bfs_collect(self, start: str, max_depth: int = 5) -> Set[str]:
        """BFS from *start* up to *max_depth* hops, return visited nodes."""
        visited: Set[str] = set()
        queue: deque = deque()
        queue.append((start, 0))
        visited.add(start)
        while queue:
            node, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbour in (self._g.successors(node) if HAS_NX else self._g.successors(node)):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append((neighbour, depth + 1))
        return visited

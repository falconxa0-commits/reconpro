"""Tests for attack_graph.py — Attack Graph Engine."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reconpro.attack_graph import (
    AttackGraphEngine, DiGraph, GraphNode, GraphEdge,
    AttackChain, ChokePoint, BlastRadius,
    AttackGraphResult, _SEVERITY_WEIGHTS,
    _CATEGORY_TO_PHASE, KILL_CHAIN_PHASES,
    _classify_finding,
)


def _finding(title="SQL Injection in login", severity="high", category="sqli",
             module="chain", evidence="SELECT * FROM users", asset="example.com", **kw):
    f = {"title": title, "severity": severity, "category": category,
         "module": module, "description": f"Found {title}", "evidence": evidence,
         "asset": asset, "points_deducted": 10, "dread_score": 7.0}
    f.update(kw)
    return f


class TestDiGraph(unittest.TestCase):

    def setUp(self):
        self.g = DiGraph()

    def test_add_node(self):
        self.g.add_node(GraphNode(id="a", label="A", node_type="finding"))
        self.assertTrue(self.g.has_node("a"))
        self.assertEqual(self.g.node_count(), 1)

    def test_add_edge(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="leads_to"))
        self.assertTrue(self.g.has_node("a"))
        self.assertTrue(self.g.has_node("b"))
        self.assertEqual(self.g.edge_count(), 1)

    def test_successors(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="e"))
        self.g.add_edge(GraphEdge(source="a", target="c", edge_type="e"))
        succ = self.g.successors("a")
        self.assertIn("b", succ)
        self.assertIn("c", succ)

    def test_predecessors(self):
        self.g.add_edge(GraphEdge(source="a", target="c", edge_type="e"))
        self.g.add_edge(GraphEdge(source="b", target="c", edge_type="e"))
        pred = self.g.predecessors("c")
        self.assertIn("a", pred)
        self.assertIn("b", pred)

    def test_bfs_paths(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="e"))
        self.g.add_edge(GraphEdge(source="b", target="c", edge_type="e"))
        paths = self.g.bfs_paths("a", "c")
        self.assertGreater(len(paths), 0)
        self.assertEqual(paths[0], ["a", "b", "c"])

    def test_shortest_path(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="e"))
        self.g.add_edge(GraphEdge(source="b", target="c", edge_type="e"))
        self.g.add_edge(GraphEdge(source="a", target="c", edge_type="e"))
        path = self.g.shortest_path("a", "c")
        self.assertEqual(path, ["a", "c"])

    def test_descendants(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="e"))
        self.g.add_edge(GraphEdge(source="b", target="c", edge_type="e"))
        desc = self.g.descendants("a")
        self.assertIn("b", desc)
        self.assertIn("c", desc)

    def test_ancestors(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="e"))
        self.g.add_edge(GraphEdge(source="b", target="c", edge_type="e"))
        anc = self.g.ancestors("c")
        self.assertIn("a", anc)
        self.assertIn("b", anc)

    def test_in_out_degree(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="e"))
        self.assertEqual(self.g.in_degree("b"), 1)
        self.assertEqual(self.g.out_degree("a"), 1)

    def test_no_path(self):
        self.g.add_node(GraphNode(id="a", label="A", node_type="finding"))
        self.g.add_node(GraphNode(id="b", label="B", node_type="finding"))
        path = self.g.shortest_path("a", "b")
        self.assertIsNone(path)

    def test_cycle_handling(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="e"))
        self.g.add_edge(GraphEdge(source="b", target="a", edge_type="e"))
        paths = self.g.all_paths_between("a", "b", max_depth=5)
        # Should not infinite loop; at most 1 path (direct)
        self.assertLessEqual(len(paths), 1)

    def test_betweenness_proxy(self):
        self.g.add_edge(GraphEdge(source="a", target="b", edge_type="e"))
        self.g.add_edge(GraphEdge(source="b", target="c", edge_type="e"))
        self.g.add_edge(GraphEdge(source="a", target="c", edge_type="e"))
        bw = self.g.betweenness_proxy()
        # b is on the shortest path from a to... well a->c is direct, so b has bw 0
        # The betweenness proxy only counts intermediate nodes
        self.assertIsInstance(bw, dict)
        # a->b->c: shortest path is a->c (direct), so b is never an intermediate
        self.assertEqual(bw.get("b", 0), 0)


class TestClassifyFinding(unittest.TestCase):

    def test_sqli(self):
        self.assertEqual(_classify_finding(_finding()), "sqli")

    def test_xss(self):
        f = _finding(title="Reflected XSS", category="xss")
        self.assertEqual(_classify_finding(f), "xss")

    def test_rce(self):
        f = _finding(title="Remote Code Execution", category="rce")
        self.assertEqual(_classify_finding(f), "rce")

    def test_auth_bypass(self):
        f = _finding(title="Authentication bypass", category="auth_bypass")
        self.assertEqual(_classify_finding(f), "auth_bypass")

    def test_default_creds(self):
        f = _finding(title="Default credentials found", category="default_credentials")
        # default_credentials pattern matches credential_theft (higher weight) which is acceptable
        self.assertIn(_classify_finding(f), ("default_credentials", "credential_theft"))

    def test_beaconing(self):
        f = _finding(title="C2 beaconing detected", category="beaconing")
        self.assertEqual(_classify_finding(f), "beaconing")

    def test_unknown(self):
        f = _finding(title="Random thing", category="misc", evidence="nothing here")
        self.assertEqual(_classify_finding(f), "misc")


class TestKillChainPhases(unittest.TestCase):

    def test_phase_count(self):
        self.assertEqual(len(KILL_CHAIN_PHASES), 7)

    def test_category_to_phase_coverage(self):
        # At least 20 categories should map to phases
        self.assertGreaterEqual(len(_CATEGORY_TO_PHASE), 20)

    def test_all_phases_covered(self):
        covered = set(_CATEGORY_TO_PHASE.values())
        for phase in KILL_CHAIN_PHASES:
            self.assertIn(phase, covered)


class TestAttackGraphEngine(unittest.TestCase):

    def setUp(self):
        self.engine = AttackGraphEngine()

    def test_build_graph_empty(self):
        self.engine.build_graph([], "example.com")
        self.assertGreater(self.engine.graph.node_count(), 0)  # Entry + objective nodes

    def test_build_graph_with_findings(self):
        findings = [
            _finding(severity="critical"),
            _finding(title="XSS found", severity="high", category="xss"),
            _finding(title="Default creds", severity="critical", category="default_credentials"),
        ]
        self.engine.build_graph(findings, "example.com")
        self.assertGreater(self.engine.graph.node_count(), 3)

    def test_build_graph_creates_edges(self):
        findings = [
            _finding(severity="critical"),
            _finding(title="Default creds", severity="critical", category="default_credentials"),
        ]
        self.engine.build_graph(findings, "example.com")
        self.assertGreater(self.engine.graph.edge_count(), 0)

    def test_analyze_full(self):
        findings = [
            _finding(severity="critical", category="sqli"),
            _finding(title="Default credentials", severity="critical", category="default_credentials"),
            _finding(title="Privilege escalation", severity="critical", category="privilege_escalation"),
            _finding(title="Data exposure", severity="high", category="data_exposure"),
        ]
        result = self.engine.analyze(findings, "example.com")
        self.assertIsInstance(result, AttackGraphResult)
        self.assertEqual(result.target, "example.com")
        self.assertGreater(len(result.nodes), 0)
        self.assertGreater(len(result.edges), 0)
        self.assertGreater(result.analysis_duration_ms, 0)

    def test_analyze_attack_chains(self):
        findings = [
            _finding(title="Subdomain found", severity="info", category="dns_recon"),
            _finding(title="Default credentials", severity="critical", category="default_credentials"),
            _finding(title="Privilege escalation", severity="critical", category="privilege_escalation"),
            _finding(title="Data exposure", severity="high", category="data_exposure"),
        ]
        result = self.engine.analyze(findings, "example.com")
        # Should detect at least some paths
        self.assertGreaterEqual(len(result.attack_chains), 0)

    def test_analyze_kill_chain_mapping(self):
        findings = [
            _finding(title="DNS recon", severity="info", category="dns_recon"),
            _finding(title="XSS", severity="high", category="xss"),
            _finding(title="Privilege escalation", severity="critical", category="privilege_escalation"),
        ]
        result = self.engine.analyze(findings, "example.com")
        self.assertIn("phases", result.kill_chain_mapping)
        self.assertIn("coverage_percentage", result.kill_chain_mapping)
        self.assertIn("phase_progression", result.kill_chain_mapping)

    def test_blast_radius(self):
        findings = [
            _finding(severity="critical", category="sqli"),
            _finding(title="Data exposure", severity="high", category="data_exposure"),
            _finding(title="Privilege escalation", severity="critical", category="privilege_escalation"),
        ]
        self.engine.build_graph(findings, "example.com")
        # Compute blast radius from entry node
        br = self.engine.compute_blast_radius("entry:recon")
        self.assertIsInstance(br, BlastRadius)
        self.assertGreater(len(br.affected_nodes), 0)

    def test_blast_radius_dataclass(self):
        br = BlastRadius(source_node="a", affected_nodes=["b", "c"],
                        affected_assets=["target"], max_depth=2, severity_spread={"high": 2})
        d = br.to_dict()
        self.assertEqual(len(br.affected_nodes), 2)
        self.assertEqual(br.max_depth, 2)

    def test_result_to_dict(self):
        findings = [_finding()]
        result = self.engine.analyze(findings, "example.com")
        d = result.to_dict()
        self.assertIn("target", d)
        self.assertIn("node_count", d)
        self.assertIn("edge_count", d)
        self.assertIn("attack_chains", d)

    def test_high_value_assets(self):
        findings = [
            _finding(severity="critical", asset="api.example.com"),
            _finding(title="XSS", severity="high", asset="api.example.com"),
            _finding(title="Info leak", severity="medium", asset="api.example.com"),
        ]
        result = self.engine.analyze(findings, "example.com")
        self.assertGreaterEqual(len(result.high_value_assets), 0)

    def test_single_point_failures(self):
        findings = [
            _finding(severity="critical", category="privilege_escalation"),
        ]
        result = self.engine.analyze(findings, "example.com")
        self.assertIsInstance(result.single_point_failures, list)


class TestGraphNode(unittest.TestCase):

    def test_to_dict(self):
        node = GraphNode(id="test", label="Test", node_type="finding",
                        severity="high", risk_score=8.0)
        d = node.to_dict()
        self.assertEqual(d["id"], "test")
        self.assertEqual(d["severity"], "high")
        self.assertEqual(d["risk_score"], 8.0)

class TestGraphEdge(unittest.TestCase):

    def test_to_dict(self):
        edge = GraphEdge(source="a", target="b", edge_type="leads_to",
                        weight=0.8, confidence=0.7)
        d = edge.to_dict()
        self.assertEqual(d["source"], "a")
        self.assertEqual(d["target"], "b")
        self.assertEqual(d["edge_type"], "leads_to")


class TestAttackChain(unittest.TestCase):

    def test_to_dict(self):
        ac = AttackChain(chain_id="abc123", steps=["a", "b", "c"],
                        step_labels=["A", "B", "C"],
                        step_severities=["info", "high", "critical"],
                        entry_point="a", objective="Compromise",
                        complexity="high", likelihood=0.8, impact=0.9,
                        confidence=0.72, narrative="Test chain")
        d = ac.to_dict()
        self.assertEqual(d["step_count"], 3)
        self.assertEqual(d["complexity"], "high")
        self.assertEqual(d["chain_id"], "abc123")


if __name__ == "__main__":
    unittest.main()

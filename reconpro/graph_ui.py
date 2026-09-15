"""
ReconPro v8.5 — Interactive Knowledge Graph UI

Generates a self-contained HTML file with D3.js force-directed graph visualization.
No external dependencies beyond Python stdlib; all JS/CSS embedded inline.

Exports:
    GraphUIRenderer   – main renderer class
"""

from __future__ import annotations

import json
import html as html_mod
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Node colour map ──────────────────────────────────────────────────────
NODE_COLORS: Dict[str, str] = {
    "target": "#3b82f6",       # blue
    "subdomain": "#60a5fa",    # lighter blue
    "port": "#a78bfa",         # purple
    "service": "#c084fc",      # lighter purple
    "vulnerability": "#ef4444",  # red
    "finding": "#f87171",      # lighter red
    "cve": "#f97316",          # orange
    "asset": "#22c55e",        # green
    "endpoint": "#a855f7",     # purple
    "technology": "#6b7280",   # gray
    "certificate": "#eab308",  # yellow
}

DEFAULT_COLOR = "#64748b"


class GraphUIRenderer:
    """Render a SecurityKnowledgeGraph as a self-contained interactive HTML page.

    Parameters
    ----------
    width, height : int
        Default canvas dimensions (pixels).
    """

    def __init__(self, width: int = 1200, height: int = 800) -> None:
        self.width = width
        self.height = height

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def render(self, graph_data: dict, output_path: str = "") -> str:
        """Build the full HTML string from *graph_data*.

        *graph_data* must be a dict with ``"nodes"`` (list of dicts, each
        with at least ``id``, optionally ``node_type``, ``label``, ``severity",
        ``description``, ``cves``, ``remediation``) and ``"edges"`` (list of
        dicts each with ``source``, ``target``, optionally ``edge_type``).

        When *output_path* is given the HTML is also written to disk.

        Returns the HTML string.
        """
        nodes_raw = graph_data.get("nodes", [])
        edges_raw = graph_data.get("edges", [])

        nodes = self._normalise_nodes(nodes_raw)
        edges = self._normalise_edges(edges_raw, nodes)
        degree_map = self._compute_degrees(edges)

        nodes_json = json.dumps(nodes, ensure_ascii=False)
        edges_json = json.dumps(edges, ensure_ascii=False)
        degree_json = json.dumps(degree_map, ensure_ascii=False)

        page = self._build_html(nodes_json, edges_json, degree_json)

        if output_path:
            return self.render_to_file(graph_data, output_path)

        return page

    def render_to_file(self, graph_data: dict, path: str) -> str:
        """Write the HTML to *path* and return the absolute path."""
        path = os.path.abspath(path)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

        nodes_raw = graph_data.get("nodes", [])
        edges_raw = graph_data.get("edges", [])

        nodes = self._normalise_nodes(nodes_raw)
        edges = self._normalise_edges(edges_raw, nodes)
        degree_map = self._compute_degrees(edges)

        nodes_json = json.dumps(nodes, ensure_ascii=False)
        edges_json = json.dumps(edges, ensure_ascii=False)
        degree_json = json.dumps(degree_map, ensure_ascii=False)

        page = self._build_html(nodes_json, edges_json, degree_json)

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(page)

        return path

    # ------------------------------------------------------------------
    # Data normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_nodes(raw: list) -> list:
        out = []
        for n in raw:
            if isinstance(n, dict):
                nid = n.get("id") or n.get("node_id", str(id(n)))
                node_type = n.get("node_type", n.get("type", "technology"))
                label = n.get("label", n.get("name", nid))
                out.append({
                    "id": str(nid),
                    "label": str(label),
                    "node_type": str(node_type),
                    "severity": str(n.get("severity", "")).lower(),
                    "description": n.get("description", ""),
                    "cves": n.get("cves", []),
                    "remediation": n.get("remediation", ""),
                    "extra": {k: v for k, v in n.items()
                             if k not in ("id", "node_id", "label", "name",
                                           "node_type", "type", "severity",
                                           "description", "cves", "remediation")},
                })
            else:
                out.append({
                    "id": str(n),
                    "label": str(n),
                    "node_type": "technology",
                    "severity": "",
                    "description": "",
                    "cves": [],
                    "remediation": "",
                    "extra": {},
                })
        return out

    @staticmethod
    def _normalise_edges(raw: list, nodes: list) -> list:
        node_ids = {n["id"] for n in nodes}
        out = []
        for e in raw:
            if isinstance(e, dict):
                src = str(e.get("source", ""))
                tgt = str(e.get("target", ""))
                if not src or not tgt:
                    continue
                if src not in node_ids:
                    continue
                if tgt not in node_ids:
                    continue
                out.append({
                    "source": src,
                    "target": tgt,
                    "edge_type": e.get("edge_type", e.get("relationship", "links_to")),
                    "description": e.get("description", ""),
                })
            elif isinstance(e, (list, tuple)) and len(e) >= 2:
                src, tgt = str(e[0]), str(e[1])
                if src in node_ids and tgt in node_ids:
                    out.append({"source": src, "target": tgt, "edge_type": "links_to", "description": ""})
        return out

    @staticmethod
    def _compute_degrees(edges: list) -> dict:
        deg: dict[str, int] = {}
        for e in edges:
            deg[e["source"]] = deg.get(e["source"], 0) + 1
            deg[e["target"]] = deg.get(e["target"], 0) + 1
        return deg

    # ------------------------------------------------------------------
    # HTML generation
    # ------------------------------------------------------------------

    def _build_html(self, nodes_json: str, edges_json: str, degree_json: str) -> str:
        ts = int(time.time())
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconPro Knowledge Graph</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    background: #0a0a14;
    color: #e2e8f0;
    font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
    overflow: hidden;
    height: 100vh;
}}
#toolbar {{
    position: fixed; top: 0; left: 0; right: 0; z-index: 100;
    display: flex; align-items: center; gap: 10px;
    padding: 10px 16px;
    background: rgba(10,10,20,0.92);
    border-bottom: 1px solid #1e293b;
    backdrop-filter: blur(8px);
}}
#toolbar .brand {{
    color: #00ffcc;
    font-weight: 700;
    font-size: 14px;
    white-space: nowrap;
    letter-spacing: 1px;
}}
#search-input {{
    flex: 1; max-width: 280px;
    padding: 6px 12px;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    color: #e2e8f0;
    font-size: 13px;
    outline: none;
    transition: border-color 0.2s;
}}
#search-input:focus {{ border-color: #00ffcc; }}
#search-input::placeholder {{ color: #64748b; }}
.tb-btn {{
    padding: 6px 14px;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    color: #e2e8f0;
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.2s;
}}
.tb-btn:hover {{ background: #334155; border-color: #00ffcc; color: #00ffcc; }}
.tb-btn.active {{ background: #00ffcc; color: #0a0a14; border-color: #00ffcc; font-weight: 600; }}
#blast-hops {{
    width: 50px; padding: 6px 8px;
    background: #1e293b; border: 1px solid #334155; border-radius: 6px;
    color: #e2e8f0; font-size: 12px; text-align: center; outline: none;
}}
#blast-hops:focus {{ border-color: #00ffcc; }}
#path-select {{
    padding: 6px 10px; background: #1e293b; border: 1px solid #334155;
    border-radius: 6px; color: #e2e8f0; font-size: 12px; outline: none; max-width: 180px;
}}
#graph-canvas {{
    width: 100vw; height: 100vh; cursor: grab;
}}
#graph-canvas:active {{ cursor: grabbing; }}
#detail-panel {{
    position: fixed; top: 56px; right: 0; bottom: 0; width: 360px;
    background: rgba(15,15,30,0.96);
    border-left: 1px solid #1e293b;
    padding: 20px;
    overflow-y: auto;
    z-index: 90;
    transform: translateX(100%);
    transition: transform 0.3s ease;
    backdrop-filter: blur(10px);
}}
#detail-panel.open {{ transform: translateX(0); }}
#detail-panel h2 {{
    font-size: 15px; color: #00ffcc; margin-bottom: 6px; word-break: break-all;
}}
#detail-panel .type-badge {{
    display: inline-block; padding: 2px 10px; border-radius: 10px;
    font-size: 11px; font-weight: 600; margin-bottom: 12px;
    text-transform: uppercase; letter-spacing: 0.5px;
}}
#detail-panel .field {{ margin-bottom: 10px; }}
#detail-panel .field-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }}
#detail-panel .field-value {{ font-size: 13px; color: #cbd5e1; margin-top: 2px; word-break: break-word; }}
#detail-panel .severity-tag {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600;
}}
.sev-critical {{ background: #7f1d1d; color: #fca5a5; }}
.sev-high {{ background: #78350f; color: #fdba74; }}
.sev-medium {{ background: #713f12; color: #fde68a; }}
.sev-low {{ background: #1e3a1e; color: #86efac; }}
.sev-info {{ background: #1e293b; color: #94a3b8; }}
#detail-panel .cve-list {{ list-style: none; padding: 0; }}
#detail-panel .cve-list li {{
    padding: 3px 0; font-size: 12px; color: #f97316; border-bottom: 1px solid #1e293b;
}}
#detail-panel .remediation {{
    background: #0f2a1e; border-left: 3px solid #22c55e;
    padding: 8px 12px; border-radius: 0 6px 6px 0; font-size: 12px; color: #86efac;
}}
#detail-panel .close-btn {{
    position: absolute; top: 12px; right: 12px;
    background: none; border: none; color: #64748b; font-size: 18px; cursor: pointer;
}}
#detail-panel .close-btn:hover {{ color: #e2e8f0; }}
.edge-label {{
    fill: #64748b; font-size: 9px; pointer-events: none;
    text-anchor: middle;
}}
#legend {{
    position: fixed; bottom: 16px; left: 16px; z-index: 90;
    background: rgba(10,10,20,0.9); border: 1px solid #1e293b;
    border-radius: 8px; padding: 12px 16px;
    backdrop-filter: blur(8px);
}}
#legend h4 {{ font-size: 11px; color: #64748b; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }}
.legend-item {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; font-size: 11px; color: #94a3b8; }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
#stats-bar {{
    position: fixed; bottom: 16px; right: 16px; z-index: 90;
    background: rgba(10,10,20,0.9); border: 1px solid #1e293b;
    border-radius: 8px; padding: 8px 14px; font-size: 11px; color: #64748b;
    backdrop-filter: blur(8px);
}}
#stats-bar span {{ color: #00ffcc; font-weight: 600; }}
.highlight-node {{ stroke-width: 4px !important; stroke: #00ffcc !important; filter: drop-shadow(0 0 8px rgba(0,255,204,0.6)); }}
.highlight-edge {{ stroke-width: 3px !important; stroke: #00ffcc !important; opacity: 1 !important; }}
.dimmed {{ opacity: 0.15 !important; }}
.path-node {{ stroke-width: 3px !important; stroke: #facc15 !important; filter: drop-shadow(0 0 6px rgba(250,204,21,0.5)); }}
.path-edge {{ stroke-width: 3px !important; stroke: #facc15 !important; opacity: 1 !important; }}
</style>
</head>
<body>
<div id="toolbar">
    <span class="brand">⟁ RECONPRO GRAPH</span>
    <input type="text" id="search-input" placeholder="Search nodes (name / type / severity)…" />
    <button class="tb-btn" id="btn-clear">Clear</button>
    <span style="color:#334155;">|</span>
    <select id="path-select"><option value="">— Path From —</option></select>
    <select id="path-to"><option value="">— Path To —</option></select>
    <button class="tb-btn" id="btn-path">Find Path</button>
    <span style="color:#334155;">|</span>
    <button class="tb-btn" id="btn-blast">Blast Radius</button>
    <input type="number" id="blast-hops" value="2" min="1" max="6" title="Hops" />
    <button class="tb-btn" id="btn-reset">Reset View</button>
</div>

<svg id="graph-canvas"></svg>

<div id="detail-panel">
    <button class="close-btn" id="close-panel">✕</button>
    <h2 id="dp-title">—</h2>
    <div id="dp-body"></div>
</div>

<div id="legend"></div>
<div id="stats-bar"></div>

<script>
// ── Data ──────────────────────────────────────────────────────────
const NODES = {nodes_json};
const EDGES = {edges_json};
const DEGREES = {degree_json};
const TIMESTAMP = {ts};

const TYPE_COLORS = {json.dumps(NODE_COLORS, ensure_ascii=False)};
const DEFAULT_COL = "{DEFAULT_COLOR}";

// ── SVG setup ─────────────────────────────────────────────────────
const W = window.innerWidth, H = window.innerHeight;
const svg = d3.select("#graph-canvas").attr("width", W).attr("height", H);

const g = svg.append("g");
const zoom = d3.zoom().scaleExtent([0.1, 8]).on("zoom", (e) => g.attr("transform", e.transform));
svg.call(zoom);

// Arrow marker
svg.append("defs").append("marker")
    .attr("id", "arrowhead").attr("viewBox", "0 -5 10 10")
    .attr("refX", 20).attr("refY", 0).attr("markerWidth", 6).attr("markerHeight", 6)
    .attr("orient", "auto").append("path").attr("d", "M0,-5L10,0L0,5").attr("fill", "#334155");

// ── Build simulation data ─────────────────────────────────────────
const nodeMap = {{}};
NODES.forEach(n => {{ nodeMap[n.id] = n; }});

const simNodes = NODES.map(n => ({{
    ...n,
    x: W/2 + (Math.random()-0.5)*300,
    y: H/2 + (Math.random()-0.5)*300,
}}));

const simEdges = EDGES.map(e => ({{
    source: e.source,
    target: e.target,
    edge_type: e.edge_type,
    description: e.description || "",
}}));

// ── Draw edges ─────────────────────────────────────────────────────
const link = g.append("g").selectAll("line")
    .data(simEdges).join("line")
    .attr("stroke", "#334155").attr("stroke-width", 1.2)
    .attr("stroke-opacity", 0.5).attr("marker-end", "url(#arrowhead)");

const edgeLabels = g.append("g").selectAll("text")
    .data(simEdges).join("text")
    .attr("class", "edge-label")
    .text(d => d.edge_type.replace(/_/g,' '));

// ── Draw nodes ─────────────────────────────────────────────────────
const node = g.append("g").selectAll("circle")
    .data(simNodes).join("circle")
    .attr("r", d => Math.max(6, Math.min(24, 4 + (DEGREES[d.id]||0)*2)))
    .attr("fill", d => TYPE_COLORS[d.node_type] || DEFAULT_COL)
    .attr("stroke", "#1e293b").attr("stroke-width", 1.5)
    .attr("cursor", "pointer")
    .on("click", (ev, d) => showNodeDetail(d))
    .on("dblclick", (ev, d) => {{ ev.stopPropagation(); triggerBlast(d.id); }});

const nodeLabels = g.append("g").selectAll("text")
    .data(simNodes).join("text")
    .attr("text-anchor", "middle").attr("dy", -10)
    .attr("fill", "#94a3b8").attr("font-size", 9)
    .attr("pointer-events", "none")
    .text(d => d.label.length > 28 ? d.label.slice(0,26)+"…" : d.label);

// ── Force simulation ───────────────────────────────────────────────
const sim = d3.forceSimulation(simNodes)
    .force("link", d3.forceLink(simEdges).id(d => d.id).distance(120))
    .force("charge", d3.forceManyBody().strength(-400))
    .force("center", d3.forceCenter(W/2, H/2))
    .force("collision", d3.forceCollide().radius(d => Math.max(6, Math.min(24, 4+(DEGREES[d.id]||0)*2))+4))
    .on("tick", () => {{
        link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
        edgeLabels.attr("x", d => (d.source.x+d.target.x)/2)
                  .attr("y", d => (d.source.y+d.target.y)/2);
        node.attr("cx", d => d.x).attr("cy", d => d.y);
        nodeLabels.attr("x", d => d.x).attr("y", d => d.y);
    }});

// ── Edge click ─────────────────────────────────────────────────────
link.on("click", (ev, d) => {{
    ev.stopPropagation();
    showEdgeDetail(d);
}});

// ── Detail panel ───────────────────────────────────────────────────
const panel = document.getElementById("detail-panel");
const dpTitle = document.getElementById("dp-title");
const dpBody = document.getElementById("dp-body");

document.getElementById("close-panel").onclick = () => panel.classList.remove("open");

function showNodeDetail(d) {{
    const nd = nodeMap[d.id] || {{}};
    const color = TYPE_COLORS[nd.node_type] || DEFAULT_COL;
    dpTitle.textContent = nd.label || d.id;
    let html = `<span class="type-badge" style="background:${{color}}22;color:${{color}};border:1px solid ${{color}}44">${{nd.node_type||"unknown"}}</span>`;
    if (nd.severity && nd.severity !== "" && nd.severity !== "info") {{
        html += ` <span class="severity-tag sev-${{nd.severity}}">${{nd.severity.toUpperCase()}}</span>`;
    }}
    html += `<div class="field"><div class="field-label">Node ID</div><div class="field-value">${{d.id}}</div></div>`;
    if (nd.description) {{
        html += `<div class="field"><div class="field-label">Description</div><div class="field-value">${{escHtml(nd.description)}}</div></div>`;
    }}
    if (nd.cves && nd.cves.length) {{
        html += `<div class="field"><div class="field-label">CVEs</div><ul class="cve-list">`;
        nd.cves.forEach(c => {{ html += `<li>${{escHtml(c)}}</li>`; }});
        html += `</ul></div>`;
    }}
    if (nd.remediation) {{
        html += `<div class="field"><div class="field-label">Remediation</div><div class="remediation">${{escHtml(nd.remediation)}}</div></div>`;
    }}
    const conns = DEGREES[d.id] || 0;
    html += `<div class="field"><div class="field-label">Connections</div><div class="field-value">${{conns}}</div></div>`;
    dpBody.innerHTML = html;
    panel.classList.add("open");
}}

function showEdgeDetail(d) {{
    dpTitle.textContent = d.edge_type.replace(/_/g, ' ');
    let html = `<div class="field"><div class="field-label">Source</div><div class="field-value">${{escHtml(d.source)}}</div></div>`;
    html += `<div class="field"><div class="field-label">Target</div><div class="field-value">${{escHtml(d.target)}}</div></div>`;
    html += `<div class="field"><div class="field-label">Relationship</div><div class="field-value">${{escHtml(d.edge_type)}}</div></div>`;
    if (d.description) {{
        html += `<div class="field"><div class="field-label">Description</div><div class="field-value">${{escHtml(d.description)}}</div></div>`;
    }}
    dpBody.innerHTML = html;
    panel.classList.add("open");
}}

function escHtml(s) {{
    const d = document.createElement("div"); d.textContent = s; return d.innerHTML;
}}

// ── Search ─────────────────────────────────────────────────────────
const searchInput = document.getElementById("search-input");
let searchTimeout = null;
searchInput.addEventListener("input", () => {{
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(applySearch, 200);
}});

document.getElementById("btn-clear").onclick = () => {{
    searchInput.value = "";
    resetHighlights();
}};

function applySearch() {{
    const q = searchInput.value.trim().toLowerCase();
    if (!q) {{ resetHighlights(); return; }}
    const matchedIds = new Set();
    NODES.forEach(n => {{
        if (n.label.toLowerCase().includes(q)
            || n.node_type.toLowerCase().includes(q)
            || (n.severity && n.severity.toLowerCase().includes(q))
            || n.id.toLowerCase().includes(q)) {{
            matchedIds.add(n.id);
        }}
    }});
    node.classed("dimmed", d => !matchedIds.has(d.id));
    link.classed("dimmed", d => !matchedIds.has(d.source.id || d.source) && !matchedIds.has(d.target.id || d.target));
    nodeLabels.classed("dimmed", d => !matchedIds.has(d.id));
    edgeLabels.classed("dimmed", d => !matchedIds.has(d.source.id || d.source) && !matchedIds.has(d.target.id || d.target));
}}

// ── Path finder ────────────────────────────────────────────────────
const pathFrom = document.getElementById("path-select");
const pathTo = document.getElementById("path-to");

NODES.forEach(n => {{
    const lbl = n.label.length > 40 ? n.label.slice(0,38)+"…" : n.label;
    pathFrom.innerHTML += `<option value="${{n.id}}">${{escHtml(lbl)}}</option>`;
    pathTo.innerHTML += `<option value="${{n.id}}">${{escHtml(lbl)}}</option>`;
}});

document.getElementById("btn-path").onclick = () => {{
    const src = pathFrom.value, tgt = pathTo.value;
    if (!src || !tgt) return;
    resetHighlights();
    const path = bfsPath(src, tgt);
    if (!path) {{ dpTitle.textContent = "No Path Found"; dpBody.innerHTML = "<p style=\"color:#ef4444\">No path between the selected nodes.</p>"; panel.classList.add("open"); return; }}
    const pathSet = new Set(path);
    node.classed("path-node", d => pathSet.has(d.id));
    node.classed("dimmed", d => !pathSet.has(d.id));
    link.classed("path-edge", d => {{
        const sId = d.source.id || d.source, tId = d.target.id || d.target;
        for (let i = 0; i < path.length-1; i++) {{
            if (path[i]===sId && path[i+1]===tId) return true;
        }}
        return false;
    }});
    link.classed("dimmed", d => !d.classList || !d.classList.contains("path-edge"));
    nodeLabels.classed("dimmed", d => !pathSet.has(d.id));
    edgeLabels.classed("dimmed", true);

    let html = "<div class=\"field\"><div class=\"field-label\">Path Length</div><div class=\"field-value\">" + (path.length-1) + " hops</div></div>";
    html += "<div class=\"field\"><div class=\"field-label\">Route</div><div class=\"field-value\">";
    path.forEach((id, i) => {{
        const nd = nodeMap[id] || {{}};
        html += escHtml(nd.label || id);
        if (i < path.length-1) html += " → ";
    }});
    html += "</div></div>";
    dpTitle.textContent = "Shortest Path";
    dpBody.innerHTML = html;
    panel.classList.add("open");
}};

function bfsPath(src, tgt) {{
    const adj = {{}};
    simEdges.forEach(e => {{
        const sId = e.source.id || e.source, tId = e.target.id || e.target;
        if (!adj[sId]) adj[sId] = [];
        if (!adj[tId]) adj[tId] = [];
        adj[sId].push(tId);
        adj[tId].push(sId);
    }});
    const visited = new Set([src]);
    const queue = [[src]];
    while (queue.length) {{
        const path = queue.shift();
        const cur = path[path.length-1];
        if (cur === tgt) return path;
        (adj[cur]||[]).forEach(nb => {{
            if (!visited.has(nb)) {{ visited.add(nb); queue.push([...path, nb]); }}
        }});
    }}
    return null;
}}

// ── Blast radius ───────────────────────────────────────────────────
document.getElementById("btn-blast").onclick = () => {{
    const sel = document.querySelector('.highlight-node, .path-node');
    if (!sel) return;
    const nid = sel.__data__ ? sel.__data__.id : null;
    if (!nid) return;
    triggerBlast(nid);
}};

function triggerBlast(startId) {{
    resetHighlights();
    const hops = parseInt(document.getElementById("blast-hops").value) || 2;
    const visited = new Set([startId]);
    let frontier = [startId];
    for (let h = 0; h < hops; h++) {{
        const next = [];
        frontier.forEach(nid => {{
            simEdges.forEach(e => {{
                const sId = e.source.id || e.source, tId = e.target.id || e.target;
                if (sId === nid && !visited.has(tId)) {{ visited.add(tId); next.push(tId); }}
                if (tId === nid && !visited.has(sId)) {{ visited.add(sId); next.push(sId); }}
            }});
        }});
        frontier = next;
    }}
    node.classed("highlight-node", d => visited.has(d.id));
    node.classed("dimmed", d => !visited.has(d.id));
    link.classed("highlight-edge", d => {{
        const sId = d.source.id || d.source, tId = d.target.id || d.target;
        return visited.has(sId) && visited.has(tId);
    }});
    link.classed("dimmed", d => !d.classList || !d.classList.contains("highlight-edge"));
    nodeLabels.classed("dimmed", d => !visited.has(d.id));
    edgeLabels.classed("dimmed", d => {{
        const sId = d.source.id || d.source, tId = d.target.id || d.target;
        return !(visited.has(sId) && visited.has(tId));
    }});
}}

// ── Reset ──────────────────────────────────────────────────────────
function resetHighlights() {{
    node.classed("highlight-node", false).classed("path-node", false).classed("dimmed", false);
    link.classed("highlight-edge", false).classed("path-edge", false).classed("dimmed", false);
    nodeLabels.classed("dimmed", false);
    edgeLabels.classed("dimmed", false);
}}

document.getElementById("btn-reset").onclick = () => {{
    resetHighlights();
    searchInput.value = "";
    pathFrom.value = "";
    pathTo.value = "";
    panel.classList.remove("open");
    svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
}};

// ── Click background to deselect ───────────────────────────────────
svg.on("click", () => {{ panel.classList.remove("open"); }});

// ── Legend ──────────────────────────────────────────────────────────
const legendEl = document.getElementById("legend");
const typeCounts = {{}};
NODES.forEach(n => {{ typeCounts[n.node_type] = (typeCounts[n.node_type]||0)+1; }});
let legendHtml = "<h4>Node Types</h4>";
Object.entries(typeCounts).sort((a,b) => b[1]-a[1]).forEach(([t, c]) => {{
    legendHtml += `<div class="legend-item"><span class="legend-dot" style="background:${{TYPE_COLORS[t]||DEFAULT_COL}}"></span>${{t}} ({{c}})</div>`;
}});
legendEl.innerHTML = legendHtml;

// ── Stats bar ───────────────────────────────────────────────────────
document.getElementById("stats-bar").innerHTML =
    `Nodes: <span>${{NODES.length}}</span> &nbsp; Edges: <span>${{EDGES.length}}</span> &nbsp; Types: <span>${{Object.keys(typeCounts).length}}</span>`;

// ── Resize ─────────────────────────────────────────────────────────
window.addEventListener("resize", () => {{
    svg.attr("width", window.innerWidth).attr("height", window.innerHeight);
    sim.force("center", d3.forceCenter(window.innerWidth/2, window.innerHeight/2));
    sim.alpha(0.3).restart();
}});
</script>
</body>
</html>"""


# Module-level convenience export
render_graph = GraphUIRenderer().render
render_graph_to_file = GraphUIRenderer().render_to_file

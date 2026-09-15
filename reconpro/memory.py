"""
ReconPro v7.5 — Unified Memory Store

Single source of truth for all ReconPro state.  Replaces and enhances
``knowledge_graph.py`` as the primary interface.  Wraps the existing
``SecurityKnowledgeGraph`` and adds three new sub-systems:

1. **FindingStore**  – time-series findings indexed by target (JSON on disk)
2. **AgentBlackboard** – session-scoped shared state for swarm/adversarial runs
3. **CredentialVault** – obfuscated storage for discovered credentials

Zero external dependencies beyond what ``knowledge_graph.py`` already
pulls in (networkx is optional).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .knowledge_graph import (
    EDGE_TYPES,
    NODE_TYPES,
    SEVERITY_ORDER,
    SecurityKnowledgeGraph as KnowledgeGraph,
    DEFAULT_GRAPH_DIR,
)

# ─── Storage paths ────────────────────────────────────────────────────

MEMORY_DIR: Path = Path.home() / ".reconpro" / "memory"
FINDINGS_DIR: Path = MEMORY_DIR / "findings"
VAULT_PATH: Path = MEMORY_DIR / "vault.json"


# ======================================================================
#  UnifiedMemoryStore
# ======================================================================


class UnifiedMemoryStore:
    """Single source of truth for all ReconPro memory.

    Combines four sub-systems behind a thread-safe, unified API:

    * **Knowledge Graph** — delegated to ``SecurityKnowledgeGraph``
    * **Finding Store** — per-target time-series on disk
    * **Agent Blackboard** — in-memory, session-only shared state
    * **Credential Vault** — obfuscated JSON on disk
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # ── a) Knowledge Graph ────────────────────────────────────────
        self._graph = KnowledgeGraph()

        # ── b) Finding Store (in-memory index; flushed to disk) ───────
        self._findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self._findings_loaded: bool = False

        # ── c) Agent Blackboard (session-only, in-memory) ─────────────
        self._blackboard: Dict[str, Dict[str, Any]] = {}

        # ── d) Credential Vault ──────────────────────────────────────
        self._vault: List[Dict[str, str]] = []
        self._vault_loaded: bool = False

    # ==================================================================
    #  a) Knowledge Graph sub-system  (~200 lines)
    # ==================================================================

    def add_target(self, target: str, **attrs: Any) -> None:
        """Add or update a target node in the knowledge graph."""
        with self._lock:
            nid = self._graph._add_indexed_node("target", target, **attrs)

    def add_vulnerability(
        self,
        name: str,
        target: str,
        severity: str = "info",
        **attrs: Any,
    ) -> None:
        """Add a vulnerability/finding node linked to *target*."""
        with self._lock:
            self._graph.add_finding({
                "title": name,
                "target": target,
                "severity": severity,
                **attrs,
            })

    def add_asset(self, label: str, **attrs: Any) -> None:
        """Add an asset node."""
        with self._lock:
            self._graph._add_indexed_node("asset", label, **attrs)

    def add_cve(
        self,
        cve_id: str,
        severity: str = "info",
        description: str = "",
        affected: str = "",
    ) -> None:
        """Add a CVE node (idempotent)."""
        with self._lock:
            self._graph.add_cve(cve_id, severity, description, affected)

    def add_endpoint(
        self,
        path: str,
        target: str,
        method: str = "GET",
        **attrs: Any,
    ) -> None:
        """Add an endpoint node linked to *target*."""
        with self._lock:
            self._graph._add_indexed_node("target", target)
            ep_id = self._graph._add_indexed_node(
                "endpoint",
                f"{target}:{method}:{path}",
                path=path,
                method=method,
                **attrs,
            )
            target_id = self._graph._node_id("target", target)
            self._graph._add_indexed_edge(target_id, ep_id, "exposes")

    def add_technology(self, name: str, **attrs: Any) -> None:
        """Add a technology node."""
        with self._lock:
            self._graph._add_indexed_node("technology", name, **attrs)

    def add_relation(
        self,
        from_node: str,
        to_node: str,
        edge_type: str,
        **attrs: Any,
    ) -> None:
        """Add an edge between two existing or new nodes.

        *from_node* / *to_node* may be full node ids (``type:label``) or
        plain labels.  If a plain label does not match any existing node
        it is created as a generic node.
        """
        with self._lock:
            # Try to resolve to existing nodes
            src = self._graph._resolve_node(from_node)
            if src is None:
                # Use as-is or create a generic node
                if ":" in from_node:
                    src = from_node
                else:
                    src = self._graph._add_indexed_node("asset", from_node)

            dst = self._graph._resolve_node(to_node)
            if dst is None:
                if ":" in to_node:
                    dst = to_node
                else:
                    dst = self._graph._add_indexed_node("asset", to_node)

            if edge_type not in EDGE_TYPES:
                edge_type = "links_to"
            self._graph._add_indexed_edge(src, dst, edge_type, **attrs)

    def get_attack_surface(self, target: str) -> Dict[str, List[Dict[str, Any]]]:
        """Return endpoints, ports, vulnerabilities, and technologies for *target*."""
        with self._lock:
            return self._graph.get_attack_surface(target)

    def get_blast_radius(self, node: str) -> List[Dict[str, Any]]:
        """BFS from *node* to find all connected vulnerabilities/CVEs."""
        with self._lock:
            return self._graph.get_blast_radius(node)

    def find_chains(
        self, source: str, target: Optional[str] = None
    ) -> List[List[Dict[str, Any]]]:
        """Find attack chains originating from *source*.

        If *target* is provided, only chains that reach *target* (or a
        node belonging to *target*) are returned.
        """
        with self._lock:
            all_chains = self._graph.find_chains(source)
            if target is None:
                return all_chains
            target_id = self._graph._resolve_node(target)
            if target_id is None:
                return all_chains
            filtered: List[List[Dict[str, Any]]] = []
            for chain in all_chains:
                if chain and chain[-1].get("node_id") == target_id:
                    filtered.append(chain)
                elif chain and target_id in [
                    step.get("node_id", "") for step in chain
                ]:
                    filtered.append(chain)
            return filtered

    def shortest_path(
        self, source: str, target: str
    ) -> Optional[List[Dict[str, Any]]]:
        """BFS shortest path between *source* and *target* nodes.

        Returns a list of node-data dicts, or ``None`` if no path exists.
        """
        with self._lock:
            src_id = self._graph._resolve_node(source)
            tgt_id = self._graph._resolve_node(target)
            if src_id is None or tgt_id is None:
                return None
            if src_id == tgt_id:
                if src_id in (self._graph._g.nodes() if hasattr(self._graph._g, 'has_node') else []):
                    return []
                return None

            # BFS
            from collections import deque
            visited: Set[str] = set()
            parent: Dict[str, Optional[str]] = {}
            queue: deque = deque()
            queue.append(src_id)
            visited.add(src_id)
            parent[src_id] = None
            found = False
            while queue and not found:
                current = queue.popleft()
                for neighbour in self._graph._g.successors(current):
                    if neighbour not in visited:
                        visited.add(neighbour)
                        parent[neighbour] = current
                        if neighbour == tgt_id:
                            found = True
                            break
                        queue.append(neighbour)

            if not found:
                return None

            # Reconstruct path
            path_ids: List[str] = []
            cur: Optional[str] = tgt_id
            while cur is not None:
                path_ids.append(cur)
                cur = parent.get(cur)
            path_ids.reverse()

            result: List[Dict[str, Any]] = []
            for nid in path_ids:
                try:
                    data = dict(self._graph._g.nodes[nid])
                except Exception:
                    data = self._graph._g.get_node_data(nid)
                result.append(data)

            return result

    def graph_stats(self) -> Dict[str, Any]:
        """Return summary statistics for the knowledge graph."""
        with self._lock:
            return self._graph.stats()

    # Pass-through access to the underlying graph for advanced usage
    @property
    def graph(self) -> KnowledgeGraph:
        """Direct access to the wrapped ``SecurityKnowledgeGraph`` instance."""
        return self._graph

    # ==================================================================
    #  b) FindingStore sub-system  (~150 lines)
    # ==================================================================

    @staticmethod
    def _target_hash(target: str) -> str:
        """Deterministic hash for a target string (used as filename)."""
        return hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]

    def _ensure_findings_loaded(self) -> None:
        """Lazily load all findings from disk on first access."""
        if self._findings_loaded:
            return
        with self._lock:
            if self._findings_loaded:
                return
            self._findings_loaded = True
            if not FINDINGS_DIR.is_dir():
                return
            for fname in FINDINGS_DIR.glob("findings_*.json"):
                try:
                    data = json.loads(fname.read_text("utf-8"))
                    target_key = data.get("_target", "")
                    if target_key:
                        entries = data.get("entries", [])
                        self._findings[target_key] = entries
                except Exception:
                    continue

    def _findings_path(self, target: str) -> Path:
        """Return the JSON file path for *target*'s findings."""
        h = self._target_hash(target)
        return FINDINGS_DIR / f"findings_{h}.json"

    def save_finding(self, target: str, finding_dict: Dict[str, Any]) -> None:
        """Append a finding to *target*'s time-series and persist."""
        with self._lock:
            self._ensure_findings_loaded()
            entry = dict(finding_dict)
            entry.setdefault("_ts", datetime.now(timezone.utc).isoformat())
            entry["_target"] = target
            self._findings[target].append(entry)
            # Flush this target's file
            self._flush_findings_target(target)

    def _flush_findings_target(self, target: str) -> None:
        """Write one target's findings to its JSON file."""
        path = self._findings_path(target)
        FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "_target": target,
            "entries": self._findings[target],
        }
        path.write_text(json.dumps(payload, indent=2, default=str), "utf-8")

    def _flush_all_findings(self) -> None:
        """Write every target's findings to disk."""
        FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
        for target, entries in self._findings.items():
            path = self._findings_path(target)
            payload = {
                "_target": target,
                "entries": entries,
            }
            path.write_text(json.dumps(payload, indent=2, default=str), "utf-8")

    def get_findings(
        self,
        target: str,
        since: Optional[str] = None,
        severity: Optional[str] = None,
        module: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve findings for *target* with optional filters.

        Parameters
        ----------
        target:
            The target hostname / IP to query.
        since:
            ISO-8601 timestamp; only findings after this time are returned.
        severity:
            If set, only findings matching this severity (case-insensitive).
        module:
            If set, only findings whose ``module`` field matches.
        """
        with self._lock:
            self._ensure_findings_loaded()
            entries = list(self._findings.get(target, []))

            if since is not None:
                try:
                    since_dt = datetime.fromisoformat(since)
                except (ValueError, TypeError):
                    since_dt = None
                if since_dt is not None:
                    entries = [
                        e for e in entries
                        if "_ts" in e
                        and datetime.fromisoformat(e["_ts"]) >= since_dt
                    ]

            if severity is not None:
                sev_lower = severity.strip().lower()
                entries = [
                    e for e in entries
                    if str(e.get("severity", "")).strip().lower() == sev_lower
                ]

            if module is not None:
                mod_lower = module.strip().lower()
                entries = [
                    e for e in entries
                    if str(e.get("module", "")).strip().lower() == mod_lower
                ]

            return entries

    def get_latest_findings(
        self, target: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Return the most recent *limit* findings for *target*."""
        with self._lock:
            self._ensure_findings_loaded()
            entries = list(self._findings.get(target, []))
            entries.sort(key=lambda e: e.get("_ts", ""), reverse=True)
            return entries[:limit]

    def finding_count(self, target: str, severity: Optional[str] = None) -> int:
        """Count findings for *target*, optionally filtered by *severity*."""
        with self._lock:
            self._ensure_findings_loaded()
            entries = self._findings.get(target, [])
            if severity is None:
                return len(entries)
            sev_lower = severity.strip().lower()
            return sum(
                1 for e in entries
                if str(e.get("severity", "")).strip().lower() == sev_lower
            )

    def trend(self, target: str, days: int = 30) -> List[Dict[str, Any]]:
        """Daily severity breakdown for *target* over the last *days* days.

        Returns a list of dicts, one per day that has findings::

            [{"date": "2025-01-15", "critical": 0, "high": 1, "medium": 3, "low": 0, "score": 7.0}, ...]
        """
        with self._lock:
            self._ensure_findings_loaded()
            entries = self._findings.get(target, [])

            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(days=days)

            daily: Dict[str, Dict[str, int]] = defaultdict(
                lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            )

            for entry in entries:
                ts = entry.get("_ts", "")
                if not ts:
                    continue
                try:
                    dt = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    continue
                if dt < cutoff:
                    continue
                day_str = dt.strftime("%Y-%m-%d")
                sev = str(entry.get("severity", "info")).strip().lower()
                if sev in daily[day_str]:
                    daily[day_str][sev] += 1
                else:
                    daily[day_str]["info"] += 1

            # Build result sorted by date
            result: List[Dict[str, Any]] = []
            for day in sorted(daily.keys()):
                counts = daily[day]
                score = (
                    counts.get("critical", 0) * 10.0
                    + counts.get("high", 0) * 5.0
                    + counts.get("medium", 0) * 2.0
                    + counts.get("low", 0) * 0.5
                )
                result.append({
                    "date": day,
                    "critical": counts.get("critical", 0),
                    "high": counts.get("high", 0),
                    "medium": counts.get("medium", 0),
                    "low": counts.get("low", 0),
                    "score": round(score, 1),
                })

            # Fill in missing days
            if result:
                start_date = datetime.strptime(result[0]["date"], "%Y-%m-%d").date()
                end_date = now.date()
                filled: List[Dict[str, Any]] = []
                idx = 0
                current = start_date
                while current <= end_date:
                    day_str = current.isoformat()
                    if idx < len(result) and result[idx]["date"] == day_str:
                        filled.append(result[idx])
                        idx += 1
                    else:
                        filled.append({
                            "date": day_str,
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0,
                            "score": 0.0,
                        })
                    current += timedelta(days=1)
                return filled

            return result

    # ==================================================================
    #  c) AgentBlackboard sub-system  (~100 lines)
    # ==================================================================

    def bb_set(
        self,
        key: str,
        value: Any,
        agent_id: str,
        ttl: int = 3600,
    ) -> None:
        """Store *value* on the blackboard with *agent_id* attribution and *ttl*.

        The entry is automatically expired after *ttl* seconds (default 1 hour).
        """
        with self._lock:
            self._blackboard[key] = {
                "value": value,
                "agent_id": agent_id,
                "set_at": time.time(),
                "expires_at": time.time() + ttl,
            }

    def bb_get(self, key: str) -> Optional[Any]:
        """Retrieve a value from the blackboard.

        Returns ``None`` if the key does not exist or has expired.
        """
        with self._lock:
            entry = self._blackboard.get(key)
            if entry is None:
                return None
            if time.time() > entry.get("expires_at", 0):
                del self._blackboard[key]
                return None
            return entry["value"]

    def bb_get_all(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Return all active (non-expired) blackboard entries.

        If *agent_id* is given, only entries from that agent are returned.

        Returns a dict of ``{key: value}``.
        """
        with self._lock:
            now = time.time()
            # Prune expired entries first
            expired_keys = [
                k for k, v in self._blackboard.items()
                if now > v.get("expires_at", 0)
            ]
            for k in expired_keys:
                del self._blackboard[k]

            result: Dict[str, Any] = {}
            for key, entry in self._blackboard.items():
                if agent_id is not None and entry.get("agent_id") != agent_id:
                    continue
                result[key] = entry["value"]
            return result

    def bb_clear(self) -> None:
        """Wipe all blackboard entries."""
        with self._lock:
            self._blackboard.clear()

    # ==================================================================
    #  d) CredentialVault sub-system  (~100 lines)
    # ==================================================================

    @staticmethod
    def _machine_key() -> bytes:
        """Derive a deterministic obfuscation key from machine identity."""
        raw = f"reconpro-vault:{platform.node()}:{platform.system()}"
        return hashlib.sha256(raw.encode("utf-8")).digest()

    @staticmethod
    def _obfuscate(plaintext: str, key: bytes) -> str:
        """XOR + base64 obfuscation (NOT cryptographic encryption)."""
        data = plaintext.encode("utf-8")
        xored = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        return base64.b64encode(xored).decode("ascii")

    @staticmethod
    def _deobfuscate(ciphertext: str, key: bytes) -> str:
        """Reverse the XOR + base64 obfuscation."""
        try:
            xored = base64.b64decode(ciphertext.encode("ascii"))
            key_bytes = key
            data = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(xored))
            return data.decode("utf-8")
        except Exception:
            return ""

    def _ensure_vault_loaded(self) -> None:
        """Lazily load vault from disk on first access."""
        if self._vault_loaded:
            return
        with self._lock:
            if self._vault_loaded:
                return
            self._vault_loaded = True
            if not VAULT_PATH.is_file():
                return
            try:
                raw = json.loads(VAULT_PATH.read_text("utf-8"))
                self._vault = raw if isinstance(raw, list) else []
            except Exception:
                self._vault = []

    def _flush_vault(self) -> None:
        """Persist vault to disk."""
        MEMORY_DIR.mkdir(parents=True, exist_ok=True)
        VAULT_PATH.write_text(
            json.dumps(self._vault, indent=2, default=str), "utf-8"
        )

    def vault_store(
        self,
        source: str,
        username: str,
        password: str,
        url: Optional[str] = None,
        notes: str = "",
    ) -> None:
        """Store a credential in the vault.

        Passwords are obfuscated with a machine-specific key before storage.
        """
        with self._lock:
            self._ensure_vault_loaded()
            key = self._machine_key()
            entry: Dict[str, str] = {
                "source": source,
                "username": username,
                "password": self._obfuscate(password, key),
                "_ts": datetime.now(timezone.utc).isoformat(),
            }
            if url is not None:
                entry["url"] = url
            if notes:
                entry["notes"] = notes
            self._vault.append(entry)
            self._flush_vault()

    def vault_get_all(self, source: Optional[str] = None) -> List[Dict[str, str]]:
        """Retrieve all credentials, optionally filtered by *source*.

        Passwords are deobfuscated before returning.
        """
        with self._lock:
            self._ensure_vault_loaded()
            key = self._machine_key()
            results: List[Dict[str, str]] = []
            for entry in self._vault:
                if source is not None and entry.get("source") != source:
                    continue
                decrypted = dict(entry)
                decrypted["password"] = self._deobfuscate(
                    entry.get("password", ""), key
                )
                decrypted.pop("_ts", None)
                results.append(decrypted)
            return results

    def vault_search(self, query: str) -> List[Dict[str, str]]:
        """Search credentials by *query* (matches username, url, notes, source).

        Case-insensitive substring match.
        """
        with self._lock:
            self._ensure_vault_loaded()
            key = self._machine_key()
            q_lower = query.lower()
            results: List[Dict[str, str]] = []
            for entry in self._vault:
                searchable = " ".join([
                    entry.get("source", ""),
                    entry.get("username", ""),
                    entry.get("url", ""),
                    entry.get("notes", ""),
                ]).lower()
                if q_lower in searchable:
                    decrypted = dict(entry)
                    decrypted["password"] = self._deobfuscate(
                        entry.get("password", ""), key
                    )
                    decrypted.pop("_ts", None)
                    results.append(decrypted)
            return results

    def vault_purge(self) -> None:
        """Securely clear all credentials from memory and disk."""
        with self._lock:
            # Overwrite in-memory data
            for entry in self._vault:
                for k in list(entry.keys()):
                    entry[k] = "\x00" * len(str(entry[k]))
            self._vault.clear()
            self._vault_loaded = True

            # Remove or overwrite file
            if VAULT_PATH.is_file():
                try:
                    size = VAULT_PATH.stat().st_size
                    VAULT_PATH.write_bytes(b"\x00" * size)
                    VAULT_PATH.unlink()
                except Exception:
                    pass

    # ==================================================================
    #  e) Integration methods  (~50 lines)
    # ==================================================================

    def add_scan_result(self, scan_dict: Dict[str, Any]) -> None:
        """Ingest a full scan result dict.

        Populates both the knowledge graph and the finding store.

        Expected keys (all optional)::
            target, host, subdomains, ports, technologies,
            findings, certificates, endpoints, module, scan_time
        """
        with self._lock:
            # ── Feed the knowledge graph ──
            self._graph.add_scan_result(scan_dict)

            # ── Feed the finding store ──
            target = scan_dict.get("target") or scan_dict.get("host", "unknown")
            module = scan_dict.get("module", "")
            scan_time = scan_dict.get("scan_time", "")

            for finding in scan_dict.get("findings", []):
                entry = dict(finding)
                entry["_target"] = target
                if module:
                    entry["module"] = module
                if scan_time and "_ts" not in entry:
                    entry["_ts"] = scan_time
                self._findings[target].append(entry)

            # Also record a summary entry for the scan itself
            summary: Dict[str, Any] = {
                "_target": target,
                "title": f"Scan completed: {module or 'general'}",
                "severity": "info",
                "module": module,
                "finding_count": len(scan_dict.get("findings", [])),
                "port_count": len(scan_dict.get("ports", [])),
                "tech_count": len(scan_dict.get("technologies", [])),
            }
            if scan_time:
                summary["_ts"] = scan_time
            self._findings[target].append(summary)

            # Flush findings for this target
            self._flush_findings_target(target)

    def export_all(self) -> Dict[str, Any]:
        """Export everything for backup.

        Returns a dict with keys ``graph``, ``findings``, ``vault``.
        """
        with self._lock:
            # Graph
            try:
                graph_data = self._graph.save()
                with open(graph_data, "r") as fh:
                    graph_json = json.load(fh)
            except Exception:
                graph_json = {}

            # Findings
            self._ensure_findings_loaded()
            findings_data = {
                target: list(entries)
                for target, entries in self._findings.items()
            }

            # Vault (export obfuscated — caller can deobfuscate if needed)
            self._ensure_vault_loaded()
            vault_data = list(self._vault)

            return {
                "graph": graph_json,
                "findings": findings_data,
                "vault": vault_data,
                "exported_at": datetime.now(timezone.utc).isoformat(),
            }

    def clear_all(self) -> None:
        """Wipe all memory: graph, findings, blackboard, and vault."""
        with self._lock:
            # Graph
            self._graph = KnowledgeGraph()

            # Findings
            self._findings.clear()
            self._findings_loaded = True
            if FINDINGS_DIR.is_dir():
                for f in FINDINGS_DIR.glob("findings_*.json"):
                    try:
                        f.unlink()
                    except Exception:
                        pass

            # Blackboard
            self._blackboard.clear()

            # Vault
            self.vault_purge()

    def save(self) -> None:
        """Persist graph + findings + vault to disk."""
        with self._lock:
            # Graph
            try:
                self._graph.save()
            except Exception:
                pass

            # Findings
            self._flush_all_findings()

            # Vault
            if self._vault:
                self._flush_vault()

    def load(self) -> None:
        """Restore graph + findings + vault from disk."""
        with self._lock:
            # Graph
            try:
                self._graph.load()
            except Exception:
                pass

            # Findings
            self._findings_loaded = False
            self._ensure_findings_loaded()

            # Vault
            self._vault_loaded = False
            self._ensure_vault_loaded()

    # ==================================================================
    #  Convenience / stats
    # ==================================================================

    # DEAD CODE: consider removal
    def stats(self) -> Dict[str, Any]:
        """Return a unified stats dict across all sub-systems."""
        with self._lock:
            self._ensure_findings_loaded()
            self._ensure_vault_loaded()

            total_findings = sum(len(v) for v in self._findings.values())
            target_count = len(self._findings)

            # Severity breakdown from findings
            sev_counts: Dict[str, int] = defaultdict(int)
            for entries in self._findings.values():
                for e in entries:
                    s = str(e.get("severity", "info")).strip().lower()
                    sev_counts[s] += 1

            return {
                "graph": self._graph.stats(),
                "findings": {
                    "total_findings": total_findings,
                    "targets_tracked": target_count,
                    "severity_distribution": dict(sev_counts),
                },
                "blackboard": {
                    "active_entries": len(self._blackboard),
                },
                "vault": {
                    "total_credentials": len(self._vault),
                },
            }


# ======================================================================
#  Module-level singleton
# ======================================================================

_MEMORY_INSTANCE: Optional[UnifiedMemoryStore] = None
_MEMORY_LOCK = threading.Lock()


# DEAD CODE: consider removal
def get_memory() -> UnifiedMemoryStore:
    """Return the module-level ``UnifiedMemoryStore`` singleton.

    Thread-safe: only one instance is ever created per process.
    """
    global _MEMORY_INSTANCE
    if _MEMORY_INSTANCE is None:
        with _MEMORY_LOCK:
            if _MEMORY_INSTANCE is None:
                _MEMORY_INSTANCE = UnifiedMemoryStore()
    return _MEMORY_INSTANCE

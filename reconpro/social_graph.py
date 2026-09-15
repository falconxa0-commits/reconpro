"""
ReconPro v9.2.0 - OSINT Social Graph Intelligence Engine

Extracts and maps relationships from reconnaissance data, building a graph of
entities (domains, IPs, organizations, emails, etc.) and the connections
between them. Pure Python stdlib — zero external dependencies.

Classes:
    Entity           - A node in the social graph (domain, IP, org, etc.)
    Relationship     - A directed edge between two entities
    RelationshipExtractor - Pulls entities/relationships from DNS, WHOIS, HTTP, crt.sh
    SocialGraph      - In-memory graph with analysis algorithms
    GraphIntelligence - Top-level orchestrator that builds a full graph for a target
"""
from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Valid entity types recognised by the graph
VALID_ENTITY_TYPES = {
    "domain", "ip", "org", "email", "person", "asn", "certificate", "service",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Entity:
    """A node in the social graph.

    Attributes:
        entity_id:    Unique identifier (e.g. the domain name, IP address, or email).
        entity_type:  One of VALID_ENTITY_TYPES.
        name:         Human-readable display name.
        properties:   Arbitrary key-value metadata.
    """
    entity_id: str
    entity_type: str
    name: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.entity_type not in VALID_ENTITY_TYPES:
            raise ValueError(
                f"Invalid entity_type {self.entity_type!r}. "
                f"Must be one of {sorted(VALID_ENTITY_TYPES)}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "name": self.name,
            "properties": self.properties,
        }


@dataclass
class Relationship:
    """A directed edge between two entities.

    Attributes:
        source:           entity_id of the source node.
        target:           entity_id of the target node.
        relationship_type: Semantic label (e.g. 'resolves_to', 'managed_by').
        confidence:       0.0 – 1.0 confidence score.
        evidence:         Free-text justification.
        timestamp:        ISO-8601 timestamp of when the relationship was discovered.
    """
    source: str
    target: str
    relationship_type: str
    confidence: float
    evidence: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relationship_type": self.relationship_type,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# RelationshipExtractor
# ---------------------------------------------------------------------------

class RelationshipExtractor:
    """Passively extracts Entity/Relationship pairs from various OSINT sources.

    Each ``extract_from_*`` method returns ``(entities, relationships)`` where
    *entities* is a list of :class:`Entity` and *relationships* is a list of
    :class:`Relationship`.
    """

    DNS_TIMEOUT: float = 5.0
    WHOIS_TIMEOUT: int = 10
    HTTP_TIMEOUT: int = 8
    CRTSH_TIMEOUT: int = 15

    # -- DNS ---------------------------------------------------------------

    def extract_from_dns(self, target: str) -> Tuple[List[Entity], List[Relationship]]:
        """Resolve *target* via DNS and create entities/relationships.

        Attempts A, AAAA, MX, NS, TXT, and CNAME lookups.
        """
        entities: List[Entity] = []
        relationships: List[Relationship] = []
        ts = datetime.now(timezone.utc).isoformat()

        # Determine if target looks like an IP or domain
        is_ip = self._looks_like_ip(target)

        # A records
        try:
            addrs = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
            seen: Set[str] = set()
            for family, _stype, _proto, _canonname, sockaddr in addrs:
                ip = sockaddr[0]
                if ip in seen:
                    continue
                seen.add(ip)
                entities.append(Entity(entity_id=ip, entity_type="ip", name=ip))
                rel_type = "binds_to" if is_ip else "resolves_to"
                relationships.append(
                    Relationship(
                        source=target, target=ip, relationship_type=rel_type,
                        confidence=0.95,
                        evidence=f"DNS A record: {target} -> {ip}",
                        timestamp=ts,
                    )
                )
        except (socket.gaierror, OSError) as exc:
            logger.debug("DNS A lookup failed for %s: %s", target, exc)

        # AAAA records
        try:
            addrs6 = socket.getaddrinfo(target, None, socket.AF_INET6, socket.SOCK_STREAM)
            seen6: Set[str] = set()
            for family, _stype, _proto, _canonname, sockaddr in addrs6:
                ip6 = sockaddr[0]
                if ip6 in seen6:
                    continue
                seen6.add(ip6)
                entities.append(Entity(entity_id=ip6, entity_type="ip", name=ip6))
                relationships.append(
                    Relationship(
                        source=target, target=ip6, relationship_type="resolves_to",
                        confidence=0.95,
                        evidence=f"DNS AAAA record: {target} -> {ip6}",
                        timestamp=ts,
                    )
                )
        except (socket.gaierror, OSError) as exc:
            logger.debug("DNS AAAA lookup failed for %s: %s", target, exc)

        # Try MX, NS, CNAME, TXT via dig subprocess (if available)
        for rtype in ("MX", "NS", "CNAME", "TXT"):
            try:
                result = subprocess.run(
                    ["dig", "+short", target, rtype],
                    capture_output=True, text=True, timeout=self.DNS_TIMEOUT,
                )
                for line in result.stdout.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    value = line.rstrip(".")
                    if rtype == "MX":
                        # Format: priority mailserver
                        parts = value.split()
                        if len(parts) >= 2:
                            mailserver = parts[1].rstrip(".")
                            entities.append(
                                Entity(entity_id=mailserver, entity_type="domain",
                                       name=mailserver, properties={"record_type": "MX"})
                            )
                            relationships.append(
                                Relationship(
                                    source=target, target=mailserver,
                                    relationship_type="mx_record",
                                    confidence=0.9,
                                    evidence=f"DNS MX: {line}", timestamp=ts,
                                )
                            )
                    elif rtype == "NS":
                        entities.append(
                            Entity(entity_id=value, entity_type="service",
                                   name=value, properties={"record_type": "NS"})
                        )
                        relationships.append(
                            Relationship(
                                source=target, target=value,
                                relationship_type="nameserver",
                                confidence=0.9,
                                evidence=f"DNS NS: {value}", timestamp=ts,
                            )
                        )
                    elif rtype == "CNAME":
                        entities.append(
                            Entity(entity_id=value, entity_type="domain",
                                   name=value, properties={"record_type": "CNAME"})
                        )
                        relationships.append(
                            Relationship(
                                source=target, target=value,
                                relationship_type="cname_of",
                                confidence=0.9,
                                evidence=f"DNS CNAME: {target} -> {value}", timestamp=ts,
                            )
                        )
                    elif rtype == "TXT":
                        entities.append(
                            Entity(entity_id=f"txt:{target}", entity_type="service",
                                   name=f"TXT record for {target}",
                                   properties={"value": line, "record_type": "TXT"})
                        )
                        relationships.append(
                            Relationship(
                                source=target, target=f"txt:{target}",
                                relationship_type="has_txt",
                                confidence=0.85,
                                evidence=f"DNS TXT: {line}", timestamp=ts,
                            )
                        )
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
                logger.debug("dig %s %s failed: %s", rtype, target, exc)

        return entities, relationships

    # -- WHOIS -------------------------------------------------------------

    def extract_from_whois(self, target: str) -> Tuple[List[Entity], List[Relationship]]:
        """Parse WHOIS output for org names, emails, and nameservers.

        Falls back to ``whois`` command-line tool.
        """
        entities: List[Entity] = []
        relationships: List[Relationship] = []
        ts = datetime.now(timezone.utc).isoformat()

        raw = self._run_whois(target)
        if not raw:
            return entities, relationships

        # Organisation / registrant
        org_patterns = [
            r"(?i)org(?:anisation|anization)?[\s:]+(.+)",
            r"(?i)registrant[\s_](?:org|organisation)[\s:]+(.+)",
            r"(?i)registrant[\s_](?:name|organization)[\s:]+(.+)",
        ]
        for pat in org_patterns:
            m = re.search(pat, raw)
            if m:
                org_name = m.group(1).strip()
                if org_name and len(org_name) > 2:
                    eid = re.sub(r"\s+", "_", org_name.lower())
                    entities.append(
                        Entity(entity_id=eid, entity_type="org", name=org_name)
                    )
                    relationships.append(
                        Relationship(
                            source=target, target=eid,
                            relationship_type="registered_to",
                            confidence=0.8,
                            evidence=f"WHOIS org field: {org_name}",
                            timestamp=ts,
                        )
                    )
                    break  # take first match

        # Emails
        emails = re.findall(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", raw, re.IGNORECASE)
        seen_emails: Set[str] = set()
        for email in emails:
            if email in seen_emails:
                continue
            seen_emails.add(email)
            entities.append(
                Entity(entity_id=email, entity_type="email", name=email)
            )
            relationships.append(
                Relationship(
                    source=target, target=email,
                    relationship_type="contact_email",
                    confidence=0.75,
                    evidence=f"WHOIS email: {email}",
                    timestamp=ts,
                )
            )

        # Name servers (from WHOIS rather than dig)
        ns_matches = re.findall(r"(?i)name\s*server[:\s]+([\w.-]+)", raw)
        seen_ns: Set[str] = set()
        for ns in ns_matches:
            ns = ns.rstrip(".").lower()
            if ns in seen_ns:
                continue
            seen_ns.add(ns)
            entities.append(
                Entity(entity_id=ns, entity_type="service", name=ns,
                       properties={"record_type": "NS"})
            )
            relationships.append(
                Relationship(
                    source=target, target=ns,
                    relationship_type="nameserver",
                    confidence=0.85,
                    evidence=f"WHOIS NS: {ns}",
                    timestamp=ts,
                )
            )

        # Registrar
        reg_m = re.search(r"(?i)registrar[:\s]+(.+)", raw)
        if reg_m:
            registrar = reg_m.group(1).strip()
            eid = re.sub(r"\s+", "_", registrar.lower())
            entities.append(
                Entity(entity_id=eid, entity_type="org", name=registrar,
                       properties={"role": "registrar"})
            )
            relationships.append(
                Relationship(
                    source=target, target=eid,
                    relationship_type="registered_via",
                    confidence=0.8,
                    evidence=f"WHOIS registrar: {registrar}",
                    timestamp=ts,
                )
            )

        return entities, relationships

    # -- HTTP headers ------------------------------------------------------

    def extract_from_headers(self, base_url: str) -> Tuple[List[Entity], List[Relationship]]:
        """Fetch HTTP headers from *base_url* and derive CDN, proxy, forwarding relationships.
        """
        entities: List[Entity] = []
        relationships: List[Relationship] = []
        ts = datetime.now(timezone.utc).isoformat()

        headers = self._fetch_headers(base_url)
        if headers is None:
            return entities, relationships

        # CDN / hosting detection
        cdn_headers = {
            "cf-ray": "Cloudflare",
            "x-amz-cf-id": "AWS CloudFront",
            "x-fastly-request-id": "Fastly",
            "x-served-by": "Fastly",
            "x-vercel-id": "Vercel",
            "x-netlify-request-id": "Netlify",
            "fly-request-id": "Fly.io",
            "x-edge-ip": "Akamai",
            "x-akamai": "Akamai",
            "x-cdn": "Generic CDN",
        }
        for hdr, provider in cdn_headers.items():
            val = headers.get(hdr)
            if val:
                eid = provider.lower().replace(" ", "_")
                entities.append(
                    Entity(entity_id=eid, entity_type="org", name=provider,
                           properties={"header": hdr, "value": val})
                )
                relationships.append(
                    Relationship(
                        source=base_url, target=eid,
                        relationship_type="cdn_protected_by",
                        confidence=0.85,
                        evidence=f"Header {hdr}: {val}",
                        timestamp=ts,
                    )
                )

        # Server header
        server = headers.get("server", "")
        if server:
            eid = f"server:{server.lower()}"
            entities.append(
                Entity(entity_id=eid, entity_type="service", name=server,
                       properties={"header": "Server"})
            )
            relationships.append(
                Relationship(
                    source=base_url, target=eid,
                    relationship_type="uses_server",
                    confidence=0.9,
                    evidence=f"Server header: {server}",
                    timestamp=ts,
                )
            )

        # X-Forwarded-For / Via (proxy chains)
        proxy_headers = ["x-forwarded-for", "x-forwarded-host", "via", "x-real-ip"]
        for hdr in proxy_headers:
            val = headers.get(hdr)
            if val:
                for proxy_ip in val.split(","):
                    proxy_ip = proxy_ip.strip()
                    if self._looks_like_ip(proxy_ip):
                        entities.append(
                            Entity(entity_id=proxy_ip, entity_type="ip",
                                   name=proxy_ip)
                        )
                        relationships.append(
                            Relationship(
                                source=base_url, target=proxy_ip,
                                relationship_type="forwarded_via",
                                confidence=0.7,
                                evidence=f"{hdr}: {proxy_ip}",
                                timestamp=ts,
                            )
                        )

        # Strict-Transport-Security → HSTS
        if headers.get("strict-transport-security"):
            entities.append(
                Entity(entity_id="hsts_enabled", entity_type="service",
                       name="HSTS Enabled",
                       properties={"value": headers["strict-transport-security"]})
            )
            relationships.append(
                Relationship(
                    source=base_url, target="hsts_enabled",
                    relationship_type="security_header",
                    confidence=0.95,
                    evidence=f"HSTS: {headers['strict-transport-security']}",
                    timestamp=ts,
                )
            )

        # Link header for discovered URLs
        link_hdr = headers.get("link", "")
        if link_hdr:
            for url_match in re.finditer(r"<(https?://[^>]+)", link_hdr):
                disc_url = url_match.group(1)
                entities.append(
                    Entity(entity_id=disc_url, entity_type="domain",
                           name=disc_url)
                )
                relationships.append(
                    Relationship(
                        source=base_url, target=disc_url,
                        relationship_type="linked_resource",
                        confidence=0.8,
                        evidence=f"Link header: {disc_url}",
                        timestamp=ts,
                    )
                )

        return entities, relationships

    # -- crt.sh ------------------------------------------------------------

    def extract_from_crtsh(self, domain: str) -> Tuple[List[Entity], List[Relationship]]:
        """Query crt.sh for certificate transparency logs and co-hosted domains.

        Uses the JSON endpoint: ``https://crt.sh/?q=%.{domain}&output=json``
        """
        entities: List[Entity] = []
        relationships: List[Relationship] = []
        ts = datetime.now(timezone.utc).isoformat()

        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "ReconPro/9.2.0 (OSINT Research)",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=self.CRTSH_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                certs = json.loads(raw)
        except (urllib.error.URLError, json.JSONDecodeError, OSError, TimeoutError) as exc:
            logger.warning("crt.sh query failed for %s: %s", domain, exc)
            return entities, relationships

        if not isinstance(certs, list):
            return entities, relationships

        seen_names: Set[str] = set()
        for cert in certs:
            if not isinstance(cert, dict):
                continue
            # name_value may contain multiple names separated by newlines
            raw_names = cert.get("name_value", "")
            for name in raw_names.split("\n"):
                name = name.strip().lstrip("*.")
                if not name or name in seen_names:
                    continue
                if not self._valid_domain(name):
                    continue
                seen_names.add(name)

                cert_id = str(cert.get("id", ""))
                eid = f"cert:{cert_id}" if cert_id else f"cert:{name}"

                # Certificate entity
                entities.append(
                    Entity(
                        entity_id=eid, entity_type="certificate",
                        name=f"Certificate for {name}",
                        properties={
                            "common_name": name,
                            "issuer": cert.get("issuer_name", ""),
                            "not_before": cert.get("not_before", ""),
                            "not_after": cert.get("not_after", ""),
                            "serial_number": cert.get("serial_number", ""),
                        },
                    )
                )
                relationships.append(
                    Relationship(
                        source=name, target=eid,
                        relationship_type="has_certificate",
                        confidence=0.95,
                        evidence=f"crt.sh certificate #{cert_id} covers {name}",
                        timestamp=ts,
                    )
                )

                # Domain entity (if not the query domain itself)
                if name.lower() != domain.lower():
                    entities.append(
                        Entity(entity_id=name, entity_type="domain", name=name)
                    )
                    relationships.append(
                        Relationship(
                            source=domain, target=name,
                            relationship_type="co_hosted",
                            confidence=0.8,
                            evidence=f"Shared certificate on crt.sh: {cert_id}",
                            timestamp=ts,
                        )
                    )

        return entities, relationships

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _looks_like_ip(s: str) -> bool:
        """Return True if *s* looks like an IPv4 or IPv6 address."""
        parts = s.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                pass
        if ":" in s:
            try:
                socket.inet_pton(socket.AF_INET6, s)
                return True
            except OSError:
                pass
        return False

    @staticmethod
    def _valid_domain(s: str) -> bool:
        """Rough domain-name validation."""
        return bool(re.match(r"^(?:[\w-]+\.)+[a-z]{2,}$", s, re.IGNORECASE))

    @staticmethod
    def _run_whois(target: str, timeout: int = 10) -> Optional[str]:
        """Run the system ``whois`` command and return stdout."""
        try:
            result = subprocess.run(
                ["whois", target],
                capture_output=True, text=True, timeout=timeout,
            )
            return result.stdout or ""
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("whois failed for %s: %s", target, exc)
            return None

    @staticmethod
    def _fetch_headers(base_url: str, timeout: int = 8) -> Optional[Dict[str, str]]:
        """Issue a HEAD request and return a dict of response headers."""
        try:
            req = urllib.request.Request(
                base_url, method="HEAD",
                headers={"User-Agent": "ReconPro/9.2.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return {k.lower(): v for k, v in resp.getheaders()}
        except (urllib.error.URLError, ValueError, OSError, TimeoutError) as exc:
            logger.debug("HTTP HEAD %s failed: %s", base_url, exc)
            return None


# ---------------------------------------------------------------------------
# SocialGraph
# ---------------------------------------------------------------------------

class SocialGraph:
    """In-memory entity-relationship graph with analysis primitives.

    Stores entities in a dict keyed by ``entity_id`` and relationships in a
    flat list.  Provides graph algorithms: clustering, bridge detection, and
    shortest-path (unweighted BFS).
    """

    def __init__(self) -> None:
        self.entities: Dict[str, Entity] = {}
        self.relationships: List[Relationship] = []
        # Adjacency list for fast lookups
        self._adj: Dict[str, List[str]] = defaultdict(list)
        self._rev_adj: Dict[str, List[str]] = defaultdict(list)

    # -- mutation ----------------------------------------------------------

    def add_entity(self, entity: Entity) -> None:
        """Insert an entity; silently skip duplicates."""
        if entity.entity_id not in self.entities:
            self.entities[entity.entity_id] = entity

    def add_relationship(self, rel: Relationship) -> None:
        """Insert a relationship and update adjacency lists."""
        self.relationships.append(rel)
        self._adj[rel.source].append(rel.target)
        self._rev_adj[rel.target].append(rel.source)

    # -- queries -----------------------------------------------------------

    def get_neighbors(self, entity_id: str, direction: str = "both") -> List[str]:
        """Return neighbour entity IDs.

        Args:
            entity_id: The node to query.
            direction:  ``'out'`` (follows source→target), ``'in'`` (reverse),
                        or ``'both'`` (default).
        """
        neighbours: List[str] = []
        if direction in ("out", "both"):
            neighbours.extend(self._adj.get(entity_id, []))
        if direction in ("in", "both"):
            neighbours.extend(self._rev_adj.get(entity_id, []))
        return list(dict.fromkeys(neighbours))  # deduplicate, preserve order

    def get_relationships(self, source: Optional[str] = None,
                          target: Optional[str] = None) -> List[Relationship]:
        """Filter relationships by source and/or target."""
        results: List[Relationship] = []
        for rel in self.relationships:
            if source and rel.source != source:
                continue
            if target and rel.target != target:
                continue
            results.append(rel)
        return results

    def find_entities_by_type(self, entity_type: str) -> List[Entity]:
        """Return all entities of a given type."""
        return [
            e for e in self.entities.values() if e.entity_type == entity_type
        ]

    # -- algorithms --------------------------------------------------------

    def find_clusters(self) -> List[Set[str]]:
        """Compute connected components using BFS.

        Returns a list of sets, each set being the entity IDs in one cluster.
        """
        visited: Set[str] = set()
        all_nodes = set(self._adj.keys()) | set(self._rev_adj.keys())
        # Also include isolated entity IDs
        all_nodes.update(self.entities.keys())

        clusters: List[Set[str]] = []
        for node in all_nodes:
            if node in visited:
                continue
            cluster: Set[str] = set()
            queue = deque([node])
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                cluster.add(current)
                for neighbour in self._adj.get(current, []):
                    if neighbour not in visited:
                        queue.append(neighbour)
                for neighbour in self._rev_adj.get(current, []):
                    if neighbour not in visited:
                        queue.append(neighbour)
            clusters.append(cluster)
        return clusters

    def find_bridge_entities(self) -> List[str]:
        """Identify nodes that connect otherwise-disconnected clusters.

        A bridge entity is any node whose removal would increase the number
        of connected components.  We use a simple articulation-point check
        (Tarjan-style DFS) on the undirected view of the graph.
        """
        # Build undirected adjacency
        undirected: Dict[str, Set[str]] = defaultdict(set)
        for rel in self.relationships:
            undirected[rel.source].add(rel.target)
            undirected[rel.target].add(rel.source)
        # Add isolated nodes
        for eid in self.entities:
            if eid not in undirected:
                undirected[eid]  # ensure key exists

        bridges: List[str] = []
        disc: Dict[str, int] = {}
        low: Dict[str, int] = {}
        parent: Dict[str, Optional[str]] = {}
        ap: Set[str] = set()
        time_counter = [0]

        def dfs(u: str) -> None:
            children = 0
            disc[u] = low[u] = time_counter[0]
            time_counter[0] += 1
            for v in undirected.get(u, set()):
                if v not in disc:
                    children += 1
                    parent[v] = u
                    dfs(v)
                    low[u] = min(low[u], low[v])
                    # u is an articulation point if:
                    if parent.get(u) is None and children > 1:
                        ap.add(u)
                    if parent.get(u) is not None and low[v] >= disc[u]:
                        ap.add(u)
                elif v != parent.get(u):
                    low[u] = min(low[u], disc[v])

        for node in undirected:
            if node not in disc:
                parent[node] = None
                dfs(node)

        bridges = sorted(ap)
        return bridges

    def shortest_path(self, start: str, end: str) -> Optional[List[str]]:
        """Unweighted BFS shortest path on the undirected graph.

        Returns a list of entity IDs from *start* to *end* (inclusive), or
        ``None`` if no path exists.
        """
        if start == end:
            return [start]

        # Build undirected adjacency for BFS
        undirected: Dict[str, List[str]] = defaultdict(list)
        for rel in self.relationships:
            if rel.target not in undirected[rel.source]:
                undirected[rel.source].append(rel.target)
            if rel.source not in undirected[rel.target]:
                undirected[rel.target].append(rel.source)

        visited: Set[str] = {start}
        prev: Dict[str, Optional[str]] = {start: None}
        queue = deque([start])

        while queue:
            current = queue.popleft()
            for neighbour in undirected.get(current, []):
                if neighbour in visited:
                    continue
                visited.add(neighbour)
                prev[neighbour] = current
                if neighbour == end:
                    # Reconstruct path
                    path: List[str] = []
                    node: Optional[str] = end
                    while node is not None:
                        path.append(node)
                        node = prev[node]
                    path.reverse()
                    return path
                queue.append(neighbour)
        return None

    # -- serialization -----------------------------------------------------

    def export_json(self, indent: int = 2) -> str:
        """Serialize the graph to a JSON string."""
        data = {
            "entities": [e.to_dict() for e in self.entities.values()],
            "relationships": [r.to_dict() for r in self.relationships],
            "stats": self.stats(),
        }
        return json.dumps(data, indent=indent, default=str)

    def stats(self) -> Dict[str, Any]:
        """Return summary statistics about the graph."""
        type_counts: Dict[str, int] = defaultdict(int)
        for e in self.entities.values():
            type_counts[e.entity_type] += 1
        clusters = self.find_clusters()
        bridges = self.find_bridge_entities()
        return {
            "total_entities": len(self.entities),
            "total_relationships": len(self.relationships),
            "entity_type_breakdown": dict(type_counts),
            "clusters": len(clusters),
            "cluster_sizes": [len(c) for c in clusters],
            "bridge_entities": bridges,
            "bridge_count": len(bridges),
        }

    def __repr__(self) -> str:
        return (
            f"SocialGraph(entities={len(self.entities)}, "
            f"relationships={len(self.relationships)})"
        )


# ---------------------------------------------------------------------------
# GraphIntelligence
# ---------------------------------------------------------------------------

class GraphIntelligence:
    """Top-level orchestrator that builds a complete SocialGraph for a target.

    Usage::

        gi = GraphIntelligence()
        graph = gi.build_graph("example.com", "https://example.com")
        print(graph.stats())
        print(graph.export_json())
    """

    def __init__(self) -> None:
        self.extractor = RelationshipExtractor()
        self._results: Dict[str, Any] = {}

    def build_graph(self, target: str, base_url: Optional[str] = None) -> SocialGraph:
        """Build and return a :class:`SocialGraph` for *target*.

        Runs all extraction pipelines in sequence and merges results into a
        single graph.

        Args:
            target:   Domain name or IP address to analyse.
            base_url: Optional URL for HTTP header analysis (e.g.
                      ``"https://example.com"``).
        """
        graph = SocialGraph()

        # Ensure the target itself is an entity
        target_type = "ip" if self.extractor._looks_like_ip(target) else "domain"
        graph.add_entity(Entity(
            entity_id=target, entity_type=target_type, name=target,
            properties={"primary_target": True},
        ))

        # 1) DNS
        logger.info("[SocialGraph] Extracting from DNS for %s", target)
        dns_entities, dns_rels = self.extractor.extract_from_dns(target)
        for e in dns_entities:
            graph.add_entity(e)
        for r in dns_rels:
            graph.add_relationship(r)
        self._results["dns"] = {
            "entities": len(dns_entities), "relationships": len(dns_rels),
        }

        # 2) WHOIS
        logger.info("[SocialGraph] Extracting from WHOIS for %s", target)
        whois_entities, whois_rels = self.extractor.extract_from_whois(target)
        for e in whois_entities:
            graph.add_entity(e)
        for r in whois_rels:
            graph.add_relationship(r)
        self._results["whois"] = {
            "entities": len(whois_entities), "relationships": len(whois_rels),
        }

        # 3) HTTP headers
        if base_url:
            logger.info("[SocialGraph] Extracting from HTTP headers for %s", base_url)
            hdr_entities, hdr_rels = self.extractor.extract_from_headers(base_url)
            for e in hdr_entities:
                graph.add_entity(e)
            for r in hdr_rels:
                graph.add_relationship(r)
            self._results["http_headers"] = {
                "entities": len(hdr_entities), "relationships": len(hdr_rels),
            }

        # 4) crt.sh (only for domains)
        if not self.extractor._looks_like_ip(target):
            logger.info("[SocialGraph] Querying crt.sh for %s", target)
            cert_entities, cert_rels = self.extractor.extract_from_crtsh(target)
            for e in cert_entities:
                graph.add_entity(e)
            for r in cert_rels:
                graph.add_relationship(r)
            self._results["crtsh"] = {
                "entities": len(cert_entities), "relationships": len(cert_rels),
            }

        logger.info("[SocialGraph] Graph built: %s", graph)
        return graph

    def get_extraction_results(self) -> Dict[str, Any]:
        """Return per-pipeline extraction counts from the last run."""
        return self._results

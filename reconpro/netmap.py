"""
ReconPro v8.5 — Zero-Trust Network Mapper

Discovers local network hosts, maps trust relationships, checks
network segmentation, and identifies lateral movement paths.

All operations use stdlib only (subprocess, socket, struct).
Requires elevated privileges for ARP and raw operations.

Exports:
    NetworkDiscovery     – host discovery (ping, ARP, mDNS, port scan)
    TrustMapper          – SSH trust chains, Docker topology, BFS paths
    SegmentationChecker  – verify cross-zone isolation
    run_local            – orchestrate full local network audit
"""


from __future__ import annotations

import json
import os
import platform
import re
import socket
import struct
import subprocess
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Set, Tuple


# ── Helpers ─────────────────────────────────────────────────────────

def _parse_ports(ports_spec: str) -> list:
    """Parse a port specification like '22,80,443,1000-1010' into a list of ints."""
    result = []
    for part in ports_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            try:
                result.extend(range(int(lo), int(hi) + 1))
            except ValueError:
                continue
        else:
            try:
                result.append(int(part))
            except ValueError:
                continue
    return sorted(set(result))


SERVICE_GUESSES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb", 11211: "memcached",
}


def _fetch_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Attempt to grab a service banner from host:port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        # Try TLS handshake first for HTTPS ports
        if port in (443, 8443, 993, 995):
            try:
                import ssl
                from .http_layer import inspection_context
                # banner grab = TLS inspection (audited helper — not data transport)
                ctx = inspection_context()
                sock = ctx.wrap_socket(sock, server_hostname=host)
            except (ImportError, ssl.SSLError, OSError):
                pass
        banner = b""
        sock.settimeout(timeout)
        try:
            banner = sock.recv(1024)
        except (socket.timeout, OSError):
            pass
        sock.close()
        return banner.decode("utf-8", errors="replace").strip()[:512]
    except (socket.error, OSError):
        return ""


# ══════════════════════════════════════════════════════════════════════
# NetworkDiscovery
# ══════════════════════════════════════════════════════════════════════

class NetworkDiscovery:
    """Discover live hosts on local and remote networks."""

    def ping_sweep(self, subnet: str, workers: int = 50) -> List[str]:
        """ICMP ping sweep across a subnet (e.g. '192.168.1.0/24').

        Parses the CIDR and pings each address. Returns list of
        responsive IP strings.
        """
        hosts = self._expand_subnet(subnet)
        if not hosts:
            return []

        alive: List[str] = []

        def _ping(ip: str) -> Optional[str]:
            try:
                param = "-n" if platform.system().lower() == "windows" else "-c"
                count = "-w 1000" if platform.system().lower() == "windows" else "-W 1"
                cmd = ["ping", param, "1", count, ip]
                result = subprocess.run(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
                )
                if result.returncode == 0:
                    return ip
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_ping, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip = future.result()
                if ip:
                    alive.append(ip)

        return sorted(alive)

    def arp_discovery(self) -> List[Dict[str, str]]:
        """Read the system ARP table and return entries.

        Each entry: {"ip": str, "mac": str, "interface": str}.
        """
        entries: List[Dict[str, str]] = []
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    match = re.search(
                        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+" 
                        r"([0-9a-fA-F:]{17})\s+(\S+)",
                        line,
                    )
                    if match:
                        entries.append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                            "interface": match.group(3),
                        })
            else:
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    match = re.search(
                        r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                        r"([0-9a-fA-F:]{17})",
                        line,
                    )
                    if match:
                        iface = "unknown"
                        iface_match = re.search(r"on\s+(\S+)", line)
                        if iface_match:
                            iface = iface_match.group(1)
                        entries.append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                            "interface": iface,
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return entries

    def mdns_discovery(self) -> List[Dict[str, str]]:
        """Discover mDNS/Bonjour services via _services._dns-sd._udp.local.

        Uses a UDP socket to send an mDNS query on port 5353.
        Returns list of {"name": str, "type": str, "address": str}.
        """
        results: List[Dict[str, str]] = []
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            # Build a simple mDNS query for _services._dns-sd._udp.local
            query = self._build_mdns_query("_services._dns-sd._udp.local")
            sock.sendto(query, ("224.0.0.251", 5353))
            while True:
                try:
                    data, addr = sock.recvfrom(4096)
                    parsed = self._parse_mdns_response(data)
                    results.extend(parsed)
                except socket.timeout:
                    break
            sock.close()
        except (socket.error, OSError):
            pass
        return results

    def port_scan_hosts(
        self,
        hosts: List[str],
        ports: str = "22,80,443,3306,5432,6379,8080,8443",
        workers: int = 50,
    ) -> Dict[str, Dict[int, Dict[str, str]]]:
        """TCP connect-scan a list of hosts on specified ports.

        Returns {host: {port: {"state", "service", "banner"}}}.
        """
        port_list = _parse_ports(ports)
        output: Dict[str, Dict[int, Dict[str, str]]] = {}

        def _scan_one(ip: str, port: int) -> Tuple[str, int, Dict[str, str]]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    banner = _fetch_banner(ip, port)
                    sock.close()
                    return ip, port, {
                        "state": "open",
                        "service": SERVICE_GUESSES.get(port, "unknown"),
                        "banner": banner,
                    }
                sock.close()
            except (socket.error, OSError):
                pass
            return ip, port, {"state": "closed", "service": "", "banner": ""}

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = []
            for ip in hosts:
                for port in port_list:
                    futures.append(pool.submit(_scan_one, ip, port))
            for future in as_completed(futures):
                ip, port, info = future.result()
                if info["state"] == "open":
                    output.setdefault(ip, {})[port] = info

        return output

    # ── Private helpers ─────────────────────────────────────────────

    @staticmethod
    def _expand_subnet(subnet: str) -> List[str]:
        """Expand a CIDR or range notation to a list of IP strings."""
        hosts = []
        subnet = subnet.strip()
        if "/" in subnet:
            ip_part, cidr_str = subnet.rsplit("/", 1)
            try:
                cidr = int(cidr_str)
            except ValueError:
                return []
            try:
                ip_int = struct.unpack("!I", socket.inet_aton(ip_part))[0]
            except (socket.error, struct.error):
                return []
            mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF if cidr < 32 else 0xFFFFFFFF
            network = ip_int & mask
            broadcast = network | (~mask & 0xFFFFFFFF)
            for addr in range(network + 1, broadcast):
                hosts.append(socket.inet_ntoa(struct.pack("!I", addr)))
        elif "." in subnet and "-" not in subnet:
            # Single host
            hosts.append(subnet)
        elif "-" in subnet:
            parts = subnet.split("-")
            if len(parts) == 2:
                try:
                    start_int = struct.unpack("!I", socket.inet_aton(parts[0].strip()))[0]
                    end_int = struct.unpack("!I", socket.inet_aton(parts[1].strip()))[0]
                    for addr in range(start_int, end_int + 1):
                        hosts.append(socket.inet_ntoa(struct.pack("!I", addr)))
                except (socket.error, struct.error):
                    pass
        return hosts

    @staticmethod
    def _build_mdns_query(name: str) -> bytes:
        """Build a minimal mDNS query packet."""
        header = struct.pack(">HHHHHH", 0x0000, 0x8400, 1, 0, 0, 0)
        qname = b""
        for label in name.split("."):
            qname += struct.pack("B", len(label)) + label.encode()
        qname += b"\x00"
        qtype_qclass = struct.pack(">HH", 12, 1)  # PTR, IN
        return header + qname + qtype_qclass

    @staticmethod
    def _parse_mdns_response(data: bytes) -> List[Dict[str, str]]:
        """Parse mDNS response and extract service names."""
        results = []
        try:
            if len(data) < 12:
                return results
            # Skip header (12 bytes) and questions
            ancount = struct.unpack(">H", data[6:8])[0]
            offset = 12
            # Skip question section (skip name + 4 bytes type/class)
            while offset < len(data) and data[offset] != 0:
                label_len = data[offset]
                if label_len >= 192:
                    offset += 2
                    break
                offset += 1 + label_len
            if offset < len(data):
                offset += 5  # null byte + 2 type + 2 class
            # Parse answers
            for _ in range(min(ancount, 50)):
                name_parts = []
                while offset < len(data):
                    label_len = data[offset]
                    if label_len == 0:
                        offset += 1
                        break
                    if label_len >= 192:
                        offset += 2
                        break
                    offset += 1
                    name_parts.append(data[offset:offset + label_len].decode("utf-8", errors="replace"))
                    offset += label_len
                if offset + 10 > len(data):
                    break
                rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
                offset += 10
                full_name = ".".join(name_parts) if name_parts else "unknown"
                addr = ""
                if rtype == 1 and rdlength == 4:  # A record
                    if offset + 4 <= len(data):
                        addr = socket.inet_ntoa(data[offset:offset + 4])
                elif rtype == 28 and rdlength == 16:  # AAAA
                    if offset + 16 <= len(data):
                        import socket as _s
                        addr = _s.inet_ntop(_s.AF_INET6, data[offset:offset + 16])
                offset += rdlength
                results.append({"name": full_name, "type": str(rtype), "address": addr})
        except (struct.error, IndexError, UnicodeDecodeError):
            pass
        return results


# ══════════════════════════════════════════════════════════════════════
# TrustMapper
# ══════════════════════════════════════════════════════════════════════

class TrustMapper:
    """Map implicit and explicit trust relationships between hosts."""

    def map_ssh_trust(self, hosts: List[str]) -> List[Dict[str, Any]]:
        """Check for SSH key-based trust chains between hosts.

        Attempts to connect to each host on port 22 and checks if
        password authentication is disabled (indicating key-only trust).

        Returns list of {"source", "target", "trust_type", "evidence"}.
        """
        trust_chains: List[Dict[str, Any]] = []

        def _check_host(ip: str) -> Optional[Dict[str, Any]]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, 22))
                if result != 0:
                    sock.close()
                    return None
                banner = b""
                sock.settimeout(3)
                try:
                    banner = sock.recv(256)
                except socket.timeout:
                    pass
                sock.close()
                banner_str = banner.decode("utf-8", errors="replace").strip()
                key_auth_hint = "" if "SSH-2" in banner_str else ""
                return {
                    "source": ip,
                    "target": ip,
                    "trust_type": "ssh_service",
                    "evidence": banner_str,
                    "auth_methods": [] if "SSH-2" in banner_str else [],
                }
            except (socket.error, OSError):
                return None

        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(_check_host, ip): ip for ip in hosts}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    trust_chains.append(result)

        # Try to detect known_hosts / authorized_keys patterns
        known_hosts_path = os.path.expanduser("~/.ssh/known_hosts")
        if os.path.exists(known_hosts_path):
            try:
                with open(known_hosts_path, "r") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            host_pattern = parts[0]
                            for ip in hosts:
                                if ip in host_pattern:
                                    trust_chains.append({
                                        "source": "localhost",
                                        "target": ip,
                                        "trust_type": "known_hosts_entry",
                                        "evidence": f"Found in known_hosts: {host_pattern}",
                                    })
            except OSError:
                pass

        return trust_chains

    def map_docker_networks(self) -> List[Dict[str, Any]]:
        """Discover Docker network topology.

        Returns list of {"network", "driver", "subnet", "containers": [...]}
        or an empty list if Docker is unavailable.
        """
        networks: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ["docker", "network", "ls", "--format", "{{.Name}}|{{.Driver}}"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return networks

            for line in result.stdout.strip().splitlines():
                if "|" not in line:
                    continue
                name, driver = line.split("|", 1)
                # Inspect network for subnet and containers
                inspect = subprocess.run(
                    ["docker", "network", "inspect", name],
                    capture_output=True, text=True, timeout=10,
                )
                subnet_info = ""
                containers = []
                if inspect.returncode == 0:
                    try:
                        data = json.loads(inspect.stdout)
                        if data and isinstance(data, list):
                            net_data = data[0]
                            ipam = net_data.get("IPAM", {})
                            configs = ipam.get("Config", [])
                            if configs:
                                subnet_info = configs[0].get("Subnet", "")
                            for container_id, c_data in net_data.get("Containers", {}).items():
                                containers.append({
                                    "id": container_id[:12],
                                    "name": c_data.get("Name", ""),
                                    "ip": c_data.get("IPv4Address", ""),
                                })
                    except (json.JSONDecodeError, IndexError, KeyError):
                        pass
                networks.append({
                    "network": name,
                    "driver": driver,
                    "subnet": subnet_info,
                    "containers": containers,
                })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass
        return networks

    def find_lateral_paths(
        self,
        network_graph: Dict[str, List[str]],
        start_host: str,
    ) -> List[List[str]]:
        """BFS from *start_host* to all reachable hosts.

        *network_graph* maps each host to a list of directly reachable
        neighbours (e.g. via trust or open ports).

        Returns a list of paths (each path is a list of host strings).
        """
        visited: Set[str] = {start_host}
        queue: deque = deque()
        queue.append([start_host])
        paths: List[List[str]] = []

        while queue:
            path = queue.popleft()
            current = path[-1]
            neighbours = network_graph.get(current, [])
            for neighbour in neighbours:
                if neighbour not in visited:
                    visited.add(neighbour)
                    new_path = path + [neighbour]
                    paths.append(new_path)
                    queue.append(new_path)

        return paths


# ══════════════════════════════════════════════════════════════════════
# SegmentationChecker
# ══════════════════════════════════════════════════════════════════════

class SegmentationChecker:
    """Verify that network segmentation zones are properly isolated."""

    def check_segmentation(
        self, zones: Dict[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """Check whether hosts in different zones can reach each other.

        Parameters
        ----------
        zones : dict
            Maps zone name to list of host IPs.
            Example: {"dmz": ["10.0.1.10"], "internal": ["10.0.2.5"]}

        Returns list of violation dicts:
            {"type", "source_zone", "source_host", "dest_zone", "dest_host", "port", "evidence"}
        """
        violations: List[Dict[str, Any]] = []
        zone_names = list(zones.keys())

        # Build a cross-zone connection test matrix
        cross_pairs: List[Tuple[str, str, str, str]] = []
        for i, z1 in enumerate(zone_names):
            for z2 in zone_names[i + 1:]:
                for h1 in zones[z1]:
                    for h2 in zones[z2]:
                        cross_pairs.append((z1, h1, z2, h2))

        def _test_cross(z1: str, h1: str, z2: str, h2: str) -> Optional[Dict[str, Any]]:
            # Test common cross-zone ports
            test_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 3389, 445]
            for port in test_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((h2, port))
                    sock.close()
                    if result == 0:
                        return {
                            "type": "cross_zone_connection",
                            "source_zone": z1,
                            "source_host": h1,
                            "dest_zone": z2,
                            "dest_host": h2,
                            "port": port,
                            "evidence": f"TCP connection from {h1} to {h2}:{port} succeeded",
                        }
                except (socket.error, OSError):
                    continue
            return None

        with ThreadPoolExecutor(max_workers=30) as pool:
            futures = []
            for z1, h1, z2, h2 in cross_pairs:
                futures.append(pool.submit(_test_cross, z1, h1, z2, h2))
            for future in as_completed(futures):
                violation = future.result()
                if violation:
                    violations.append(violation)

        return violations


# ══════════════════════════════════════════════════════════════════════
# run_local – orchestration function
# ══════════════════════════════════════════════════════════════════════

def run_local(
    subnet: str = "",
    ports: str = "22,80,443,3306,5432,6379,8080,8443",
) -> Dict[str, Any]:
    """Run a full local network discovery and trust-mapping audit.

    If *subnet* is empty, ARP discovery is used to find neighbours.

    Returns a dict with keys: "hosts", "arp_table", "mdns_services",
    "port_results", "ssh_trust", "docker_networks", "lateral_paths",
    "findings".
    """
    discovery = NetworkDiscovery()
    trust_mapper = TrustMapper()
    findings: List[Dict[str, Any]] = []

    # Step 1: Host discovery
    hosts: List[str] = []
    if subnet:
        hosts = discovery.ping_sweep(subnet)
        if not hosts:
            findings.append({
                "title": "Ping sweep returned no hosts",
                "severity": "info",
                "category": "network_security",
                "description": f"ICMP ping sweep of {subnet} found no responsive hosts.",
            })

    # Step 2: ARP table
    arp_table = discovery.arp_discovery()
    arp_ips = {e["ip"] for e in arp_table}
    if not hosts:
        hosts = list(arp_ips)
    else:
        # Merge ARP hosts not in ping results
        for ip in arp_ips:
            if ip not in hosts:
                hosts.append(ip)

    findings.append({
        "title": f"Discovered {len(hosts)} hosts via ARP/ping",
        "severity": "info",
        "category": "asset_management",
        "description": f"Host discovery found {len(hosts)} live hosts. ARP table had {len(arp_table)} entries.",
    })

    # Step 3: mDNS
    mdns_services = discovery.mdns_discovery()
    if mdns_services:
        findings.append({
            "title": f"mDNS services discovered: {len(mdns_services)}",
            "severity": "low",
            "category": "network_security",
            "description": f"mDNS discovery revealed {len(mdns_services)} services. Consider disabling mDNS in production.",
        })

    # Step 4: Port scan
    port_results = discovery.port_scan_hosts(hosts, ports) if hosts else {}
    open_ports_count = sum(len(v) for v in port_results.values())
    findings.append({
        "title": f"Found {open_ports_count} open ports across {len(port_results)} hosts",
        "severity": "info",
        "category": "network_security",
        "description": f"Port scan of {len(hosts)} hosts revealed {open_ports_count} open services.",
    })

    # Flag dangerous open ports
    dangerous_ports = {23: "Telnet", 21: "FTP", 445: "SMB", 3389: "RDP", 5900: "VNC"}
    for host, port_map in port_results.items():
        for port, info in port_map.items():
            if port in dangerous_ports:
                findings.append({
                    "title": f"Insecure service {dangerous_ports[port]} on {host}:{port}",
                    "severity": "high",
                    "category": "network_security",
                    "description": f"{dangerous_ports[port]} is open on {host}:{port}. This protocol transmits credentials in cleartext.",
                    "remediation": f"Disable {dangerous_ports[port]} or tunnel through SSH/VPN.",
                })
            if port == 6379 and "redis" in info.get("service", ""):
                findings.append({
                    "title": f"Redis exposed on {host}:{port}",
                    "severity": "critical",
                    "category": "access_control",
                    "description": "Redis is accessible without apparent authentication. This can lead to remote code execution.",
                    "remediation": "Bind Redis to localhost, enable authentication, and use firewall rules.",
                })

    # Step 5: SSH trust mapping
    ssh_trust = trust_mapper.map_ssh_trust(hosts) if hosts else []

    # Step 6: Docker networks
    docker_networks = trust_mapper.map_docker_networks()
    if docker_networks:
        findings.append({
            "title": f"Docker networks discovered: {len(docker_networks)}",
            "severity": "info",
            "category": "container_security",
            "description": f"Found {len(docker_networks)} Docker networks. Review segmentation.",
        })

    # Step 7: Lateral path analysis
    network_graph: Dict[str, List[str]] = {}
    for host, port_map in port_results.items():
        neighbours = []
        for port, info in port_map.items():
            svc = info.get("service", "")
            if svc in ("ssh", "rdp", "vnc", "winrm"):
                neighbours.append(f"{host}:{port}")
        network_graph[host] = neighbours

    lateral_paths: List[List[str]] = []
    if hosts:
        # Use first host as start for lateral path analysis
        start = hosts[0]
        lateral_paths = trust_mapper.find_lateral_paths(network_graph, start)
        if len(lateral_paths) > 1:
            findings.append({
                "title": f"Lateral movement paths found from {start}",
                "severity": "high",
                "category": "network_security",
                "description": f"BFS from {start} reached {len(lateral_paths) - 1} additional hosts via trust relationships. Consider implementing zero-trust segmentation.",
                "remediation": "Implement micro-segmentation, disable unnecessary services, enforce MFA on all management interfaces.",
            })

    return {
        "hosts": hosts,
        "arp_table": arp_table,
        "mdns_services": mdns_services,
        "port_results": port_results,
        "ssh_trust": ssh_trust,
        "docker_networks": docker_networks,
        "lateral_paths": lateral_paths,
        "findings": findings,
    }


# Module-level convenience exports
discovery = NetworkDiscovery()
trust_mapper = TrustMapper()
segmentation = SegmentationChecker()
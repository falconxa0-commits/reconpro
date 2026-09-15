"""
ReconPro v8.5 — Raw Packet Assembly

SYN scanning (with scapy if available, connect-scan fallback),
UDP probing, TTL-based OS fingerprinting, and ARP table discovery.

Exports:
    SynScanner     – TCP SYN port scanner
    UdpProber      – UDP service prober
    TtlAnalyzer    – TTL-based OS fingerprinting
    ArpSpy         – ARP table discovery
"""

from __future__ import annotations

import re
import socket
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional


# ── Optional scapy import ───────────────────────────────────────────
HAS_SCAPY = False
try:
    from scapy.all import (  # type: ignore
        IP, TCP, UDP, ICMP, sr1, sr,
        conf as scapy_conf,
    )
    scapy_conf.verb = 0
    HAS_SCAPY = True
except ImportError:
    pass


# ── Shared helpers ──────────────────────────────────────────────────

SERVICE_GUESSES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 179: "bgp", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5672: "amqp",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb", 11211: "memcached",
}

UDP_SERVICE_GUESSES = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    123: "ntp", 161: "snmp", 162: "snmptrap", 500: "ike",
    514: "syslog", 520: "rip", 523: "ibm-db2", 1194: "openvpn",
    1900: "upnp", 4500: "nat-t", 5353: "mdns", 5060: "sip",
}


def _parse_ports(ports_spec: str) -> list:
    """Parse port spec like '22,80,443,1-1024' into sorted list of ints."""
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


def _grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Try to read a service banner via TCP connect."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (443, 8443, 993, 995, 465):
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


def _build_udp_probe(port: int) -> bytes:
    """Build a minimal UDP probe payload for a given port."""
    if port == 53:
        # DNS query for version.bind TXT CHAOS
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b"\x07version\x04bind\x00"
        qtype_qclass = struct.pack(">HH", 16, 3)  # TXT, CHAOS
        return header + qname + qtype_qclass
    elif port == 123:
        # NTP version request
        header = b"\xe3\x00\x04\xfa\x00\x01\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"\xc4\x7a\x5c\x9d"
        return header
    elif port == 161:
        # SNMP v1 get-request for sysDescr
        return bytes.fromhex(
            "302902010104067075626c6963a01c020401000000020100020100"
            "300e300c06082b060102010100050000"
        )
    elif port == 1900:
        # SSDP M-SEARCH
        return (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"Host:239.255.255.250:1900\r\n"
            b"Man:\"ssdp:discover\"\r\n"
            b"ST:ssdp:all\r\n"
            b"MX:1\r\n\r\n"
        )
    elif port == 514:
        return b"<14>ReconPro probe\n"
    elif port == 500:
        # IKE v1 main mode
        return bytes.fromhex(
            "0000000000000000000000000000000001220100000000000000000000"
            "0c00000001000000010000002801010001000000200101000080010005"
            "80020002800300018004000280050002"
        )
    else:
        return b"\x00\x01\x02\x03"


# ══════════════════════════════════════════════════════════════════════
# SynScanner
# ══════════════════════════════════════════════════════════════════════

class SynScanner:
    """TCP SYN port scanner with scapy fast-path or connect() fallback."""

    def scan(
        self,
        host: str,
        ports: str = "1-1024",
        timeout: float = 2.0,
        workers: int = 100,
    ) -> List[Dict[str, Any]]:
        """Scan *host* on specified *ports*.

        Returns list of {"port", "state", "service", "banner"}.
        """
        port_list = _parse_ports(ports)
        if not port_list:
            return []

        if HAS_SCAPY:
            return self._scan_scapy(host, port_list, timeout)
        return self._scan_connect(host, port_list, timeout, workers)

    def _scan_scapy(
        self, host: str, ports: list, timeout: float
    ) -> List[Dict[str, Any]]:
        """Scapy-based SYN scan."""
        results: List[Dict[str, Any]] = []

        try:
            from scapy.all import RandShort  # type: ignore
            src_port = RandShort()
        except ImportError:
            src_port = 1024 + int(time.time() * 1000) % 60000

        # Send SYN packets
        try:
            ans = sr1(
                IP(dst=host) / TCP(sport=src_port, dport=ports, flags="S"),
                timeout=timeout,
                verbose=0,
                inter=0.01,
            )
        except Exception:
            # sr1 may not work for multi-port; fall back to connect
            return self._scan_connect(host, ports, timeout, 50)

        if ans is None:
            # Try individual ports with sr
            for port in ports:
                try:
                    pkt = IP(dst=host) / TCP(sport=src_port, dport=port, flags="S")
                    resp = sr1(pkt, timeout=timeout, verbose=0)
                    if resp is not None and resp.haslayer(TCP):
                        flags = resp[TCP].flags
                        if flags & 0x12:  # SYN-ACK
                            banner = _grab_banner(host, port, timeout)
                            results.append({
                                "port": port,
                                "state": "open",
                                "service": SERVICE_GUESSES.get(port, "unknown"),
                                "banner": banner,
                            })
                            # Send RST to close
                            try:
                                rst = IP(dst=host) / TCP(
                                    sport=src_port, dport=port, flags="R"
                                )
                                sr1(rst, timeout=1, verbose=0)
                            except Exception:
                                pass
                        elif flags & 0x14:  # RST-ACK
                            results.append({
                                "port": port,
                                "state": "closed",
                                "service": "",
                                "banner": "",
                            })
                except Exception:
                    continue
            return results

        # If sr1 returned a single response
        if ans.haslayer(TCP):
            flags = ans[TCP].flags
            sport = ans[TCP].sport
            if flags & 0x12:
                banner = _grab_banner(host, sport, timeout)
                results.append({
                    "port": sport,
                    "state": "open",
                    "service": SERVICE_GUESSES.get(sport, "unknown"),
                    "banner": banner,
                })

        return results

    def _scan_connect(
        self, host: str, ports: list, timeout: float, workers: int
    ) -> List[Dict[str, Any]]:
        """Fallback connect()-based scanner."""
        results: List[Dict[str, Any]] = []

        def _probe(port: int) -> Optional[Dict[str, Any]]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    banner = ""
                    # Grab banner for well-known service ports
                    if port in SERVICE_GUESSES or port < 1024:
                        banner = _grab_banner(host, port, min(timeout, 3))
                    sock.close()
                    return {
                        "port": port,
                        "state": "open",
                        "service": SERVICE_GUESSES.get(port, "unknown"),
                        "banner": banner,
                    }
                sock.close()
            except (socket.error, OSError):
                pass
            return None

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_probe, p): p for p in ports}
            for future in as_completed(futures):
                r = future.result()
                if r:
                    results.append(r)

        results.sort(key=lambda x: x["port"])
        return results


# ══════════════════════════════════════════════════════════════════════
# UdpProber
# ══════════════════════════════════════════════════════════════════════

class UdpProber:
    """Probe UDP ports and record responses."""

    def probe(
        self,
        host: str,
        ports: str = "53,123,161,500,514,1900",
        timeout: float = 3.0,
        workers: int = 30,
    ) -> List[Dict[str, Any]]:
        """Send UDP probes to *host* on specified *ports*.

        Returns list of {"port", "state", "response"}.
        state is "open|filtered" if any response, "filtered" if no response.
        """
        port_list = _parse_ports(ports)
        results: List[Dict[str, Any]] = []

        def _probe_port(port: int) -> Dict[str, Any]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                payload = _build_udp_probe(port)
                sock.sendto(payload, (host, port))
                response = b""
                try:
                    response, _ = sock.recvfrom(4096)
                except socket.timeout:
                    pass
                sock.close()

                state = "open|filtered" if response else "open|filtered"
                resp_str = response.decode("utf-8", errors="replace").strip()[:512]
                # Try to detect "closed" via ICMP port unreachable
                if not response:
                    state = "open|filtered"
                else:
                    state = "open"

                return {
                    "port": port,
                    "state": state,
                    "service": UDP_SERVICE_GUESSES.get(port, "unknown"),
                    "response": resp_str,
                }
            except (socket.error, OSError):
                return {
                    "port": port,
                    "state": "filtered",
                    "service": UDP_SERVICE_GUESSES.get(port, "unknown"),
                    "response": "",
                }

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_probe_port, p): p for p in port_list}
            for future in as_completed(futures):
                results.append(future.result())

        results.sort(key=lambda x: x["port"])
        return results


# ══════════════════════════════════════════════════════════════════════
# TtlAnalyzer
# ══════════════════════════════════════════════════════════════════════

TTL_SIGNATURES = {
    64:  {"os": "Linux/Unix/macOS", "confidence": "high"},
    128: {"os": "Windows", "confidence": "high"},
    255: {"os": "Network Device (Router/Switch/Firewall)", "confidence": "high"},
    60:  {"os": "Linux/Unix (1 hop away)", "confidence": "medium"},
    62:  {"os": "Linux/Unix (2 hops away)", "confidence": "medium"},
    61:  {"os": "Linux/Unix (3 hops away)", "confidence": "medium"},
    126: {"os": "Windows (2 hops away)", "confidence": "medium"},
    124: {"os": "Windows (4 hops away)", "confidence": "medium"},
    252: {"os": "Network Device (3 hops away)", "confidence": "medium"},
    254: {"os": "Network Device (1 hop away)", "confidence": "medium"},
}


class TtlAnalyzer:
    """TTL-based OS fingerprinting."""

    def analyze(self, host: str, probes: int = 3, timeout: float = 3.0) -> Dict[str, Any]:
        """Send probes to *host* and analyze TTL values to guess the OS.

        Returns {"ttl", "ttl_values", "guessed_os", "confidence", "method"}.
        """
        ttl_values = []
        method = ""

        # Method 1: ICMP echo (ping)
        try:
            for _ in range(probes):
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", str(int(timeout)), host],
                    capture_output=True, text=True, timeout=timeout + 2,
                )
                for line in result.stdout.splitlines():
                    if "ttl=" in line.lower():
                        match = re.search(r"ttl[=:]\s*(\d+)", line, re.IGNORECASE)
                        if match:
                            ttl_values.append(int(match.group(1)))
                            method = "icmp_ping"
                            break
                if method:
                    break
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Method 2: TCP connect and read IP TTL from received packet
        if not ttl_values:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, 80))
                # We can't read TTL from a connected socket without raw
                # sockets, so try scapy if available
                sock.close()
                if HAS_SCAPY:
                    try:
                        from scapy.all import IP, TCP, sr1  # type: ignore
                        pkt = IP(dst=host) / TCP(dport=80, flags="S")
                        resp = sr1(pkt, timeout=timeout, verbose=0)
                        if resp and resp.haslayer(IP):
                            ttl_values.append(resp[IP].ttl)
                            method = "scapy_syn"
                    except Exception:
                        pass
            except (socket.error, OSError):
                pass

        # Method 3: UDP DNS query
        if not ttl_values:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                sock.sendto(b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", (host, 53))
                try:
                    data, _ = sock.recvfrom(1024)
                    if HAS_SCAPY:
                        from scapy.all import IP  # type: ignore
                        pkt = IP(data)
                        ttl_values.append(pkt.ttl)
                        method = "scapy_dns"
                except socket.timeout:
                    pass
                sock.close()
            except (socket.error, OSError):
                pass

        if not ttl_values:
            return {
                "ttl": None,
                "ttl_values": [],
                "guessed_os": "Unknown",
                "confidence": "none",
                "method": "none",
            }

        # Use the most common TTL value
        from collections import Counter
        ttl_counter = Counter(ttl_values)
        most_common_ttl = ttl_counter.most_common(1)[0][0]

        # Try to normalize to initial TTL
        initial_ttl = self._estimate_initial_ttl(most_common_ttl)
        signature = TTL_SIGNATURES.get(initial_ttl, TTL_SIGNATURES.get(most_common_ttl))

        if not signature:
            # Heuristic: closest known base
            if most_common_ttl <= 64:
                signature = {"os": "Linux/Unix/macOS (possibly routed)", "confidence": "low"}
            elif most_common_ttl <= 128:
                signature = {"os": "Windows (possibly routed)", "confidence": "low"}
            else:
                signature = {"os": "Network Device (possibly routed)", "confidence": "low"}

        return {
            "ttl": most_common_ttl,
            "ttl_values": ttl_values,
            "guessed_os": signature["os"],
            "confidence": signature["confidence"],
            "method": method,
            "estimated_initial_ttl": initial_ttl,
        }

    @staticmethod
    def _estimate_initial_ttl(ttl: int) -> int:
        """Guess the initial TTL from the observed value."""
        if ttl <= 32:
            return 32
        if ttl <= 64:
            return 64
        if ttl <= 96:
            return 128
        if ttl <= 128:
            return 128
        if ttl <= 192:
            return 255
        return 255


# ══════════════════════════════════════════════════════════════════════
# ArpSpy
# ══════════════════════════════════════════════════════════════════════

class ArpSpy:
    """Discover and monitor ARP table entries."""

    def discover(self, timeout: float = 5.0) -> List[Dict[str, str]]:
        """Read the system ARP cache.

        Returns list of {"ip", "mac", "interface", "type"}.
        """
        import re as _re
        entries: List[Dict[str, str]] = []

        try:
            import platform as _plat
            system = _plat.system().lower()

            if system == "windows":
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=timeout,
                )
                for line in result.stdout.splitlines():
                    match = _re.search(
                        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+"
                        r"([0-9a-fA-F:\-]{17})\s+(\S+)",
                        line,
                    )
                    if match:
                        mac = match.group(2).replace("-", ":")
                        entry_type = "dynamic"
                        if mac.endswith(":00:00:00:00:00"):
                            entry_type = "incomplete"
                        entries.append({
                            "ip": match.group(1),
                            "mac": mac,
                            "interface": match.group(3),
                            "type": entry_type,
                        })
            else:
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=timeout,
                )
                for line in result.stdout.splitlines():
                    match = _re.search(
                        r"\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+"
                        r"([0-9a-fA-F:]{17})",
                        line,
                    )
                    if match:
                        iface = "unknown"
                        iface_m = _re.search(r"on\s+(\S+)", line)
                        if iface_m:
                            iface = iface_m.group(1)
                        entry_type = "dynamic"
                        if "PERM" in line.upper() or "STATIC" in line.upper():
                            entry_type = "static"
                        entries.append({
                            "ip": match.group(1),
                            "mac": match.group(2),
                            "interface": iface,
                            "type": entry_type,
                        })
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError, _re.error):
            pass

        return entries

    def detect_spoofing(self, entries: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, Any]]:
        """Detect potential ARP spoofing by looking for duplicate MACs.

        If *entries* is None, calls discover() first.
        Returns list of {"type": "arp_spoof", "mac", "ips", "description"}.
        """
        if entries is None:
            entries = self.discover()

        mac_to_ips: Dict[str, List[str]] = {}
        for e in entries:
            mac = e["mac"].lower()
            if mac == "ff:ff:ff:ff:ff:ff" or mac.endswith(":00:00:00:00:00"):
                continue
            mac_to_ips.setdefault(mac, []).append(e["ip"])

        alerts: List[Dict[str, Any]] = []
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                alerts.append({
                    "type": "arp_spoof",
                    "mac": mac,
                    "ips": ips,
                    "description": (
                        f"MAC {mac} is associated with multiple IPs: {', '.join(ips)}. "
                        f"This may indicate ARP spoofing or a legitimate multi-homed host."
                    ),
                })

        return alerts


# Module-level convenience exports
syn_scanner = SynScanner()
udp_prober = UdpProber()
ttl_analyzer = TtlAnalyzer()
arp_spy = ArpSpy()

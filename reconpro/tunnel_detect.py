r"""
ReconPro v9.2.0 - Protocol Tunnel Detection

Detects covert protocol tunneling in network traffic.  Probes a target host
for indicators of DNS, ICMP, IPv6, GRE, SSH, and HTTP tunneling.

Pure Python stdlib -- zero external dependencies.

Classes:
    TunnelType        - Enum of supported tunnel types.
    TunnelIndicator   - Dataclass for a single tunnel detection result.
    EntropyAnalyzer   - Shannon-entropy calculator for data randomness.
    DNSEntropyChecker - Specialised checker for high-entropy DNS labels.
    TunnelDetector    - Main orchestrator that runs all detection methods.
"""
from __future__ import annotations

import enum
import http.client
import logging
import math
import re
import socket
import struct
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TunnelType enum
# ---------------------------------------------------------------------------

class TunnelType(enum.Enum):
    """Supported tunnel protocol categories."""
    DNS_TUNNEL = "DNS Tunneling"
    ICMP_TUNNEL = "ICMP Tunneling"
    IPV6_TUNNEL = "IPv6 Tunneling"
    GRE_TUNNEL = "GRE Tunneling"
    SSH_TUNNEL = "SSH Tunneling"
    HTTP_TUNNEL = "HTTP CONNECT Tunneling"
    HTTPS_TUNNEL = "HTTPS Tunneling"
    TCP_OVER_UDP = "TCP-over-UDP Tunneling"


# ---------------------------------------------------------------------------
# TunnelIndicator
# ---------------------------------------------------------------------------

@dataclass
class TunnelIndicator:
    """A single indicator that a specific tunnel type may be present.

    Attributes:
        tunnel_type:      The :class:`TunnelType` detected.
        confidence:       0.0 – 1.0 confidence in this finding.
        evidence:         Free-text description of what was observed.
        source_ip:        IP of the probing host (may be empty).
        destination_ip:   IP of the target host.
        protocol_details: Extra metadata (port numbers, banners, etc.).
    """
    tunnel_type: TunnelType
    confidence: float
    evidence: str
    source_ip: str = ""
    destination_ip: str = ""
    protocol_details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tunnel_type": self.tunnel_type.value,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol_details": self.protocol_details,
        }


# ---------------------------------------------------------------------------
# EntropyAnalyzer
# ---------------------------------------------------------------------------

class EntropyAnalyzer:
    """Calculate Shannon entropy of byte or string data.

    High entropy (> 4.0 bits/byte for ASCII) suggests encrypted or compressed
    payloads -- a strong tunneling indicator.
    """

    @staticmethod
    def shannon_entropy(data: bytes | str) -> float:
        """Calculate Shannon entropy in bits per byte (0-8 range).

        Args:
            data: Input bytes or string to analyse.

        Returns:
            Entropy value between 0.0 (uniform/low randomness) and 8.0
            (maximum randomness).
        """
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        if not data:
            return 0.0

        length = len(data)
        freq: Dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        for count in freq.values():
            if count > 0:
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def is_high_entropy(data: bytes | str, threshold: float = 4.0) -> bool:
        """Return True if *data* has entropy above *threshold*."""
        return EntropyAnalyzer.shannon_entropy(data) >= threshold

    @staticmethod
    def byte_distribution(data: bytes | str) -> Dict[int, float]:
        """Return a dict mapping byte value (0-255) to its frequency."""
        if isinstance(data, str):
            data = data.encode("utf-8", errors="replace")
        if not data:
            return {}
        length = len(data)
        dist: Dict[int, float] = {}
        for byte in data:
            dist[byte] = dist.get(byte, 0.0) + 1.0 / length
        return dist


# ---------------------------------------------------------------------------
# DNSEntropyChecker
# ---------------------------------------------------------------------------

class DNSEntropyChecker:
    """Specialised analyser for detecting high-entropy DNS labels.

    DNS tunneling tools encode data into subdomain labels.  These encoded
    labels have significantly higher entropy than normal domain names.
    """

    # Normal English domain labels rarely exceed this entropy
    LABEL_ENTROPY_THRESHOLD = 3.5
    # Very long labels are themselves suspicious
    MAX_NORMAL_LABEL_LEN = 30
    # Base64 character set
    BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    HEX_CHARS = set("0123456789abcdef")

    def __init__(self, entropy_analyzer: Optional[EntropyAnalyzer] = None) -> None:
        self.entropy = entropy_analyzer or EntropyAnalyzer()

    def check_label(self, label: str) -> Dict[str, Any]:
        """Analyse a single DNS label for tunneling indicators.

        Returns a dict with keys: ``entropy``, ``is_high_entropy``,
        ``is_base64_like``, ``is_hex_like``, ``label_length``, ``suspicious``.
        """
        label_lower = label.lower()
        label_len = len(label_lower)
        ent = self.entropy.shannon_entropy(label_lower)

        is_base64 = (
            label_len > 12
            and all(c in self.BASE64_CHARS for c in label_lower)
        )
        is_hex = (
            label_len > 10
            and all(c in self.HEX_CHARS for c in label_lower)
        )

        suspicious = (
            ent >= self.LABEL_ENTROPY_THRESHOLD
            or label_len > self.MAX_NORMAL_LABEL_LEN
            or is_base64
            or is_hex
        )

        return {
            "label": label,
            "entropy": ent,
            "is_high_entropy": ent >= self.LABEL_ENTROPY_THRESHOLD,
            "is_base64_like": is_base64,
            "is_hex_like": is_hex,
            "label_length": label_len,
            "suspicious": suspicious,
        }

    def check_fqdn(self, fqdn: str) -> Dict[str, Any]:
        """Analyse all labels in a fully-qualified domain name.

        Returns:
            ``{"fqdn": ..., "labels": [...], "suspicious_labels": [...], "overall_suspicious": bool}``
        """
        labels = fqdn.rstrip(".").split(".")
        results = [self.check_label(lbl) for lbl in labels]
        suspicious = [r for r in results if r["suspicious"]]
        return {
            "fqdn": fqdn,
            "labels": results,
            "suspicious_labels": suspicious,
            "overall_suspicious": len(suspicious) > 0,
        }


# ---------------------------------------------------------------------------
# TunnelDetector
# ---------------------------------------------------------------------------

class TunnelDetector:
    """Main tunnel detection orchestrator.

    Probes the target host for indicators of various tunnel types and
    returns a list of :class:`TunnelIndicator` results.
    """

    DEFAULT_TIMEOUT: int = 8

    def __init__(self) -> None:
        self.entropy_analyzer = EntropyAnalyzer()
        self.dns_checker = DNSEntropyChecker(self.entropy_analyzer)

    def detect_all(
        self,
        host: str,
        base_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> List[TunnelIndicator]:
        """Run all tunnel detectors against *host*.

        Args:
            host:     Target hostname or IP address.
            base_url: Optional URL for HTTP/HTTPS tunnel checks.
            timeout:  Network timeout in seconds.

        Returns:
            List of :class:`TunnelIndicator` sorted by confidence descending.
        """
        indicators: List[TunnelIndicator] = []

        # Resolve target to IP
        dest_ip = self._resolve_host(host)

        # 1. DNS tunnel detection
        logger.info("[TunnelDetect] Checking DNS tunnel indicators for %s", host)
        indicators.extend(self.detect_dns_tunnel(host, timeout=timeout))

        # 2. ICMP tunnel detection
        logger.info("[TunnelDetect] Checking ICMP tunnel indicators for %s", host)
        indicators.extend(self.detect_icmp_tunnel(host, timeout=timeout))

        # 3. IPv6 tunnel detection
        logger.info("[TunnelDetect] Checking IPv6 tunnel indicators for %s", host)
        indicators.extend(self.detect_ipv6_tunnel(host, timeout=timeout))

        # 4. GRE tunnel detection
        logger.info("[TunnelDetect] Checking GRE tunnel indicators for %s", host)
        indicators.extend(self.detect_gre_tunnel(host, timeout=timeout))

        # 5. SSH tunnel detection
        logger.info("[TunnelDetect] Checking SSH tunnel indicators for %s", host)
        indicators.extend(self.detect_ssh_tunnel(host, timeout=timeout, dest_ip=dest_ip))

        # 6. HTTP CONNECT tunnel detection
        if base_url:
            logger.info("[TunnelDetect] Checking HTTP CONNECT tunnel indicators for %s", base_url)
            indicators.extend(self.detect_http_tunnel(base_url, timeout=timeout))

        # Sort by confidence descending
        indicators.sort(key=lambda i: i.confidence, reverse=True)
        return indicators

    # -- DNS tunnel --------------------------------------------------------

    def detect_dns_tunnel(
        self, host: str, timeout: int = 8
    ) -> List[TunnelIndicator]:
        """Analyse DNS response patterns for tunneling indicators.

        Checks:
        - Unusually long TXT records
        - Entropy of subdomain labels
        - Base64/hex encoded data in DNS responses
        - Frequency of queryable subdomains
        """
        indicators: List[TunnelIndicator] = []

        # 1. TXT record analysis
        txt_records = self._query_txt_records(host, timeout)
        for txt in txt_records:
            ent = self.entropy_analyzer.shannon_entropy(txt)
            details: Dict[str, Any] = {
                "record_length": len(txt),
                "entropy": ent,
            }
            if len(txt) > 200:
                indicators.append(
                    TunnelIndicator(
                        tunnel_type=TunnelType.DNS_TUNNEL,
                        confidence=min(0.5 + (len(txt) - 200) / 1000, 0.95),
                        evidence=(
                            f"Unusually long TXT record ({len(txt)} bytes, "
                            f"entropy={ent:.2f}): {txt[:80]}..."
                        ),
                        destination_ip=host,
                        protocol_details=details,
                    )
                )
            if ent > 4.0:
                indicators.append(
                    TunnelIndicator(
                        tunnel_type=TunnelType.DNS_TUNNEL,
                        confidence=min(0.4 + (ent - 4.0) * 0.15, 0.9),
                        evidence=(
                            f"High-entropy TXT record (entropy={ent:.2f}): {txt[:80]}..."
                        ),
                        destination_ip=host,
                        protocol_details=details,
                    )
                )

        # 2. Entropy check on the host itself
        label_analysis = self.dns_checker.check_fqdn(host)
        if label_analysis["overall_suspicious"]:
            sus_labels = label_analysis["suspicious_labels"]
            evidence_parts = [
                f"label '{s['label']}' (len={s['label_length']}, ent={s['entropy']:.2f})"
                for s in sus_labels[:3]
            ]
            indicators.append(
                TunnelIndicator(
                    tunnel_type=TunnelType.DNS_TUNNEL,
                    confidence=0.5,
                    evidence=f"Suspicious DNS labels: {'; '.join(evidence_parts)}",
                    destination_ip=host,
                    protocol_details={"label_analysis": sus_labels},
                )
            )

        # 3. Check for base64-like subdomain acceptance (tunneling surface)
        test_subdomains = self._probe_dns_subdomains(host, timeout)
        if test_subdomains:
            indicators.append(
                TunnelIndicator(
                    tunnel_type=TunnelType.DNS_TUNNEL,
                    confidence=0.6,
                    evidence=(
                        f"Host accepts base64-like subdomains: {test_subdomains[:3]}"
                    ),
                    destination_ip=host,
                    protocol_details={"resolvable_subdomains": test_subdomains},
                )
            )

        # 4. Check ANY response size via dig
        any_output = self._dig_any(host, timeout)
        if any_output and len(any_output) > 512:
            ent = self.entropy_analyzer.shannon_entropy(any_output)
            indicators.append(
                TunnelIndicator(
                    tunnel_type=TunnelType.DNS_TUNNEL,
                    confidence=min(0.3 + (len(any_output) - 512) / 2000, 0.85),
                    evidence=(
                        f"Large DNS ANY response ({len(any_output)} bytes, "
                        f"entropy={ent:.2f})"
                    ),
                    destination_ip=host,
                    protocol_details={"response_size": len(any_output), "entropy": ent},
                )
            )

        return indicators

    # -- ICMP tunnel -------------------------------------------------------

    def detect_icmp_tunnel(
        self, host: str, timeout: int = 8
    ) -> List[TunnelIndicator]:
        """Send pings and analyse response patterns for tunneling.

        Checks:
        - Payload size in responses
        - Response timing consistency (low jitter = stable tunnel)
        - Payload data content (non-standard padding)
        - Whether large payloads are accepted
        """
        indicators: List[TunnelIndicator] = []

        # 1. Standard 4-ping
        try:
            result = subprocess.run(
                ["ping", "-c", "4", "-W", str(timeout), host],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            output = result.stdout + result.stderr

            if result.returncode != 0:
                return indicators  # Host doesn't respond to ping

            # Parse timing
            times = re.findall(r"time=([\d.]+)\s*ms", output)
            if len(times) >= 2:
                float_times = [float(t) for t in times]
                avg = sum(float_times) / len(float_times)
                jitter = max(float_times) - min(float_times)
                std_dev = self._std_dev(float_times)

                details: Dict[str, Any] = {
                    "avg_ms": round(avg, 2),
                    "jitter_ms": round(jitter, 2),
                    "std_dev_ms": round(std_dev, 2),
                    "samples": len(float_times),
                }

                # Very low jitter suggests a stable tunnel channel
                if jitter < 2.0 and len(float_times) >= 3:
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.ICMP_TUNNEL,
                            confidence=0.55,
                            evidence=(
                                f"Very low ICMP jitter ({jitter:.2f}ms, std={std_dev:.2f}ms) "
                                f"across {len(float_times)} pings -- stable timing channel"
                            ),
                            destination_ip=host,
                            protocol_details=details,
                        )
                    )

            # Parse payload size
            size_match = re.search(r"(\d+)\s*bytes?\s+(?:from|of data)", output)
            if size_match:
                payload = int(size_match.group(1))
                if payload > 64:
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.ICMP_TUNNEL,
                            confidence=min(0.4 + (payload - 64) / 200, 0.85),
                            evidence=(
                                f"ICMP payload size {payload} bytes exceeds standard 64 bytes"
                            ),
                            destination_ip=host,
                            protocol_details={"payload_bytes": payload},
                        )
                    )

            # Check TTL consistency
            ttls = re.findall(r"ttl=(\d+)", output)
            if len(ttls) >= 2:
                ttl_values = [int(t) for t in ttls]
                ttl_range = max(ttl_values) - min(ttl_values)
                if ttl_range > 2:
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.ICMP_TUNNEL,
                            confidence=0.5,
                            evidence=(
                                f"Inconsistent TTL values: {ttl_values} "
                                f"(range={ttl_range}) -- possible tunnel hop"
                            ),
                            destination_ip=host,
                            protocol_details={"ttl_values": ttl_values},
                        )
                    )

        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.debug("ICMP detection failed: %s", exc)
            return indicators

        # 2. Large-payload ping
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-s", "1400", "-W", str(timeout), host],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            if result.returncode == 0:
                output2 = result.stdout
                if "1400" in output2 or "1428" in output2:
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.ICMP_TUNNEL,
                            confidence=0.7,
                            evidence=(
                                "Host accepts large ICMP payloads (1400+ bytes) "
                                "-- significant data channel capacity"
                            ),
                            destination_ip=host,
                            protocol_details={"large_payload_accepted": True},
                        )
                    )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return indicators

    # -- IPv6 tunnel -------------------------------------------------------

    def detect_ipv6_tunnel(
        self, host: str, timeout: int = 8
    ) -> List[TunnelIndicator]:
        """Check for IPv6 transition tunnel endpoints.

        Detects 6to4, Teredo, ISATAP, and 6in4 tunnel encodings via DNS
        AAAA records and well-known tunnel relay addresses.
        """
        indicators: List[TunnelIndicator] = []

        # 1. Check for AAAA records
        try:
            addrs = socket.getaddrinfo(host, None, socket.AF_INET6, socket.SOCK_STREAM)
            v6_addrs: List[str] = []
            for _fam, _st, _pr, _canon, sockaddr in addrs:
                ip6 = sockaddr[0]
                if ip6 not in v6_addrs:
                    v6_addrs.append(ip6)

            for ip6 in v6_addrs:
                tunnel_info = self._classify_ipv6_tunnel(ip6)
                if tunnel_info:
                    ttype, confidence, desc = tunnel_info
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.IPV6_TUNNEL,
                            confidence=confidence,
                            evidence=f"{ttype} tunnel endpoint: {ip6} -- {desc}",
                            destination_ip=host,
                            protocol_details={
                                "ipv6_address": ip6,
                                "tunnel_technology": ttype,
                            },
                        )
                    )
        except (socket.gaierror, OSError) as exc:
            logger.debug("IPv6 AAAA lookup failed for %s: %s", host, exc)

        # 2. Check DNS for tunnel-related subdomains
        tunnel_subdomains = [
            ("teredo", "teredo.{host}"),
            ("isatap", "isatap.{host}"),
            ("6to4", "6to4.{host}"),
            ("ipv6", "ipv6.{host}"),
        ]
        for tname, subdomain in tunnel_subdomains:
            try:
                addrs = socket.getaddrinfo(subdomain, None)
                if addrs:
                    ip = addrs[0][4][0]
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.IPV6_TUNNEL,
                            confidence=0.65,
                            evidence=(
                                f"Tunnel-related subdomain '{subdomain}' resolves to {ip}"
                            ),
                            destination_ip=host,
                            protocol_details={
                                "tunnel_subdomain": subdomain,
                                "resolved_ip": ip,
                            },
                        )
                    )
            except socket.gaierror:
                continue

        return indicators

    # -- GRE tunnel --------------------------------------------------------

    def detect_gre_tunnel(
        self, host: str, timeout: int = 8
    ) -> List[TunnelIndicator]:
        """Check for GRE protocol (IP protocol 47) availability.

        GRE tunneling cannot be reliably detected without raw sockets or
        captured traffic, so we check indirect indicators:
        - PPTP port 1723 (often used with GRE)
        - DNS records suggesting VPN infrastructure
        - Known GRE-tunnel-friendly patterns
        """
        indicators: List[TunnelIndicator] = []

        # 1. Check PPTP port (1723) -- commonly paired with GRE
        pptp_open = self._check_port(host, 1723, timeout)
        if pptp_open:
            indicators.append(
                TunnelIndicator(
                    tunnel_type=TunnelType.GRE_TUNNEL,
                    confidence=0.55,
                    evidence=(
                        f"PPTP port 1723 is open on {host} -- "
                        f"PPTP uses GRE (protocol 47) for data"
                    ),
                    destination_ip=host,
                    protocol_details={"port_1723_open": True},
                )
            )

        # 2. Check for VPN-related DNS TXT records
        vpn_keywords = ["vpn", "tunnel", "gre", "pptp", "ipsec"]
        txt_records = self._query_txt_records(host, timeout)
        for txt in txt_records:
            for kw in vpn_keywords:
                if kw in txt.lower():
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.GRE_TUNNEL,
                            confidence=0.4,
                            evidence=f"VPN/tunnel-related TXT record: {txt[:100]}",
                            destination_ip=host,
                            protocol_details={"txt_record": txt},
                        )
                    )
                    break

        # 3. Common GRE/VPN ports
        vpn_ports = {
            47: "GRE",
            1723: "PPTP",
            500: "IKE (IPSec)",
            4500: "NAT-T (IPSec)",
            1194: "OpenVPN",
            1293: "IPSec",
            2134: "GRE over IP",
        }
        open_ports: Dict[int, str] = {}
        for port, name in vpn_ports.items():
            if port == 1723:  # already checked
                continue
            if self._check_port(host, port, timeout):
                open_ports[port] = name

        if open_ports:
            indicators.append(
                TunnelIndicator(
                    tunnel_type=TunnelType.GRE_TUNNEL,
                    confidence=0.45,
                    evidence=(
                        f"VPN/tunnel ports open: "
                        + ", ".join(f"{p} ({n})" for p, n in open_ports.items())
                    ),
                    destination_ip=host,
                    protocol_details={"open_vpn_ports": open_ports},
                )
            )

        return indicators

    # -- SSH tunnel --------------------------------------------------------

    def detect_ssh_tunnel(
        self, host: str, timeout: int = 8,
        dest_ip: Optional[str] = None
    ) -> List[TunnelIndicator]:
        """Check SSH port 22 availability and analyse the banner.

        An open SSH port with a permissive configuration (e.g. allowing
        port forwarding) is a potential tunneling vector.
        """
        indicators: List[TunnelIndicator] = []

        ssh_port = 22
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, ssh_port))
            if result != 0:
                sock.close()
                return indicators

            # Read banner
            banner = b""
            try:
                banner = sock.recv(1024)
            except OSError:
                pass
            sock.close()

            banner_text = banner.decode("utf-8", errors="replace").strip()

            if not banner_text:
                return indicators

            details: Dict[str, Any] = {
                "port": ssh_port,
                "banner": banner_text,
            }

            indicators.append(
                TunnelIndicator(
                    tunnel_type=TunnelType.SSH_TUNNEL,
                    confidence=0.5,
                    evidence=f"SSH port {ssh_port} is open: {banner_text}",
                    destination_ip=dest_ip or host,
                    protocol_details=details,
                )
            )

            # Analyse banner for tunnel-friendly software
            tunnel_friendly = [
                (r"OpenSSH", 0.5, "OpenSSH supports Local/Remote/Dynamic port forwarding"),
                (r"Dropbear", 0.55, "Dropbear is a lightweight SSH often used in embedded tunnel setups"),
                (r"libssh", 0.45, "libssh library-based server -- programmatic tunneling possible"),
            ]
            for pattern, conf, desc in tunnel_friendly:
                if re.search(pattern, banner_text, re.IGNORECASE):
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.SSH_TUNNEL,
                            confidence=conf,
                            evidence=f"{desc}: {banner_text}",
                            destination_ip=dest_ip or host,
                            protocol_details=details,
                        )
                    )

            # Check for non-standard SSH port (sometimes used to hide tunnels)
            # Scan common alternate SSH ports
            alt_ssh_ports = [2222, 222, 8022, 443, 8443]
            for port in alt_ssh_ports:
                try:
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(timeout)
                    r = sock2.connect_ex((host, port))
                    if r == 0:
                        alt_banner = b""
                        try:
                            alt_banner = sock2.recv(512)
                        except OSError:
                            pass
                        sock2.close()
                        alt_text = alt_banner.decode("utf-8", errors="replace").strip()
                        if "ssh" in alt_text.lower():
                            indicators.append(
                                TunnelIndicator(
                                    tunnel_type=TunnelType.SSH_TUNNEL,
                                    confidence=0.6,
                                    evidence=(
                                        f"SSH running on non-standard port {port}: {alt_text}"
                                    ),
                                    destination_ip=dest_ip or host,
                                    protocol_details={"port": port, "banner": alt_text},
                                )
                            )
                    else:
                        sock2.close()
                except OSError:
                    pass

        except OSError as exc:
            logger.debug("SSH tunnel detection failed for %s: %s", host, exc)

        return indicators

    # -- HTTP CONNECT tunnel ----------------------------------------------

    def detect_http_tunnel(
        self, base_url: str, timeout: int = 8
    ) -> List[TunnelIndicator]:
        """Check for HTTP CONNECT method support (proxy functionality).

        An open HTTP proxy allows arbitrary TCP connections, making it a
        powerful tunneling vector.
        """
        indicators: List[TunnelIndicator] = []

        parsed = urllib.parse.urlparse(base_url)
        proxy_host = parsed.hostname or ""
        proxy_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme or "http"

        # 1. Send CONNECT request
        try:
            connect_target = "example.com:443"
            conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
            conn.request("CONNECT", connect_target, headers={
                "Host": connect_target,
                "User-Agent": "ReconPro/9.2.0",
            })
            resp = conn.getresponse()
            status = resp.status
            resp.read()
            conn.close()

            if status == 200:
                indicators.append(
                    TunnelIndicator(
                        tunnel_type=TunnelType.HTTP_TUNNEL,
                        confidence=0.85,
                        evidence=(
                            f"HTTP CONNECT to {connect_target} returned 200 -- "
                            f"open proxy / tunnel endpoint"
                        ),
                        destination_ip=proxy_host,
                        protocol_details={
                            "method": "CONNECT",
                            "target": connect_target,
                            "status": status,
                        },
                    )
                )
            elif status in (403, 407):
                indicators.append(
                    TunnelIndicator(
                        tunnel_type=TunnelType.HTTP_TUNNEL,
                        confidence=0.3,
                        evidence=(
                            f"HTTP CONNECT returned {status} -- proxy detected "
                            f"but access restricted (may be exploitable with creds)"
                        ),
                        destination_ip=proxy_host,
                        protocol_details={"status": status},
                    )
                )

        except (OSError, TimeoutError, Exception) as exc:
            logger.debug("HTTP CONNECT test failed: %s", exc)

        # 2. Check for proxy-related headers in normal response
        try:
            req = urllib.request.Request(
                base_url, headers={"User-Agent": "ReconPro/9.2.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.getheaders()}

            proxy_headers = [
                ("via", "Proxy chain detected"),
                ("x-forwarded-for", "Forwarding proxy present"),
                ("forwarded", "Forwarded header present"),
                ("proxy-connection", "Proxy-Connection header (proxy behavior)"),
                ("x-proxy-id", "Proxy ID header detected"),
            ]
            for hdr, desc in proxy_headers:
                val = headers.get(hdr)
                if val:
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.HTTP_TUNNEL,
                            confidence=0.4,
                            evidence=f"{desc}: {hdr}={val}",
                            destination_ip=proxy_host,
                            protocol_details={"header": hdr, "value": val},
                        )
                    )

        except (urllib.error.URLError, OSError, TimeoutError):
            pass

        # 3. HTTPS tunnel detection (check for TLS 1.3 + large certificate chain)
        if scheme == "https":
            try:
                # We can't easily inspect TLS from stdlib, but check for HSTS
                # and certificate transparency which suggest HTTPS tunnel surface
                req = urllib.request.Request(
                    base_url, headers={"User-Agent": "ReconPro/9.2.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    hdrs = {k.lower(): v for k, v in resp.getheaders()}
                if "strict-transport-security" in hdrs:
                    indicators.append(
                        TunnelIndicator(
                            tunnel_type=TunnelType.HTTPS_TUNNEL,
                            confidence=0.25,
                            evidence=(
                                "HSTS enabled -- encrypted HTTPS tunnel surface exists "
                                "(normal for legitimate sites, but enables covert TLS tunnels)"
                            ),
                            destination_ip=proxy_host,
                            protocol_details={
                                "hsts": hdrs["strict-transport-security"]
                            },
                        )
                    )
            except (urllib.error.URLError, OSError, TimeoutError):
                pass

        return indicators

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _resolve_host(host: str) -> str:
        """Resolve hostname to IP.  Returns the IP or the original string."""
        try:
            addrs = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            if addrs:
                return addrs[0][4][0]
        except (socket.gaierror, OSError):
            pass
        return host

    @staticmethod
    def _query_txt_records(host: str, timeout: int = 5) -> List[str]:
        """Return TXT record values via dig."""
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", host],
                capture_output=True, text=True, timeout=timeout,
            )
            records: List[str] = []
            for line in result.stdout.strip().splitlines():
                line = line.strip().strip('"')
                if line:
                    records.append(line)
            return records
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

    def _probe_dns_subdomains(
        self, host: str, timeout: int = 5, count: int = 3
    ) -> List[str]:
        """Try resolving base64-like subdomains to test DNS tunnel surface."""
        import base64
        resolved: List[str] = []
        for i in range(count):
            payload = base64.b64encode(
                f"RECONPRO_TUNNEL_TEST_{i}_{datetime.now(timezone.utc).timestamp()}".encode()
            ).decode("ascii")
            label = payload[:50]  # DNS label max 63 chars
            fqdn = f"{label}.{host}"
            try:
                socket.setdefaulttimeout(timeout)
                socket.getaddrinfo(fqdn, None)
                resolved.append(fqdn)
            except socket.gaierror:
                pass
        return resolved

    @staticmethod
    def _dig_any(host: str, timeout: int = 5) -> str:
        """Run dig ANY and return stdout."""
        try:
            result = subprocess.run(
                ["dig", "+short", "ANY", host],
                capture_output=True, text=True, timeout=timeout,
            )
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    @staticmethod
    def _check_port(host: str, port: int, timeout: int = 5) -> bool:
        """Return True if a TCP connection to (host, port) succeeds."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except OSError:
            return False

    @staticmethod
    def _classify_ipv6_tunnel(ip6: str) -> Optional[Tuple[str, float, str]]:
        """Classify an IPv6 address as a known tunnel type.

        Returns ``(tunnel_name, confidence, description)`` or ``None``.
        """
        # 6to4: 2002::/16, embedded IPv4
        if ip6.startswith("2002:"):
            # Extract embedded IPv4 from bytes 2-5
            try:
                # Expand :: if needed
                parts = ip6.split(":")
                if len(parts) >= 3:
                    embedded = ".".join(
                        str(int(p, 16) if len(p) <= 4 else 0)
                        for p in parts[2:6]
                    )
                    return (
                        "6to4",
                        0.8,
                        f"6to4 tunnel with embedded IPv4: {embedded}",
                    )
            except (ValueError, IndexError):
                return ("6to4", 0.6, "6to4 tunnel prefix detected")

        # Teredo: 2001:0000::/32
        if ip6.startswith("2001:0:") or ip6.startswith("2001:0000:"):
            return (
                "Teredo",
                0.75,
                "Teredo tunnel address (2001:0::/32 prefix)",
            )

        # ISATAP: ::0200:5efe:/96 or ::0000:5efe:/96
        if ":5efe:" in ip6.lower():
            return (
                "ISATAP",
                0.8,
                f"ISATAP tunnel address (contains :5efe:)",
            )

        # 6in4 / 6rd: typically uses a /64 from a tunnel broker
        # Hard to detect from address alone, skip low-confidence guess

        return None

    @staticmethod
    def _std_dev(values: List[float]) -> float:
        """Calculate population standard deviation."""
        if not values:
            return 0.0
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        return math.sqrt(variance)

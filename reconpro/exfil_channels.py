"""
ReconPro v9.2.0 - Data Exfiltration Channel Mapping

Identifies, scores, and reports on all possible ways data could leave a target
network.  Pure Python stdlib -- zero external dependencies.

Classes:
    ExfilChannel          - Dataclass describing a single exfiltration vector.
    ExfilChannelMapper    - Probes the target to discover available channels.
    ExfilRiskScorer       - Scores channels and generates a consolidated report.
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ExfilChannel:
    """Describes a potential data-exfiltration vector.

    Attributes:
        channel_type:        Human-readable label (e.g. 'DNS Tunneling').
        viability_score:     0-100 how feasible the channel is.
        bandwidth_estimate:  Qualitative bandwidth (e.g. 'Low (~1 KB/s)').
        stealth_score:       0-100 how hard the channel is to detect.
        detection_difficulty: 0-100 difficulty for defenders to notice.
        indicators:          List of observed indicators / evidence strings.
        remediation:         Suggested fix or mitigation.
        overall_risk:        0-100 composite risk score.
    """
    channel_type: str
    viability_score: int
    bandwidth_estimate: str
    stealth_score: int
    detection_difficulty: int
    indicators: List[str] = field(default_factory=list)
    remediation: str = ""
    overall_risk: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "channel_type": self.channel_type,
            "viability_score": self.viability_score,
            "bandwidth_estimate": self.bandwidth_estimate,
            "stealth_score": self.stealth_score,
            "detection_difficulty": self.detection_difficulty,
            "indicators": self.indicators,
            "remediation": self.remediation,
            "overall_risk": self.overall_risk,
        }


# ---------------------------------------------------------------------------
# ExfilChannelMapper
# ---------------------------------------------------------------------------

class ExfilChannelMapper:
    """Probes a target to discover all potential data-exfiltration channels.

    Each ``analyze_*`` method returns an :class:`ExfilChannel` describing the
    findings for one channel type.
    """

    DEFAULT_TIMEOUT: int = 8

    def map_all_channels(
        self,
        target: str,
        base_url: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> Dict[str, Any]:
        """Run all channel analyzers and return a consolidated dict.

        Returns:
            ``{"channels": [ExfilChannel, ...], "summary": {...}}``
        """
        channels: List[ExfilChannel] = []

        # DNS exfiltration
        logger.info("[ExfilMapper] Analyzing DNS exfiltration for %s", target)
        dns_ch = self.analyze_dns_exfil(target, timeout=timeout)
        channels.append(dns_ch)

        # HTTP exfiltration
        if base_url:
            logger.info("[ExfilMapper] Analyzing HTTP exfiltration for %s", base_url)
            http_ch = self.analyze_http_exfil(base_url, timeout=timeout)
            channels.append(http_ch)

            # WebSocket exfiltration
            logger.info("[ExfilMapper] Analyzing WebSocket exfiltration for %s", base_url)
            ws_ch = self.analyze_websocket_exfil(base_url, timeout=timeout)
            channels.append(ws_ch)

            # Cloud exfiltration
            logger.info("[ExfilMapper] Analyzing cloud exfiltration for %s", base_url)
            cloud_ch = self.analyze_cloud_exfil(base_url, timeout=timeout)
            channels.append(cloud_ch)

        # Email exfiltration
        logger.info("[ExfilMapper] Analyzing email exfiltration for %s", target)
        email_ch = self.analyze_email_exfil(target, timeout=timeout)
        channels.append(email_ch)

        # ICMP exfiltration
        logger.info("[ExfilMapper] Analyzing ICMP exfiltration for %s", target)
        icmp_ch = self.analyze_icmp_exfil(target, timeout=timeout)
        channels.append(icmp_ch)

        # Score each channel
        scorer = ExfilRiskScorer()
        scored = scorer.score_channels(channels)

        return {
            "channels": scored,
            "summary": scorer.generate_exfil_report(scored),
        }

    # -- DNS exfiltration --------------------------------------------------

    def analyze_dns_exfil(self, host: str, timeout: int = 8) -> ExfilChannel:
        """Assess DNS-based exfiltration risk.

        Checks for:
        - Open DNS resolvers
        - TXT record support (large payloads)
        - Whether subdomains accept arbitrary labels (base64 tunneling)
        """
        indicators: List[str] = []
        viability = 0
        stealth = 50
        detection = 50

        # 1. Check if we can resolve arbitrary subdomain (open resolver indicator)
        test_label = "reconpro_test_exfil_" + datetime.now(timezone.utc).strftime("%H%M%S")
        test_fqdn = f"{test_label}.{host}"
        try:
            socket.setdefaulttimeout(timeout)
            addrs = socket.getaddrinfo(test_fqdn, None)
            if addrs:
                indicators.append(
                    f"Wildcard DNS: {test_fqdn} resolved (accepts arbitrary subdomains)"
                )
                viability += 30
                stealth += 15
        except socket.gaierror:
            indicators.append("No wildcard DNS -- arbitrary subdomains rejected")
            viability += 5

        # 2. Try to fetch TXT records (for payload capacity)
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", host],
                capture_output=True, text=True, timeout=timeout,
            )
            txt_output = result.stdout.strip()
            if txt_output:
                lines = txt_output.splitlines()
                indicators.append(f"TXT records present ({len(lines)} records)")
                total_len = sum(len(l) for l in lines)
                indicators.append(f"Combined TXT payload capacity: {total_len} bytes")
                viability += 25
                if total_len > 255:
                    viability += 10
                    stealth += 10
                    indicators.append("Large TXT records suggest data encoding capability")
            else:
                indicators.append("No TXT records found")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            indicators.append("dig not available for TXT analysis")

        # 3. Check for DNS-over-HTTPS support (encrypted tunnel)
        doh_hosts = ["dns.google", "cloudflare-dns.com", "dns.quad9.net"]
        for doh in doh_hosts:
            try:
                doh_url = f"https://{doh}/resolve?name={host}&type=A"
                req = urllib.request.Request(doh_url, headers={
                    "User-Agent": "ReconPro/9.2.0",
                    "Accept": "application/dns-json",
                })
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode())
                    if data.get("Answer"):
                        indicators.append(
                            f"DoH resolver {doh} is reachable (potential encrypted tunnel)"
                        )
                        viability += 15
                        stealth += 20
                        break
            except (urllib.error.URLError, OSError, json.JSONDecodeError):
                continue

        # 4. Check base64-like subdomain acceptance
        b64_test = self._generate_base64_subdomain(host, timeout)
        if b64_test:
            indicators.append(b64_test)
            viability += 20
            stealth += 15

        viability = min(viability, 100)
        stealth = min(stealth, 100)
        detection = min(detection, 100)

        return ExfilChannel(
            channel_type="DNS Tunneling",
            viability_score=viability,
            bandwidth_estimate=self._dns_bandwidth_label(viability),
            stealth_score=stealth,
            detection_difficulty=detection,
            indicators=indicators,
            remediation=(
                "Implement DNS query logging and anomaly detection. "
                "Block or rate-limit long/entropy-high subdomain queries. "
                "Restrict recursive DNS to authorized resolvers only."
            ),
        )

    # -- HTTP exfiltration -------------------------------------------------

    def analyze_http_exfil(self, base_url: str, timeout: int = 8) -> ExfilChannel:
        """Assess HTTP-based exfiltration risk.

        Checks for:
        - POST endpoint availability
        - Upload form presence
        - CORS wildcard (Access-Control-Allow-Origin: *)
        - Large response body capacity
        - Redirect targets (open redirect for data exfil)
        """
        indicators: List[str] = []
        viability = 0
        stealth = 30
        detection = 40

        try:
            req = urllib.request.Request(
                base_url, headers={"User-Agent": "ReconPro/9.2.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in resp.getheaders()}
                status = resp.getcode()
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return ExfilChannel(
                channel_type="HTTP Exfiltration",
                viability_score=0,
                bandwidth_estimate="None",
                stealth_score=0,
                detection_difficulty=0,
                indicators=[f"Could not reach {base_url}: {exc}"],
                remediation="N/A -- host unreachable.",
            )

        indicators.append(f"HTTP {status} response received")

        # 1. Check CORS
        cors = headers.get("access-control-allow-origin", "")
        if cors == "*":
            indicators.append("CORS wildcard (*) -- any origin can read responses")
            viability += 35
            stealth += 20
            detection -= 10
        elif cors:
            indicators.append(f"CORS restricted to: {cors}")
            viability += 10
        else:
            indicators.append("No CORS header present")

        # 2. Check for upload forms
        upload_patterns = [
            r'<form[^>]*enctype=["\']multipart/form-data["\']',
            r'<input[^>]*type=["\']file["\']',
            r'<form[^>]*method=["\']post["\'][^>]*>',
        ]
        form_count = 0
        for pat in upload_patterns:
            matches = re.findall(pat, body, re.IGNORECASE)
            if matches:
                form_count += len(matches)
        if form_count > 0:
            indicators.append(f"Found {form_count} upload-capable form element(s)")
            viability += 30
            stealth += 10

        # 3. Check Content-Length / body size
        body_size = len(body)
        indicators.append(f"Response body size: {body_size} bytes")
        if body_size > 100_000:
            indicators.append("Large response body suggests high-bandwidth capability")
            viability += 15
        elif body_size > 10_000:
            viability += 5

        # 4. Check for JSON API endpoints in body
        json_endpoints = re.findall(r'["\'](/[\w/._-]+)["\']\s*:', body)
        api_paths = [p for p in json_endpoints if any(
            kw in p.lower() for kw in ("api", "upload", "submit", "send", "log", "track")
        )]
        if api_paths:
            indicators.append(f"Potential API endpoints: {', '.join(set(api_paths[:5]))}")
            viability += 20

        # 5. Check for redirect targets
        redirects = re.findall(r'(?:href|action|location)\s*=\s*["\']((?:https?://|/)[^"\'>\s]+)', body, re.IGNORECASE)
        external = [r for r in redirects if r.startswith("http") and not self._same_origin(r, base_url)]
        if external:
            indicators.append(f"{len(external)} external URL(s) found in page")
            viability += 10

        # 6. Check for tracking / analytics scripts
        analytics_patterns = [
            r'google-analytics\.com',
            r'googletagmanager\.com',
            r'facebook\.net/en_US/fbevents',
            r'connect\.facebook\.net',
            r'hotjar\.com',
            r'clarity\.ms',
            r'segment\.com',
            r'mixpanel\.com',
        ]
        for pat in analytics_patterns:
            if re.search(pat, body, re.IGNORECASE):
                indicators.append(f"Analytics/tracking script detected: {pat}")
                viability += 10
                stealth += 15
                break

        viability = min(max(viability, 0), 100)
        stealth = min(max(stealth, 0), 100)
        detection = min(max(detection, 0), 100)

        return ExfilChannel(
            channel_type="HTTP Exfiltration",
            viability_score=viability,
            bandwidth_estimate=self._http_bandwidth_label(viability, body_size),
            stealth_score=stealth,
            detection_difficulty=detection,
            indicators=indicators,
            remediation=(
                "Restrict CORS to specific trusted origins. "
                "Implement request size limits and content-type validation. "
                "Use CSP headers to restrict outbound connections. "
                "Monitor for anomalous POST volume to unusual endpoints."
            ),
        )

    # -- WebSocket exfiltration -------------------------------------------

    def analyze_websocket_exfil(self, base_url: str, timeout: int = 8) -> ExfilChannel:
        """Assess WebSocket-based exfiltration risk.

        Checks for:
        - WebSocket endpoint availability (upgrade headers in response)
        - wss:// references in page source
        - Binary frame support indicators
        """
        indicators: List[str] = []
        viability = 0
        stealth = 40
        detection = 45

        # 1. Try HTTP upgrade
        try:
            ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://")
            req = urllib.request.Request(
                ws_url,
                headers={
                    "User-Agent": "ReconPro/9.2.0",
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Sec-WebSocket-Version": "13",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.getcode()
                resp_headers = {k.lower(): v for k, v in resp.getheaders()}
                if status in (101, 200, 301, 302, 400, 426):
                    # 426 = Upgrade Required, indicates WS support
                    if status == 426 or "websocket" in resp_headers.get("upgrade", "").lower():
                        indicators.append(f"WebSocket upgrade supported (HTTP {status})")
                        viability += 40
                        stealth += 20
                    elif status in (200, 301, 302):
                        indicators.append(f"HTTP {status} -- server responded to WS handshake")
                        viability += 10
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            indicators.append(f"WebSocket probe failed: {exc}")

        # 2. Check page source for WebSocket URLs
        try:
            req = urllib.request.Request(
                base_url, headers={"User-Agent": "ReconPro/9.2.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, TimeoutError):
            body = ""

        ws_patterns = [
            r'wss?://[\w.-]+(?::\d+)?[\w/._-]*',
            r'new\s+WebSocket\s*\(',
            r'\.onmessage\s*=',
            r'\.send\(\s*[\w]+\)',
        ]
        ws_urls: List[str] = []
        for pat in ws_patterns:
            matches = re.findall(pat, body, re.IGNORECASE)
            for m in matches:
                if m.startswith("wss://") or m.startswith("ws://"):
                    ws_urls.append(m)
        if ws_urls:
            unique = list(dict.fromkeys(ws_urls))
            indicators.append(f"WebSocket URL(s) found: {', '.join(unique[:5])}")
            viability += 30
            stealth += 15

        # 3. Check for binary data handling patterns
        binary_patterns = [
            r'ArrayBuffer',
            r'Blob\s*\(',
            r'binaryType\s*[:=]\s*["\']arraybuffer["\']',
            r'Int8Array|Uint8Array|DataView',
        ]
        binary_found = False
        for pat in binary_patterns:
            if re.search(pat, body, re.IGNORECASE):
                binary_found = True
                break
        if binary_found:
            indicators.append("Binary frame handling code detected (ArrayBuffer/Blob)")
            viability += 15
            stealth += 10

        # 4. Socket.IO / SignalR detection
        realtime_libs = [
            r'socket\.io',
            r'signalr',
            r'pusher',
            r'ably\.io',
            r'phoenix\s*channel',
        ]
        for pat in realtime_libs:
            if re.search(pat, body, re.IGNORECASE):
                indicators.append(f"Real-time library detected: {pat}")
                viability += 15
                break

        viability = min(max(viability, 0), 100)
        stealth = min(max(stealth, 0), 100)
        detection = min(max(detection, 0), 100)

        return ExfilChannel(
            channel_type="WebSocket Exfiltration",
            viability_score=viability,
            bandwidth_estimate="High (~100+ KB/s)" if viability > 50 else "Low (~10 KB/s)",
            stealth_score=stealth,
            detection_difficulty=detection,
            indicators=indicators,
            remediation=(
                "Restrict WebSocket endpoints with authentication. "
                "Implement message size limits and rate limiting. "
                "Monitor WebSocket traffic for anomalous data volumes. "
                "Use WAF rules to detect binary data patterns."
            ),
        )

    # -- Email exfiltration -----------------------------------------------

    def analyze_email_exfil(self, host: str, timeout: int = 8) -> ExfilChannel:
        """Assess email-based exfiltration risk.

        Checks for:
        - MX records (mail servers)
        - SPF, DKIM, DMARC records
        - Open SMTP relay (port 25 check)
        """
        indicators: List[str] = []
        viability = 0
        stealth = 35
        detection = 30

        # 1. MX records
        try:
            mx_result = subprocess.run(
                ["dig", "+short", "MX", host],
                capture_output=True, text=True, timeout=timeout,
            )
            mx_output = mx_result.stdout.strip()
            if mx_output:
                mx_lines = [l.strip() for l in mx_output.splitlines() if l.strip()]
                indicators.append(f"MX records ({len(mx_lines)}): {', '.join(mx_lines[:3])}")
                viability += 25
            else:
                indicators.append("No MX records found")
                viability += 5
        except (FileNotFoundError, subprocess.TimeoutExpired):
            indicators.append("dig not available for MX lookup")

        # 2. SPF record
        try:
            spf_result = subprocess.run(
                ["dig", "+short", "TXT", host],
                capture_output=True, text=True, timeout=timeout,
            )
            for line in spf_result.stdout.strip().splitlines():
                if 'v=spf1' in line.lower():
                    indicators.append(f"SPF record: {line}")
                    if "+all" in line or "?all" in line:
                        indicators.append("SPF allows any sender (+all or ?all) -- weak policy")
                        viability += 20
                    elif "-all" in line or "~all" in line:
                        indicators.append("SPF has strict/soft fail policy")
                    viability += 10
                    break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # 3. DMARC record
        try:
            dmarc_domain = f"_dmarc.{host}"
            dmarc_result = subprocess.run(
                ["dig", "+short", "TXT", dmarc_domain],
                capture_output=True, text=True, timeout=timeout,
            )
            dmarc_output = dmarc_result.stdout.strip()
            if dmarc_output and "v=dmarc1" in dmarc_output.lower():
                indicators.append(f"DMARC record present: {dmarc_output}")
                if "p=none" in dmarc_output.lower():
                    indicators.append("DMARC policy is 'none' -- no enforcement")
                    viability += 15
            else:
                indicators.append("No DMARC record found -- email spoofing possible")
                viability += 20
        except (FileNotFoundError, subprocess.TimeoutExpired):
            indicators.append("dig not available for DMARC lookup")

        # 4. DKIM record
        try:
            # Common DKIM selector names
            for selector in ("default", "google", "selector1", "selector2", "k1"):
                dkim_domain = f"{selector}._domainkey.{host}"
                dkim_result = subprocess.run(
                    ["dig", "+short", "TXT", dkim_domain],
                    capture_output=True, text=True, timeout=timeout,
                )
                if dkim_result.stdout.strip():
                    indicators.append(f"DKIM record found (selector: {selector})")
                    viability += 5
                    break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # 5. Open SMTP check (port 25)
        smtp_open = self._check_smtp_open(host, timeout)
        if smtp_open:
            indicators.append(f"SMTP port 25 is OPEN on {host}")
            viability += 35
            stealth += 20
        else:
            indicators.append("SMTP port 25 is closed or filtered")

        viability = min(max(viability, 0), 100)
        stealth = min(max(stealth, 0), 100)
        detection = min(max(detection, 0), 100)

        return ExfilChannel(
            channel_type="Email Exfiltration",
            viability_score=viability,
            bandwidth_estimate="Low (~10 KB/s)" if viability < 50 else "Medium (~50 KB/s)",
            stealth_score=stealth,
            detection_difficulty=detection,
            indicators=indicators,
            remediation=(
                "Publish and enforce strict DMARC (p=reject), SPF (-all), and DKIM. "
                "Close open SMTP relays (port 25). "
                "Implement email gateway DLP and outbound scanning. "
                "Block external email from untrusted internal hosts."
            ),
        )

    # -- ICMP exfiltration -------------------------------------------------

    def analyze_icmp_exfil(self, host: str, timeout: int = 8) -> ExfilChannel:
        """Assess ICMP-based exfiltration risk.

        Checks for:
        - Ping response via subprocess
        - Payload size in responses
        - Timing patterns
        """
        indicators: List[str] = []
        viability = 10
        stealth = 55
        detection = 60

        # 1. Basic ping
        try:
            result = subprocess.run(
                ["ping", "-c", "4", "-W", str(timeout), host],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            output = result.stdout + result.stderr

            if result.returncode == 0:
                indicators.append(f"Host responds to ICMP echo (ping)")
                viability += 20

                # Parse payload size
                size_match = re.search(r'(?:bytes from|icmp_seq=\d+ ttl=\d+ time=)[^\n]*?(\d+)\s*bytes', output)
                if size_match:
                    payload_size = int(size_match.group(1))
                    indicators.append(f"ICMP payload size: {payload_size} bytes")
                    if payload_size >= 64:
                        indicators.append("Payload > 64 bytes -- potential data carrier")
                        viability += 15
                        stealth += 10

                # Parse timing for jitter
                times = re.findall(r'time=([\d.]+)\s*ms', output)
                if len(times) >= 2:
                    floats = [float(t) for t in times]
                    avg_time = sum(floats) / len(floats)
                    jitter = max(floats) - min(floats)
                    indicators.append(
                        f"ICMP timing: avg={avg_time:.1f}ms, jitter={jitter:.1f}ms, samples={len(floats)}"
                    )
                    if jitter < 5.0:
                        indicators.append("Low jitter -- stable timing for covert channel")
                        viability += 10

                # Check TTL
                ttl_match = re.search(r'ttl=(\d+)', output)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    indicators.append(f"TTL: {ttl}")
            else:
                indicators.append("Host does not respond to ICMP echo")
                viability = 0
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            indicators.append(f"Ping unavailable: {exc}")
            viability = 5

        # 2. Check if large ICMP payloads are accepted
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-s", "1024", "-W", str(timeout), host],
                capture_output=True, text=True, timeout=timeout + 5,
            )
            if result.returncode == 0:
                indicators.append("Large ICMP payload (1024+ bytes) accepted")
                viability += 25
                stealth += 15
            else:
                indicators.append("Large ICMP payload rejected or filtered")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        viability = min(max(viability, 0), 100)
        stealth = min(max(stealth, 0), 100)
        detection = min(max(detection, 0), 100)

        return ExfilChannel(
            channel_type="ICMP Exfiltration",
            viability_score=viability,
            bandwidth_estimate="Very Low (~100 B/s)" if viability < 50 else "Low (~1 KB/s)",
            stealth_score=stealth,
            detection_difficulty=detection,
            indicators=indicators,
            remediation=(
                "Block outbound ICMP at the firewall except for essential diagnostics. "
                "Implement IDS rules for oversized or unusual ICMP payloads. "
                "Monitor for abnormal ICMP frequency and timing patterns. "
                "Rate-limit ICMP per source."
            ),
        )

    # -- Cloud exfiltration -----------------------------------------------

    def analyze_cloud_exfil(self, base_url: str, timeout: int = 8) -> ExfilChannel:
        """Assess cloud-storage-based exfiltration risk.

        Checks for:
        - AWS S3 bucket references
        - Google Cloud Storage references
        - Azure Blob Storage references
        - Other cloud endpoints (Dropbox, etc.)
        """
        indicators: List[str] = []
        viability = 0
        stealth = 45
        detection = 50

        # 1. Fetch page body
        try:
            req = urllib.request.Request(
                base_url, headers={"User-Agent": "ReconPro/9.2.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            return ExfilChannel(
                channel_type="Cloud Storage Exfiltration",
                viability_score=0,
                bandwidth_estimate="None",
                stealth_score=0,
                detection_difficulty=0,
                indicators=[f"Could not reach {base_url}: {exc}"],
                remediation="N/A -- host unreachable.",
            )

        # 2. S3 bucket detection
        s3_patterns = [
            r's3\.amazonaws\.com/[\w.-]+',
            r'[\w.-]+\.s3\.amazonaws\.com',
            r's3\.console\.aws\.amazon\.com',
            r'aws\.amazonaws\.com',
            r'bucket\.s3\.amazonaws',
        ]
        s3_refs: List[str] = []
        for pat in s3_patterns:
            matches = re.findall(pat, body, re.IGNORECASE)
            s3_refs.extend(matches)
        if s3_refs:
            unique_s3 = list(dict.fromkeys(s3_refs))
            indicators.append(f"AWS S3 reference(s) found: {', '.join(unique_s3[:5])}")
            viability += 35
            stealth += 15

        # 3. GCS detection
        gcs_patterns = [
            r'storage\.googleapis\.com/[\w.-]+',
            r'[\w.-]+\.storage\.googleapis\.com',
            r'gs://[\w.-]+',
        ]
        gcs_refs: List[str] = []
        for pat in gcs_patterns:
            matches = re.findall(pat, body, re.IGNORECASE)
            gcs_refs.extend(matches)
        if gcs_refs:
            unique_gcs = list(dict.fromkeys(gcs_refs))
            indicators.append(f"GCS reference(s) found: {', '.join(unique_gcs[:5])}")
            viability += 30
            stealth += 15

        # 4. Azure Blob detection
        azure_patterns = [
            r'[\w]+\.blob\.core\.windows\.net',
            r'[\w]+\.file\.core\.windows\.net',
            r'azurestorage',
            r'azure\.net',
        ]
        azure_refs: List[str] = []
        for pat in azure_patterns:
            matches = re.findall(pat, body, re.IGNORECASE)
            azure_refs.extend(matches)
        if azure_refs:
            unique_az = list(dict.fromkeys(azure_refs))
            indicators.append(f"Azure Storage reference(s) found: {', '.join(unique_az[:5])}")
            viability += 30
            stealth += 15

        # 5. Other cloud services
        other_patterns = [
            (r'dropbox\.com/s/[\w]+', 'Dropbox'),
            (r'drive\.google\.com', 'Google Drive'),
            (r'docs\.google\.com', 'Google Docs'),
            (r'onedrive\.live\.com', 'OneDrive'),
            (r'github\.com/[\w-]+/[\w-]+', 'GitHub'),
            (r'pastebin\.com', 'Pastebin'),
        ]
        for pat, service in other_patterns:
            if re.search(pat, body, re.IGNORECASE):
                indicators.append(f"{service} reference detected")
                viability += 15
                break

        # 6. Check for API keys / credentials in source
        cred_patterns = [
            r'AKIA[0-9A-Z]{16}',  # AWS access key
            r'AIza[\w-]{35}',  # Google API key
            r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+',  # JWT
        ]
        for pat in cred_patterns:
            if re.search(pat, body):
                indicators.append(f"Potential credential/API key pattern detected: {pat[:30]}...")
                viability += 25
                stealth += 20
                break

        # 7. Check for upload SDK references
        upload_sdks = [
            r'aws-sdk', r'@aws-sdk',
            r'google-cloud/storage', r'@google-cloud/storage',
            r'azure/storage-blob', r'@azure/storage-blob',
            r'multer', r'formidable', r'busboy',
        ]
        for sdk in upload_sdks:
            if re.search(re.escape(sdk), body, re.IGNORECASE):
                indicators.append(f"Cloud upload SDK detected: {sdk}")
                viability += 15
                break

        if not indicators:
            indicators.append("No cloud storage references found in page source")

        viability = min(max(viability, 0), 100)
        stealth = min(max(stealth, 0), 100)
        detection = min(max(detection, 0), 100)

        return ExfilChannel(
            channel_type="Cloud Storage Exfiltration",
            viability_score=viability,
            bandwidth_estimate="High (1+ MB/s)" if viability > 60 else "Medium (~100 KB/s)",
            stealth_score=stealth,
            detection_difficulty=detection,
            indicators=indicators,
            remediation=(
                "Implement CASB (Cloud Access Security Broker) to monitor cloud traffic. "
                "Restrict outbound access to approved cloud storage endpoints. "
                "Scan source code for exposed API keys and rotate them. "
                "Use DLP to inspect data before it reaches cloud services."
            ),
        )

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _generate_base64_subdomain(host: str, timeout: int = 5) -> Optional[str]:
        """Try resolving a base64-looking subdomain to test DNS tunneling surface."""
        import base64
        payload = base64.b64encode(
            b"RECONPRO_EXFIL_TEST_PAYLOAD_12345"
        ).decode("ascii")
        # Split into DNS-label-sized chunks
        chunks = [payload[i:i+60] for i in range(0, len(payload), 60)]
        test_fqdn = ".".join(chunks) + f".{host}"
        try:
            socket.setdefaulttimeout(timeout)
            addrs = socket.getaddrinfo(test_fqdn, None)
            if addrs:
                return f"Base64 subdomain resolved: {test_fqdn[:80]}..."
        except socket.gaierror:
            pass
        return None

    @staticmethod
    def _check_smtp_open(host: str, timeout: int = 5) -> bool:
        """Check if port 25 (SMTP) is open via TCP connect."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, 25))
            banner = b""
            if result == 0:
                try:
                    banner = sock.recv(512)
                except OSError:
                    pass
            sock.close()
            return result == 0
        except OSError:
            return False

    @staticmethod
    def _same_origin(url: str, base_url: str) -> bool:
        """Check if *url* shares the same origin as *base_url*."""
        try:
            parsed_url = urllib.parse.urlparse(url)
            parsed_base = urllib.parse.urlparse(base_url)
            return parsed_url.netloc.lower() == parsed_base.netloc.lower()
        except ValueError:
            return False

    @staticmethod
    def _dns_bandwidth_label(viability: int) -> str:
        if viability >= 70:
            return "Medium (~10 KB/s)"
        if viability >= 40:
            return "Low (~1 KB/s)"
        return "Very Low (<1 KB/s)"

    @staticmethod
    def _http_bandwidth_label(viability: int, body_size: int) -> str:
        if viability >= 70 or body_size > 100_000:
            return "High (100+ KB/s)"
        if viability >= 40 or body_size > 10_000:
            return "Medium (~50 KB/s)"
        return "Low (~10 KB/s)"


# ---------------------------------------------------------------------------
# ExfilRiskScorer
# ---------------------------------------------------------------------------

class ExfilRiskScorer:
    """Score exfiltration channels and produce a summary report."""

    @staticmethod
    def score_channel(channel: ExfilChannel) -> ExfilChannel:
        """Calculate the overall_risk for a single channel.

        Formula: ``overall_risk = 0.4*viability + 0.3*stealth + 0.3*detection_difficulty``
        """
        channel.overall_risk = int(
            0.4 * channel.viability_score
            + 0.3 * channel.stealth_score
            + 0.3 * channel.detection_difficulty
        )
        return channel

    def score_channels(self, channels: List[ExfilChannel]) -> List[ExfilChannel]:
        """Score a list of channels, sorted by overall_risk descending."""
        for ch in channels:
            self.score_channel(ch)
        return sorted(channels, key=lambda c: c.overall_risk, reverse=True)

    def generate_exfil_report(self, channels: List[ExfilChannel]) -> Dict[str, Any]:
        """Produce a summary report dict for all scored channels."""
        if not channels:
            return {"error": "No channels analysed"}

        total_channels = len(channels)
        critical = [c for c in channels if c.overall_risk >= 70]
        high = [c for c in channels if 50 <= c.overall_risk < 70]
        medium = [c for c in channels if 30 <= c.overall_risk < 50]
        low = [c for c in channels if c.overall_risk < 30]

        avg_risk = sum(c.overall_risk for c in channels) / total_channels
        max_risk = max(c.overall_risk for c in channels)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_channels": total_channels,
            "average_risk": round(avg_risk, 1),
            "max_risk": max_risk,
            "risk_breakdown": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
            },
            "critical_channels": [c.channel_type for c in critical],
            "channels": [c.to_dict() for c in channels],
            "recommendations": self._top_recommendations(channels),
        }

    @staticmethod
    def _top_recommendations(channels: List[ExfilChannel]) -> List[str]:
        """Return the top 3 remediation strings from the highest-risk channels."""
        recs: List[str] = []
        for ch in channels:
            if ch.remediation and ch.remediation not in recs:
                recs.append(ch.remediation)
            if len(recs) >= 3:
                break
        return recs

from __future__ import annotations

import re
from typing import Any, Dict, List
from ..http_layer import http_probe, Finding


BOT_SIGNATURES = [
    ("Mirai C2", [r"\x00\x00.*\x00", r"mi\x00rak\x00i"], ["/c2"]),
    ("Cobalt Strike Beacon", [r"cobalt.?strike", r"c2\.config", r"sleep\.mask", r"jitter"], ["/beacon", "/c2", "/api/beacon"]),
    ("Metasploit Handler", [r"metasploit", r"meterpreter", r"reverse_tcp", r"payload/stage"], ["/metasploit", "/msf"]),
    ("Emotet C2", [r"emotet", r"geodo", r"heodo"], None),
    ("TrickBot C2", [r"trickbot", r"trickloader", r"trick_door", r"postback"], None),
    ("QakBot C2", [r"qakbot", r"qbot", r"pink.?botnet", r"chthonic"], None),
    ("SolarWinds SUNBURST", [r"solarwinds", r"sunburst", r"s\.?orion", r"supernova"], None),
    ("Log4Shell Exploitation", [r"jndi:ldap", r"jndi:rmi", r"log4j", r"log4shell", r"\$\{jndi:"], None),
    ("Generic Bot Panel", ["botnet", "bot panel", "c2 panel", "command & control"], ["/c2"]),
    ("DGA Domain", None, None),
]

C2_INDICATORS = [
    "botnet", "c2 server", "command and control", "zombie",
    "bot panel", "ddos panel", "stresser", "booter",
    "cobalt strike", "beacon", "meterpreter", "metasploit",
    "emotet", "trickbot", "qakbot", "solarwinds",
    "jndi:ldap", "jndi:rmi", "log4shell", "log4j",
    "reverse_shell", "backdoor", "webshell",
    "malware", "trojan", "rat.exe", "implant",
]


def _check_bot_indicators(body: str, headers: Dict[str, str]) -> List[str]:
    """Check if a response looks like a bot/C2 panel."""
    found = []
    haystack = (body + " " + " ".join(headers.values())).lower()
    for indicator in C2_INDICATORS:
        if indicator in haystack:
            found.append(indicator)
    return found


def _check_common_c2_paths(base_url: str, timeout: int = 8,
                             verify_tls: bool = True) -> List[Finding]:
    """Probe common C2/bot panel paths."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    c2_paths = [
        "/c2", "/bot", "/panel", "/admin.php", "/gate.php",
        "/config.php", "/task.php", "/report.php",
        "/api/bot", "/api/c2", "/api/task",
        "/wp-content/plugins/", "/shell.php", "/backdoor.php",
        "/.hidden/", "/_hidden/", "/temp/", "/cache/",
    ]

    for path in c2_paths:
        url = base_url.rstrip("/") + path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body = resp.get("body", "")[:4096]
        headers = resp.get("headers", {})

        if status == 200 and len(body) > 10:
            indicators = _check_bot_indicators(body, headers)
            if indicators:
                findings.append(Finding(
                    title="Bot/C2 panel: {}".format(path),
                    severity="critical", category="bot_detection",
                    module="bot",
                    description="Bot/C2 indicators found at {}: {}".format(path, ", ".join(indicators)),
                    evidence="GET {} -> 200, indicators: {}".format(path, ", ".join(indicators)),
                    asset=host, points_deducted=15,
                    remediation="Remove any bot/C2 panels. Scan for compromise.",
                ))

            php_sigs = ["eval(", "base64_decode(", "system(", "exec(",
                       "passthru(", "shell_exec(", "assert(", "preg_replace.*e"]
            for sig in php_sigs:
                if sig in body:
                    findings.append(Finding(
                        title="Potential webshell: {}".format(path),
                        severity="critical", category="webshell",
                        module="bot",
                        description="PHP webshell signature '{}' found at {}".format(sig, path),
                        evidence="GET {} -> 200, signature: {}".format(path, sig),
                        asset=host, points_deducted=15,
                        remediation="Remove the webshell immediately. Audit server access logs.",
                    ))
                    break

    return findings


def _check_malware_signatures(base_url: str, timeout: int = 8,
                               verify_tls: bool = True) -> List[Finding]:
    """Check response against known malware family signatures."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    for name, patterns, paths in BOT_SIGNATURES:
        if patterns is None:
            continue
        targets = [base_url]
        if paths:
            targets = [base_url.rstrip("/") + p for p in paths]
        for target_url in targets:
            try:
                resp = http_probe(target_url, timeout=timeout, verify_tls=verify_tls)
                haystack = (resp.get("body", "")[:8192] + " " + " ".join(resp.get("headers", {}).values())).lower()
                for pat in patterns:
                    try:
                        if re.search(pat, haystack, re.IGNORECASE):
                            findings.append(Finding(
                                title="{} signature detected".format(name),
                                severity="critical", category="malware_signature",
                                module="bot",
                                description="Known malware signature for {} found at {}".format(name, target_url[:80]),
                                evidence="Pattern: {}".format(pat[:60]),
                                asset=host, points_deducted=15,
                                remediation="Isolate the host. Investigate for compromise. Block C2 domains at firewall.",
                            ))
                            break
                    except re.error:
                        if pat.lower() in haystack:
                            findings.append(Finding(
                                title="{} signature detected".format(name),
                                severity="critical", category="malware_signature",
                                module="bot",
                                description="Known malware signature for {} found".format(name),
                                evidence="String match: {}".format(pat[:60]),
                                asset=host, points_deducted=15,
                                remediation="Isolate the host. Investigate for compromise.",
                            ))
                            break
            except Exception:
                pass
    return findings


def _check_honeypot_signs(base_url: str, timeout: int = 8,
                          verify_tls: bool = True) -> List[Finding]:
    """Detect if the target might be a honeypot."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    body = resp.get("body", "")[:8192]
    headers = resp.get("headers", {})

    honeypot_sigs = [
        ("Cowrie", ["cowrie", "telnet", "ssh honeypot"]),
        ("Dionaea", ["dionaea"]),
        ("T-Pot", ["t-pot", "hpotter"]),
        ("HFish", ["hfish"]),
        ("General honeypot", ["honeypot", "honeynet"]),
    ]

    haystack = (body + " " + " ".join(headers.values())).lower()
    for name, sigs in honeypot_sigs:
        if any(s in haystack for s in sigs):
            findings.append(Finding(
                title="Honeypot detected: {}".format(name),
                severity="info", category="honeypot",
                module="bot",
                description="Honeypot signature '{}' detected — target may be a decoy".format(name),
                evidence="Signature match in response", asset=host, points_deducted=0,
                remediation="This finding is informational. Honeypot detection means the target may not be genuine.",
            ))
            break

    return findings


def _check_threat_feeds(base_url: str, timeout: int = 8,
                        verify_tls: bool = True) -> List[Finding]:
    """v9.1.0: Check target IPs against threat feeds and DNSBLs."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        import socket
        ips = []
        # Resolve the host to IPs
        for family in (socket.AF_INET,):
            try:
                results = socket.getaddrinfo(host, None, family)
                ips.extend(r[4][0] for r in results)
            except (socket.gaierror, OSError):
                pass

        if not ips:
            return findings

        from ..threat_feeds import ThreatFeedManager, DNSBLChecker, check_ip_reputation
        dnsbl = DNSBLChecker(timeout=3.0)

        for ip in ips[:3]:  # Limit to first 3 IPs
            # DNSBL check (fast, local DNS)
            try:
                hits = dnsbl.check_ip(ip)
                if hits:
                    listed_on = [h["dnsbl"] for h in hits[:3]]
                    findings.append(Finding(
                        title="DNSBL listed: {}".format(ip),
                        severity="high", category="dnsbl_listing",
                        module="bot",
                        description="IP {} listed on DNSBLs: {}".format(ip, ", ".join(listed_on)),
                        evidence="DNSBL hits: {}".format(", ".join(f"{h['dnsbl']}" for h in hits[:3])),
                        asset=host, points_deducted=10,
                        remediation="Investigate why the IP is blacklisted. May indicate compromised host or spam.",
                    ))
            except Exception:
                pass

            # Threat feed reputation check
            try:
                threat_mgr = ThreatFeedManager()
                rep = check_ip_reputation(ip)
                score = rep.get("score", 0)
                if score > 0:
                    if score > 70:
                        severity = "critical"
                    elif score > 40:
                        severity = "high"
                    elif score > 10:
                        severity = "medium"
                    else:
                        severity = "low"
                    feed_names = [f["feed"] for f in rep.get("threat_feeds", [])]
                    dnsbl_hits = rep.get("dnsbl_hits", [])
                    desc_parts = ["IP {} has a threat reputation score of {}.".format(ip, score)]
                    if feed_names:
                        desc_parts.append("Matched threat feeds: {}".format(", ".join(feed_names)))
                    if dnsbl_hits:
                        desc_parts.append("DNSBL hits: {}".format(", ".join(dnsbl_hits)))
                    findings.append(Finding(
                        title="Threat reputation: {} (score {})".format(ip, score),
                        severity=severity, category="threat_intel",
                        module="bot",
                        description=" ".join(desc_parts),
                        evidence="Threat score: {}, feeds: {}, DNSBL: {}".format(
                            score,
                            ", ".join(feed_names) if feed_names else "none",
                            ", ".join(dnsbl_hits) if dnsbl_hits else "none",
                        ),
                        asset=host, points_deducted=5 if severity == "low" else 10 if severity == "medium" else 15,
                        remediation="Investigate the IP against the identified threat feeds. Consider blocking if confirmed malicious.",
                    ))
            except Exception:
                pass

            # GeoIP enrichment
            try:
                from ..geoip import GeoIPLookup, is_hosting_ip, is_proxy_ip
                geo = GeoIPLookup()
                geo_data = geo.enrich_ip(ip, use_cache=True)
                tags = []
                if geo_data.get("proxy") or is_proxy_ip(geo_data):
                    tags.append("proxy")
                if geo_data.get("hosting") or is_hosting_ip(geo_data):
                    tags.append("hosting")
                if tags:
                    geo_info = "{} ({}), ISP: {}".format(
                        geo_data.get("city", "?"), geo_data.get("countryCode", "??"),
                        geo_data.get("isp", "?"),
                    )
                    findings.append(Finding(
                        title="IP intelligence: {} [{}]".format(ip, ", ".join(tags).upper()),
                        severity="medium", category="ip_intelligence",
                        module="bot",
                        description="GeoIP enrichment for {}: {}".format(ip, geo_info),
                        evidence=geo_info,
                        asset=host, points_deducted=3,
                        remediation="Review hosting/proxy status for security posture.",
                    ))
            except Exception:
                pass

    except Exception:
        pass

    return findings


def run_bot(target: str, base_url: str, timeout: int = 8,
             verify_tls: bool = True) -> List[Finding]:
    """C2 / bot infrastructure detection with threat feeds, DNSBL, GeoIP,
    tunnel detection, and exfiltration channel mapping.

    v9.2.0: Adds protocol tunnel detection and exfil channel analysis.
    """
    findings: List[Finding] = []
    findings.extend(_check_common_c2_paths(base_url, timeout=timeout, verify_tls=verify_tls))
    findings.extend(_check_malware_signatures(base_url, timeout=timeout, verify_tls=verify_tls))
    findings.extend(_check_honeypot_signs(base_url, timeout=timeout, verify_tls=verify_tls))
    # v9.1.0: Threat feeds + DNSBL + GeoIP
    findings.extend(_check_threat_feeds(base_url, timeout=timeout, verify_tls=verify_tls))
    # v9.2.0: Tunnel detection + Exfil channel mapping
    findings.extend(_check_tunnel_exfil(base_url, timeout=timeout, verify_tls=verify_tls))
    return findings


def _check_tunnel_exfil(base_url: str, timeout: int = 8,
                         verify_tls: bool = True) -> List[Finding]:
    """v9.2.0: Detect protocol tunnels and exfiltration channels."""
    findings: List[Finding] = []
    host = base_url.replace("https://", "").replace("http://", "").split("/")[0]

    # Tunnel detection
    try:
        from ..tunnel_detect import TunnelDetector
        td = TunnelDetector()
        tunnels = td.detect_all(host, timeout=min(timeout, 5))
        for t in tunnels[:5]:
            if t.confidence > 0.3:
                findings.append(Finding(
                    title="Tunnel detected: {} (confidence {:.0f}%)".format(
                        t.tunnel_type.value, t.confidence * 100),
                    severity="high" if t.confidence > 0.7 else "medium",
                    category="tunnel_detection",
                    module="bot",
                    description="Potential {} tunnel detected on {}".format(t.tunnel_type.value, host),
                    evidence=t.evidence[:200],
                    asset=host,
                    points_deducted=8 if t.confidence > 0.7 else 4,
                    remediation="Investigate and block {} tunnels if not authorized.".format(t.tunnel_type.value),
                ))
    except Exception:
        pass

    # Exfil channel analysis
    try:
        from ..exfil_channels import ExfilChannelMapper
        mapper = ExfilChannelMapper()
        channels = mapper.map_all_channels(host, base_url, timeout=min(timeout, 5))
        high_risk = [c for c in channels.get("channels", []) if c.overall_risk >= 60]
        if high_risk:
            ch_names = [c.channel_type for c in high_risk[:5]]
            max_risk = max(c.overall_risk for c in high_risk)
            findings.append(Finding(
                title="High-risk exfil channels: {} (max risk {})".format(
                    len(high_risk), max_risk),
                severity="high" if max_risk >= 80 else "medium",
                category="exfil_channel",
                module="bot",
                description="{} data exfiltration channels detected with risk >= 60: {}".format(
                    len(high_risk), ", ".join(ch_names)),
                evidence="Channels: {}".format(", ".join(ch_names)),
                asset=host, points_deducted=10 if max_risk >= 80 else 5,
                remediation="Harden exfiltration channels: restrict outbound DNS, block ICMP tunnels, enforce TLS everywhere.",
            ))
    except Exception:
        pass

    return findings

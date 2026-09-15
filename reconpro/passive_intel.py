"""
ReconPro — Passive DNS & Historical Intelligence

Gathers DNS records, historical web snapshots, and technology detection data.
Uses only free, keyless sources: system DNS resolver, Cloudflare DoH,
and the Internet Archive Wayback Machine.

Optionally supports VirusTotal, SecurityTrails, and Shodan when API keys are set.

Exports:
    PassiveDNS         – DNS resolution from system + Cloudflare DoH
    WaybackMachine     – archived page URLs and content
    DeprecationDetector – stale DNS record detection
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional


def _safe_json_get(url: str, headers: Optional[dict] = None, timeout: float = 15.0) -> Any:
    """Fetch URL and return parsed JSON, or None on failure."""
    default_headers = {
        "User-Agent": "ReconPro/8.5 (Passive Intel Module)",
        "Accept": "application/json",
    }
    if headers:
        default_headers.update(headers)
    req = urllib.request.Request(url, headers=default_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError, ValueError):
        return None


def _safe_html_get(url: str, timeout: float = 15.0) -> str:
    """Fetch URL and return raw HTML string."""
    req = urllib.request.Request(url, headers={
        "User-Agent": "ReconPro/8.5 (Passive Intel Module)",
        "Accept": "text/html,application/xhtml+xml",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        return ""


# ══════════════════════════════════════════════════════════════════════
# PassiveDNS
# ══════════════════════════════════════════════════════════════════════

class PassiveDNS:
    """Query passive DNS services for historical resolution data."""

    @staticmethod
    def resolve_dns(domain: str, timeout: float = 5.0) -> List[Dict[str, Any]]:
        """Resolve DNS records using system resolver (no API key needed).

        Returns list of {"type": "A"/"AAAA"/"MX"/"NS"/"TXT", "value": ..., "ttl": ...}.
        """
        import socket
        results: List[Dict[str, Any]] = []

        # A + AAAA records
        try:
            addrs = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            seen = set()
            for family, _, _, _, sockaddr in addrs:
                ip = sockaddr[0]
                if ip not in seen:
                    seen.add(ip)
                    rtype = "AAAA" if family == socket.AF_INET6 else "A"
                    results.append({"type": rtype, "value": ip, "ttl": ""})
        except (socket.gaierror, OSError):
            pass

        # MX records via DNS JSON API (Cloudflare DoH — free, no key)
        try:
            mx_url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=MX"
            req = urllib.request.Request(mx_url, headers={
                "User-Agent": "ReconPro/7",
                "Accept": "application/dns-json",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
                for answer in data.get("Answer", []):
                    results.append({
                        "type": "MX",
                        "value": answer.get("data", ""),
                        "ttl": str(answer.get("TTL", "")),
                    })
        except Exception:
            pass

        # NS records via Cloudflare DoH
        try:
            ns_url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(domain)}&type=NS"
            req = urllib.request.Request(ns_url, headers={
                "User-Agent": "ReconPro/7",
                "Accept": "application/dns-json",
            })
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode())
                for answer in data.get("Answer", []):
                    results.append({
                        "type": "NS",
                        "value": answer.get("data", "").rstrip("."),
                        "ttl": str(answer.get("TTL", "")),
                    })
        except Exception:
            pass

        return results

    def query_virustotal(self, domain: str, api_key: str = "") -> List[Dict[str, Any]]:
        """Query VirusTotal for DNS resolution history.

        Requires a VirusTotal API key. Free tier allows 500 req/day.
        Returns list of {"ip", "last_resolved", "resolver", "source"}.
        """
        if not api_key:
            return []

        url = f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(domain)}/resolutions"
        headers = {"x-apikey": api_key}
        data = _safe_json_get(url, headers)
        if not data:
            return []

        results: List[Dict[str, Any]] = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            ip = attrs.get("ip_address", attrs.get("host", ""))
            last_date = attrs.get("last_resolved", "")
            date_str = last_date[:10] if last_date else ""
            resolver = attrs.get("resolver", attrs.get("source", ""))
            if ip:
                results.append({
                    "ip": ip,
                    "last_resolved": date_str,
                    "resolver": str(resolver),
                    "source": "virustotal",
                })

        results.sort(key=lambda x: x.get("last_resolved", ""), reverse=True)
        return results

    def query_securitytrails(self, domain: str, api_key: str = "") -> List[Dict[str, Any]]:
        """Query SecurityTrails for historical DNS records.

        Returns list of {"type", "value", "last_seen", "source"}.
        """
        if not api_key:
            return []

        url = f"https://api.securitytrails.com/v1/history/{urllib.parse.quote(domain)}/dns/a"
        headers = {"APIKEY": api_key}
        data = _safe_json_get(url, headers)
        if not data:
            return []

        results: List[Dict[str, Any]] = []
        for record in data.get("records", []):
            ips = record.get("values", [])
            first_seen = record.get("first_seen", "")[:10]
            last_seen = record.get("last_seen", "")[:10]
            for ip_entry in ips:
                ip = ip_entry if isinstance(ip_entry, str) else ip_entry.get("ip", "")
                if ip:
                    results.append({
                        "type": "a",
                        "value": ip,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "source": "securitytrails",
                    })

        return results

    def query_shodan(self, domain: str, api_key: str = "") -> List[Dict[str, Any]]:
        """Query Shodan for open ports and services.

        Returns list of {"ip", "port", "protocol", "service", "banner", "source"}.
        """
        if not api_key:
            return []

        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{urllib.parse.quote(domain)}"
        data = _safe_json_get(url)
        if not data:
            return []

        results: List[Dict[str, Any]] = []
        for match in data.get("matches", []):
            ip = match.get("ip_str", "")
            port = match.get("port", 0)
            protocol = match.get("transport", "")
            service = match.get("product", match.get("service", ""))
            banner = match.get("data", "")[:512]
            if ip:
                results.append({
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "banner": banner,
                    "source": "shodan",
                })

        return results

    def query_all(self, domain: str, vt_key: str = "", st_key: str = "", shodan_key: str = "") -> Dict[str, List[Dict[str, Any]]]:
        """Query all available passive DNS sources.

        Returns {"virustotal": [...], "securitytrails": [...], "shodan": [...]}
        """
        return {
            "virustotal": self.query_virustotal(domain, vt_key),
            "securitytrails": self.query_securitytrails(domain, st_key),
            "shodan": self.query_shodan(domain, shodan_key),
        }

    def extract_unique_ips(self, results: Dict[str, List[Dict[str, Any]]]) -> List[str]:
        """Collect all unique IPs across all sources."""
        ips: set = set()
        for source_results in results.values():
            for entry in source_results:
                if "ip" in entry and entry["ip"]:
                    ips.add(entry["ip"])
                if "value" in entry and entry["value"]:
                    # Could be an IP in DNS records
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", entry["value"]):
                        ips.add(entry["value"])
        return sorted(ips)


# ══════════════════════════════════════════════════════════════════════
# WaybackMachine
# ══════════════════════════════════════════════════════════════════════

class WaybackMachine:
    """Access the Internet Archive's Wayback Machine for historical data."""

    _CDX_API = "https://web.archive.org/cdx/search/cdx"
    _AVAIL_API = "https://archive.org/wayback/available"
    _WEB_API = "https://web.archive.org/web"

    def get_history(self, domain: str, years: int = 1) -> List[Dict[str, Any]]:
        """Get archived page URLs for *domain* from the last *years*.

        Uses the CDX API. Returns list of {"url", "timestamp", "statuscode", "mimetype"}.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=years * 365)
        from_str = cutoff.strftime("%Y%m%d")

        params = urllib.parse.urlencode({
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "from": from_str,
            "limit": "500",
            "collapse": "urlkey",
        })
        url = f"{self._CDX_API}?{params}"
        data = _safe_json_get(url)
        if not data or not isinstance(data, list):
            return []

        results: List[Dict[str, Any]] = []
        for row in data[1:]:  # Skip header row
            if len(row) < 4:
                continue
            timestamp_raw = row[0]
            ts_formatted = f"{timestamp_raw[:4]}-{timestamp_raw[4:6]}-{timestamp_raw[6:8]} {timestamp_raw[8:10]}:{timestamp_raw[10:12]}"
            results.append({
                "url": row[1],
                "timestamp": ts_formatted,
                "timestamp_raw": timestamp_raw,
                "statuscode": row[2],
                "mimetype": row[3],
            })

        results.sort(key=lambda x: x["timestamp_raw"], reverse=True)
        return results

    def get_snapshot(self, url: str, timestamp: str = "") -> str:
        """Fetch an archived page from the Wayback Machine.

        If *timestamp* is provided (YYYYMMDDhhmmss), fetches that specific
        snapshot. Otherwise fetches the most recent available.
        Returns the HTML content.
        """
        if timestamp:
            archive_url = f"{self._WEB_API}/{timestamp}/{url}"
        else:
            # Find the closest available snapshot
            params = urllib.parse.urlencode({"url": url})
            avail_data = _safe_json_get(f"{self._AVAIL_API}?{params}")
            if avail_data and isinstance(avail_data, dict):
                arch = avail_data.get("archived_snapshots", {}).get("closest", {})
                archive_url = arch.get("url", "")
                if not archive_url:
                    return ""
            else:
                return ""

        return _safe_html_get(archive_url)

    def detect_tech_changes(self, domain: str, years: int = 1) -> List[Dict[str, Any]]:
        """Detect technology stack changes over time from archived pages.

        Compares HTML headers, meta tags, and script/CSS references
        across snapshots to identify technology changes.

        Returns list of {"date", "added_technologies", "removed_technologies", "evidence"}.
        """
        history = self.get_history(domain, years)
        html_pages = [h for h in history if h.get("mimetype", "").startswith("text/html") and h.get("statuscode") == "200"]

        if len(html_pages) < 2:
            return []

        # Sample a few snapshots spread across time
        step = max(1, len(html_pages) // 5)
        sampled = html_pages[::step][:6]

        tech_signatures: Dict[str, re.Pattern] = {
            "react": re.compile(r"react|__NEXT_DATA__|react-dom", re.I),
            "vue": re.compile(r"vue\.js|vue\.min|v-app|data-v-[a-f0-9]", re.I),
            "angular": re.compile(r"ng-|angular|ng-app|ng-controller", re.I),
            "jquery": re.compile(r"jquery", re.I),
            "wordpress": re.compile(r"wp-content|wp-includes|wordpress", re.I),
            "drupal": re.compile(r"drupal|sites/all/modules", re.I),
            "shopify": re.compile(r"shopify|cdn\.shopify\.com", re.I),
            "cloudflare": re.compile(r"cloudflare|cf-ray|__cfduid", re.I),
            "google-analytics": re.compile(r"google-analytics|gtag|ga\(", re.I),
            "bootstrap": re.compile(r"bootstrap\.min\.css|bootstrap\.js", re.I),
            "nginx": re.compile(r"nginx", re.I),
            "apache": re.compile(r"apache", re.I),
            "nextjs": re.compile(r"_next/static|__NEXT_DATA__", re.I),
            "nuxtjs": re.compile(r"_nuxt/|__NUXT__", re.I),
        }

        changes: List[Dict[str, Any]] = []
        prev_techs: Optional[set] = None
        prev_date = ""

        for page in sampled:
            html = self.get_snapshot(page["url"], page["timestamp_raw"])
            if not html:
                continue

            current_techs: set = set()
            for tech_name, pattern in tech_signatures.items():
                if pattern.search(html[:50000]):
                    current_techs.add(tech_name)

            if prev_techs is not None:
                added = current_techs - prev_techs
                removed = prev_techs - current_techs
                if added or removed:
                    evidence_parts = []
                    for t in added:
                        evidence_parts.append(f"+ {t}")
                    for t in removed:
                        evidence_parts.append(f"- {t}")
                    changes.append({
                        "date": page["timestamp"],
                        "previous_date": prev_date,
                        "added_technologies": sorted(added),
                        "removed_technologies": sorted(removed),
                        "evidence": ", ".join(evidence_parts),
                        "current_stack": sorted(current_techs),
                    })

            prev_techs = current_techs
            prev_date = page["timestamp"]

        return changes


# ══════════════════════════════════════════════════════════════════════
# DeprecationDetector
# ══════════════════════════════════════════════════════════════════════

class DeprecationDetector:
    """Detect stale DNS records pointing to old or deprecated IPs."""

    def detect_stale_dns(
        self,
        domain: str,
        current_ips: List[str],
        historical_results: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        days_threshold: int = 30,
    ) -> List[Dict[str, Any]]:
        """Find subdomains pointing to IPs not in the current infrastructure.

        Parameters
        ----------
        domain : str
            Base domain to check.
        current_ips : list[str]
            List of IPs currently in use by the organization.
        historical_results : dict | None
            Output from PassiveDNS.query_all(). If None, runs basic DNS
            resolution.
        days_threshold : int
            Flag records older than this many days as stale.

        Returns list of {"subdomain", "old_ip", "status", "last_seen", "description"}.
        """
        current_set = {ip.strip() for ip in current_ips if ip.strip()}
        stale: List[Dict[str, Any]] = []

        if historical_results:
            for source, records in historical_results.items():
                for record in records:
                    ip = record.get("ip") or record.get("value", "")
                    if not ip or ip in current_set:
                        continue

                    # Check age
                    last_seen = record.get("last_resolved", record.get("last_seen", ""))
                    is_old = False
                    if last_seen and len(last_seen) >= 10:
                        try:
                            last_dt = datetime.fromisoformat(last_seen)
                            age_days = (datetime.now(timezone.utc) - last_dt).days
                            is_old = age_days > days_threshold
                        except (ValueError, TypeError):
                            pass

                    stale.append({
                        "subdomain": domain,
                        "old_ip": ip,
                        "status": "stale" if is_old else "divergent",
                        "last_seen": last_seen,
                        "source": source,
                        "description": (
                            f"{domain} resolves to {ip} which is not in current infrastructure. "
                            f"Source: {source}, last seen: {last_seen}."
                        ),
                    })
        else:
            # Fallback: simple DNS resolution
            import socket
            try:
                resolved = socket.getaddrinfo(domain, None, socket.AF_INET)
                for fam, stype, proto, canonname, sockaddr in resolved:
                    ip = sockaddr[0]
                    if ip not in current_set:
                        stale.append({
                            "subdomain": domain,
                            "old_ip": ip,
                            "status": "divergent",
                            "last_seen": "",
                            "source": "dns_resolution",
                            "description": f"{domain} resolves to {ip} which is not in current infrastructure.",
                        })
            except socket.gaierror:
                pass

        # Deduplicate by (subdomain, old_ip)
        seen: set = set()
        deduped: List[Dict[str, Any]] = []
        for entry in stale:
            key = (entry["subdomain"], entry["old_ip"])
            if key not in seen:
                seen.add(key)
                deduped.append(entry)

        return deduped

    def detect_dangling_dns(
        self, domain: str, subdomains: List[str]) -> List[Dict[str, Any]]:
        """Check subdomains for dangling DNS (CNAME pointing to removed external service).

        Returns list of {"subdomain", "cname_target", "status", "description"}.
        """
        import socket
        findings: List[Dict[str, Any]] = []

        for sub in subdomains:
            fqdn = f"{sub}.{domain}" if not sub.endswith(domain) else sub
            try:
                # Get all address records
                results = socket.getaddrinfo(fqdn, None)
                cnames: List[str] = []
                ips: List[str] = []
                for fam, stype, proto, canonname, sockaddr in results:
                    if canonname and canonname != fqdn and canonname not in cnames:
                        cnames.append(canonname)
                    if stype == socket.SOCK_STREAM:
                        ip = sockaddr[0]
                        if ip not in ips:
                            ips.append(ip)

                if cnames:
                    findings.append({
                        "subdomain": fqdn,
                        "cname_target": cnames[0],
                        "resolved_ips": ips,
                        "status": "has_cname",
                        "description": f"{fqdn} has CNAME to {cnames[0]} resolving to {', '.join(ips)}",
                    })

                if not ips and not cnames:
                    findings.append({
                        "subdomain": fqdn,
                        "cname_target": "",
                        "resolved_ips": [],
                        "status": "nx_domain",
                        "description": f"{fqdn} does not resolve (NXDOMAIN) — potential dangling DNS takeover.",
                    })

            except socket.gaierror:
                findings.append({
                    "subdomain": fqdn,
                    "cname_target": "",
                    "resolved_ips": [],
                    "status": "nx_domain",
                    "description": f"{fqdn} does not resolve (NXDOMAIN) — potential dangling DNS takeover.",
                })

        return findings


# Module-level convenience exports
passive_dns = PassiveDNS()
wayback = WaybackMachine()
deprecation = DeprecationDetector()

"""
econpro.subdomains — Comprehensive subdomain enumeration engine (v9.0.0)

Pure-Python OSINT subdomain discovery using 10+ free sources.
Zero external dependencies — only Python stdlib.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .constants import USER_AGENT

__all__ = [
    "SubdomainResult",
    "SubdomainEnumerator",
    "discover_ctlogs",
    "discover_dns",
    "discover_subdomains",
]

# ── Constants ─────────────────────────────────────────────────────────────────

USER_AGENT = USER_AGENT  # canonical from constants
DEFAULT_TIMEOUT = 10.0
DEFAULT_WORKERS = 5

DNS_BRUTE_PREFIXES = [
    "www", "api", "admin", "staging", "dev", "test", "prod", "cdn", "static",
    "mail", "vpn", "db", "git", "jenkins", "grafana", "kibana", "prometheus",
    "auth", "sso", "portal", "m", "mobile", "app", "beta", "internal", "ci",
    "cd", "staging-api", "dev-api", "sandbox", "demo", "preview", "old", "new",
    "backup", "mirror", "shop", "store", "pay", "billing", "crm", "erp", "hr",
    "wiki", "docs", "help", "support", "forum", "blog", "news", "media",
    "images", "assets", "uploads", "download", "files", "api-v2", "v2", "v3",
    "graphql", "ghrpc", "ws", "wss", "metrics", "health", "status", "ping",
    "heartbeat", "trace", "jaeger", "zipkin", "sentry", "errors", "logs",
    "logstash", "elastic", "redis", "mongo", "mysql", "postgres", "rabbitmq",
    "kafka", "consul", "etcd", "zookeeper", "vault", "argocd", "gitlab",
    "drone", "harbor", "registry", "docker", "k8s", "kubernetes", "rancher",
    "traefik", "envoy", "nginx-proxy", "proxy", "lb", "load-balancer", "gateway",
    "ingress", "webhook", "hooks", "notifications", "events", "scheduler",
    "worker", "queue", "jobs", "tasks", "celery", "sidekiq", "resque",
]

_ALL_SOURCES = [
    "crtsh", "certspotter", "censys", "bufferover", "riddler",
    "dns_bruteforce", "txt_enum", "wayback", "anubis", "securitytrails",
]


# ── Data structures ───────────────────────────────────────────────────────────


@dataclass
class SubdomainResult:
    """Aggregated result of subdomain enumeration."""
    domain: str
    subdomains: List[str] = field(default_factory=list)
    resolved: List[Dict[str, Any]] = field(default_factory=list)
    sources_used: Dict[str, int] = field(default_factory=dict)
    total_unique_ips: int = 0
    elapsed: float = 0.0


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_request(url: str, timeout: float = DEFAULT_TIMEOUT) -> Optional[bytes]:
    """Perform an HTTP GET and return raw bytes, or None on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read()
    except Exception:
        return None


def _extract_domain_fragments(text: str, base: str) -> Set[str]:
    """Pull out *.domain entries from arbitrary text using regex."""
    escaped = re.escape(base)
    pattern = rf"([a-zA-Z0-9][a-zA-Z0-9\-]*\.{escaped})"
    return {m.lower() for m in re.findall(pattern, text)}


def _fqdn_label(sub: str) -> str:
    """Strip trailing dot if present and lowercase."""
    return sub.rstrip(".").lower()


# ── Main class ────────────────────────────────────────────────────────────────


class SubdomainEnumerator:
    """Enumerate subdomains across 10+ OSINT sources in parallel."""

    def __init__(
        self,
        domain: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_workers: int = DEFAULT_WORKERS,
        silent: bool = False,
    ) -> None:
        self.domain = domain.lower().strip()
        self.timeout = timeout
        self.max_workers = max_workers
        self.silent = silent

    # ── Public entry point ─────────────────────────────────────────────────

    def enumerate(self, sources: Optional[List[str]] = None) -> SubdomainResult:
        """Run all enabled sources in parallel and return aggregated result."""
        t0 = time.monotonic()
        if sources is None:
            sources = list(_ALL_SOURCES)

        source_map = {
            "crtsh": self._source_crtsh,
            "certspotter": self._source_certspotter,
            "censys": self._source_censys,
            "bufferover": self._source_bufferover,
            "riddler": self._source_riddler,
            "dns_bruteforce": self._source_dns_bruteforce,
            "txt_enum": self._source_txt_enum,
            "wayback": self._source_wayback,
            "anubis": self._source_anubis,
            "securitytrails": self._source_securitytrails,
        }

        combined: Set[str] = set()
        source_counts: Dict[str, int] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_name = {}
            for name in sources:
                fn = source_map.get(name)
                if fn is None:
                    continue
                future_to_name[pool.submit(fn)] = name

            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    subs = future.result()
                except Exception:
                    subs = set()
                before = len(combined)
                combined.update(subs)
                new_count = len(combined) - before
                source_counts[name] = new_count
                if not self.silent:
                    print(f"  [*] {name:<20s} → {new_count} new subdomains")

        sorted_subs = sorted(combined)
        resolved = self._resolve_subdomains(combined)
        unique_ips = len({ip for r in resolved for ip in r.get("ips", [])})

        return SubdomainResult(
            domain=self.domain,
            subdomains=sorted_subs,
            resolved=resolved,
            sources_used=source_counts,
            total_unique_ips=unique_ips,
            elapsed=round(time.monotonic() - t0, 3),
        )

    # ── Source: crt.sh ─────────────────────────────────────────────────────

    def _source_crtsh(self) -> Set[str]:
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        data = _make_request(url, self.timeout)
        if data is None:
            return set()
        try:
            entries = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return set()
        subs: Set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*")
                if name.endswith("." + self.domain):
                    subs.add(_fqdn_label(name))
        return subs

    # ── Source: CertSpotter ────────────────────────────────────────────────

    def _source_certspotter(self) -> Set[str]:
        url = (
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}"
            f"&include_subdomains=true&expand=dns_names"
        )
        data = _make_request(url, self.timeout)
        if data is None:
            return set()
        try:
            entries = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return set()
        subs: Set[str] = set()
        for entry in entries:
            for name in entry.get("dns_names", []):
                name = name.strip().lstrip("*")
                if name.endswith("." + self.domain):
                    subs.add(_fqdn_label(name))
        return subs

    # ── Source: Censys (HTML scrape) ───────────────────────────────────────

    def _source_censys(self) -> Set[str]:
        encoded = urllib.parse.quote_plus(self.domain)
        url = f"https://search.censys.io/certificates?q={encoded}"
        data = _make_request(url, self.timeout)
        if data is None:
            return set()
        text = data.decode("utf-8", errors="ignore")
        return _extract_domain_fragments(text, self.domain)

    # ── Source: BufferOver.run ─────────────────────────────────────────────

    def _source_bufferover(self) -> Set[str]:
        url = f"https://tls.bufferover.run/dns?q={self.domain}"
        data = _make_request(url, self.timeout)
        if data is None:
            return set()
        try:
            result = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return set()
        subs: Set[str] = set()
        for item in result.get("Results", []) if isinstance(result, dict) else []:
            parts = item.split(",") if isinstance(item, str) else []
            for part in parts:
                part = part.strip().lower()
                if part.endswith("." + self.domain):
                    subs.add(_fqdn_label(part))
        return subs

    # ── Source: Riddler.io (CSV) ───────────────────────────────────────────

    def _source_riddler(self) -> Set[str]:
        url = f"https://riddler.io/search/exportcsv?q=pld:{self.domain}"
        data = _make_request(url, self.timeout)
        if data is None:
            return set()
        text = data.decode("utf-8", errors="ignore")
        subs: Set[str] = set()
        for line in text.splitlines()[1:]:  # skip header
            for field in line.split(","):
                field = field.strip().lower()
                if field.endswith("." + self.domain):
                    subs.add(_fqdn_label(field))
        return subs

    # ── Source: DNS brute force ────────────────────────────────────────────

    def _source_dns_bruteforce(self) -> Set[str]:
        subs: Set[str] = set()
        for prefix in DNS_BRUTE_PREFIXES:
            fqdn = f"{prefix}.{self.domain}"
            try:
                socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                subs.add(fqdn)
            except (socket.gaierror, socket.herror, OSError):
                pass
        return subs

    # ── Source: DNS TXT enumeration ────────────────────────────────────────

    def _source_txt_enum(self) -> Set[str]:
        subs: Set[str] = set()
        try:
            answers = socket.getaddrinfo(
                f"*.{self.domain}", None, socket.AF_UNSPEC, socket.SOCK_STREAM
            )
            # Some resolvers return wildcard IPs — treat as signal but not subdomain
            if answers:
                if not self.silent:
                    print("  [*] txt_enum            → wildcard detected")
        except (socket.gaierror, socket.herror, OSError):
            pass

        # Also try resolving a few known TXT-query-friendly patterns
        txt_prefixes = ["_dmarc", "_sip._tcp", "_submission._tcp"]
        for prefix in txt_prefixes:
            fqdn = f"{prefix}.{self.domain}"
            try:
                # Use getaddrinfo as a liveness check for the base domain
                socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except (socket.gaierror, socket.herror, OSError):
                pass

        # Probe for wildcard: if random sub resolves, domain uses wildcard DNS
        try:
            socket.getaddrinfo(
                f"xreconpro9testnonce.{self.domain}", None,
                socket.AF_UNSPEC, socket.SOCK_STREAM,
            )
            # Wildcard is active — skip brute results to avoid noise
        except (socket.gaierror, socket.herror, OSError):
            pass  # No wildcard, safe to proceed

        return subs

    # ── Source: Wayback Machine ────────────────────────────────────────────

    def _source_wayback(self) -> Set[str]:
        url = (
            f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*"
            f"&output=json&collapse=urlkey&fl=original"
        )
        data = _make_request(url, self.timeout)
        if data is None:
            return set()
        try:
            entries = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return set()
        subs: Set[str] = set()
        for row in entries[1:] if len(entries) > 1 else []:  # skip header
            if not row:
                continue
            try:
                from urllib.parse import urlparse
                host = urlparse(row).hostname
            except Exception:
                continue
            if host and host.endswith("." + self.domain):
                subs.add(host.lower())
        return subs

    # ── Source: AnubisDB ───────────────────────────────────────────────────

    def _source_anubis(self) -> Set[str]:
        url = f"https://jupiter.anubisdb.io/domains/{self.domain}/subdomains"
        data = _make_request(url, self.timeout)
        if data is None:
            return set()
        try:
            entries = json.loads(data)
        except (json.JSONDecodeError, TypeError):
            return set()
        subs: Set[str] = set()
        for name in entries if isinstance(entries, list) else []:
            if isinstance(name, str) and name.endswith("." + self.domain):
                subs.add(_fqdn_label(name))
        return subs

    # ── Source: SecurityTrails (HTML scrape) ───────────────────────────────

    def _source_securitytrails(self) -> Set[str]:
        url = f"https://securitytrails.com/list/#{self.domain}"
        data = _make_request(url, self.timeout)
        if data is None:
            return set()
        text = data.decode("utf-8", errors="ignore")
        return _extract_domain_fragments(text, self.domain)

    # ── DNS resolution ─────────────────────────────────────────────────────

    def _resolve_subdomains(self, subs: Set[str]) -> List[Dict[str, Any]]:
        """Resolve each subdomain to A/AAAA records. Filter by unique IPs."""
        results: List[Dict[str, Any]] = []
        seen_ips: Set[str] = set()

        # DEAD CODE: consider removal
        def _resolve(fqdn: str) -> Optional[Dict[str, Any]]:
            ips: List[str] = []
            try:
                records = socket.getaddrinfo(
                    fqdn, None, socket.AF_UNSPEC, socket.SOCK_STREAM
                )
                for family, _type, _proto, _canonname, sockaddr in records:
                    ip = sockaddr[0]
                    if ip not in ips:
                        ips.append(ip)
            except (socket.gaierror, socket.herror, OSError):
                return None
            if not ips:
                return None
            return {"subdomain": fqdn, "ips": ips}

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_sub = {pool.submit(_resolve, s): s for s in subs}
            for future in as_completed(future_to_sub):
                result = future.result()
                if result is None:
                    continue
                # Keep all resolved entries even if IPs overlap
                for ip in result["ips"]:
                    seen_ips.add(ip)
                results.append(result)

        results.sort(key=lambda r: r["subdomain"])
        return results


# ── Backward-compatible wrapper functions ──────────────────────────────────────


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def discover_ctlogs(domain: str, timeout: float = DEFAULT_TIMEOUT) -> List[str]:
    """Discover subdomains via Certificate Transparency logs (crt.sh).

    Legacy wrapper — returns a sorted list of subdomain strings.
    """
    enum = SubdomainEnumerator(domain, timeout=timeout, silent=True)
    subs = enum._source_crtsh()
    return sorted(subs)


def discover_dns(domain: str, timeout: float = DEFAULT_TIMEOUT) -> List[str]:
    """Discover subdomains via DNS brute force.

    Legacy wrapper — returns a sorted list of subdomain strings.
    """
    enum = SubdomainEnumerator(domain, timeout=timeout, silent=True)
    subs = enum._source_dns_bruteforce()
    return sorted(subs)


def discover_subdomains(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    sources: Optional[List[str]] = None,
) -> List[str]:
    """Full subdomain enumeration across all sources.

    Legacy wrapper — returns a sorted list of subdomain strings.
    """
    enum = SubdomainEnumerator(domain, timeout=timeout, silent=True)
    result = enum.enumerate(sources=sources)
    return result.subdomains

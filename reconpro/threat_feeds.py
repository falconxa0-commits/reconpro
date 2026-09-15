"""ReconPro v9.1.0 — Threat Feed Ingestion System.

Aggregates and deduplicates threat intelligence from multiple open-source feeds:
  - Blocklist.de (strong IPs, bot IPs)
  - Spamhaus DROP / EDROP (hijacked/bogon CIDRs)
  - Firehol Level 1 (comprehensive IP/CIDR blocklist)
  - EmergingThreats Suricata rules (compromised IPs extracted from rules)
  - DShield top 100 attackers (JSON API)

All feeds are fetched via HTTP using urllib (zero external dependencies).
Results are cached to ~/.reconpro/threat_feeds/ with a configurable TTL (default 6 hours).
DNSBL checking is supported via standard DNS queries (socket.getaddrinfo).

Usage:
    from reconpro.threat_feeds import ThreatFeedManager, DNSBLChecker, is_ip_in_cidr

    mgr = ThreatFeedManager()
    results = mgr.refresh_all()
    hits = mgr.check_ip("1.2.3.4")

    checker = DNSBLChecker()
    listings = checker.check_ip("1.2.3.4")

    if is_ip_in_cidr("1.2.3.4", "1.2.3.0/24"):
        print("IP is in CIDR range")
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import struct
import time
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple, Union

logger = logging.getLogger("reconpro.threat_feeds")

# ── Constants ──────────────────────────────────────────────────────────────────

FEEDS_DIR: Path = Path.home() / ".reconpro" / "threat_feeds"
DEFAULT_TTL: int = 6 * 3600  # 6 hours in seconds
USER_AGENT: str = "ReconPro/11.1.0 (Threat Intelligence Aggregator; +https://reconpro.dev)"

# DNSBL servers to query — (zone, human-readable name)
DNSBL_SERVERS: List[Tuple[str, str]] = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("dbl.spamhaus.org", "Spamhaus DBL"),
    ("barracuda.bdc", "Barracuda BDC"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
    ("combined.abuse.ch", "Abuse.ch Combined"),
    ("dnsbl-1.uceprotect.net", "UCE Protect Level 1"),
    ("dnsbl-2.uceprotect.net", "UCE Protect Level 2"),
    ("dnsbl-3.uceprotect.net", "UCE Protect Level 3"),
]


# ── Utility Functions ──────────────────────────────────────────────────────────

def is_ip_in_cidr(ip: str, cidr: str) -> bool:
    """Check if an IPv4 address falls within a CIDR range.

    Uses the ipaddress module for correctness, with a manual fallback.

    Args:
        ip: IPv4 address string (e.g. "192.168.1.100").
        cidr: CIDR notation string (e.g. "192.168.1.0/24").

    Returns:
        True if the IP is within the CIDR range, False otherwise.
    """
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False


def _ip_to_int(ip: str) -> int:
    """Convert an IPv4 address to a 32-bit integer."""
    try:
        parts = ip.split(".")
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0


def _cidr_to_range(cidr: str) -> Tuple[int, int]:
    """Convert a CIDR notation to (network_int, broadcast_int)."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        net_int = _ip_to_int(str(network.network_address))
        bcast_int = _ip_to_int(str(network.broadcast_address))
        return net_int, bcast_int
    except Exception:
        return 0, 0


def _is_valid_ipv4(ip: str) -> bool:
    """Validate an IPv4 address string."""
    try:
        parts = ip.strip().split(".")
        if len(parts) != 4:
            return False
        return all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, AttributeError):
        return False


def _reverse_ip(ip: str) -> str:
    """Reverse the octets of an IPv4 address for DNSBL queries.

    Example: '1.2.3.4' -> '4.3.2.1'
    """
    parts = ip.strip().split(".")
    return ".".join(reversed(parts))


# ── Base Threat Feed Client ───────────────────────────────────────────────────

class ThreatFeedClient:
    """Abstract base class for all threat feed clients.

    Subclasses must override parse() to handle the specific feed format.
    Each feed is cached locally as JSON under ~/.reconpro/threat_feeds/.
    """

    def __init__(
        self,
        name: str,
        url: str,
        ttl: int = DEFAULT_TTL,
        feeds_dir: Optional[Path] = None,
        timeout: int = 30,
    ) -> None:
        """Initialize a threat feed client.

        Args:
            name: Unique identifier for this feed (used for cache filename).
            url: URL to fetch the feed from.
            ttl: Time-to-live for the cached feed data in seconds.
            feeds_dir: Directory for cache files. Defaults to ~/.reconpro/threat_feeds/.
            timeout: HTTP request timeout in seconds.
        """
        self.name = name
        self.url = url
        self._ttl = ttl
        self._timeout = timeout
        self._feeds_dir = feeds_dir or FEEDS_DIR
        self._cache_file = self._feeds_dir / f"{name}.json"
        self._ips: Set[str] = set()
        self._cidrs: List[str] = []
        self._last_fetch: float = 0.0
        self._loaded: bool = False

    def fetch(self, force: bool = False) -> int:
        """Fetch and parse the threat feed, respecting the TTL cache.

        Args:
            force: If True, bypass the cache and re-fetch from the source.

        Returns:
            Total count of indicators (IPs + CIDRs) in this feed.
        """
        import urllib.request
        import urllib.error

        # Serve from cache if still fresh and data exists
        if not force and self._loaded and self.is_fresh():
            return len(self._ips) + len(self._cidrs)

        # Try loading from disk cache first if not forced
        if not force and not self._loaded:
            self._load_cache()
            if self._loaded and self.is_fresh():
                return len(self._ips) + len(self._cidrs)

        # Fetch raw content from URL
        raw_content = self._fetch_raw()
        if raw_content is None:
            if self._loaded:
                logger.warning("[%s] Fetch failed — serving stale cache", self.name)
                return len(self._ips) + len(self._cidrs)
            logger.error("[%s] Fetch failed and no cache available", self.name)
            return 0

        # Parse and cache
        ips, cidrs = self.parse(raw_content)
        self._ips = ips
        self._cidrs = cidrs
        self._last_fetch = time.time()
        self._loaded = True
        self._save_cache()

        logger.info(
            "[%s] Fetched %d IPs, %d CIDRs from %s",
            self.name, len(self._ips), len(self._cidrs), self.url,
        )
        return len(self._ips) + len(self._cidrs)

    def _fetch_raw(self) -> Optional[str]:
        """Perform an HTTP GET request and return the response body as a string.

        Uses only urllib (no external dependencies).
        """
        import urllib.request
        import urllib.error

        try:
            req = urllib.request.Request(
                self.url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/plain, application/json, */*",
                },
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            logger.error("[%s] HTTP %d fetching %s", self.name, exc.code, self.url)
        except urllib.error.URLError as exc:
            logger.error("[%s] URL error fetching %s: %s", self.name, self.url, exc.reason)
        except Exception as exc:
            logger.error("[%s] Unexpected error fetching %s: %s", self.name, self.url, exc)
        return None

    def parse(self, raw: str) -> Tuple[Set[str], List[str]]:
        """Parse raw feed content into a set of IPs and a list of CIDRs.

        Subclasses must override this to handle feed-specific formats.
        The default implementation handles plain IP lists with '#' or ';' comments.
        """
        ips: Set[str] = set()
        cidrs: List[str] = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Extract the first token (before whitespace or tab)
            token = line.split()[0]
            if "/" in token:
                try:
                    ipaddress.ip_network(token, strict=False)
                    cidrs.append(token)
                except ValueError:
                    pass
            elif _is_valid_ipv4(token):
                ips.add(token)
        return ips, cidrs

    def cache(self, ips: Set[str], cidrs: List[str]) -> None:
        """Manually set and persist feed data to the cache.

        Args:
            ips: Set of IPv4 address strings.
            cidrs: List of CIDR notation strings.
        """
        self._ips = set(ips)
        self._cidrs = list(cidrs)
        self._last_fetch = time.time()
        self._loaded = True
        self._save_cache()

    def is_fresh(self) -> bool:
        """Check whether the cached feed data is still within its TTL."""
        if not self._loaded:
            return False
        return (time.time() - self._last_fetch) < self._ttl

    def contains_ip(self, ip: str) -> bool:
        """Check whether a specific IP is present in this feed.

        Checks both exact IP matches and CIDR range membership.
        """
        if not self._loaded:
            self._load_cache()
        if ip in self._ips:
            return True
        return any(is_ip_in_cidr(ip, cidr) for cidr in self._cidrs)

    def get_ips(self) -> Set[str]:
        """Return a copy of all IPs in this feed."""
        if not self._loaded:
            self._load_cache()
        return set(self._ips)

    def get_cidrs(self) -> List[str]:
        """Return a copy of all CIDRs in this feed."""
        if not self._loaded:
            self._load_cache()
        return list(self._cidrs)

    def get_stats(self) -> Dict[str, Any]:
        """Return feed statistics."""
        return {
            "name": self.name,
            "url": self.url,
            "ip_count": len(self._ips),
            "cidr_count": len(self._cidrs),
            "last_fetch": self._last_fetch,
            "fresh": self.is_fresh(),
            "ttl": self._ttl,
        }

    # ── Private cache methods ────────────────────────────────────────

    def _load_cache(self) -> None:
        """Load feed data from the local JSON cache file."""
        if not self._cache_file.exists():
            return
        try:
            data = json.loads(self._cache_file.read_text(encoding="utf-8"))
            self._ips = set(data.get("ips", []))
            self._cidrs = data.get("cidrs", [])
            self._last_fetch = data.get("last_fetch", 0.0)
            self._loaded = True
            logger.debug("[%s] Loaded cache with %d IPs, %d CIDRs", self.name, len(self._ips), len(self._cidrs))
        except (json.JSONDecodeError, OSError, KeyError) as exc:
            logger.warning("[%s] Failed to load cache: %s", self.name, exc)

    def _save_cache(self) -> None:
        """Persist feed data to the local JSON cache file."""
        try:
            self._feeds_dir.mkdir(parents=True, exist_ok=True)
            data = {
                "name": self.name,
                "url": self.url,
                "ips": sorted(self._ips),
                "cidrs": sorted(self._cidrs),
                "last_fetch": self._last_fetch,
                "ttl": self._ttl,
            }
            tmp_path = self._cache_file.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp_path.replace(self._cache_file)
            logger.debug("[%s] Cache saved (%d IPs, %d CIDRs)", self.name, len(self._ips), len(self._cidrs))
        except OSError as exc:
            logger.warning("[%s] Failed to save cache: %s", self.name, exc)


# ── Concrete Feed Implementations ─────────────────────────────────────────────

class BlocklistDEFeed(ThreatFeedClient):
    """Fetches IP lists from blocklist.de (https://www.blocklist.de/en/export.html).

    Supports 'strong' (all strong IPs) and 'bots' (botnet IPs) sub-lists.
    Format is plain text with one IP per line, prefixed with optional timestamps.
    """

    STRONG_URL = "https://lists.blocklist.de/lists/all.txt"
    BOTS_URL = "https://lists.blocklist.de/lists/bots.txt"

    def __init__(
        self,
        feed_type: str = "strong",
        ttl: int = DEFAULT_TTL,
        feeds_dir: Optional[Path] = None,
    ) -> None:
        """Initialize the Blocklist.de feed.

        Args:
            feed_type: Either 'strong' or 'bots'.
            ttl: Cache TTL in seconds.
            feeds_dir: Override default cache directory.
        """
        if feed_type == "bots":
            url = self.BOTS_URL
            name = "blocklist_de_bots"
        else:
            url = self.STRONG_URL
            name = "blocklist_de_strong"
        super().__init__(name=name, url=url, ttl=ttl, feeds_dir=feeds_dir)

    def parse(self, raw: str) -> Tuple[Set[str], List[str]]:
        """Parse blocklist.de format: plain IPs, one per line.

        Lines may contain timestamps or other metadata — only the first token is used.
        """
        ips: Set[str] = set()
        cidrs: List[str] = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            token = line.split()[0]
            if _is_valid_ipv4(token):
                ips.add(token)
        return ips, cidrs


class SpamhausDROPFeed(ThreatFeedClient):
    """Fetches Spamhaus DROP and EDROP lists.

    - DROP: https://www.spamhaus.org/drop/drop.txt
    - EDROP: https://www.spamhaus.org/drop/drop-edon.txt

    Format uses semicolon-separated fields: CIDR;sdn;net;comment
    CIDR ranges represent hijacked or bogon network space.
    """

    DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
    EDROP_URL = "https://www.spamhaus.org/drop/drop-edon.txt"

    def __init__(
        self,
        drop_type: str = "drop",
        ttl: int = DEFAULT_TTL,
        feeds_dir: Optional[Path] = None,
    ) -> None:
        """Initialize the Spamhaus DROP feed.

        Args:
            drop_type: Either 'drop' or 'edrop'.
            ttl: Cache TTL in seconds.
            feeds_dir: Override default cache directory.
        """
        if drop_type == "edrop":
            url = self.EDROP_URL
            name = "spamhaus_edrop"
        else:
            url = self.DROP_URL
            name = "spamhaus_drop"
        super().__init__(name=name, url=url, ttl=ttl, feeds_dir=feeds_dir)

    def parse(self, raw: str) -> Tuple[Set[str], List[str]]:
        """Parse Spamhaus DROP format: 'CIDR ; sdn ; comment'.

        Lines starting with ';' are comments. First field is the CIDR.
        """
        ips: Set[str] = set()
        cidrs: List[str] = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            # Spamhaus format: CIDR ; SDN ; comment
            parts = line.split(";")
            if not parts:
                continue
            entry = parts[0].strip()
            if "/" in entry:
                try:
                    ipaddress.ip_network(entry, strict=False)
                    cidrs.append(entry)
                except ValueError:
                    pass
            elif _is_valid_ipv4(entry):
                ips.add(entry)
        return ips, cidrs


class FireholFeed(ThreatFeedClient):
    """Fetches the Firehol Level 1 blocklist.

    URL: https://iplists.firehol.org/files/firehol_level1.netset
    Format: plain IP/CIDR list with comments prefixed by '#'.
    Combines multiple upstream blocklists for maximum coverage.
    """

    FIREHOL_L1_URL = "https://iplists.firehol.org/files/firehol_level1.netset"

    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        feeds_dir: Optional[Path] = None,
    ) -> None:
        super().__init__(
            name="firehol_level1",
            url=self.FIREHOL_L1_URL,
            ttl=ttl,
            feeds_dir=feeds_dir,
        )

    def parse(self, raw: str) -> Tuple[Set[str], List[str]]:
        """Parse Firehol netset format: IP or CIDR per line, '#' comments.

        Handles both individual IPs and CIDR ranges.
        """
        ips: Set[str] = set()
        cidrs: List[str] = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            token = line.split()[0]
            if "/" in token:
                try:
                    ipaddress.ip_network(token, strict=False)
                    cidrs.append(token)
                except ValueError:
                    pass
            elif _is_valid_ipv4(token):
                ips.add(token)
        return ips, cidrs


class EmergingThreatsFeed(ThreatFeedClient):
    """Fetches EmergingThreats Suricata rules and extracts IP addresses.

    URL: https://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules
    Format: Suricata rule syntax with IPs embedded in rule fields.
    Extracts IPs from 'content', 'src_ip', 'dst_ip', and '$HOME_NET' patterns.
    """

    ET_URL = "https://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules"

    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        feeds_dir: Optional[Path] = None,
    ) -> None:
        super().__init__(
            name="emerging_threats",
            url=self.ET_URL,
            ttl=ttl,
            feeds_dir=feeds_dir,
        )

    def parse(self, raw: str) -> Tuple[Set[str], List[str]]:
        """Parse Suricata rule files to extract IP addresses.

        Looks for IPs in various rule fields:
          - 'alert ... any -> $HOME_NET any' (header IPs)
          - '[msg="..."]' blocks with IP content
          - 'content:"|...|"' binary patterns (skipped)
          - Standalone IPv4 addresses in rule options
        """
        import re

        ips: Set[str] = set()
        cidrs: List[str] = []
        # Pattern to match IPv4 addresses (not part of larger numbers)
        ip_pattern = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        )

        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Skip rules that don't look like alert/drop/pass
            if not re.match(r"^(alert|drop|reject|pass)\s", line):
                continue

            # Find all IP addresses in the rule
            for match in ip_pattern.finditer(line):
                token = match.group()
                if _is_valid_ipv4(token):
                    # Skip reserved/private ranges that appear in rule syntax
                    # but aren't threat indicators (e.g., $HOME_NET, any)
                    first_octet = int(token.split(".")[0])
                    if first_octet == 0:
                        continue
                    ips.add(token)

        return ips, cidrs


class DShieldFeed(ThreatFeedClient):
    """Fetches DShield's top 100 attacker IPs via their JSON API.

    URL: https://isc.sans.edu/api/top/ips/100?json
    Format: JSON array with 'number', 'count', 'attacks', 'as', 'name', etc.
    Extracts the 'number' field as the attacker IP.
    """

    DSHIELD_URL = "https://isc.sans.edu/api/top/ips/100?json"

    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        feeds_dir: Optional[Path] = None,
    ) -> None:
        super().__init__(
            name="dshield_top100",
            url=self.DSHIELD_URL,
            ttl=ttl,
            feeds_dir=feeds_dir,
        )

    def parse(self, raw: str) -> Tuple[Set[str], List[str]]:
        """Parse DShield JSON API response.

        Expected format: JSON array of objects, each with a 'number' key
        containing the attacker IP address.
        Handles both array and single-object responses.
        """
        ips: Set[str] = set()
        cidrs: List[str] = []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.error("[%s] Failed to parse JSON: %s", self.name, exc)
            return ips, cidrs

        # Normalize to a list
        if isinstance(data, dict):
            # If the response is a wrapper dict, look for an array inside
            for key in ("data", "top", "results", "ips"):
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
            else:
                data = [data]
        elif not isinstance(data, list):
            data = []

        for entry in data:
            if not isinstance(entry, dict):
                continue
            # Try multiple field names that DShield has used historically
            for field in ("number", "ip", "address", "source"):
                if field in entry:
                    ip_val = entry[field]
                    if isinstance(ip_val, str) and _is_valid_ipv4(ip_val.strip()):
                        ips.add(ip_val.strip())
                    break

        return ips, cidrs


# ── Threat Feed Manager ─────────────────────────────────────────────────────────

class ThreatFeedManager:
    """Aggregates all threat feeds, deduplicates, and caches to disk.

    Provides a unified interface to check IPs against all feed sources.
    Feed data is persisted in ~/.reconpro/threat_feeds/ with JSON files.

    Usage:
        mgr = ThreatFeedManager(ttl=3600)  # 1-hour TTL
        counts = mgr.refresh_all()
        hits = mgr.check_ip("1.2.3.4")
        all_ips = mgr.get_unified_ip_set()
    """

    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        feeds_dir: Optional[Path] = None,
        enable_feeds: Optional[List[str]] = None,
    ) -> None:
        """Initialize the ThreatFeedManager.

        Args:
            ttl: Time-to-live for all feed caches in seconds (default: 6 hours).
            feeds_dir: Override the default cache directory.
            enable_feeds: List of feed names to enable. If None, all feeds are enabled.
        """
        self._ttl = ttl
        self._feeds_dir = feeds_dir
        self._feeds: Dict[str, ThreatFeedClient] = {
            "blocklist_de_strong": BlocklistDEFeed("strong", ttl=ttl, feeds_dir=feeds_dir),
            "blocklist_de_bots": BlocklistDEFeed("bots", ttl=ttl, feeds_dir=feeds_dir),
            "spamhaus_drop": SpamhausDROPFeed("drop", ttl=ttl, feeds_dir=feeds_dir),
            "spamhaus_edrop": SpamhausDROPFeed("edrop", ttl=ttl, feeds_dir=feeds_dir),
            "firehol_level1": FireholFeed(ttl=ttl, feeds_dir=feeds_dir),
            "emerging_threats": EmergingThreatsFeed(ttl=ttl, feeds_dir=feeds_dir),
            "dshield_top100": DShieldFeed(ttl=ttl, feeds_dir=feeds_dir),
        }

        # Filter enabled feeds if specified
        if enable_feeds is not None:
            self._feeds = {
                k: v for k, v in self._feeds.items() if k in enable_feeds
            }

    def refresh_all(self, force: bool = False) -> Dict[str, int]:
        """Fetch and refresh all enabled feeds.

        Args:
            force: If True, bypass the TTL cache for all feeds.

        Returns:
            Dictionary mapping feed names to their indicator counts.
            A value of -1 indicates a fetch failure with no cached data.
        """
        results: Dict[str, int] = {}
        for name, feed in self._feeds.items():
            try:
                count = feed.fetch(force=force)
                results[name] = count
            except Exception as exc:
                logger.error("[ThreatFeedManager] Error refreshing %s: %s", name, exc)
                results[name] = -1
        return results

    def check_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Check a single IP against all enabled threat feeds.

        Args:
            ip: IPv4 address to check.

        Returns:
            List of hit dictionaries, each containing 'feed', 'ip', and 'url'.
        """
        hits: List[Dict[str, Any]] = []
        for name, feed in self._feeds.items():
            try:
                if feed.contains_ip(ip):
                    hits.append({
                        "feed": name,
                        "ip": ip,
                        "url": feed.url,
                    })
            except Exception as exc:
                logger.error("[ThreatFeedManager] Error checking %s on %s: %s", ip, name, exc)
        return hits

    def check_ips(self, ips: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Check multiple IPs against all threat feeds.

        Args:
            ips: List of IPv4 addresses to check.

        Returns:
            Dictionary mapping each IP to its list of feed hits.
        """
        return {ip: self.check_ip(ip) for ip in ips}

    def get_unified_ip_set(self) -> Set[str]:
        """Return a deduplicated set of all IPs from all enabled feeds.

        CIDRs are NOT expanded — only standalone IPs are included.
        """
        all_ips: Set[str] = set()
        for feed in self._feeds.values():
            if not feed._loaded:
                feed._load_cache()
            all_ips |= feed.get_ips()
        return all_ips

    def get_unified_cidr_list(self) -> List[str]:
        """Return all CIDRs from all enabled feeds (deduplicated)."""
        seen: Set[str] = set()
        result: List[str] = []
        for feed in self._feeds.values():
            if not feed._loaded:
                feed._load_cache()
            for cidr in feed.get_cidrs():
                if cidr not in seen:
                    seen.add(cidr)
                    result.append(cidr)
        return result

    def get_stats(self) -> Dict[str, Dict[str, Any]]:
        """Return statistics for all enabled feeds.

        Returns:
            Dictionary mapping feed names to their stats dictionaries.
        """
        return {name: feed.get_stats() for name, feed in self._feeds.items()}

    def get_total_count(self) -> int:
        """Return the total number of unique indicators across all feeds."""
        return len(self.get_unified_ip_set()) + len(self.get_unified_cidr_list())

    def get_feed(self, name: str) -> Optional[ThreatFeedClient]:
        """Get a specific feed client by name."""
        return self._feeds.get(name)

    def list_feeds(self) -> List[str]:
        """Return the list of enabled feed names."""
        return list(self._feeds.keys())


# ── DNSBL Checker ──────────────────────────────────────────────────────────────

class DNSBLChecker:
    """Checks IP addresses against DNS-based Blackhole Lists (DNSBLs).

    Uses standard DNS queries via socket.getaddrinfo to query each DNSBL zone.
    For each IP, the octets are reversed and appended to the DNSBL zone name.

    Example: checking 1.2.3.4 on zen.spamhaus.org queries:
        4.3.2.1.zen.spamhaus.org

    Usage:
        checker = DNSBLChecker()
        hits = checker.check_ip("1.2.3.4")
        is_bad = checker.is_listed("1.2.3.4")
    """

    def __init__(
        self,
        servers: Optional[List[Tuple[str, str]]] = None,
        timeout: float = 3.0,
    ) -> None:
        """Initialize the DNSBL checker.

        Args:
            servers: List of (zone, name) tuples. Defaults to built-in DNSBL_SERVERS.
            timeout: DNS query timeout in seconds per server.
        """
        self._servers = servers if servers is not None else list(DNSBL_SERVERS)
        self._timeout = timeout

    def check_ip(self, ip: str) -> List[Dict[str, Any]]:
        """Check a single IP against all configured DNSBL servers.

        Args:
            ip: IPv4 address to check.

        Returns:
            List of hit dictionaries with 'dnsbl', 'server', 'ip', and 'listed' fields.
        """
        hits: List[Dict[str, Any]] = []
        reversed_ip = _reverse_ip(ip)

        for zone, name in self._servers:
            query = f"{reversed_ip}.{zone}"
            try:
                # Use getaddrinfo for DNS resolution — returns result if listed
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(self._timeout)
                try:
                    result = socket.getaddrinfo(query, None)
                finally:
                    socket.setdefaulttimeout(old_timeout)

                if result:
                    # Extract the return code (A record) for additional context
                    response_ip = result[0][4][0] if result[0][4] else "unknown"
                    hits.append({
                        "dnsbl": name,
                        "server": zone,
                        "ip": ip,
                        "listed": True,
                        "response_ip": response_ip,
                    })
            except (socket.gaierror, socket.herror):
                # Not listed — gaierror with EAI_NONAME means negative result
                pass
            except socket.timeout:
                logger.warning("[DNSBL] Timeout checking %s on %s", ip, zone)
            except Exception as exc:
                logger.error("[DNSBL] Error checking %s on %s: %s", ip, zone, exc)

        return hits

    def check_ips(self, ips: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Check multiple IPs against all DNSBL servers.

        Args:
            ips: List of IPv4 addresses.

        Returns:
            Dictionary mapping each IP to its DNSBL hit list.
        """
        return {ip: self.check_ip(ip) for ip in ips}

    def is_listed(self, ip: str) -> bool:
        """Quick boolean check: is the IP listed on any DNSBL?

        Args:
            ip: IPv4 address.

        Returns:
            True if the IP is found on at least one DNSBL.
        """
        return len(self.check_ip(ip)) > 0

    def get_listed_servers(self, ip: str) -> List[str]:
        """Return the names of DNSBL servers where the IP is listed.

        Args:
            ip: IPv4 address.

        Returns:
            List of DNSBL server names that have the IP listed.
        """
        hits = self.check_ip(ip)
        return [h["dnsbl"] for h in hits]


# ── Convenience Functions ─────────────────────────────────────────────────────

def check_ip_reputation(
    ip: str,
    feed_manager: Optional[ThreatFeedManager] = None,
    dnsbl_checker: Optional[DNSBLChecker] = None,
    ttl: int = DEFAULT_TTL,
) -> Dict[str, Any]:
    """Perform a comprehensive IP reputation check combining feed and DNSBL data.

    Args:
        ip: IPv4 address to check.
        feed_manager: Optional pre-configured ThreatFeedManager.
        dnsbl_checker: Optional pre-configured DNSBLChecker.
        ttl: TTL for feed cache if a new manager is created.

    Returns:
        Dictionary with 'ip', 'threat_feeds', 'dnsbl_hits', 'is_malicious',
        and 'threat_score' (0–100 scale).
    """
    results: Dict[str, Any] = {
        "ip": ip,
        "threat_feeds": [],
        "dnsbl_hits": [],
        "is_malicious": False,
        "threat_score": 0,
        "checked_at": time.time(),
    }

    # Check threat feeds
    if feed_manager is None:
        feed_manager = ThreatFeedManager(ttl=ttl)
        feed_manager.refresh_all()

    feed_hits = feed_manager.check_ip(ip)
    results["threat_feeds"] = feed_hits
    results["threat_score"] += len(feed_hits) * 20

    # Check DNSBLs
    if dnsbl_checker is None:
        dnsbl_checker = DNSBLChecker()

    dnsbl_hits = dnsbl_checker.check_ip(ip)
    results["dnsbl_hits"] = dnsbl_hits
    results["threat_score"] += len(dnsbl_hits) * 10

    # Clamp score to 0–100
    results["threat_score"] = min(results["threat_score"], 100)
    results["is_malicious"] = results["threat_score"] > 0

    return results


# DEAD CODE: consider removal
def quick_threat_check(ip: str) -> Dict[str, Any]:
    """Quick single-call threat check using default configuration.

    Combines ThreatFeedManager and DNSBLChecker with default settings.
    """
    return check_ip_reputation(ip)

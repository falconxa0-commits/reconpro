"""ReconPro GeoIP Enrichment — IP geolocation with local heuristics fallback.

Uses ip-api.com free JSON endpoint (no API key required, 45 req/min limit)
with local JSON cache (24h TTL) and comprehensive IP range heuristics as
fallback when the API is unavailable or rate-limited.

Cloud provider ranges are detected locally for: AWS, Azure, GCP,
Cloudflare, OVH, DigitalOcean, Hetzner, and Linode.

Cached to ~/.reconpro/geoip_cache.json with configurable TTL.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Constants ──────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

GEOIP_CACHE_DIR = Path.home() / ".reconpro"
GEOIP_CACHE_FILE = GEOIP_CACHE_DIR / "geoip_cache.json"
GEOIP_API_URL = "http://ip-api.com/json/"
GEOIP_BATCH_URL = "http://ip-api.com/batch"
DEFAULT_TTL = 86400  # 24 hours in seconds
BATCH_SIZE = 100      # ip-api.com batch endpoint limit
RATE_LIMIT_INTERVAL = 1.5  # seconds between batch requests (~40/min, under 45/min cap)
API_TIMEOUT = 10       # seconds for single IP lookup
BATCH_TIMEOUT = 30     # seconds for batch lookup

# Common hosting / cloud provider AS/org name patterns
HOSTING_AS_PATTERNS = [
    "amazon", "aws", "amazon.com", "amazonaws",
    "google cloud", "google llc", "gcp",
    "microsoft azure", "azure", "microsoft corporation",
    "digitalocean", "digital ocean",
    "linode", "akamai connected cloud",
    "akamai technologies",
    "vultr holdings",
    "ovh sas", "ovh",
    "hetzner online",
    "cloudflare",
    "oracle cloud", "alibaba",
    "rackspace", "ibm cloud",
    "scaleway", "upcloud",
    "choopa", "m247",
]

PROXY_AS_PATTERNS = [
    "vpn", "proxy", "tor ", "tor-exit",
    "anonymize", "privacy", "hide",
    "nord", "express", "surfshark", "mullvad",
    "private internet access", "pia",
    "cyberghost", "protonvpn",
]

# ── Cloud Provider IP Ranges (CIDR) ─────────────────────────

# Well-known representative CIDRs for major cloud providers.
# These are NOT exhaustive (full ranges are published via IP ranges JSON
# by each provider), but cover the most commonly observed blocks.
CLOUD_RANGES: List[Tuple[str, str, List[str]]] = [
    # (provider_name, cidr, [tags])
    ("AWS", "3.0.0.0/8", ["aws", "amazon"]),
    ("AWS", "52.0.0.0/8", ["aws", "amazon"]),
    ("AWS", "54.0.0.0/8", ["aws", "amazon"]),
    ("Azure", "4.0.0.0/8", ["azure", "microsoft"]),
    ("Azure", "20.0.0.0/8", ["azure", "microsoft"]),
    ("Azure", "40.0.0.0/8", ["azure", "microsoft"]),
    ("Azure", "104.0.0.0/8", ["azure", "microsoft"]),
    ("GCP", "35.0.0.0/8", ["gcp", "google"]),
    ("Cloudflare", "104.16.0.0/12", ["cloudflare"]),
    ("Cloudflare", "104.28.0.0/14", ["cloudflare"]),
    ("Cloudflare", "172.64.0.0/13", ["cloudflare"]),
    ("Cloudflare", "173.245.48.0/20", ["cloudflare"]),
    ("DigitalOcean", "162.243.0.0/16", ["digitalocean"]),
    ("DigitalOcean", "104.236.0.0/16", ["digitalocean"]),
    ("DigitalOcean", "128.199.0.0/16", ["digitalocean"]),
    ("Hetzner", "46.4.0.0/16", ["hetzner"]),
    ("Hetzner", "136.243.0.0/16", ["hetzner"]),
    ("Hetzner", "178.63.0.0/16", ["hetzner"]),
    ("Hetzner", "195.201.0.0/16", ["hetzner"]),
    ("Hetzner", "65.108.0.0/16", ["hetzner"]),
    ("Linode", "45.33.0.0/16", ["linode"]),
    ("Linode", "66.228.0.0/16", ["linode"]),
    ("Linode", "96.126.0.0/16", ["linode"]),
    ("Linode", "139.144.0.0/16", ["linode"]),
    ("Linode", "172.232.0.0/16", ["linode"]),
    ("OVH", "5.135.0.0/16", ["ovh"]),
    ("OVH", "37.59.0.0/16", ["ovh"]),
    ("OVH", "51.15.0.0/16", ["ovh"]),
    ("OVH", "51.178.0.0/16", ["ovh"]),
    ("OVH", "91.121.0.0/16", ["ovh"]),
    ("OVH", "92.222.0.0/16", ["ovh"]),
    ("OVH", "94.23.0.0/16", ["ovh"]),
    ("OVH", "141.94.0.0/16", ["ovh"]),
    ("OVH", "149.202.0.0/16", ["ovh"]),
    ("OVH", "213.186.0.0/16", ["ovh"]),
]

# Pre-parse CIDR networks for fast membership testing
_PARSED_CLOUD_NETWORKS: List[Tuple[ipaddress.IPv4Network, str, List[str]]] = []
for _provider, _cidr, _tags in CLOUD_RANGES:
    try:
        _PARSED_CLOUD_NETWORKS.append(
            (ipaddress.ip_network(_cidr, strict=False), _provider, _tags)
        )
    except ValueError:
        pass


# ── IP Validation Helpers ──────────────────────────────────

def _is_valid_ipv4(ip: str) -> bool:
    """Check if the string is a valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except (socket.error, ValueError, OSError):
        return False


def _is_private(ip: str) -> bool:
    """Check if IP is in private, loopback, or reserved range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        return True


def _detect_cloud_provider(ip: str) -> Optional[Dict[str, Any]]:
    """Check if an IP falls within known cloud provider ranges.

    Args:
        ip: IPv4 address string.

    Returns:
        Dict with 'provider', 'tags', 'hosting' if matched, else None.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    for network, provider, tags in _PARSED_CLOUD_NETWORKS:
        if addr in network:
            return {
                "provider": provider,
                "tags": tags,
                "hosting": True,
            }
    return None


def _local_fallback(ip: str) -> Dict[str, Any]:
    """Generate a local heuristic-based GeoIP result when API is unavailable.

    Checks private ranges and known cloud provider ranges.

    Args:
        ip: The IP address string.

    Returns:
        Dict with best-effort geo fields populated.
    """
    result: Dict[str, Any] = {
        "ip": ip,
        "country": "Unknown",
        "countryCode": "--",
        "city": "Unknown",
        "region": "Unknown",
        "regionName": "Unknown",
        "isp": "Unknown",
        "org": "Unknown",
        "as": "AS????",
        "lat": 0.0,
        "lon": 0.0,
        "proxy": False,
        "hosting": False,
        "source": "local_heuristic",
        "cloud_provider": None,
    }

    if _is_private(ip):
        result["country"] = "RFC1918"
        result["city"] = "Private Network"
        result["isp"] = "Private/Reserved"
        return result

    cloud = _detect_cloud_provider(ip)
    if cloud:
        result["hosting"] = True
        result["isp"] = cloud["provider"]
        result["org"] = cloud["provider"]
        result["cloud_provider"] = cloud["provider"]

    return result


# ── API Field Spec ─────────────────────────────────────

API_FIELDS = (
    "status,message,country,countryCode,city,region,regionName,"
    "isp,org,as,lat,lon,proxy,hosting,query"
)


# ───────────────────────────────────────────────────────
# GeoIP Lookup (Single IP)
# ───────────────────────────────────────────────────────

class GeoIPLookup:
    """Single-IP GeoIP enrichment using ip-api.com with local cache.

    Features:
        - Queries ip-api.com free JSON endpoint (no API key needed).
        - Caches results to ~/.reconpro/geoip_cache.json with 24h TTL.
        - Falls back to local IP range heuristics on API failure.
        - Thread-safe with internal locking.
        - Detects cloud providers via local CIDR matching.

    Usage:
        geo = GeoIPLookup()
        result = geo.enrich_ip("8.8.8.8")
        print(result["country"], result["city"], result["isp"])

    Attributes:
        ttl:        Cache time-to-live in seconds.
        cache_file: Path to the JSON cache file.
    """

    def __init__(self, ttl: int = DEFAULT_TTL,
                 cache_file: Optional[Path] = None) -> None:
        self._ttl = ttl
        self._cache_file = cache_file or GEOIP_CACHE_FILE
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._hits = 0
        self._misses = 0
        self._errors = 0
        self._lock = threading.Lock()
        self._load_cache()

    @property
    def ttl(self) -> int:
        return self._ttl

    @property
    def cache_file(self) -> Path:
        return self._cache_file

    # ── Cache I/O ────────────────────────────────────────

    def _load_cache(self) -> None:
        """Load cache from disk, discarding expired entries."""
        if self._cache_file.exists():
            try:
                data = json.loads(self._cache_file.read_text(encoding="utf-8"))
                now = time.time()
                self._cache = {
                    ip: entry for ip, entry in data.items()
                    if now - entry.get("_cached_at", 0) < self._ttl
                }
                logger.debug("GeoIP cache loaded: %d valid entries", len(self._cache))
            except Exception as exc:
                logger.warning("GeoIP cache load failed: %s", exc)
                self._cache = {}

    def _save_cache(self) -> None:
        """Persist cache to disk."""
        try:
            self._cache_file.parent.mkdir(parents=True, exist_ok=True)
            self._cache_file.write_text(
                json.dumps(self._cache, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error("GeoIP cache save failed: %s", exc)

    # ── API ──────────────────────────────────────────────

    def _fetch_from_api(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query ip-api.com JSON endpoint for a single IP.

        Args:
            ip: Valid IPv4 address string.

        Returns:
            Parsed JSON dict if successful, None on any error.
        """
        import urllib.request
        import urllib.error

        url = f"{GEOIP_API_URL}{ip}?fields={API_FIELDS}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "ReconPro/9.1.0"},
            )
            with urllib.request.urlopen(req, timeout=API_TIMEOUT) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                data = json.loads(raw)
                if data.get("status") == "success":
                    data["source"] = "ip-api.com"
                    return data
                logger.debug("ip-api error for %s: %s", ip, data.get("message"))
                return None
        except urllib.error.HTTPError as exc:
            logger.debug("ip-api HTTP error for %s: %s", ip, exc.code)
            self._errors += 1
            return None
        except urllib.error.URLError as exc:
            logger.debug("ip-api URL error for %s: %s", ip, exc.reason)
            self._errors += 1
            return None
        except Exception as exc:
            logger.debug("ip-api lookup failed for %s: %s", ip, exc)
            self._errors += 1
            return None

    # ── Public API ───────────────────────────────────────

    def enrich_ip(self, ip: str, use_cache: bool = True) -> Dict[str, Any]:
        """Enrich a single IP with geolocation data.

        Args:
            ip:         IPv4 address string.
            use_cache:  Whether to check the local cache first.

        Returns:
            Dict with: country, city, region, ISP, AS, org, lat, lon,
            proxy (bool), hosting (bool), and source.
        """
        # Validate IP format
        if not _is_valid_ipv4(ip):
            return {"ip": ip, "error": "invalid_ip", "source": "error"}

        # Private IPs get instant local result
        if _is_private(ip):
            return _local_fallback(ip)

        with self._lock:
            # Check cache
            if use_cache and ip in self._cache:
                cached = dict(self._cache[ip])
                cached.pop("_cached_at", None)
                cached["source"] = "cache"
                self._hits += 1
                return cached

            self._misses += 1

        # Fetch from API
        result = self._fetch_from_api(ip)
        if result:
            result["_cached_at"] = time.time()
            with self._lock:
                self._cache[ip] = result
                # Periodic save every 10 new entries to amortize I/O
                if len(self._cache) % 10 == 0:
                    self._save_cache()
            out = {k: v for k, v in result.items() if not k.startswith("_")}
            return out

        # Fallback to local heuristics
        return _local_fallback(ip)

    def enrich_ips(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Enrich multiple IPs sequentially. Returns {ip: geo_data} dict.

        For large batches, prefer BatchGeoIP.enrich_batch() which uses
        the batch endpoint with proper rate limiting.

        Args:
            ips: List of IPv4 address strings.

        Returns:
            Dict mapping each IP to its enrichment result.
        """
        return {ip: self.enrich_ip(ip) for ip in ips}

    def save(self) -> None:
        """Force-save the cache to disk."""
        with self._lock:
            self._save_cache()

    def clear_cache(self) -> int:
        """Clear all cached entries and delete the cache file.

        Returns:
            Number of entries that were cleared.
        """
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._errors = 0
            try:
                if self._cache_file.exists():
                    self._cache_file.unlink()
            except Exception:
                pass
            return count

    def get_cache_stats(self) -> Dict[str, Any]:
        """Return cache hit/miss/error statistics and configuration."""
        return {
            "cached_ips": len(self._cache),
            "cache_hits": self._hits,
            "cache_misses": self._misses,
            "api_errors": self._errors,
            "ttl_seconds": self._ttl,
            "cache_file": str(self._cache_file),
            "hit_rate": round(self._hits / max(1, self._hits + self._misses), 3),
        }


# ───────────────────────────────────────────────────────
# Batch GeoIP
# ───────────────────────────────────────────────────────

class BatchGeoIP:
    """Batch GeoIP enrichment using ip-api.com batch endpoint.

    Handles rate limiting (45 req/min cap, we target ~40) and splits
    large batches into chunks of 100 (the API maximum).

    For each chunk, a single POST request is made to the batch endpoint.
    On failure, individual fallback lookups are attempted.

    Usage:
        batch = BatchGeoIP()
        results = batch.enrich_batch(["8.8.8.8", "1.1.1.1", "8.8.4.4"])
        for ip, data in results.items():
            print(ip, data["country"])
    """

    def __init__(self, ttl: int = DEFAULT_TTL) -> None:
        self._lookup = GeoIPLookup(ttl=ttl)
        self._last_request_time = 0.0
        self._total_batches = 0
        self._total_ips = 0

    def enrich_batch(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Enrich a batch of IPs using the batch API with rate limiting.

        Args:
            ips: List of IPv4 address strings.

        Returns:
            Dict mapping each IP to its enrichment result.
        """
        results: Dict[str, Dict[str, Any]] = {}
        to_fetch: List[str] = []

        # Separate cached from uncached
        for ip in ips:
            if not _is_valid_ipv4(ip):
                results[ip] = {"ip": ip, "error": "invalid_ip", "source": "error"}
                continue
            if _is_private(ip):
                results[ip] = _local_fallback(ip)
                continue
            cached = self._lookup.enrich_ip(ip, use_cache=True)
            if cached.get("source") == "cache":
                results[ip] = cached
            else:
                to_fetch.append(ip)

        if not to_fetch:
            return results

        # Fetch uncached IPs via batch API
        self._rate_limit_wait()
        batch_results = self._batch_api_request(to_fetch)
        results.update(batch_results)

        # Update cache for successful API results
        for ip, data in batch_results.items():
            if data.get("source") == "ip-api.com":
                data["_cached_at"] = time.time()
                with self._lookup._lock:
                    self._lookup._cache[ip] = data

        self._lookup.save()
        self._total_ips += len(to_fetch)
        return results

    def _batch_api_request(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Send batch requests to ip-api.com, splitting into 100-IP chunks.

        Args:
            ips: List of valid, non-private IPv4 addresses.

        Returns:
            Dict mapping IP to enrichment result.
        """
        import urllib.request
        import urllib.error

        results: Dict[str, Dict[str, Any]] = {}

        for chunk_start in range(0, len(ips), BATCH_SIZE):
            chunk = ips[chunk_start:chunk_start + BATCH_SIZE]

            try:
                payload = [
                    {"query": ip, "fields": API_FIELDS}
                    for ip in chunk
                ]
                body = json.dumps(payload).encode("utf-8")

                req = urllib.request.Request(
                    GEOIP_BATCH_URL,
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "ReconPro/9.1.0",
                    },
                )

                with urllib.request.urlopen(req, timeout=BATCH_TIMEOUT) as resp:
                    raw = resp.read().decode("utf-8", errors="replace")
                    data = json.loads(raw)

                    for entry in data:
                        ip = entry.get("query", "")
                        if entry.get("status") == "success":
                            entry["source"] = "ip-api.com"
                            results[ip] = entry
                        else:
                            if ip:
                                results[ip] = _local_fallback(ip)

                self._total_batches += 1
                logger.debug("GeoIP batch %d: %d IPs processed", self._total_batches, len(chunk))

            except urllib.error.HTTPError as exc:
                logger.warning("GeoIP batch HTTP error: %s", exc.code)
                # Rate-limited (429) or server error — fall back to individual
                self._fallback_individual(chunk, results)
                self._lookup._errors += 1

            except Exception as exc:
                logger.warning("GeoIP batch request failed: %s", exc)
                self._fallback_individual(chunk, results)
                self._lookup._errors += 1

            # Rate limit between chunks
            if chunk_start + BATCH_SIZE < len(ips):
                self._rate_limit_wait()

        return results

    def _fallback_individual(self, ips: List[str],
                             results: Dict[str, Dict[str, Any]]) -> None:
        """Attempt individual lookups for IPs that failed in batch.

        Falls back to local heuristics if API is still failing.
        """
        for ip in ips:
            if ip in results:
                continue
            api_result = self._lookup._fetch_from_api(ip)
            if api_result:
                results[ip] = api_result
            else:
                results[ip] = _local_fallback(ip)
            time.sleep(0.1)  # Minimal throttle for individual fallbacks

    def _rate_limit_wait(self) -> None:
        """Wait to respect ip-api.com rate limit (~45 req/min).

        We target ~40 req/min by waiting at least RATE_LIMIT_INTERVAL
        seconds between batch requests.
        """
        elapsed = time.time() - self._last_request_time
        if elapsed < RATE_LIMIT_INTERVAL:
            time.sleep(RATE_LIMIT_INTERVAL - elapsed)
        self._last_request_time = time.time()

    def get_stats(self) -> Dict[str, Any]:
        """Return batch operation statistics."""
        cache_stats = self._lookup.get_cache_stats()
        return {
            **cache_stats,
            "total_batches_sent": self._total_batches,
            "total_ips_enriched": self._total_ips,
        }


# ───────────────────────────────────────────────────────
# Utility Functions
# ───────────────────────────────────────────────────────

def is_hosting_ip(geo_data: Dict[str, Any]) -> bool:
    """Check if a GeoIP result indicates a hosting/cloud provider.

    Checks both the API's 'hosting' flag and local AS/org pattern matching.

    Args:
        geo_data: Enrichment result dict from enrich_ip() or enrich_batch().

    Returns:
        True if the IP is likely hosted by a cloud/provider.
    """
    if geo_data.get("hosting"):
        return True
    if geo_data.get("cloud_provider"):
        return True
    as_str = geo_data.get("as", "").lower()
    org_str = geo_data.get("org", "").lower()
    combined = f"{as_str} {org_str}"
    return any(p in combined for p in HOSTING_AS_PATTERNS)


def is_proxy_ip(geo_data: Dict[str, Any]) -> bool:
    """Check if a GeoIP result indicates a proxy/VPN/Tor exit node.

    Args:
        geo_data: Enrichment result dict.

    Returns:
        True if the IP is likely a proxy or VPN.
    """
    if geo_data.get("proxy"):
        return True
    as_str = geo_data.get("as", "").lower()
    org_str = geo_data.get("org", "").lower()
    combined = f"{as_str} {org_str}"
    return any(p in combined for p in PROXY_AS_PATTERNS)


# DEAD CODE: consider removal
def format_geoip_summary(geo_data: Dict[str, Any]) -> str:
    """Format a GeoIP result as a compact single-line summary.

    Args:
        geo_data: Enrichment result dict.

    Returns:
        Human-readable summary string.
    """
    parts = [
        geo_data.get("ip", "?"),
        geo_data.get("countryCode", "??"),
        geo_data.get("city", "?"),
        geo_data.get("isp", "?"),
    ]
    tags: List[str] = []
    if geo_data.get("proxy") or is_proxy_ip(geo_data):
        tags.append("PROXY")
    if geo_data.get("hosting") or is_hosting_ip(geo_data):
        tags.append("HOSTING")
    provider = geo_data.get("cloud_provider")
    if provider:
        tags.append(provider.upper())
    if tags:
        parts.append("[" + ",".join(tags) + "]")
    return " | ".join(parts)


# DEAD CODE: consider removal
def detect_cloud_provider(ip: str) -> Optional[str]:
    """Quickly detect if an IP belongs to a known cloud provider.

    This is a pure local check — no API call is made.

    Args:
        ip: IPv4 address string.

    Returns:
        Provider name (e.g. 'AWS', 'Cloudflare') or None.
    """
    result = _detect_cloud_provider(ip)
    return result["provider"] if result else None

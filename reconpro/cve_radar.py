"""CVE / NVD Threat Radar.

Enriches ReconPro findings with real-time CVE data from the NVD REST API.
Results are cached locally to respect rate limits.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional

from reconpro.http_layer import http_probe, RateLimiter


# ── NVD API ────────────────────────────────────────────────────────────

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# 5 req/sec without API key, 50 with one
_RATE_LIMIT = 50 if NVD_API_KEY else 5

# ── Category → NVD search query mapping (15+) ─────────────────────────

CATEGORY_QUERIES: Dict[str, str] = {
    "security_headers":      "HTTP security headers missing",
    "sql_injection":         "SQL injection vulnerability",
    "xss":                   "cross-site scripting XSS",
    "ssrf":                  "server-side request forgery SSRF",
    "open_port":             "open port vulnerability network scanning",
    "command_injection":     "command injection vulnerability",
    "hardcoded_secret":      "hardcoded password credential leak",
    "dangerous_eval":        "code execution eval injection",
    "dangerous_exec":        "arbitrary code execution",
    "unsafe_deserialization": "insecure deserialization vulnerability",
    "weak_crypto":           "weak cryptographic algorithm",
    "debug_mode":            "debug mode information disclosure",
    "cors_wildcard":         "CORS misconfiguration cross-origin",
    "csrf_disabled":         "CSRF cross-site request forgery",
    "cleartext_http":        "HTTP cleartext transport security",
    "weak_random":           "weak random number generator PRNG",
    "path_traversal":        "path traversal directory traversal",
    "temp_file_race":        "temp file race condition TOCTOU",
    "sensitive_logging":     "sensitive data logging information leak",
    "jwt_no_verify":         "JWT JSON web token bypass",
    "broken_access_control": "broken access control IDOR",
    "information_disclosure": "information disclosure vulnerability",
    "misconfiguration":      "security misconfiguration",
    "outdated_component":    "outdated component vulnerability",
}

# Default query when no mapping exists
_DEFAULT_QUERY = "web application security vulnerability"


# ── Cache helpers ─────────────────────────────────────────────────────

def _cache_dir() -> Path:
    d = Path.home() / ".reconpro" / "memory"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _cache_path() -> Path:
    return _cache_dir() / "cve_cache.json"


def _load_cache() -> Dict[str, Any]:
    p = _cache_path()
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass
    return {"queries": {}, "cves": {}}


def _save_cache(cache: Dict[str, Any]) -> None:
    try:
        _cache_path().write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError:
        pass


def _cache_key(query: str) -> str:
    """Deterministic key for a query string."""
    return query.lower().strip()


# ── CVERadar ───────────────────────────────────────────────────────────


class CVERadar:
    """Enrich findings with real CVE data from the NVD.

    Usage::

        radar = CVERadar()
        enriched = radar.bulk_enrich(findings_list)
        summary = radar.threat_summary(enriched)
    """

    def __init__(self) -> None:
        self._cache = _load_cache()
        self._lock = Lock()
        self._limiter = RateLimiter(max_per_second=_RATE_LIMIT)
        self._request_count = 0

    # -- NVD API interaction ---------------------------------------------

    def search_nvd(self, query: str, max_results: int = 5) -> List[Dict[str, Any]]:
        """Query the NVD REST API for CVEs matching *query*.

        Returns a list of simplified CVE dicts.  Empty list on any error.
        """
        key = _cache_key(query)

        # Check cache first (valid for 24 hours)
        cached = self._cache.get("queries", {}).get(key)
        if cached:
            ts = cached.get("ts", 0)
            if time.time() - ts < 86400:
                return cached.get("results", [])[:max_results]

        # Rate-limit
        self._limiter.acquire()

        params: Dict[str, str] = {
            "keywordSearch": query,
            "resultsPerPage": str(min(max_results, 40)),
        }
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{NVD_BASE}?{qs}"

        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        resp = http_probe(url, headers=headers, timeout=15)
        self._request_count += 1

        if not resp.get("ok"):
            # Rate limited — back off
            status = resp.get("status", 0)
            if status == 403:
                time.sleep(1.0)
            return []

        try:
            body = json.loads(resp.get("body", "{}"))
        except json.JSONDecodeError:
            return []

        vulns = body.get("vulnerabilities", [])
        results: List[Dict[str, Any]] = []

        for item in vulns[:max_results]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            
            # Extract description
            descs = cve.get("descriptions", [])
            desc_text = ""
            for d in descs:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break

            # Extract CVSS v3.1 score
            metrics = cve.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", [{}])[0]
            cvss_data = cvss.get("cvssData", {})
            base_score = cvss_data.get("baseScore", 0.0)
            base_severity = cvss_data.get("baseSeverity", "UNKNOWN")

            # Published date
            published = cve.get("published", "")

            entry: Dict[str, Any] = {
                "cve_id": cve_id,
                "description": desc_text[:300],
                "cvss_score": base_score,
                "severity": base_severity,
                "published": published,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
            results.append(entry)

            # Store individual CVE in cache
            self._cache.setdefault("cves", {})[cve_id] = entry

        # Update query cache
        self._cache.setdefault("queries", {})[key] = {
            "ts": time.time(),
            "results": results,
        }
        _save_cache(self._cache)

        return results

    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full details for a single CVE by its ID (e.g. CVE-2024-1234)."""
        # Check cache
        cached = self._cache.get("cves", {}).get(cve_id)
        if cached:
            return cached

        self._limiter.acquire()
        url = f"{NVD_BASE}?cveId={cve_id}"
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        resp = http_probe(url, headers=headers, timeout=15)
        self._request_count += 1

        if not resp.get("ok"):
            return None

        try:
            body = json.loads(resp.get("body", "{}"))
        except json.JSONDecodeError:
            return None

        vulns = body.get("vulnerabilities", [])
        if not vulns:
            return None

        cve = vulns[0].get("cve", {})
        descs = cve.get("descriptions", [])
        desc_text = ""
        for d in descs:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        metrics = cve.get("metrics", {})
        cvss_list = metrics.get("cvssMetricV31", [])
        cvss = cvss_list[0] if cvss_list else {}
        cvss_data = cvss.get("cvssData", {})

        entry: Dict[str, Any] = {
            "cve_id": cve_id,
            "description": desc_text,
            "cvss_score": cvss_data.get("baseScore", 0.0),
            "severity": cvss_data.get("baseSeverity", "UNKNOWN"),
            "published": cve.get("published", ""),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }

        self._cache.setdefault("cves", {})[cve_id] = entry
        _save_cache(self._cache)
        return entry

    # -- Enrichment ------------------------------------------------------

    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single finding dict with related CVEs.

        Adds a ``related_cves`` key to the finding dict.
        """
        category = finding.get("category", "")
        title = finding.get("title", "")

        query = CATEGORY_QUERIES.get(category)
        if not query:
            # Fall back to title-based search
            query = title if title else _DEFAULT_QUERY

        cves = self.search_nvd(query, max_results=3)
        enriched = dict(finding)
        enriched["related_cves"] = cves

        # Attach highest CVSS from CVEs
        if cves:
            max_score = max(c.get("cvss_score", 0) for c in cves)
            enriched["nvd_max_cvss"] = max_score
        else:
            enriched["nvd_max_cvss"] = None

        return enriched

    def bulk_enrich(self, findings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich multiple findings, de-duplicating NVD queries by category.

        Returns a new list with ``related_cves`` added to each finding.
        """
        # Group findings by the NVD query they will trigger
        query_map: Dict[str, List[int]] = {}
        for i, f in enumerate(findings_list):
            cat = f.get("category", "")
            title = f.get("title", "")
            q = CATEGORY_QUERIES.get(cat, title or _DEFAULT_QUERY)
            query_map.setdefault(q, []).append(i)

        # Fetch once per unique query
        query_results: Dict[str, List[Dict[str, Any]]] = {}
        for q, indices in query_map.items():
            cves = self.search_nvd(q, max_results=5)
            query_results[q] = cves

        # Merge into findings
        enriched: List[Dict[str, Any]] = []
        for i, f in enumerate(findings_list):
            cat = f.get("category", "")
            title = f.get("title", "")
            q = CATEGORY_QUERIES.get(cat, title or _DEFAULT_QUERY)
            cves = query_results.get(q, [])

            ef = dict(f)
            ef["related_cves"] = cves
            ef["nvd_max_cvss"] = max((c.get("cvss_score", 0) for c in cves), default=None)
            enriched.append(ef)

        return enriched

    # -- Threat intelligence summary -------------------------------------

    def threat_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a threat intelligence summary from enriched findings."""
        total = len(findings)
        enriched_count = sum(1 for f in findings if f.get("related_cves"))

        # Collect all referenced CVEs (de-duped)
        all_cves: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            for c in f.get("related_cves", []):
                cid = c.get("cve_id", "")
                if cid and cid not in all_cves:
                    all_cves[cid] = c

        # Severity breakdown
        severity_counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Category breakdown
        category_counts: Dict[str, int] = {}
        for f in findings:
            cat = f.get("category", "unknown")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Top CVEs by CVSS
        sorted_cves = sorted(
            all_cves.values(),
            key=lambda c: c.get("cvss_score", 0),
            reverse=True,
        )[:10]

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": total,
            "enriched_with_cves": enriched_count,
            "unique_cves_found": len(all_cves),
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "top_cves": sorted_cves,
            "nvd_requests_made": self._request_count,
            "recommendation": self._generate_recommendation(severity_counts, sorted_cves),
        }

    @staticmethod
    def _generate_recommendation(
        severity_counts: Dict[str, int],
        top_cves: List[Dict[str, Any]],
    ) -> str:
        """Produce a human-readable threat recommendation."""
        parts: List[str] = []

        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)

        if critical:
            parts.append(f"{critical} CRITICAL finding(s) require immediate remediation.")
        if high:
            parts.append(f"{high} HIGH finding(s) should be prioritized this sprint.")

        if top_cves:
            top = top_cves[0]
            parts.append(
                f"Highest CVSS: {top.get('cve_id')} "
                f"(CVSS {top.get('cvss_score', 'N/A')})"
            )

        if not parts:
            parts.append("No significant threats detected. Maintain current security posture.")

        return " ".join(parts)

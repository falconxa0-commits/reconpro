"""Module: INFRASTRUCTURE_GHOST — Digital Infrastructure Ghost for ReconPro v9.2.0.

Creates a complete digital ghost of a target's infrastructure by:
  1. IP Discovery & Mapping — enumerate all IPs via DNS, HTTP redirects, certificates.
  2. Subdomain Infrastructure Scan — map tech stacks, cert chains, response patterns.
  3. Certificate Transparency Mining — extract subdomains, org details from CT logs.
  4. CDN/Cloud Provider Detection — identify hosting, CDNs, cloud services.
  5. Technology Stack Clustering — group assets by shared technologies.
  6. Lookalike Infrastructure Detection — find related domains/hosts.
  7. Infrastructure Drift Detection — compare against historical patterns.
  8. Attack Surface Scoring — score total exposed infrastructure.

Uses ONLY the Python stdlib. No external dependencies.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

from ..http_layer import http_probe, Finding, default_limiter


# ════════════════════════════════════════════════════════════════════════
# DATABASES
# ════════════════════════════════════════════════════════════════════════

CLOUD_PROVIDER_SIGNS: Dict[str, Dict[str, Any]] = {
    "aws": {
        "name": "Amazon Web Services",
        "header_patterns": [
            re.compile(r"x-amz-request-id", re.I),
            re.compile(r"x-amz-cf-id", re.I),
            re.compile(r"x-amzn-requestid", re.I),
        ],
        "body_patterns": [
            re.compile(r"awselasticbeanstalk", re.I),
            re.compile(r"amazon(?:s3|aws|cloudfront)", re.I),
            re.compile(r"aws\.amazon\.com", re.I),
            re.compile(r"s3\.amazonaws\.com", re.I),
        ],
        "cname_patterns": [
            re.compile(r"\.amazonaws\.com$", re.I),
            re.compile(r"\.elb\.amazonaws\.com$", re.I),
            re.compile(r"\.cloudfront\.net$", re.I),
            re.compile(r"\.elasticbeanstalk\.com$", re.I),
        ],
        "ip_ranges": [
            ("3.0.0.0", "3.127.255.255"),
            ("13.32.0.0", "13.64.255.255"),
            ("23.20.0.0", "23.23.255.255"),
            ("34.192.0.0", "34.255.255.255"),
            ("35.160.0.0", "35.183.255.255"),
            ("43.192.0.0", "43.255.255.255"),
            ("44.192.0.0", "44.255.255.255"),
            ("46.137.0.0", "46.137.255.255"),
            ("50.16.0.0", "50.19.255.255"),
            ("52.0.0.0", "52.255.255.255"),
            ("54.0.0.0", "54.255.255.255"),
            ("99.77.0.0", "99.77.255.255"),
            ("107.20.0.0", "107.23.255.255"),
            ("172.16.0.0", "172.31.255.255"),
        ],
    },
    "azure": {
        "name": "Microsoft Azure",
        "header_patterns": [
            re.compile(r"x-ms-request-id", re.I),
            re.compile(r"x-azure-ref", re.I),
            re.compile(r"x-ms-version", re.I),
        ],
        "body_patterns": [
            re.compile(r"microsoftazure", re.I),
            re.compile(r"windows\.net", re.I),
            re.compile(r"azurewebsites\.net", re.I),
            re.compile(r"blob\.core\.windows\.net", re.I),
        ],
        "cname_patterns": [
            re.compile(r"\.cloudapp\.azure\.com$", re.I),
            re.compile(r"\.azurewebsites\.net$", re.I),
            re.compile(r"\.azure\.com$", re.I),
            re.compile(r"\.blob\.core\.windows\.net$", re.I),
        ],
        "ip_ranges": [
            ("4.128.0.0", "4.255.255.255"),
            ("13.64.0.0", "13.107.255.255"),
            ("20.0.0.0", "20.255.255.255"),
            ("40.64.0.0", "40.127.255.255"),
            ("51.4.0.0", "51.16.255.255"),
            ("52.96.0.0", "52.191.255.255"),
            ("65.52.0.0", "65.55.255.255"),
            ("104.40.0.0", "104.47.255.255"),
            ("138.91.0.0", "138.91.255.255"),
        ],
    },
    "gcp": {
        "name": "Google Cloud Platform",
        "header_patterns": [
            re.compile(r"x-goog-request-id", re.I),
            re.compile(r"x-guploader-uploadid", re.I),
        ],
        "body_patterns": [
            re.compile(r"googleapis\.com", re.I),
            re.compile(r"gstatic\.com", re.I),
            re.compile(r"appspot\.com", re.I),
            re.compile(r"googlecloud", re.I),
        ],
        "cname_patterns": [
            re.compile(r"\.appspot\.com$", re.I),
            re.compile(r"\.googleapis\.com$", re.I),
            re.compile(r"\.run\.app$", re.I),
            re.compile(r"\.cloudfunctions\.net$", re.I),
        ],
        "ip_ranges": [
            ("8.34.208.0", "8.35.255.255"),
            ("8.35.192.0", "8.35.207.255"),
            ("34.0.0.0", "34.255.255.255"),
            ("35.184.0.0", "35.255.255.255"),
            ("104.154.0.0", "104.155.255.255"),
            ("104.196.0.0", "104.199.255.255"),
            ("107.167.160.0", "107.167.191.255"),
            ("130.211.0.0", "130.211.255.255"),
        ],
    },
    "digitalocean": {
        "name": "DigitalOcean",
        "header_patterns": [
            re.compile(r"x-do-grid", re.I),
            re.compile(r"x-srv", re.I),
        ],
        "body_patterns": [
            re.compile(r"digitalocean", re.I),
            re.compile(r"droplet", re.I),
        ],
        "cname_patterns": [
            re.compile(r"\.digitaloceanspaces\.com$", re.I),
            re.compile(r"\.cdn\.digitaloceanspaces\.com$", re.I),
        ],
        "ip_ranges": [
            ("45.55.0.0", "45.55.255.255"),
            ("64.225.0.0", "64.227.255.255"),
            ("104.16.0.0", "104.31.255.255"),
            ("134.209.0.0", "134.209.255.255"),
            ("142.93.0.0", "142.93.255.255"),
            ("159.65.0.0", "159.65.255.255"),
            ("165.22.0.0", "165.22.255.255"),
            ("167.99.0.0", "167.99.255.255"),
            ("188.166.0.0", "188.166.255.255"),
            ("198.51.128.0", "198.51.255.255"),
            ("192.81.208.0", "192.81.223.255"),
            ("206.189.0.0", "206.189.255.255"),
        ],
    },
    "cloudflare": {
        "name": "Cloudflare",
        "header_patterns": [
            re.compile(r"^cf-ray", re.I),
            re.compile(r"^cf-cache-status", re.I),
            re.compile(r"cloudflare", re.I),
        ],
        "body_patterns": [
            re.compile(r"cloudflare", re.I),
            re.compile(r"cf-browser-verification", re.I),
            re.compile(r"_cfduid", re.I),
        ],
        "cname_patterns": [
            re.compile(r"\.cdn\.cloudflare\.com$", re.I),
        ],
        "ip_ranges": [
            ("103.21.244.0", "103.21.244.255"),
            ("103.22.200.0", "103.22.200.255"),
            ("103.31.4.0", "103.31.4.255"),
            ("104.16.0.0", "104.31.255.255"),
            ("108.162.192.0", "108.162.255.255"),
            ("131.0.72.0", "131.0.72.255"),
            ("141.101.64.0", "141.101.127.255"),
            ("162.158.0.0", "162.158.255.255"),
            ("172.64.0.0", "172.71.255.255"),
            ("173.245.48.0", "173.245.63.255"),
            ("188.114.96.0", "188.114.127.255"),
            ("190.93.240.0", "190.93.255.255"),
            ("197.234.240.0", "197.234.241.255"),
            ("198.41.128.0", "198.41.255.255"),
        ],
    },
    "oracle": {
        "name": "Oracle Cloud",
        "header_patterns": [
            re.compile(r"x-oracle", re.I),
        ],
        "body_patterns": [
            re.compile(r"oraclecloud", re.I),
            re.compile(r"oracle\.com", re.I),
        ],
        "cname_patterns": [
            re.compile(r"\.oraclecloud\.com$", re.I),
        ],
        "ip_ranges": [
            ("129.213.0.0", "129.213.255.255"),
            ("132.145.0.0", "132.145.255.255"),
            ("140.91.0.0", "140.91.255.255"),
            ("150.136.0.0", "150.136.255.255"),
            ("152.67.0.0", "152.67.255.255"),
        ],
    },
    "linode": {
        "name": "Akamai (Linode)",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"linode", re.I),
        ],
        "cname_patterns": [
            re.compile(r"\.linode\.com$", re.I),
            re.compile(r"\.akamaized\.net$", re.I),
        ],
        "ip_ranges": [
            ("23.92.0.0", "23.95.255.255"),
            ("45.33.0.0", "45.45.255.255"),
            ("45.56.0.0", "45.63.255.255"),
            ("45.74.0.0", "45.79.255.255"),
            ("66.228.0.0", "66.228.63.255"),
            ("69.164.192.0", "69.164.255.255"),
            ("96.126.0.0", "96.126.127.255"),
            ("97.107.128.0", "97.107.143.255"),
            ("139.144.0.0", "139.144.255.255"),
            ("172.104.0.0", "172.105.255.255"),
            ("178.79.128.0", "178.79.191.255"),
            ("192.155.80.0", "192.155.95.255"),
        ],
    },
    "vultr": {
        "name": "Vultr",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"vultr", re.I),
        ],
        "cname_patterns": [
            re.compile(r"\.vultrusercontent\.com$", re.I),
        ],
        "ip_ranges": [
            ("45.32.0.0", "45.77.255.255"),
            ("64.120.0.0", "64.120.127.255"),
            ("66.42.0.0", "66.42.127.255"),
            ("95.179.128.0", "95.179.255.255"),
            ("104.238.0.0", "104.238.255.255"),
            ("108.61.0.0", "108.61.255.255"),
            ("140.82.0.0", "140.82.63.255"),
            ("149.28.0.0", "149.28.255.255"),
            ("161.35.0.0", "161.35.255.255"),
            ("207.246.64.0", "207.246.127.255"),
        ],
    },
}

CDN_FINGERPRINTS: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "name": "Cloudflare",
        "headers": {
            "cf-ray": None,
            "cf-cache-status": None,
            "server": re.compile(r"cloudflare", re.I),
        },
        "body_patterns": [
            re.compile(r"cloudflare[-\s]?(?:challenge|jsd|cdn)", re.I),
            re.compile(r"__cfduid|_cf_bm", re.I),
            re.compile(r"attention required.*cloudflare", re.I),
        ],
        "tls_ja3_hints": ["TLS_AES_128_GCM_SHA256"],
    },
    "akamai": {
        "name": "Akamai",
        "headers": {
            "x-akamai": None,
            "x-akamai-staging": None,
            "x-cache": re.compile(r"^(?:TCP_|AKAMAI)", re.I),
            "x-akamai-transformed": None,
        },
        "body_patterns": [
            re.compile(r"akamaized\.net", re.I),
            re.compile(r"akamai", re.I),
        ],
        "tls_ja3_hints": [],
    },
    "fastly": {
        "name": "Fastly",
        "headers": {
            "x-fastly-request-id": None,
            "x-fastly-trace-id": None,
            "x-served-by": re.compile(r"cache-[\w-]+", re.I),
            "x-cache": re.compile(r"^(?:HIT|MISS|MISS).*fastly", re.I),
        },
        "body_patterns": [
            re.compile(r"fastly", re.I),
        ],
        "tls_ja3_hints": [],
    },
    "cloudfront": {
        "name": "Amazon CloudFront",
        "headers": {
            "x-amz-cf-id": None,
            "x-cache": re.compile(r"^(?:Hit|Miss)\s+from\s+cloudfront", re.I),
            "via": re.compile(r"(?:\d+\s+)?cloudfront\.net", re.I),
        },
        "body_patterns": [
            re.compile(r"cloudfront\.net", re.I),
        ],
        "tls_ja3_hints": [],
    },
    "azure_cdn": {
        "name": "Azure CDN",
        "headers": {
            "x-azure-ref": None,
            "x-azurefdid": None,
            "x-cache": re.compile(r"^(?:HIT|MISS|PARTIAL)_", re.I),
        },
        "body_patterns": [
            re.compile(r"azure\.com.*cdn", re.I),
        ],
        "tls_ja3_hints": [],
    },
    "google_cdn": {
        "name": "Google Cloud CDN",
        "headers": {
            "x-goog-request-id": None,
            "served-by": re.compile(r"cache-\w+", re.I),
        },
        "body_patterns": [
            re.compile(r"googlehosted\.com", re.I),
        ],
        "tls_ja3_hints": [],
    },
    "sucuri": {
        "name": "Sucuri Firewall",
        "headers": {
            "x-sucuri-id": None,
            "x-sucuri-cache": None,
        },
        "body_patterns": [
            re.compile(r"sucuri", re.I),
            re.compile(r"access\s+denied.*sucuri", re.I),
        ],
        "tls_ja3_hints": [],
    },
    "incapsula": {
        "name": "Imperva (Incapsula)",
        "headers": {
            "x-iinfo": None,
            "x-cdn": re.compile(r"incapsula", re.I),
            "visid_incap": None,
            "incap_ses": None,
        },
        "body_patterns": [
            re.compile(r"incapsula", re.I),
            re.compile(r"incap_ses_\d+", re.I),
        ],
        "tls_ja3_hints": [],
    },
    "sectionio": {
        "name": "Section",
        "headers": {
            "x-section-id": None,
            "x-section-pop": None,
        },
        "body_patterns": [],
        "tls_ja3_hints": [],
    },
    "bunny_cdn": {
        "name": "BunnyCDN",
        "headers": {
            "server": re.compile(r"^BunnyCDN", re.I),
            "x-pull": None,
        },
        "body_patterns": [
            re.compile(r"bunnycdn", re.I),
        ],
        "tls_ja3_hints": [],
    },
    "quicly": {
        "name": "QUIC.cloud",
        "headers": {
            "x-qc-pop": None,
            "x-qc-cache": None,
        },
        "body_patterns": [
            re.compile(r"quic\.cloud", re.I),
        ],
        "tls_ja3_hints": [],
    },
}

TECH_STACK_DB: Dict[str, Dict[str, Any]] = {
    # ── Web servers ──
    "nginx": {
        "category": "web_server",
        "header_patterns": [re.compile(r"^nginx/?[\d.]*", re.I)],
        "body_patterns": [re.compile(r"nginx", re.I)],
        "cookie_patterns": [],
    },
    "apache": {
        "category": "web_server",
        "header_patterns": [re.compile(r"^Apache/?[\d.]*", re.I)],
        "body_patterns": [
            re.compile(r"apache/?[\d.]*", re.I),
            re.compile(r"mod_\w+", re.I),
        ],
        "cookie_patterns": [],
    },
    "iis": {
        "category": "web_server",
        "header_patterns": [re.compile(r"^Microsoft-IIS/?[\d.]*$", re.I)],
        "body_patterns": [
            re.compile(r"ASP\.NET", re.I),
            re.compile(r"X-Powered-By.*ASP", re.I),
        ],
        "cookie_patterns": [re.compile(r"ASPSESSIONID", re.I)],
    },
    "caddy": {
        "category": "web_server",
        "header_patterns": [],
        "body_patterns": [],
        "cookie_patterns": [],
        "alt_svc_pattern": re.compile(r"h3=\":443\"; ma=\d+", re.I),
    },
    "openresty": {
        "category": "web_server",
        "header_patterns": [re.compile(r"^openresty/?[\d.]*", re.I)],
        "body_patterns": [re.compile(r"openresty", re.I)],
        "cookie_patterns": [],
    },
    "lite_speed": {
        "category": "web_server",
        "header_patterns": [re.compile(r"^LiteSpeed", re.I)],
        "body_patterns": [re.compile(r"litespeed", re.I)],
        "cookie_patterns": [],
    },
    # ── Backend frameworks ──
    "express": {
        "category": "framework",
        "header_patterns": [re.compile(r"^Express", re.I)],
        "body_patterns": [re.compile(r"express", re.I)],
        "cookie_patterns": [],
    },
    "django": {
        "category": "framework",
        "header_patterns": [re.compile(r"^\d+\s+\d+.*Django", re.I)],
        "body_patterns": [
            re.compile(r"csrfmiddlewaretoken", re.I),
            re.compile(r"django", re.I),
        ],
        "cookie_patterns": [re.compile(r"^csrftoken", re.I)],
    },
    "flask": {
        "category": "framework",
        "header_patterns": [re.compile(r"^Werkzeug", re.I)],
        "body_patterns": [re.compile(r"flask", re.I)],
        "cookie_patterns": [re.compile(r"^session", re.I)],
    },
    "laravel": {
        "category": "framework",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"laravel_session", re.I),
            re.compile(r"laravel", re.I),
        ],
        "cookie_patterns": [re.compile(r"laravel_session", re.I)],
    },
    "rails": {
        "category": "framework",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"csrf-param.*authenticity_token", re.I),
            re.compile(r"turbolinks", re.I),
            re.compile(r"rails", re.I),
        ],
        "cookie_patterns": [re.compile(r"_\w+_session", re.I)],
    },
    "spring": {
        "category": "framework",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"JSESSIONID", re.I),
            re.compile(r"spring", re.I),
        ],
        "cookie_patterns": [re.compile(r"JSESSIONID", re.I)],
    },
    "nextjs": {
        "category": "framework",
        "header_patterns": [re.compile(r"^x-nextjs", re.I)],
        "body_patterns": [
            re.compile(r"__next", re.I),
            re.compile(r"_next/static", re.I),
            re.compile(r"next/link", re.I),
        ],
        "cookie_patterns": [],
    },
    "nuxt": {
        "category": "framework",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"__nuxt", re.I),
            re.compile(r"/_nuxt/", re.I),
        ],
        "cookie_patterns": [],
    },
    "php": {
        "category": "language",
        "header_patterns": [re.compile(r"^PHP/?[\d.]*", re.I)],
        "body_patterns": [
            re.compile(r"\.php[\s?&]", re.I),
            re.compile(r"PHPSESSID", re.I),
        ],
        "cookie_patterns": [re.compile(r"PHPSESSID", re.I)],
    },
    "aspnet": {
        "category": "language",
        "header_patterns": [re.compile(r"X-AspNet(?:Core)?-Version", re.I)],
        "body_patterns": [
            re.compile(r"__VIEWSTATE", re.I),
            re.compile(r"__EVENTVALIDATION", re.I),
        ],
        "cookie_patterns": [re.compile(r"ASP\.NET_SessionId", re.I)],
    },
    "golang": {
        "category": "language",
        "header_patterns": [],
        "body_patterns": [],
        "cookie_patterns": [],
        "header_name_patterns": [re.compile(r"^Go-\d", re.I)],
    },
    # ── CMS ──
    "wordpress": {
        "category": "cms",
        "header_patterns": [
            re.compile(r"^WordPress", re.I),
            re.compile(r"Link.*<[^>]+/wp-json", re.I),
        ],
        "body_patterns": [
            re.compile(r"wp-content|wp-includes", re.I),
            re.compile(r"wordpress", re.I),
            re.compile(r"/wp-login", re.I),
        ],
        "cookie_patterns": [re.compile(r"wordpress_logged_in", re.I)],
    },
    "drupal": {
        "category": "cms",
        "header_patterns": [
            re.compile(r"^X-Drupal-Cache", re.I),
            re.compile(r"^X-Generator: Drupal", re.I),
        ],
        "body_patterns": [
            re.compile(r"Drupal\.settings", re.I),
            re.compile(r"sites/default/files", re.I),
        ],
        "cookie_patterns": [re.compile(r"SSESS", re.I)],
    },
    "joomla": {
        "category": "cms",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"/media/jui/", re.I),
            re.compile(r"Joomla", re.I),
        ],
        "cookie_patterns": [],
    },
    # ── WAF ──
    "cloudflare_waf": {
        "category": "waf",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"cloudflare.*challenge", re.I),
            re.compile(r"cf-browser-verification", re.I),
        ],
        "cookie_patterns": [re.compile(r"__cfduid|_cf_bm", re.I)],
    },
    "aws_waf": {
        "category": "waf",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"awswaf", re.I),
            re.compile(r"AWS\s*WAF", re.I),
        ],
        "cookie_patterns": [re.compile(r"AWSALB|AWSWAF", re.I)],
    },
    # ── Analytics ──
    "google_analytics": {
        "category": "analytics",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"google-analytics\.com/analytics\.js", re.I),
            re.compile(r"gtag\(['\"](?:config|js)['\"]\)", re.I),
            re.compile(r"UA-\d+-\d+", re.I),
            re.compile(r"G-[A-Z0-9]+", re.I),
        ],
        "cookie_patterns": [re.compile(r"_ga|_gid|_gat", re.I)],
    },
    "gtm": {
        "category": "analytics",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"googletagmanager\.com/gtag", re.I),
            re.compile(r"GTM-[A-Z0-9]+", re.I),
        ],
        "cookie_patterns": [],
    },
    # ── E-commerce ──
    "shopify": {
        "category": "ecommerce",
        "header_patterns": [re.compile(r"^X-ShopId", re.I)],
        "body_patterns": [
            re.compile(r"cdn\.shopify\.com", re.I),
            re.compile(r"Shopify\.theme", re.I),
        ],
        "cookie_patterns": [re.compile(r"_shopify", re.I)],
    },
    "magento": {
        "category": "ecommerce",
        "header_patterns": [],
        "body_patterns": [
            re.compile(r"magento", re.I),
            re.compile(r"Mage\.Cookies", re.I),
        ],
        "cookie_patterns": [re.compile(r"mage-cache", re.I)],
    },
}


# ════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════

MODULE_NAME = "infrastructure_ghost"

SEV_POINTS = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 2,
    "info": 0,
}


def _dread(damage: int, repro: int, exploit: int, affected: int, discover: int) -> float:
    """Compute DREAD score (0–10) from five component ratings."""
    return round((damage + repro + exploit + affected + discover) / 5.0, 1)


def _ip_in_range(ip: str, start: str, end: str) -> bool:
    """Check if IP falls within [start, end] range."""
    try:
        ip_n = _ip_to_int(ip)
        return _ip_to_int(start) <= ip_n <= _ip_to_int(end)
    except (ValueError, TypeError):
        return False


def _ip_to_int(ip: str) -> int:
    parts = ip.strip().split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid IP: {ip}")
    return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])


def _extract_domain(target: str) -> str:
    """Extract base domain from a target string."""
    t = target.strip().lower()
    if t.startswith("http://") or t.startswith("https://"):
        t = urllib.parse.urlparse(t).hostname or t
    t = t.rstrip("/")
    # Remove port
    if ":" in t:
        t = t.split(":")[0]
    return t


def _fingerprint_hash(host: str, techs: List[str], ips: List[str], cert_orgs: List[str]) -> str:
    """Create a stable fingerprint hash for infrastructure drift comparison."""
    blob = "|".join(sorted(set(techs))) + "||" + "|".join(sorted(set(ips))) + "||" + "|".join(sorted(set(cert_orgs)))
    return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()[:32]


def _name_similarity(a: str, b: str) -> float:
    """Compute a 0-1 similarity score between two domain/subdomain names."""
    a, b = a.lower().strip(), b.lower().strip()
    if a == b:
        return 1.0
    # Strip common suffix
    parts_a = a.rsplit(".", 2)
    parts_b = b.rsplit(".", 2)
    if len(parts_a) >= 2 and len(parts_b) >= 2 and parts_a[-2:] == parts_b[-2:]:
        a_stem, b_stem = parts_a[0], parts_b[0]
    else:
        a_stem, b_stem = a, b
    # Common prefix length
    prefix_len = 0
    for ca, cb in zip(a_stem, b_stem):
        if ca == cb:
            prefix_len += 1
        else:
            break
    max_len = max(len(a_stem), len(b_stem), 1)
    return prefix_len / max_len


# ════════════════════════════════════════════════════════════════════════
# 1. IP DISCOVERY & MAPPING
# ════════════════════════════════════════════════════════════════════════

def _resolve_dns(host: str) -> List[str]:
    """Resolve a hostname to all A/AAAA records via stdlib socket."""
    ips: List[str] = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            results = socket.getaddrinfo(host, None, family, socket.SOCK_STREAM)
            for r in results:
                ip = r[4][0]
                if ip not in ips:
                    ips.append(ip)
        except (socket.gaierror, OSError):
            continue
    return ips


def _discover_ips_from_redirects(base_url: str, timeout: int, verify_tls: bool) -> List[str]:
    """Follow HTTP redirects and collect IPs from Location headers."""
    ips: List[str] = []
    url = base_url
    seen: Set[str] = set()
    for _ in range(10):  # max redirect depth
        if url in seen:
            break
        seen.add(url)
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        # Resolve the redirect target
        for ip in _resolve_dns(host):
            if ip not in ips:
                ips.append(ip)
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
        status = resp.get("status", 0)
        if status in (301, 302, 303, 307, 308):
            location = resp.get("headers", {}).get("Location", "" or resp.get("headers", {}).get("location", ""))
            if not location:
                break
            # Handle relative redirects
            if location.startswith("/"):
                location = f"{parsed.scheme}://{parsed.netloc}{location}"
            elif not location.startswith("http"):
                location = f"{parsed.scheme}://{parsed.netloc}/{location.lstrip('/')}"
            url = location
        else:
            break
    return ips


def _discover_ips_from_certs(host: str, port: int = 443, timeout: int = 8) -> List[str]:
    """Extract subject/alt-name IPs from TLS certificate."""
    ips: List[str] = []
    try:
        from ..http_layer import inspection_context
        # certificate inspection (audited helper — not data transport)
        ctx = inspection_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert_der = tls.getpeercert(binary_form=True)
                if cert_der:
                    # Decode using stdlib — extract SANs
                    import ssl as _ssl_mod
                    cert_dict = ssl.DER_cert_to_PEM_cert(cert_der)
                    # Parse PEM for subjectAltName
                    in_san = False
                    for line in cert_dict.splitlines():
                        line = line.strip()
                        if "Subject Alternative Name" in line:
                            in_san = True
                            continue
                        if in_san:
                            if line.startswith("---"):
                                in_san = False
                                continue
                            # Extract IPs from SAN
                            for part in line.split(","):
                                part = part.strip()
                                if part.startswith("IP Address:"):
                                    ip_addr = part[len("IP Address:"):].strip()
                                    if ip_addr not in ips:
                                        ips.append(ip_addr)
    except (ssl.SSLError, socket.error, OSError, Exception):
        pass
    return ips


def _run_ip_discovery(target: str, base_url: str, timeout: int, verify_tls: bool) -> Dict[str, Any]:
    """Phase 1: Enumerate all IPs associated with the target."""
    host = _extract_domain(target)
    all_ips: List[str] = []
    sources: Dict[str, List[str]] = {}

    # DNS resolution
    dns_ips = _resolve_dns(host)
    sources["dns"] = dns_ips
    for ip in dns_ips:
        if ip not in all_ips:
            all_ips.append(ip)

    # HTTP redirect chain
    redir_ips = _discover_ips_from_redirects(base_url, timeout, verify_tls)
    sources["http_redirects"] = redir_ips
    for ip in redir_ips:
        if ip not in all_ips:
            all_ips.append(ip)

    # Certificate SAN IPs
    cert_ips = _discover_ips_from_certs(host, 443, timeout)
    sources["certificates"] = cert_ips
    for ip in cert_ips:
        if ip not in all_ips:
            all_ips.append(ip)

    return {
        "target": host,
        "total_ips": len(all_ips),
        "ips": all_ips,
        "sources": sources,
    }


# ════════════════════════════════════════════════════════════════════════
# 2. SUBDOMAIN INFRASTRUCTURE SCAN
# ════════════════════════════════════════════════════════════════════════

COMMON_SUBDOMAINS: List[str] = [
    "www", "api", "app", "mail", "smtp", "pop", "imap", "ftp", "sftp",
    "ssh", "vpn", "remote", "gateway", "admin", "portal", "dashboard",
    "staging", "dev", "test", "uat", "qa", "ci", "cd", "build",
    "cdn", "static", "assets", "images", "media", "img", "css", "js",
    "blog", "docs", "help", "support", "forum", "wiki", "knowledge",
    "shop", "store", "pay", "checkout", "billing", "account",
    "auth", "login", "sso", "oauth", "id", "identity",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "search", "analytics", "metrics", "grafana", "prometheus", "kibana",
    "webhook", "hook", "notify", "push", "notification",
    "m", "mobile", "app1", "app2", "v1", "v2", "v3", "api2", "api-v2",
    "internal", "intranet", "private", "stage", "prod", "preview",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "email", "webmail", "autodiscover",
    "git", "gitlab", "github", "repo", "code", "jenkins",
    "minio", "s3", "storage", "backup", "archive", "logs",
    "status", "health", "ping", "monitor", "trace", "jaeger",
]


def _get_certificate_info(host: str, port: int = 443, timeout: int = 8) -> Dict[str, Any]:
    """Extract certificate details: issuer, subject, SANs, org."""
    info: Dict[str, Any] = {
        "issuer": "",
        "subject": "",
        "sans": [],
        "org": "",
        "serial": "",
        "not_before": "",
        "not_after": "",
        "error": None,
    }
    try:
        from ..http_layer import inspection_context
        # certificate inspection (audited helper — not data transport)
        ctx = inspection_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                if not cert:
                    info["error"] = "no_certificate"
                    return info
                # Subject
                subject_parts = []
                for rdn in cert.get("subject", ()):
                    for attr_type, attr_val in rdn:
                        subject_parts.append(f"{attr_type}={attr_val}")
                info["subject"] = ", ".join(subject_parts)
                # Issuer
                issuer_parts = []
                for rdn in cert.get("issuer", ()):
                    for attr_type, attr_val in rdn:
                        issuer_parts.append(f"{attr_type}={attr_val}")
                info["issuer"] = ", ".join(issuer_parts)
                # Organization
                for rdn in cert.get("subject", ()):
                    for attr_type, attr_val in rdn:
                        if attr_type == "organizationName":
                            info["org"] = attr_val
                # Serial
                info["serial"] = cert.get("serialNumber", "")
                # Validity
                info["not_before"] = cert.get("notBefore", "")
                info["not_after"] = cert.get("notAfter", "")
                # SANs
                for ext in cert.get("extensions", []):
                    if ext[0] == "subjectAltName":
                        for san in ext[1]:
                            info["sans"].append(san[1])
    except (ssl.SSLError, socket.error, OSError) as exc:
        info["error"] = str(exc)
    except Exception as exc:
        info["error"] = str(exc)
    return info


def _detect_tech_stack(headers: Dict[str, str], body: str) -> List[str]:
    """Detect technologies from HTTP response headers and body."""
    detected: List[str] = []
    body_lower = body[:8192].lower()
    header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
    cookie_str = headers.get("set-cookie", "")

    for tech_name, tech_info in TECH_STACK_DB.items():
        matched = False
        # Header value patterns (e.g., Server: nginx)
        for pat in tech_info.get("header_patterns", []):
            if pat.search(header_str):
                matched = True
                break
        if not matched:
            for pat in tech_info.get("header_name_patterns", []):
                for h_key in headers:
                    if pat.search(h_key):
                        matched = True
                        break
                if matched:
                    break
        if not matched:
            for pat in tech_info.get("body_patterns", []):
                if pat.search(body_lower):
                    matched = True
                    break
        if not matched:
            for pat in tech_info.get("cookie_patterns", []):
                if pat.search(cookie_str):
                    matched = True
                    break
        if matched and tech_name not in detected:
            detected.append(tech_name)

    return detected


def _scan_subdomain_infrastructure(
    domain: str, subdomain: str, timeout: int, verify_tls: bool
) -> Dict[str, Any]:
    """Scan a single subdomain for infrastructure details."""
    fqdn = f"{subdomain}.{domain}" if subdomain else domain
    result: Dict[str, Any] = {
        "host": fqdn,
        "resolves": False,
        "ips": [],
        "http_reachable": False,
        "status": 0,
        "tech_stack": [],
        "cert": {},
        "response_time_ms": 0,
    }

    # DNS resolution
    ips = _resolve_dns(fqdn)
    if not ips:
        return result
    result["resolves"] = True
    result["ips"] = ips

    # HTTP probe
    start = time.monotonic()
    resp = http_probe(f"https://{fqdn}", timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    result["response_time_ms"] = elapsed_ms

    if resp.get("status", 0) > 0:
        result["http_reachable"] = True
        result["status"] = resp["status"]
        result["tech_stack"] = _detect_tech_stack(resp.get("headers", {}), resp.get("body", ""))
    else:
        # Try HTTP
        resp = http_probe(f"http://{fqdn}", timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
        if resp.get("status", 0) > 0:
            result["http_reachable"] = True
            result["status"] = resp["status"]
            result["tech_stack"] = _detect_tech_stack(resp.get("headers", {}), resp.get("body", ""))

    # Certificate
    cert_info = _get_certificate_info(fqdn, 443, timeout)
    if not cert_info.get("error"):
        result["cert"] = cert_info

    return result


def _run_subdomain_scan(
    domain: str, ct_subdomains: List[str], timeout: int, verify_tls: bool
) -> List[Dict[str, Any]]:
    """Phase 2: Scan all known subdomains for infrastructure details."""
    # Merge CT-discovered subs with common wordlist
    all_subs: Set[str] = set(ct_subdomains)
    for sub in COMMON_SUBDOMAINS:
        all_subs.add(sub)
    # Also add subs extracted from CT results

    results: List[Dict[str, Any]] = []
    for sub in sorted(all_subs):
        info = _scan_subdomain_infrastructure(domain, sub, timeout, verify_tls)
        if info["resolves"] or info["http_reachable"]:
            results.append(info)
    return results


# ════════════════════════════════════════════════════════════════════════
# 3. CERTIFICATE TRANSPARENCY MINING
# ════════════════════════════════════════════════════════════════════════

CT_LOG_ENDPOINTS = [
    "https://crt.sh/?q={domain}&output=json",
]


def _mine_ct_logs(domain: str, timeout: int) -> Dict[str, Any]:
    """Phase 3: Extract subdomains, org details, cert chains from CT logs."""
    result: Dict[str, Any] = {
        "subdomains": [],
        "organizations": [],
        "issuers": [],
        "cert_count": 0,
        "wildcard_count": 0,
        "expired_count": 0,
        "entries": [],
        "error": None,
    }

    url = CT_LOG_ENDPOINTS[0].format(domain=urllib.parse.quote(domain))
    resp = http_probe(url, timeout=max(timeout, 15), verify_tls=True, limiter=default_limiter)

    if not resp.get("ok") or resp.get("status") != 200:
        result["error"] = f"CT log query failed: status={resp.get('status')} {resp.get('reason')}"
        return result

    try:
        entries = json.loads(resp.get("body", ""))
    except (json.JSONDecodeError, ValueError):
        result["error"] = "Failed to parse CT log response"
        return result

    subdomains: Set[str] = set()
    orgs: Set[str] = set()
    issuers: Set[str] = set()

    for entry in entries:
        name_value = entry.get("name_value", "")
        if not name_value:
            continue

        # Count certs
        result["cert_count"] += 1

        # Check wildcard
        if name_value.startswith("*"):
            result["wildcard_count"] += 1

        # Check expiry
        not_after = entry.get("not_after", "")
        if not_after:
            try:
                from datetime import datetime
                exp = datetime.strptime(not_after.split("T")[0], "%Y-%m-%d")
                if exp < datetime.utcnow():
                    result["expired_count"] += 1
            except (ValueError, IndexError):
                pass

        # Extract names
        for name in name_value.split("\n"):
            name = name.strip().lstrip("*.")
            if name and name != domain:
                subdomains.add(name)

        # Organization
        issuer_ca = entry.get("issuer_ca_id", "")
        issuer_name = entry.get("issuer_name", "")
        if issuer_name:
            issuers.add(issuer_name)

        # Common name org
        common_name = entry.get("common_name", "")
        if common_name and "." in common_name:
            # Look for org in issuer
            for part in issuer_name.split(","):
                part = part.strip()
                if "O=" in part or "O =" in part:
                    org = part.split("=")[1].strip()
                    if org:
                        orgs.add(org)

        # Store simplified entry
        result["entries"].append({
            "name_value": name_value[:256],
            "issuer_name": issuer_name[:256] if issuer_name else "",
            "not_before": entry.get("not_before", "")[:10],
            "not_after": entry.get("not_after", "")[:10],
        })

    result["subdomains"] = sorted(subdomains)
    result["organizations"] = sorted(orgs)
    result["issuers"] = sorted(issuers)

    return result


# ════════════════════════════════════════════════════════════════════════
# 4. CDN / CLOUD PROVIDER DETECTION
# ════════════════════════════════════════════════════════════════════════

def _detect_cdn(headers: Dict[str, str], body: str) -> List[str]:
    """Detect CDN presence from response headers and body."""
    detected: List[str] = []
    body_lower = body[:8192].lower()
    header_keys_lower = {k.lower(): v for k, v in headers.items()}

    for cdn_key, cdn_info in CDN_FINGERPRINTS.items():
        matched = False
        # Header matching
        for hdr_name, hdr_val_pat in cdn_info.get("headers", {}).items():
            hdr_lookup = hdr_name.lower()
            if hdr_lookup in header_keys_lower:
                if hdr_val_pat is None:
                    # Presence of header is enough
                    matched = True
                    break
                elif isinstance(hdr_val_pat, re.Pattern) and hdr_val_pat.search(header_keys_lower[hdr_lookup]):
                    matched = True
                    break
        if not matched:
            for pat in cdn_info.get("body_patterns", []):
                if pat.search(body_lower):
                    matched = True
                    break
        if matched and cdn_key not in detected:
            detected.append(cdn_key)

    return detected


def _detect_cloud_provider(
    headers: Dict[str, str], body: str, ip: str, cname: str = ""
) -> List[str]:
    """Detect cloud provider from headers, body, IP, and CNAME."""
    detected: List[str] = []
    body_lower = body[:8192].lower()
    header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())

    for prov_key, prov_info in CLOUD_PROVIDER_SIGNS.items():
        matched = False
        # IP range check (strongest signal)
        for start, end in prov_info.get("ip_ranges", []):
            if _ip_in_range(ip, start, end):
                matched = True
                break
        # Header patterns
        if not matched:
            for pat in prov_info.get("header_patterns", []):
                if pat.search(header_str):
                    matched = True
                    break
        # Body patterns
        if not matched:
            for pat in prov_info.get("body_patterns", []):
                if pat.search(body_lower):
                    matched = True
                    break
        # CNAME patterns
        if not matched and cname:
            for pat in prov_info.get("cname_patterns", []):
                if pat.search(cname):
                    matched = True
                    break
        if matched and prov_key not in detected:
            detected.append(prov_key)

    return detected


def _run_cdn_cloud_detection(
    subdomain_results: List[Dict[str, Any]], base_url: str, timeout: int, verify_tls: bool
) -> Dict[str, Any]:
    """Phase 4: Detect CDNs and cloud providers across all infrastructure."""
    cdn_map: Dict[str, List[str]] = {}  # host -> cdn list
    cloud_map: Dict[str, List[str]] = {}  # host -> cloud list
    all_cdns: Set[str] = set()
    all_clouds: Set[str] = set()

    hosts_to_check = [r["host"] for r in subdomain_results if r.get("http_reachable")]
    # Also add the base_url host
    parsed = urllib.parse.urlparse(base_url)
    if parsed.hostname and parsed.hostname not in hosts_to_check:
        hosts_to_check.insert(0, parsed.hostname)

    for host in hosts_to_check:
        resp = http_probe(f"https://{host}", timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
        if resp.get("status", 0) == 0:
            resp = http_probe(f"http://{host}", timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)

        hdrs = resp.get("headers", {})
        body = resp.get("body", "")
        ip = "0.0.0.0"
        ips = _resolve_dns(host)
        if ips:
            ip = ips[0]

        cdns = _detect_cdn(hdrs, body)
        clouds = _detect_cloud_provider(hdrs, body, ip)

        cdn_map[host] = cdns
        cloud_map[host] = clouds
        all_cdns.update(cdns)
        all_clouds.update(clouds)

    return {
        "cdn_map": cdn_map,
        "cloud_map": cloud_map,
        "all_cdns": sorted(all_cdns),
        "all_clouds": sorted(all_clouds),
        "cdn_count": len(all_cdns),
        "cloud_count": len(all_clouds),
    }


# ════════════════════════════════════════════════════════════════════════
# 5. TECHNOLOGY STACK CLUSTERING
# ════════════════════════════════════════════════════════════════════════

def _run_tech_clustering(subdomain_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Phase 5: Group infrastructure by shared technologies."""
    # Build tech -> hosts mapping
    tech_hosts: Dict[str, List[str]] = {}
    host_techs: Dict[str, List[str]] = {}

    for r in subdomain_results:
        host = r["host"]
        techs = r.get("tech_stack", [])
        if not techs:
            continue
        host_techs[host] = techs
        for t in techs:
            if t not in tech_hosts:
                tech_hosts[t] = []
            tech_hosts[t].append(host)

    # Build clusters: groups of hosts sharing >=2 technologies
    clusters: List[Dict[str, Any]] = []
    visited: Set[str] = set()
    hosts_list = list(host_techs.keys())

    for i, host_a in enumerate(hosts_list):
        if host_a in visited:
            continue
        cluster: Dict[str, Any] = {
            "hosts": [host_a],
            "shared_techs": list(host_techs[host_a]),
        }
        visited.add(host_a)
        for j in range(i + 1, len(hosts_list)):
            host_b = hosts_list[j]
            if host_b in visited:
                continue
            shared = set(host_techs[host_a]) & set(host_techs[host_b])
            if len(shared) >= 2:
                cluster["hosts"].append(host_b)
                cluster["shared_techs"] = sorted(set(cluster["shared_techs"]) & shared | set(cluster["shared_techs"]) & set(host_techs[host_b]))
                visited.add(host_b)
        if len(cluster["hosts"]) > 1:
            clusters.append(cluster)

    # Technology prevalence
    tech_prevalence = sorted(
        [(t, len(hosts)) for t, hosts in tech_hosts.items()],
        key=lambda x: -x[1],
    )

    return {
        "clusters": clusters,
        "cluster_count": len(clusters),
        "tech_hosts": {k: v for k, v in sorted(tech_hosts.items())},
        "tech_prevalence": tech_prevalence,
        "unique_techs": sorted(tech_hosts.keys()),
    }


# ════════════════════════════════════════════════════════════════════════
# 6. LOOKALIKE INFRASTRUCTURE DETECTION
# ════════════════════════════════════════════════════════════════════════

LOOKALIKE_SUFFIXES: List[str] = [
    "-cdn", "-api", "-staging", "-dev", "-test", "-admin", "-old",
    "-new", "-v2", "-v3", "-backup", "-prod", "-stage", "-uat",
    "-internal", "-ext", "-dmz", "-mgmt", "-ops", "-infra",
    "cdn", "api", "staging", "dev", "test", "admin", "old",
    "new", "v2", "v3", "backup", "prod", "stage", "uat",
    "internal", "external", "dmz", "management", "ops", "infra",
    "secure", "public", "private", "app", "web", "mobile",
]


def _run_lookalike_detection(
    domain: str,
    subdomain_results: List[Dict[str, Any]],
    ct_data: Dict[str, Any],
    timeout: int, verify_tls: bool,
) -> Dict[str, Any]:
    """Phase 6: Find domains/hosts with similar naming, identical tech, or shared certs."""
    lookalikes: List[Dict[str, Any]] = []
    base_domain = _extract_domain(domain)
    base_parts = base_domain.split(".")
    base_stem = base_parts[0] if len(base_parts) > 2 else ""
    tld = ".".join(base_parts[-2:]) if len(base_parts) >= 2 else base_domain

    # 6a. Name-based lookalikes
    if base_stem:
        candidates_name: List[str] = []
        for suffix in LOOKALIKE_SUFFIXES:
            candidates_name.append(f"{base_stem}{suffix}.{tld}")
            # Also try with hyphen between stem and known subdomains
        # Check a subset (rate-limit aware)
        checked = 0
        for candidate in candidates_name:
            if checked >= 30:
                break
            checked += 1
            ips = _resolve_dns(candidate)
            if ips:
                resp = http_probe(
                    f"https://{candidate}", timeout=timeout, verify_tls=verify_tls, limiter=default_limiter
                )
                if resp.get("status", 0) == 0:
                    resp = http_probe(
                        f"http://{candidate}", timeout=timeout, verify_tls=verify_tls, limiter=default_limiter
                    )
                techs = []
                if resp.get("status", 0) > 0:
                    techs = _detect_tech_stack(resp.get("headers", {}), resp.get("body", ""))
                sim = _name_similarity(candidate, base_domain)
                lookalikes.append({
                    "host": candidate,
                    "type": "naming_pattern",
                    "similarity": round(sim, 2),
                    "ips": ips,
                    "tech_stack": techs,
                    "status": resp.get("status", 0),
                })

    # 6b. Same-tech-stack lookalikes from subdomain scan
    all_techs: Dict[str, List[str]] = {}  # tech fingerprint -> list of hosts
    for r in subdomain_results:
        host = r["host"]
        techs = tuple(sorted(r.get("tech_stack", [])))
        if len(techs) >= 2:
            key = "|".join(techs)
            if key not in all_techs:
                all_techs[key] = []
            all_techs[key].append(host)
    for key, hosts in all_techs.items():
        if len(hosts) > 1:
            for host in hosts:
                # Don't add duplicates
                if not any(l["host"] == host and l["type"] == "shared_tech" for l in lookalikes):
                    lookalikes.append({
                        "host": host,
                        "type": "shared_tech",
                        "similarity": 0.0,
                        "tech_fingerprint": key,
                        "peer_count": len(hosts) - 1,
                    })

    # 6c. Shared certificate lookalikes
    cert_org_hosts: Dict[str, List[str]] = {}
    for r in subdomain_results:
        host = r["host"]
        org = r.get("cert", {}).get("org", "")
        issuer = r.get("cert", {}).get("issuer", "")
        if org:
            cert_org_hosts.setdefault(org, []).append(host)
        elif issuer:
            cert_org_hosts.setdefault(issuer, []).append(host)
    for org, hosts in cert_org_hosts.items():
        if len(hosts) > 1:
            for host in hosts:
                if not any(l["host"] == host and l["type"] == "shared_cert" for l in lookalikes):
                    lookalikes.append({
                        "host": host,
                        "type": "shared_cert",
                        "similarity": 0.0,
                        "shared_cert_id": org[:128],
                        "peer_count": len(hosts) - 1,
                    })

    return {
        "lookalikes": lookalikes,
        "total_lookalikes": len(lookalikes),
        "naming_count": sum(1 for l in lookalikes if l.get("type") == "naming_pattern"),
        "shared_tech_count": sum(1 for l in lookalikes if l.get("type") == "shared_tech"),
        "shared_cert_count": sum(1 for l in lookalikes if l.get("type") == "shared_cert"),
    }


# ════════════════════════════════════════════════════════════════════════
# 7. INFRASTRUCTURE DRIFT DETECTION
# ════════════════════════════════════════════════════════════════════════

# In-memory historical store (persists for the process lifetime)
_DRIFT_HISTORY: Dict[str, Dict[str, Any]] = {}


def _compute_infra_fingerprint(ip_data: Dict, subdomain_results: List[Dict], ct_data: Dict) -> Dict[str, Any]:
    """Compute the current infrastructure fingerprint."""
    all_ips: List[str] = ip_data.get("ips", [])
    all_techs: List[str] = []
    all_orgs: List[str] = ct_data.get("organizations", [])
    subdomain_count = len(subdomain_results)
    reachable_count = sum(1 for r in subdomain_results if r.get("http_reachable"))

    for r in subdomain_results:
        all_techs.extend(r.get("tech_stack", []))

    host = ip_data.get("target", "")
    fingerprint = _fingerprint_hash(host, all_techs, all_ips, all_orgs)

    return {
        "fingerprint": fingerprint,
        "ip_count": len(all_ips),
        "unique_techs": sorted(set(all_techs)),
        "tech_count": len(set(all_techs)),
        "subdomain_count": subdomain_count,
        "reachable_count": reachable_count,
        "orgs": sorted(set(all_orgs)),
        "cert_count": ct_data.get("cert_count", 0),
        "timestamp": time.time(),
    }


def _run_drift_detection(target: str, current_fp: Dict[str, Any]) -> Dict[str, Any]:
    """Phase 7: Compare current fingerprint against historical."""
    domain = _extract_domain(target)
    result: Dict[str, Any] = {
        "drift_detected": False,
        "drift_details": [],
        "historical_snapshots": 0,
        "current_fingerprint": current_fp["fingerprint"],
    }

    if domain not in _DRIFT_HISTORY:
        _DRIFT_HISTORY[domain] = current_fp
        result["historical_snapshots"] = 1
        return result

    previous = _DRIFT_HISTORY[domain]
    result["historical_snapshots"] = len(_DRIFT_HISTORY)
    drifts: List[Dict[str, str]] = []

    # Fingerprint changed
    if previous["fingerprint"] != current_fp["fingerprint"]:
        result["drift_detected"] = True
        drifts.append({
            "type": "fingerprint_change",
            "detail": f"Infrastructure fingerprint changed: {previous['fingerprint'][:16]}... -> {current_fp['fingerprint'][:16]}...",
        })

    # IP count changed
    prev_ips = previous.get("ip_count", 0)
    curr_ips = current_fp.get("ip_count", 0)
    if prev_ips != curr_ips:
        result["drift_detected"] = True
        drifts.append({
            "type": "ip_count_change",
            "detail": f"IP count changed: {prev_ips} -> {curr_ips} (delta={curr_ips - prev_ips:+d})",
        })

    # Tech count changed
    prev_techs = set(previous.get("unique_techs", []))
    curr_techs = set(current_fp.get("unique_techs", []))
    added_techs = curr_techs - prev_techs
    removed_techs = prev_techs - curr_techs
    if added_techs or removed_techs:
        result["drift_detected"] = True
        if added_techs:
            drifts.append({
                "type": "tech_added",
                "detail": f"New technologies detected: {', '.join(sorted(added_techs))}",
            })
        if removed_techs:
            drifts.append({
                "type": "tech_removed",
                "detail": f"Technologies no longer detected: {', '.join(sorted(removed_techs))}",
            })

    # Subdomain count changed
    prev_subs = previous.get("subdomain_count", 0)
    curr_subs = current_fp.get("subdomain_count", 0)
    if prev_subs != curr_subs:
        result["drift_detected"] = True
        drifts.append({
            "type": "subdomain_count_change",
            "detail": f"Subdomain count changed: {prev_subs} -> {curr_subs} (delta={curr_subs - prev_subs:+d})",
        })

    # Org changes
    prev_orgs = set(previous.get("orgs", []))
    curr_orgs = set(current_fp.get("orgs", []))
    new_orgs = curr_orgs - prev_orgs
    if new_orgs:
        result["drift_detected"] = True
        drifts.append({
            "type": "new_organizations",
            "detail": f"New certificate organizations: {', '.join(sorted(new_orgs))}",
        })

    result["drift_details"] = drifts
    # Update history
    _DRIFT_HISTORY[domain] = current_fp

    return result


# ════════════════════════════════════════════════════════════════════════
# 8. ATTACK SURFACE SCORING
# ════════════════════════════════════════════════════════════════════════


def _score_attack_surface(
    ip_data: Dict[str, Any],
    subdomain_results: List[Dict[str, Any]],
    ct_data: Dict[str, Any],
    cdn_cloud_data: Dict[str, Any],
    tech_cluster_data: Dict[str, Any],
    lookalike_data: Dict[str, Any],
    drift_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Phase 8: Score the total infrastructure attack surface."""
    score = 0.0
    max_score = 100.0
    factors: List[Dict[str, Any]] = []

    # Factor 1: IP exposure (more IPs = larger attack surface)
    ip_count = ip_data.get("total_ips", 0)
    ip_score = min(15.0, ip_count * 2.5)
    score += ip_score
    factors.append({
        "name": "ip_exposure",
        "points": round(ip_score, 1),
        "max": 15.0,
        "detail": f"{ip_count} unique IPs discovered",
    })

    # Factor 2: Subdomain sprawl
    sub_count = len(subdomain_results)
    sub_reachable = sum(1 for r in subdomain_results if r.get("http_reachable"))
    sub_score = min(15.0, sub_count * 0.8 + sub_reachable * 0.5)
    score += sub_score
    factors.append({
        "name": "subdomain_spread",
        "points": round(sub_score, 1),
        "max": 15.0,
        "detail": f"{sub_count} subdomains ({sub_reachable} HTTP-reachable)",
    })

    # Factor 3: Certificate sprawl
    cert_count = ct_data.get("cert_count", 0)
    wildcard_count = ct_data.get("wildcard_count", 0)
    cert_score = min(10.0, cert_count * 0.3 + wildcard_count * 2.0)
    score += cert_score
    factors.append({
        "name": "certificate_spread",
        "points": round(cert_score, 1),
        "max": 10.0,
        "detail": f"{cert_count} certificates ({wildcard_count} wildcards)",
    })

    # Factor 4: Technology diversity (more tech = more attack vectors)
    tech_count = tech_cluster_data.get("unique_techs", [])
    tech_n = len(tech_count)
    tech_score = min(15.0, tech_n * 2.0)
    score += tech_score
    factors.append({
        "name": "technology_diversity",
        "points": round(tech_score, 1),
        "max": 15.0,
        "detail": f"{tech_n} unique technologies detected",
    })

    # Factor 5: Missing CDN/WAF (reduces score if absent)
    cdns = cdn_cloud_data.get("all_cdns", [])
    has_waf = any("cloudflare" in c or "sucuri" in c or "incapsula" in c or "akamai" in c for c in cdns)
    if not has_waf:
        no_waf_score = 8.0
        score += no_waf_score
        factors.append({
            "name": "missing_waf",
            "points": round(no_waf_score, 1),
            "max": 8.0,
            "detail": "No WAF detected on any infrastructure",
        })
    else:
        factors.append({
            "name": "missing_waf",
            "points": 0.0,
            "max": 8.0,
            "detail": f"WAF present: {', '.join(cdns)}",
        })

    # Factor 6: Cloud provider concentration risk
    clouds = cdn_cloud_data.get("all_clouds", [])
    if len(clouds) == 1:
        cloud_score = 5.0  # single provider = concentration risk
    elif len(clouds) == 0:
        cloud_score = 3.0  # unknown hosting
    else:
        cloud_score = 1.0  # multi-cloud = more resilient but larger surface
    score += cloud_score
    factors.append({
        "name": "cloud_concentration",
        "points": round(cloud_score, 1),
        "max": 5.0,
        "detail": f"{len(clouds)} cloud provider(s): {', '.join(clouds) or 'none detected'}",
    })

    # Factor 7: Lookalike risk
    lookalike_count = lookalike_data.get("total_lookalikes", 0)
    lookalike_score = min(10.0, lookalike_count * 1.5)
    score += lookalike_score
    factors.append({
        "name": "lookalike_risk",
        "points": round(lookalike_score, 1),
        "max": 10.0,
        "detail": f"{lookalike_count} lookalike infrastructure assets",
    })

    # Factor 8: Drift (recent changes indicate instability)
    if drift_data.get("drift_detected"):
        drift_score = 7.0
    else:
        drift_score = 0.0
    score += drift_score
    factors.append({
        "name": "infrastructure_drift",
        "points": round(drift_score, 1),
        "max": 7.0,
        "detail": f"{'Drift detected with ' + str(len(drift_data.get('drift_details', []))) + ' change(s)' if drift_data.get('drift_detected') else 'No infrastructure drift detected'}",
    })

    # Factor 9: Exposed sensitive subdomains
    sensitive_subs = [
        r for r in subdomain_results
        if any(s in r["host"] for s in ("admin", "staging", "dev", "test", "internal", "db", "git"))
        and r.get("http_reachable")
    ]
    sensitive_score = min(10.0, len(sensitive_subs) * 3.0)
    score += sensitive_score
    factors.append({
        "name": "sensitive_subdomains",
        "points": round(sensitive_score, 1),
        "max": 10.0,
        "detail": f"{len(sensitive_subs)} potentially sensitive subdomains exposed",
    })

    # Factor 10: Expired certificates
    expired = ct_data.get("expired_count", 0)
    expired_score = min(5.0, expired * 1.5)
    score += expired_score
    factors.append({
        "name": "expired_certificates",
        "points": round(expired_score, 1),
        "max": 5.0,
        "detail": f"{expired} expired certificate(s) in CT logs",
    })

    final_score = min(max_score, score)

    # Risk level
    if final_score >= 70:
        risk_level = "critical"
    elif final_score >= 50:
        risk_level = "high"
    elif final_score >= 30:
        risk_level = "medium"
    elif final_score >= 15:
        risk_level = "low"
    else:
        risk_level = "info"

    return {
        "total_score": round(final_score, 1),
        "max_score": max_score,
        "risk_level": risk_level,
        "factors": factors,
    }


# ════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════

def run_infrastructure_ghost(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Create a complete digital ghost of the target's infrastructure.

    Parameters
    ----------
    target : str
        Target domain (e.g. ``example.com``).
    base_url : str
        Base URL for HTTP probing (e.g. ``https://example.com``).
    timeout : int
        Per-request timeout in seconds (default 8).
    verify_tls : bool
        Whether to verify TLS certificates (default True).

    Returns
    -------
    List[Finding]
        All findings from the 8-phase infrastructure ghost scan.
    """
    findings: List[Finding] = []
    domain = _extract_domain(target)
    deductions = 0

    def add(
        title: str, severity: str, category: str,
        desc: str, evidence: str, pts: int,
        dread: float = 0.0, remediation: str = "",
    ) -> None:
        nonlocal deductions
        deductions += pts
        findings.append(Finding(
            title=title,
            severity=severity,
            category=category,
            module=MODULE_NAME,
            description=desc,
            evidence=evidence,
            asset=domain,
            points_deducted=pts,
            dread_score=dread,
            remediation=remediation,
        ))

    # ── Phase 1: IP Discovery & Mapping ─────────────────────────────────
    ip_data = _run_ip_discovery(target, base_url, timeout, verify_tls)
    ip_list = ip_data.get("ips", [])
    if ip_list:
        add(
            f"IP infrastructure mapped: {len(ip_list)} address(es)",
            "info", "ip_discovery",
            f"Discovered {len(ip_list)} unique IP addresses associated with {domain} "
            f"via DNS ({len(ip_data['sources'].get('dns', []))}), "
            f"HTTP redirects ({len(ip_data['sources'].get('http_redirects', []))}), and "
            f"certificate SANs ({len(ip_data['sources'].get('certificates', []))}).",
            ", ".join(ip_list[:20]), 0,
            remediation="Review which IPs are publicly exposed and ensure "
                        "only necessary services are accessible.",
        )
    else:
        add(
            "No IPs resolved for target",
            "low", "ip_discovery",
            f"Could not resolve any IP addresses for {domain}.",
            "DNS resolution returned empty", 2,
            remediation="Verify the target domain is correct and DNS is properly configured.",
        )

    # Identify cloud-hosted IPs
    cloud_ips: Dict[str, List[str]] = {}
    for ip in ip_list:
        for prov_key, prov_info in CLOUD_PROVIDER_SIGNS.items():
            for start, end in prov_info.get("ip_ranges", []):
                if _ip_in_range(ip, start, end):
                    cloud_ips.setdefault(prov_key, []).append(ip)
                    break
    if cloud_ips:
        providers_str = "; ".join(f"{k} ({len(v)} IPs)" for k, v in cloud_ips.items())
        add(
            "Cloud-hosted infrastructure detected",
            "info", "cloud_detection",
            f"IP addresses hosted on cloud providers: {providers_str}.",
            json.dumps({k: v for k, v in cloud_ips.items()}, default=str), 0,
        )

    # ── Phase 3: CT Log Mining (run before subdomain scan to get subs) ─
    ct_data = _mine_ct_logs(domain, timeout)
    ct_subs = ct_data.get("subdomains", [])

    if ct_data.get("error"):
        add(
            "Certificate Transparency log query failed",
            "low", "ct_mining",
            f"Could not query CT logs for {domain}: {ct_data['error']}",
            ct_data["error"], 2,
            remediation="CT logs may be temporarily unavailable. Retry later.",
        )
    else:
        ct_cert_count = ct_data.get("cert_count", 0)
        ct_sub_count = len(ct_subs)
        ct_wildcards = ct_data.get("wildcard_count", 0)
        ct_expired = ct_data.get("expired_count", 0)
        add(
            f"CT log mining: {ct_cert_count} certs, {ct_sub_count} subdomains",
            "info", "ct_mining",
            f"Certificate Transparency logs reveal {ct_cert_count} certificates for {domain}, "
            f"{ct_sub_count} unique subdomains, {ct_wildcards} wildcard certs, "
            f"{ct_expired} expired certs.",
            ", ".join(ct_subs[:30]), 0,
        )

        # Organizations
        ct_orgs = ct_data.get("organizations", [])
        if ct_orgs:
            add(
                f"Certificate organizations disclosed: {len(ct_orgs)}",
                "low", "ct_mining",
                f"CT logs expose {len(ct_orgs)} organization names associated with "
                f"certificates for {domain}: {', '.join(ct_orgs[:10])}.",
                ", ".join(ct_orgs[:20]), 2,
                _dread(3, 8, 3, 4, 7),
                remediation="Consider using Organization Validated (OV) or Extended Validation (EV) "
                            "certificates to limit information leakage.",
            )

        # Expired certs
        if ct_expired > 0:
            add(
                f"Expired certificates in CT logs: {ct_expired}",
                "medium", "ct_mining",
                f"Found {ct_expired} expired certificates for {domain} in CT logs. "
                f"Expired certificates may indicate maintenance gaps or "
                f"abandoned infrastructure that could be hijacked.",
                f"{ct_expired} expired certs in CT logs", 5,
                _dread(5, 7, 4, 5, 6),
                remediation="Audit expired certificates and ensure all active "
                            "infrastructure has valid, non-expired certificates.",
            )

        # Wildcard certs
        if ct_wildcards > 3:
            add(
                f"Excessive wildcard certificates: {ct_wildcards}",
                "medium", "ct_mining",
                f"Found {ct_wildcards} wildcard certificates for {domain}. "
                f"Wildcards cover all subdomains, increasing the blast radius "
                f"if the private key is compromised.",
                f"{ct_wildcards} wildcard certs", 5,
                _dread(7, 6, 5, 6, 7),
                remediation="Minimize wildcard certificate usage. Use individual "
                            "certificates for high-security subdomains.",
            )

    # ── Phase 2: Subdomain Infrastructure Scan ──────────────────────────
    subdomain_results = _run_subdomain_scan(domain, ct_subs, timeout, verify_tls)
    reachable = [r for r in subdomain_results if r.get("http_reachable")]
    add(
        f"Subdomain scan: {len(subdomain_results)} discovered, {len(reachable)} reachable",
        "info", "subdomain_scan",
        f"Scanned {len(subdomain_results)} subdomains (combining CT logs + wordlist). "
        f"{len(reachable)} are HTTP-reachable with active services.",
        ", ".join(r["host"] for r in reachable[:30]), 0,
    )

    # Sensitive subdomain exposure
    sensitive_names = ("admin", "staging", "dev", "test", "internal", "db", "git",
                       "jenkins", "grafana", "kibana", "phpmyadmin", "manager")
    exposed_sensitive = [
        r for r in reachable
        if any(s in r["host"] for s in sensitive_names)
    ]
    if exposed_sensitive:
        for r in exposed_sensitive:
            tech_str = ", ".join(r.get("tech_stack", [])) or "unknown"
            add(
                f"Sensitive subdomain exposed: {r['host']}",
                "high", "subdomain_scan",
                f"Potentially sensitive subdomain {r['host']} is publicly accessible "
                f"(HTTP {r['status']}). Detected technologies: {tech_str}. "
                f"IPs: {', '.join(r.get('ips', []))}.",
                f"{r['host']} -> {r['status']} | IPs: {', '.join(r.get('ips', []))}",
                10, _dread(8, 8, 8, 7, 8),
                remediation=f"Restrict access to {r['host']}. Use IP allowlisting, "
                            f"VPN, or authentication to protect sensitive services.",
            )

    # Certificate chain issues
    for r in subdomain_results:
        cert = r.get("cert", {})
        if not cert:
            continue
        if cert.get("issuer") and "Let's Encrypt" not in cert.get("issuer", "") and "DigiCert" not in cert.get("issuer", "") and "Sectigo" not in cert.get("issuer", ""):
            # Check if it's a self-signed or unusual issuer
            issuer = cert.get("issuer", "")
            if "CN=" in issuer:
                cn = issuer.split("CN=")[1].split(",")[0].strip()
                if cn and cn != r["host"] and "." in cn and cn.endswith(domain):
                    add(
                        f"Internal CA certificate on public host: {r['host']}",
                        "medium", "subdomain_scan",
                        f"{r['host']} uses a certificate issued by an internal CA: {issuer[:128]}. "
                        f"This may indicate a misconfigured or leaked internal certificate.",
                        f"Issuer: {issuer[:200]}",
                        5, _dread(6, 5, 6, 5, 7),
                        remediation="Use publicly trusted CAs for all internet-facing services. "
                                    "Rotate any potentially leaked internal certificates.",
                    )

    # ── Phase 4: CDN / Cloud Provider Detection ─────────────────────────
    cdn_cloud_data = _run_cdn_cloud_detection(subdomain_results, base_url, timeout, verify_tls)
    all_cdns = cdn_cloud_data.get("all_cdns", [])
    all_clouds = cdn_cloud_data.get("all_clouds", [])

    if all_cdns:
        add(
            f"CDN detected: {', '.join(all_cdns)}",
            "info", "cdn_detection",
            f"CDN services identified across infrastructure: {', '.join(all_cdns)}. "
            f"Hosts using CDN: {len(cdn_cloud_data.get('cdn_map', {}))}.",
            json.dumps(cdn_cloud_data.get("cdn_map", {}), default=str)[:512], 0,
        )
    else:
        add(
            "No CDN detected on any infrastructure",
            "low", "cdn_detection",
            f"No CDN fingerprints found on {domain} or any of its subdomains. "
            f"This may indicate direct origin exposure.",
            "No CDN headers or body fingerprints detected", 2,
            _dread(4, 5, 3, 4, 6),
            remediation="Consider deploying a CDN to add DDoS protection, improve "
                        "performance, and hide origin infrastructure.",
        )

    if all_clouds:
        add(
            f"Cloud hosting detected: {', '.join(all_clouds)}",
            "info", "cloud_detection",
            f"Infrastructure hosted on: {', '.join(all_clouds)}. "
            f"Host mappings: {json.dumps(cdn_cloud_data.get('cloud_map', {}))[:512]}",
            json.dumps(cdn_cloud_data.get("cloud_map", {}), default=str)[:512], 0,
        )

    # ── Phase 5: Technology Stack Clustering ────────────────────────────
    tech_cluster_data = _run_tech_clustering(subdomain_results)
    clusters = tech_cluster_data.get("clusters", [])
    prevalence = tech_cluster_data.get("tech_prevalence", [])
    unique_techs = tech_cluster_data.get("unique_techs", [])

    if unique_techs:
        top_techs = prevalence[:8]
        tech_summary = "; ".join(f"{t} ({c} hosts)" for t, c in top_techs)
        add(
            f"Technology fingerprint: {len(unique_techs)} technologies across infrastructure",
            "info", "tech_clustering",
            f"Detected {len(unique_techs)} unique technologies. Top: {tech_summary}. "
            f"{len(clusters)} technology cluster(s) found (hosts sharing >=2 technologies).",
            tech_summary, 0,
        )

    if clusters:
        for cl in clusters[:5]:
            hosts = cl["hosts"]
            shared = cl.get("shared_techs", [])
            add(
                f"Tech cluster: {len(hosts)} hosts sharing {', '.join(shared[:4])}",
                "info", "tech_clustering",
                f"Infrastructure cluster of {len(hosts)} hosts sharing technologies: "
                f"{', '.join(shared[:6])}. Hosts: {', '.join(hosts[:8])}.",
                f"Hosts: {', '.join(hosts[:15])} | Shared: {', '.join(shared[:10])}", 0,
                remediation="Review clustered infrastructure for consistent security "
                            "hardening across all cluster members.",
            )

    # ── Phase 6: Lookalike Infrastructure Detection ─────────────────────
    lookalike_data = _run_lookalike_detection(domain, subdomain_results, ct_data, timeout, verify_tls)
    total_lookalikes = lookalike_data.get("total_lookalikes", 0)
    naming_count = lookalike_data.get("naming_count", 0)
    shared_tech_count = lookalike_data.get("shared_tech_count", 0)
    shared_cert_count = lookalike_data.get("shared_cert_count", 0)

    if total_lookalikes > 0:
        add(
            f"Lookalike infrastructure: {total_lookalikes} related assets found",
            "medium", "lookalike_detection",
            f"Found {total_lookalikes} lookalike infrastructure assets: "
            f"{naming_count} naming-pattern matches, {shared_tech_count} shared-tech groups, "
            f"{shared_cert_count} shared-certificate groups.",
            json.dumps([l["host"] for l in lookalike_data.get("lookalikes", [])[:20]]),
            5, _dread(5, 7, 5, 6, 7),
            remediation="Audit lookalike infrastructure assets to ensure they are "
                        "authorized and properly secured.",
        )

        # Flag high-similarity naming lookalikes
        for l in lookalike_data.get("lookalikes", []):
            if l.get("type") == "naming_pattern" and l.get("status", 0) in (200, 301, 302):
                add(
                    f"Lookalike host responsive: {l['host']}",
                    "medium", "lookalike_detection",
                    f"Host {l['host']} follows {domain}'s naming pattern and is responsive "
                    f"(HTTP {l['status']}). IPs: {', '.join(l.get('ips', []))}. "
                    f"Tech: {', '.join(l.get('tech_stack', []))}.",
                    f"{l['host']} -> {l['status']} | Similarity: {l.get('similarity', 0)}",
                    5, _dread(5, 6, 5, 5, 7),
                    remediation=f"Verify that {l['host']} is an authorized asset and "
                                f"apply consistent security controls.",
                )

    # ── Phase 7: Infrastructure Drift Detection ─────────────────────────
    current_fp = _compute_infra_fingerprint(ip_data, subdomain_results, ct_data)
    drift_data = _run_drift_detection(target, current_fp)

    if drift_data.get("drift_detected"):
        for detail in drift_data.get("drift_details", []):
            drift_type = detail.get("type", "unknown")
            detail_str = detail.get("detail", "")
            add(
                f"Infrastructure drift: {drift_type}",
                "medium", "drift_detection",
                f"Infrastructure drift detected for {domain}: {detail_str}",
                detail_str, 5,
                _dread(5, 3, 4, 5, 6),
                remediation="Investigate infrastructure changes and ensure all "
                            "modifications follow change management procedures.",
            )
    else:
        add(
            "Infrastructure fingerprint captured (no historical data for comparison)",
            "info", "drift_detection",
            f"Baseline infrastructure fingerprint for {domain}: {current_fp['fingerprint'][:16]}... "
            f"({current_fp['ip_count']} IPs, {current_fp['tech_count']} technologies, "
            f"{current_fp['subdomain_count']} subdomains).",
            current_fp["fingerprint"], 0,
        )

    # ── Phase 8: Attack Surface Scoring ──────────────────────────────────
    scoring = _score_attack_surface(
        ip_data, subdomain_results, ct_data, cdn_cloud_data,
        tech_cluster_data, lookalike_data, drift_data,
    )
    total_score = scoring.get("total_score", 0)
    risk_level = scoring.get("risk_level", "info")
    factors = scoring.get("factors", [])

    # Generate factor summary
    factor_lines = [f"  - {f['name']}: {f['points']}/{f['max']} ({f['detail']})" for f in factors]
    factor_summary = "\n".join(factor_lines)

    if risk_level == "critical":
        add(
            f"Infrastructure attack surface score: {total_score}/100 (CRITICAL)",
            "critical", "attack_surface",
            f"The total infrastructure attack surface for {domain} scores {total_score}/100, "
            f"indicating a critical exposure level.\n{factor_summary}",
            json.dumps(scoring, default=str)[:1024],
            15, _dread(9, 8, 9, 8, 9),
            remediation="Immediately address the highest-scoring factors. "
                        "Reduce exposed IPs, protect sensitive subdomains, deploy WAF, "
                        "and consolidate certificate management.",
        )
    elif risk_level == "high":
        add(
            f"Infrastructure attack surface score: {total_score}/100 (HIGH)",
            "high", "attack_surface",
            f"The total infrastructure attack surface for {domain} scores {total_score}/100, "
            f"indicating a high exposure level.\n{factor_summary}",
            json.dumps(scoring, default=str)[:1024],
            10, _dread(7, 7, 7, 7, 8),
            remediation="Address high-scoring attack surface factors: reduce exposed "
                        "infrastructure, protect sensitive subdomains, and deploy WAF.",
        )
    elif risk_level == "medium":
        add(
            f"Infrastructure attack surface score: {total_score}/100 (MEDIUM)",
            "medium", "attack_surface",
            f"The total infrastructure attack surface for {domain} scores {total_score}/100, "
            f"indicating a moderate exposure level.\n{factor_summary}",
            json.dumps(scoring, default=str)[:1024],
            5, _dread(5, 5, 5, 5, 6),
            remediation="Review and address medium-scoring factors to reduce the "
                        "overall attack surface.",
        )
    elif risk_level == "low":
        add(
            f"Infrastructure attack surface score: {total_score}/100 (LOW)",
            "low", "attack_surface",
            f"The total infrastructure attack surface for {domain} scores {total_score}/100, "
            f"indicating a low but non-trivial exposure level.\n{factor_summary}",
            json.dumps(scoring, default=str)[:1024],
            2, _dread(3, 3, 3, 3, 4),
            remediation="Continue hardening infrastructure to further reduce the attack surface.",
        )
    else:
        add(
            f"Infrastructure attack surface score: {total_score}/100 (MINIMAL)",
            "info", "attack_surface",
            f"The total infrastructure attack surface for {domain} scores {total_score}/100, "
            f"indicating a minimal exposure level.\n{factor_summary}",
            json.dumps(scoring, default=str)[:1024],
            0,
        )

    return findings

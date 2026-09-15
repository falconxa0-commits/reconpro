"""evasion.py — Behavioral Fingerprint Shifting & Evasion Engine for ReconPro v7.0.

Pure-stdlib module that makes HTTP requests look like different browsers/users
to evade WAF and bot detection. No external dependencies.
"""

from __future__ import annotations

import json
import math
import os
import random
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = [
    "HeaderRotator",
    "TlsFingerprint",
    "TimingJitter",
    "PathCanonicalizer",
    "EvasionProfile",
    "EvasionSession",
    "WAFBypass",
    "PolymorphicPayload",
    "RateLimiter",
]

# ---------------------------------------------------------------------------
# 1. HeaderRotator
# ---------------------------------------------------------------------------

_USER_AGENTS: List[str] = [
    # --- Chrome on Windows ---
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.94 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Safari/537.36",
    # --- Chrome on macOS ---
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.94 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Safari/537.36",
    # --- Chrome on Linux ---
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.94 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.58 Safari/537.36",
    # --- Chrome on Android ---
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.91 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.94 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Mobile Safari/537.36",
    # --- Firefox on Windows ---
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # --- Firefox on macOS ---
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:123.0) Gecko/20100101 Firefox/123.0",
    # --- Firefox on Linux ---
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # --- Firefox on Android ---
    "Mozilla/5.0 (Android 14; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0",
    # --- Safari on macOS ---
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # --- Safari on iOS ---
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    # --- Edge on Windows ---
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.98",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
    # --- Edge on macOS ---
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.92",
    # --- Edge on Linux ---
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.98",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
]

# Accept-Language pools keyed by family for consistency
_ACCEPT_LANGS = {
    "en-US": "en-US,en;q=0.9",
    "en-GB": "en-GB,en;q=0.9,en-US;q=0.8",
    "de": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "es": "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja": "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "pt-BR": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
    "zh-CN": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "ko": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "ru": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
}

# Sec-CH-UA values per major Chrome/Edge version
_SEC_CH_UA = {
    "120": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "121": '"Not A(Brand";v="99", "Chromium";v="121", "Google Chrome";v="121"',
    "122": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "123": '"Chromium";v="123", "Not:A-Brand";v="8", "Google Chrome";v="123"',
    "124": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
}

_SEC_CH_UA_MOBILE = {
    "120": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120", "Mobile Safari";v="537.36"',
    "121": '"Not A(Brand";v="99", "Chromium";v="121", "Google Chrome";v="121", "Mobile Safari";v="537.36"',
    "122": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "123": '"Chromium";v="123", "Not:A-Brand";v="8", "Google Chrome";v="123"',
    "124": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
}

_SEC_CH_UA_EDGE = {
    "120": '"Not_A Brand";v="8", "Chromium";v="120", "Microsoft Edge";v="120"',
    "121": '"Not A(Brand";v="99", "Chromium";v="121", "Microsoft Edge";v="121"',
    "122": '"Chromium";v="122", "Not(A:Brand";v="24", "Microsoft Edge";v="122"',
    "123": '"Chromium";v="123", "Not:A-Brand";v="8", "Microsoft Edge";v="123"',
    "124": '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
}


class HeaderRotator:
    """Rotates through 50+ real browser User-Agent strings and produces a
    complete, consistent set of HTTP headers for each rotation.

    Maintains referer state across calls so successive requests look like
    a real browsing session.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)
        self._ua_pool = list(_USER_AGENTS)
        self._rng.shuffle(self._ua_pool)
        self._index = 0
        self._referer: Optional[str] = None
        self._lang_codes = list(_ACCEPT_LANGS.keys())

    # -- public API ----------------------------------------------------------

    def set_referer(self, url: str) -> None:
        """Store a referer URL that will be included on the *next* rotate()."""
        self._referer = url

    def clear_referer(self) -> None:
        """Clear stored referer."""
        self._referer = None

    def rotate(self, custom_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Return a full set of HTTP headers with a randomised User-Agent.

        Parameters
        ----------
        custom_headers:
            Optional dict of headers that override / extend the generated set.

        Returns
        -------
        dict  –  mapping of header name → value
        """
        ua = self._pick_ua()
        headers: Dict[str, str] = {
            "User-Agent": ua,
            "Accept": self._accept_for(ua),
            "Accept-Language": _ACCEPT_LANGS[self._rng.choice(self._lang_codes)],
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Connection": "keep-alive",
            "Cache-Control": "max-age=0",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        }

        # Add Sec-CH-UA only for Chrome / Edge
        sec_ch = self._sec_ch_ua(ua)
        if sec_ch is not None:
            headers["Sec-CH-UA"] = sec_ch[0]
            headers["Sec-CH-UA-Mobile"] = sec_ch[1]
            headers["Sec-CH-UA-Platform"] = sec_ch[2]

        if self._referer is not None:
            headers["Referer"] = self._referer
            self._referer = None

        if custom_headers:
            headers.update(custom_headers)

        return headers

    # -- internals -----------------------------------------------------------

    def _pick_ua(self) -> str:
        """Pick next UA in shuffled order, re-shuffle when exhausted."""
        if self._index >= len(self._ua_pool):
            self._rng.shuffle(self._ua_pool)
            self._index = 0
        ua = self._ua_pool[self._index]
        self._index += 1
        return ua

    @staticmethod
    def _accept_for(ua: str) -> str:
        """Return an Accept header appropriate for the browser family."""
        if "Edg/" in ua:
            return (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            )
        if "Firefox/" in ua:
            return (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            )
        if "Safari/" in ua and "Chrome/" not in ua:
            return (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "*/*;q=0.8"
            )
        # Chrome / generic Chromium
        return (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        )

    @staticmethod
    def _sec_ch_ua(ua: str) -> Optional[tuple]:
        """Return (Sec-CH-UA, Mobile, Platform) or None for non-Chrome."""
        if "Edg/" in ua:
            ver = _extract_chrome_ver(ua)
            ch = _SEC_CH_UA_EDGE.get(ver)
            platform = _extract_platform(ua)
            if ch:
                return (ch, "?0", f'"{platform}"')
            return None
        if "Chrome/" in ua and "Safari/" in ua and "Edg/" not in ua:
            ver = _extract_chrome_ver(ua)
            is_mobile = "Mobile" in ua
            pool = _SEC_CH_UA_MOBILE if is_mobile else _SEC_CH_UA
            ch = pool.get(ver)
            platform = _extract_platform(ua)
            if ch:
                return (ch, "?1" if is_mobile else "?0", f'"{platform}"')
            return None
        return None


# helpers for HeaderRotator


def _extract_chrome_ver(ua: str) -> str:
    """Extract the major Chrome version number from a UA string."""
    import re
    m = re.search(r"Chrome/(\d+)\.", ua)
    return m.group(1) if m else "124"


def _extract_platform(ua: str) -> str:
    """Guess the platform string for Sec-CH-UA-Platform."""
    if "Windows" in ua:
        return "Windows"
    if "Macintosh" in ua or "Mac OS X" in ua:
        return "macOS"
    if "Android" in ua:
        return "Android"
    if "iPhone" in ua or "iPad" in ua:
        return "iOS"
    if "Linux" in ua:
        return "Linux"
    return "Unknown"


# ---------------------------------------------------------------------------
# 2. TlsFingerprint
# ---------------------------------------------------------------------------


class TlsFingerprint:
    """Generates randomized TLS configurations for metadata purposes.

    These profiles describe cipher suite order, TLS version, and extensions
    that mimic real browsers.  Actual TLS control requires aiohttp-ssl or
    a custom connector — this class provides the *metadata*.
    """

    CHROME_120 = "CHROME_120"
    FIREFOX_121 = "FIREFOX_121"
    SAFARI_17 = "SAFARI_17"
    EDGE_120 = "EDGE_120"
    RANDOM = "RANDOM"

    _PRESETS: Dict[str, Dict[str, Any]] = {
        CHROME_120: {
            "cipher_suites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
            ],
            "tls_version": "TLSv1.3",
            "extensions": [
                "server_name", "extended_master_secret", "renegotiation_info",
                "supported_versions", "psk_key_exchange_modes", "key_share",
                "signature_algorithms", "supported_groups", "application_layer_protocol_negotiation",
                "signed_certificate_timestamp", "status_request",
            ],
            "grease": True,
        },
        FIREFOX_121: {
            "cipher_suites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            ],
            "tls_version": "TLSv1.3",
            "extensions": [
                "server_name", "extended_master_secret", "renegotiation_info",
                "supported_versions", "psk_key_exchange_modes", "key_share",
                "signature_algorithms", "supported_groups", "application_layer_protocol_negotiation",
                "delegated_credentials", "padding",
            ],
            "grease": True,
        },
        SAFARI_17: {
            "cipher_suites": [
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            ],
            "tls_version": "TLSv1.3",
            "extensions": [
                "server_name", "extended_master_secret", "renegotiation_info",
                "supported_versions", "key_share", "signature_algorithms",
                "supported_groups", "application_layer_protocol_negotiation",
                "status_request",
            ],
            "grease": False,
        },
        EDGE_120: {
            "cipher_suites": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                "TLS_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_RSA_WITH_AES_256_GCM_SHA384",
            ],
            "tls_version": "TLSv1.3",
            "extensions": [
                "server_name", "extended_master_secret", "renegotiation_info",
                "supported_versions", "psk_key_exchange_modes", "key_share",
                "signature_algorithms", "supported_groups", "application_layer_protocol_negotiation",
                "signed_certificate_timestamp", "status_request",
            ],
            "grease": True,
        },
    }

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)

    def get_profile(self, name: str = "CHROME_120") -> Dict[str, Any]:
        """Return a TLS fingerprint profile dict.

        Parameters
        ----------
        name : str
            One of CHROME_120, FIREFOX_121, SAFARI_17, EDGE_120, RANDOM.

        Returns
        -------
        dict with keys: cipher_suites, tls_version, extensions, grease
        """
        if name == self.RANDOM:
            return self._random_profile()
        profile = self._PRESETS.get(name)
        if profile is None:
            raise ValueError(
                f"Unknown TLS profile '{name}'. "
                f"Choose from: {', '.join(self._PRESETS)}, {self.RANDOM}"
            )
        # Return a deep-ish copy so callers can mutate safely
        return {
            "cipher_suites": list(profile["cipher_suites"]),
            "tls_version": profile["tls_version"],
            "extensions": list(profile["extensions"]),
            "grease": profile["grease"],
        }

    def _random_profile(self) -> Dict[str, Any]:
        """Create a randomized TLS profile that still looks plausible."""
        base_name = self._rng.choice(list(self._PRESETS.keys()))
        base = self._PRESETS[base_name]
        ciphers = list(base["cipher_suites"])
        self._rng.shuffle(ciphers)
        # Keep AES_128_GCM near the top 60 % of the time (most browsers prefer it)
        if self._rng.random() < 0.6:
            aes128 = "TLS_AES_128_GCM_SHA256"
            if aes128 in ciphers:
                ciphers.remove(aes128)
                ciphers.insert(self._rng.randint(0, 2), aes128)
        extensions = list(base["extensions"])
        self._rng.shuffle(extensions)
        # SNI should stay first
        if "server_name" in extensions:
            extensions.remove("server_name")
            extensions.insert(0, "server_name")
        return {
            "cipher_suites": ciphers,
            "tls_version": base["tls_version"],
            "extensions": extensions,
            "grease": base["grease"],
        }

    @classmethod
    def available_profiles(cls) -> List[str]:
        return list(cls._PRESETS.keys()) + [cls.RANDOM]


# ---------------------------------------------------------------------------
# 3. TimingJitter
# ---------------------------------------------------------------------------


class TimingJitter:
    """Add human-like timing jitter between requests.

    Uses a Gaussian distribution with configurable stddev.  Supports
    burst patterns that simulate real browsing (rapid clicks then pause).
    """

    MIN_DELAY: float = 0.05
    MAX_DELAY: float = 5.0
    DEFAULT_STDDEV: float = 0.3

    def __init__(
        self,
        stddev: float = DEFAULT_STDDEV,
        min_delay: float = MIN_DELAY,
        max_delay: float = MAX_DELAY,
        burst_enabled: bool = True,
        seed: Optional[int] = None,
    ) -> None:
        self._rng = random.Random(seed)
        self._stddev = stddev
        self._min = min_delay
        self._max = max_delay
        self._burst_enabled = burst_enabled
        self._burst_remaining = 0
        self._in_burst = False

    def add_jitter(self) -> float:
        """Return a delay in seconds drawn from a Gaussian distribution,
        clamped to [min_delay, max_delay].

        If burst mode is enabled, some calls will return near-zero delay to
        simulate rapid human clicks, followed by a longer pause.
        """
        if self._burst_enabled:
            delay = self._burst_jitter()
        else:
            delay = self._gaussian_jitter()
        return max(self._min, min(self._max, delay))

    def _gaussian_jitter(self) -> float:
        """Pure Gaussian jitter: mean=0, clamped so result is >= min."""
        sample = self._rng.gauss(0, self._stddev)
        # Shift so the result is a positive delay
        return max(self._min, abs(sample) + self._min)

    def _burst_jitter(self) -> float:
        """Simulate a burst of rapid requests then a pause.

        Each burst consists of 2-5 requests with minimal delay (~0.05-0.15s),
        then a pause of 1.5-4.0s before the next burst.
        """
        if not self._in_burst:
            # Decide whether to start a burst (40 % chance)
            if self._rng.random() < 0.4:
                self._in_burst = True
                self._burst_remaining = self._rng.randint(2, 5)
            else:
                # Normal delay
                return self._gaussian_jitter()

        if self._in_burst:
            if self._burst_remaining > 1:
                self._burst_remaining -= 1
                return self._rng.uniform(0.05, 0.15)
            else:
                # End of burst — return a longer pause
                self._in_burst = False
                self._burst_remaining = 0
                return self._rng.uniform(1.5, 4.0)

        return self._gaussian_jitter()


# ---------------------------------------------------------------------------
# 4. PathCanonicalizer
# ---------------------------------------------------------------------------


class PathCanonicalizer:
    """Generate variations of a URL path to test WAF / CDN normalisation.

    Produces 8-12 variants using techniques like dot-segments, URL-encoding,
    mixed case, trailing slashes, and overlong UTF-8 sequences.
    """

    def generate_variants(self, path: str) -> List[str]:
        """Return a list of 8-12 path variations for WAF testing.

        Parameters
        ----------
        path : str
            The original URL path (e.g. ``/api/v1/users``).

        Returns
        -------
        list[str]
        """
        if not path.startswith("/"):
            path = "/" + path

        variants: List[str] = []
        # 1. Original
        variants.append(path)
        # 2. Dot-segment prefix
        variants.append("/./" + path.lstrip("/"))
        # 3. Double-encoding of first char after slash
        variants.append(self._double_encode_char(path))
        # 4. URL-encoded full first segment
        variants.append(self._encode_segment(path))
        # 5. Mixed case — title-case each segment
        variants.append(self._mixed_case(path))
        # 6. UPPERCASE
        variants.append(path.upper())
        # 7. Trailing slash
        variants.append(path.rstrip("/") + "/")
        # 8. Double trailing slash
        variants.append(path.rstrip("/") + "//")
        # 9. Trailing dot-segment
        variants.append(path.rstrip("/") + "/.")
        # 10. Overlong UTF-8 for first slash-separated segment
        variants.append(self._overlong_utf8(path))
        # 11. Null-byte injection (common WAF bypass)
        variants.append(path.rstrip("/") + "%00")
        # 12. Semicolon / path-param injection
        variants.append(path.rstrip("/") + ";jsessionid=" + _rand_hex(8))

        # De-duplicate while preserving order
        seen: set = set()
        unique: List[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)

        return unique

    # -- variant generators --------------------------------------------------

    @staticmethod
    def _double_encode_char(path: str) -> str:
        """Double-encode the first character of each path segment.

        E.g. '/a/b' → '/%2561/%2562'
        """
        parts = path.strip("/").split("/")
        encoded_parts: List[str] = []
        for part in parts:
            if not part:
                continue
            first = part[0]
            double = "%25" + ("%02X" % ord(first))
            encoded_parts.append(double + part[1:])
        return "/" + "/".join(encoded_parts)

    @staticmethod
    def _encode_segment(path: str) -> str:
        """Fully URL-encode the first path segment."""
        parts = path.strip("/").split("/")
        if not parts or not parts[0]:
            return path
        encoded_first = urllib.parse.quote(parts[0], safe="")
        return "/" + encoded_first + ("/" + "/".join(parts[1:]) if len(parts) > 1 else "")

    @staticmethod
    def _mixed_case(path: str) -> str:
        """Title-case each segment: /api/v1/users → /Api/V1/Users."""
        parts = path.strip("/").split("/")
        titled = [p[:1].upper() + p[1:].lower() if p else "" for p in parts]
        return "/" + "/".join(titled)

    @staticmethod
    def _overlong_utf8(path: str) -> str:
        """Replace the first character of the first segment with an overlong
        UTF-8 2-byte sequence (e.g. 'a' → %C0%AF for '/').

        Specifically this targets the forward-slash character to produce
        /path%C0%AFrest style bypasses.
        """
        parts = path.strip("/").split("/")
        if not parts:
            return path
        # Use a valid overlong encoding of 'a' (U+0061) as 2-byte: 0xC1 0xA1
        # Note: many modern systems reject overlong UTF-8, but some WAFs still
        # mishandle it. We encode the first char of the first segment.
        first = parts[0][0] if parts[0] else "a"
        cp = ord(first)
        if cp < 0x80:
            # Overlong 2-byte: 110xxxxx 10xxxxxx → 0xC0|cp>>6, 0x80|cp&0x3F
            b1 = 0xC0 | (cp >> 6)
            b2 = 0x80 | (cp & 0x3F)
            overlong = f"%{b1:02X}%{b2:02X}"
            parts[0] = overlong + parts[0][1:]
        return "/" + "/".join(parts)


def _rand_hex(n: int) -> str:
    """Return a random hex string of length *n*."""
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


# ---------------------------------------------------------------------------
# 5. EvasionProfile
# ---------------------------------------------------------------------------

_PROFILE_DIR = Path.home() / ".reconpro" / "profiles"


class EvasionProfile:
    """High-level evasion profile that ties together HeaderRotator,
    TimingJitter, and PathCanonicalizer.

    Three built-in profiles:

    * **STEALTH**  – max jitter, rotated/canonicalised paths, fresh headers
    * **BALANCED** – moderate jitter, occasional path rotation
    * **SPEED**    – minimal evasion, fastest throughput
    """

    STEALTH = "STEALTH"
    BALANCED = "BALANCED"
    SPEED = "SPEED"

    _BUILTINS: Dict[str, Dict[str, Any]] = {
        STEALTH: {
            "jitter_stddev": 0.8,
            "burst_enabled": True,
            "rotate_path": True,
            "rotate_headers": True,
            "path_variant_chance": 0.7,
            "description": "Maximum evasion — slow but hard to fingerprint",
        },
        BALANCED: {
            "jitter_stddev": 0.3,
            "burst_enabled": True,
            "rotate_path": True,
            "rotate_headers": True,
            "path_variant_chance": 0.3,
            "description": "Balanced speed/evasion trade-off",
        },
        SPEED: {
            "jitter_stddev": 0.1,
            "burst_enabled": False,
            "rotate_path": False,
            "rotate_headers": True,
            "path_variant_chance": 0.0,
            "description": "Minimal evasion — maximum speed",
        },
    }

    def __init__(
        self,
        name: str = BALANCED,
        seed: Optional[int] = None,
    ) -> None:
        if name in self._BUILTINS:
            cfg = dict(self._BUILTINS[name])
        else:
            cfg = dict(self._BUILTINS[self.BALANCED])
        self._name = name
        self._config = cfg
        self._header_rotator = HeaderRotator(seed=seed)
        self._timing = TimingJitter(
            stddev=cfg["jitter_stddev"],
            burst_enabled=cfg["burst_enabled"],
            seed=seed,
        )
        self._path_canon = PathCanonicalizer()
        self._rng = random.Random(seed)
        self._tls = TlsFingerprint(seed=seed)

    # -- public API ----------------------------------------------------------

    @classmethod
    def load_profile(cls, name: str) -> "EvasionProfile":
        """Load a built-in profile by name.

        For custom profiles saved to disk, use :meth:`from_file`.
        """
        return cls(name=name)

    @classmethod
    def from_file(cls, path: str) -> "EvasionProfile":
        """Load a custom profile from a JSON file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        instance = cls(name=data.get("name", "CUSTOM"), seed=data.get("seed"))
        instance._config.update(data.get("config", {}))
        # Re-create timing with loaded stddev
        instance._timing = TimingJitter(
            stddev=instance._config.get("jitter_stddev", 0.3),
            burst_enabled=instance._config.get("burst_enabled", True),
        )
        return instance

    def save_profile(self, profile_path: Optional[str] = None) -> str:
        """Save the current profile to ``~/.reconpro/profiles/<name>.json``.

        Returns the absolute path of the saved file.
        """
        if profile_path is None:
            _PROFILE_DIR.mkdir(parents=True, exist_ok=True)
            profile_path = str(_PROFILE_DIR / f"{self._name.lower()}.json")
        data = {
            "name": self._name,
            "config": self._config,
        }
        with open(profile_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        return os.path.abspath(profile_path)

    def apply_to_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Build a fully evasive request configuration.

        Returns
        -------
        dict with keys:
            url     – possibly canonicalised URL
            headers – rotated header dict
            delay   – jitter delay in seconds (caller should ``time.sleep``)
            method  – HTTP method
        """
        # Determine if we should rotate the path
        final_url = url
        if self._config.get("rotate_path") and self._config.get("path_variant_chance", 0) > 0:
            if self._rng.random() < self._config["path_variant_chance"]:
                parsed = urllib.parse.urlparse(url)
                variants = self._path_canon.generate_variants(parsed.path)
                chosen = self._rng.choice(variants)
                final_url = urllib.parse.urlunparse(
                    (parsed.scheme, parsed.netloc, chosen, parsed.params, parsed.query, parsed.fragment)
                )

        # Rotate headers
        rotated = self._header_rotator.rotate(custom_headers=headers)

        # Compute delay
        delay = self._timing.add_jitter()

        return {
            "url": final_url,
            "headers": rotated,
            "delay": delay,
            "method": method.upper(),
        }

    @property
    def config(self) -> Dict[str, Any]:
        return dict(self._config)

    @property
    def name(self) -> str:
        return self._name

    @classmethod
    def available_profiles(cls) -> List[str]:
        return list(cls._BUILTINS.keys())


# ---------------------------------------------------------------------------
# 6. EvasionSession
# ---------------------------------------------------------------------------


class EvasionSession:
    """Stateful evasion across multiple requests to the same target.

    Maintains a consistent User-Agent, cookies, and timing pattern so that
    a sequence of requests looks like one real human browsing a site.
    """

    def __init__(
        self,
        target_base: str,
        profile_name: str = EvasionProfile.BALANCED,
        seed: Optional[int] = None,
    ) -> None:
        self._target_base = target_base.rstrip("/")
        self._profile = EvasionProfile(name=profile_name, seed=seed)
        self._rng = random.Random(seed)

        # Session state
        self._request_count = 0
        self._current_ua: Optional[str] = None
        self._current_headers: Dict[str, str] = {}
        self._cookies: Dict[str, str] = {}
        self._visited_urls: List[str] = []
        self._timing = self._profile._timing
        self._tls = TlsFingerprint(seed=seed)
        self._tls_profile_name = self._rng.choice(["CHROME_120", "FIREFOX_121", "SAFARI_17", "EDGE_120"])
        self._tls_profile = self._tls.get_profile(self._tls_profile_name)

        # Initialise with one consistent set of headers
        self._current_headers = self._profile._header_rotator.rotate()
        self._current_ua = self._current_headers.get("User-Agent", "")

    def next_request(self, url: str) -> Dict[str, Any]:
        """Return a complete request configuration for the next request.

        The returned dict has keys: url, headers, delay, method, cookies,
        tls_profile.

        The session keeps the same User-Agent across all requests (to look
        like one user) while still varying other headers slightly.
        """
        self._request_count += 1

        # Keep the same UA, but lightly rotate other headers
        headers = dict(self._current_headers)
        headers["User-Agent"] = self._current_ua

        # Set referer to the last visited URL (simulates navigation)
        if self._visited_urls:
            headers["Referer"] = self._visited_urls[-1]

        # Vary Sec-Fetch-* headers based on navigation pattern
        if self._request_count == 1:
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-Mode"] = "navigate"
        elif url.startswith(self._target_base):
            headers["Sec-Fetch-Site"] = "same-origin"
            # Every few requests simulate a sub-resource fetch
            if self._rng.random() < 0.2:
                headers["Sec-Fetch-Dest"] = "script"
                headers["Sec-Fetch-Mode"] = "no-cors"
            else:
                headers["Sec-Fetch-Dest"] = "document"
                headers["Sec-Fetch-Mode"] = "navigate"
        else:
            headers["Sec-Fetch-Site"] = "cross-site"
            headers["Sec-Fetch-Mode"] = "navigate"

        # Slightly vary Accept-Language on ~10 % of requests (user might
        # have changed language setting, or we simulate a shared IP)
        if self._rng.random() < 0.1:
            lang_keys = list(_ACCEPT_LANGS.keys())
            headers["Accept-Language"] = _ACCEPT_LANGS[self._rng.choice(lang_keys)]

        # Compute delay
        delay = self._timing.add_jitter()

        # Track visited URL
        self._visited_urls.append(url)

        # Build cookie header if we have cookies
        cookie_header = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
        if cookie_header:
            headers["Cookie"] = cookie_header

        return {
            "url": url,
            "headers": headers,
            "delay": delay,
            "method": "GET",
            "cookies": dict(self._cookies),
            "tls_profile": self._tls_profile,
            "request_count": self._request_count,
        }

    def update_cookies(self, cookies: Dict[str, str]) -> None:
        """Update the session cookie jar (e.g. from a Set-Cookie response)."""
        self._cookies.update(cookies)

    def clear_cookies(self) -> None:
        """Clear all stored cookies."""
        self._cookies.clear()

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def current_ua(self) -> str:
        return self._current_ua or ""

    @property
    def tls_profile(self) -> Dict[str, Any]:
        return dict(self._tls_profile)

    @property
    def visited_urls(self) -> List[str]:
        return list(self._visited_urls)


# ---------------------------------------------------------------------------
# 6. WAFBypass
# ---------------------------------------------------------------------------


class WAFBypass:
    """Advanced WAF bypass techniques using encoding, chunking, and unicode tricks."""

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL-encode a payload to bypass WAF pattern matching."""
        import urllib.parse
        first = urllib.parse.quote(payload)
        second = urllib.parse.quote(first)
        return second

    @staticmethod
    def unicode_normalize(payload: str) -> str:
        """Apply Unicode normalization tricks to bypass WAF."""
        replacements = {
            "<": "\uff1c", ">": "\uff1e", "'": "\uff07", '"': "\uff02",
            "(": "\uff08", ")": "\uff09", "/": "\uff0f", "%": "\uff05",
            "+": "\uff0b", "=": "\uff1d", "&": "\uff06", "#": "\uff03",
        }
        result = []
        for ch in payload:
            result.append(replacements.get(ch, ch))
        return "".join(result)

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """Encode using HTML entities."""
        result = []
        for ch in payload:
            if ch.isalpha() and random.random() < 0.5:
                result.append(f"&#{ord(ch)};")
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def chunked_encoding_bypass(payload: str) -> str:
        """Break payload into chunks to bypass WAF content-length checks."""
        chunk_size = random.randint(4, 8)
        chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
        return "".join(f"{len(c):x}\r\n{c}\r\n" for c in chunks) + "0\r\n\r\n"

    @staticmethod
    def null_byte_inject(payload: str) -> str:
        """Inject NULL bytes to bypass filters."""
        return payload.replace("=", "%00=").replace("<", "%00<").replace(">", ">%00")

    @staticmethod
    def comment_bypass(payload: str) -> str:
        """Insert inline comments to break WAF patterns (SQL specific)."""
        sql_keywords = [
            "SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
            "INSERT", "UPDATE", "DELETE", "DROP",
        ]
        result = payload
        for kw in sql_keywords:
            if kw.lower() in result.lower():
                idx = result.lower().index(kw.lower())
                result = result[:idx] + kw[0] + "/**/" + kw[1:] + result[idx + len(kw):]
        return result

    @staticmethod
    def case_alternation(payload: str) -> str:
        """Alternate case of each character to bypass case-sensitive WAF rules."""
        result = []
        upper = True
        for ch in payload:
            if ch.isalpha():
                result.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def tab_newline_replace(payload: str) -> str:
        """Replace spaces with tabs/newlines to break token matching."""
        return payload.replace(" ", "\t").replace(" ", "\n")

    @staticmethod
    def generate_bypass_variants(payload: str) -> Dict[str, str]:
        """Generate all WAF bypass variants of a payload."""
        return {
            "original": payload,
            "double_url_encode": WAFBypass.double_url_encode(payload),
            "unicode": WAFBypass.unicode_normalize(payload),
            "html_entity": WAFBypass.html_entity_encode(payload),
            "null_byte": WAFBypass.null_byte_inject(payload),
            "comment_bypass": WAFBypass.comment_bypass(payload),
            "case_alternation": WAFBypass.case_alternation(payload),
            "tab_newline": WAFBypass.tab_newline_replace(payload),
        }


# ---------------------------------------------------------------------------
# 7. PolymorphicPayload
# ---------------------------------------------------------------------------


class PolymorphicPayload:
    """Generates polymorphic variants of payloads to evade signature-based detection."""

    _ENCODERS = [
        WAFBypass.double_url_encode,
        WAFBypass.html_entity_encode,
        WAFBypass.unicode_normalize,
        WAFBypass.case_alternation,
    ]

    def __init__(self, seed: Optional[int] = None):
        self._rng = random.Random(seed)

    def generate(self, base_payload: str, count: int = 10) -> List[str]:
        """Generate N polymorphic variants."""
        variants = set()
        variants.add(base_payload)
        for _ in range(count):
            encoder = self._rng.choice(self._ENCODERS)
            variant = encoder(base_payload)
            variants.add(variant)
            # Chain two encoders
            encoder2 = self._rng.choice(self._ENCODERS)
            variants.add(encoder2(variant))
        return list(variants)


# ---------------------------------------------------------------------------
# 8. RateLimiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Token bucket rate limiter for scan requests."""

    def __init__(self, max_requests: float = 10.0, period: float = 1.0):
        self._max = max_requests
        self._period = period
        self._tokens = max_requests
        self._last_refill = time.monotonic()

    def acquire(self) -> bool:
        """Try to acquire a token. Returns True if request allowed."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(self._max, self._tokens + elapsed * (self._max / self._period))
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    def wait(self) -> float:
        """How long to wait for the next token."""
        if self._tokens >= 1.0:
            return 0.0
        return (1.0 - self._tokens) * (self._period / self._max)

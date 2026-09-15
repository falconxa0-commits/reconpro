"""DEAD_DROP module — Cryptographic Dead Drop Detection & Analysis.

ReconPro v9.2.0

A dead drop is a covert communication technique where a message is left in a
location (digital or physical) for another party to retrieve, without the
two parties ever meeting directly. This module detects eight classes of
digital dead drop channels:

  1. DNS TXT Record Dead Drop Detection
  2. HTTP ETag Dead Drop Detection
  3. Certificate Transparency Dead Drops
  4. HTTP Header Dead Drop Detection
  5. Timestamp Steganography Detection
  6. DNS CNAME Dead Drop Detection
  7. SPF/DKIM/DMARC Dead Drop Analysis
  8. Dead Drop Simulation

All cryptographic operations use pure stdlib (hashlib, hmac, base64, struct).
Zero external dependencies.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import struct
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import http_probe, Finding, default_limiter


# ═══════════════════════════════════════════════════════════════════════════
# DEAD_DROP_SIGNATURES DATABASE
# ═══════════════════════════════════════════════════════════════════════════

DEAD_DROP_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "dns_txt_dead_drop": {
        "name": "DNS TXT Dead Drop",
        "description": (
            "Encodes covert messages in DNS TXT records. TXT records are rarely "
            "monitored by standard security tooling, making them ideal for leaving "
            "encoded messages that appear as SPF/DKIM configuration or verification "
            "strings. Attackers can base64-encode C2 beacons, encryption keys, or "
            "operational timestamps within TXT RDATA."
        ),
        "severity": "high",
        "dread_score": 7.2,
        "entropy_threshold": 3.8,
        "min_value_length": 20,
        "known_patterns": [
            r"^[A-Za-z0-9+/=]{24,}$",           # base64 encoded data
            r"^[a-f0-9]{32,}$",                   # hex encoded data
            r"^[A-Za-z0-9+/=]{20,}\.[A-Za-z]+$",  # base64 with domain hint
            r"v=spf1.*[A-Za-z0-9+/=]{24,}",     # hidden in SPF
            r"google-site-verification=.*",        # disguised verification
        ],
        "stealth_score": 74,
        "bandwidth_estimate": "~255 bytes per TXT record (up to 65535 bytes in theory)",
        "detection_difficulty": "Medium — requires active DNS TXT queries",
    },
    "etag_dead_drop": {
        "name": "HTTP ETag Dead Drop",
        "description": (
            "ETag headers are commonly used for cache validation but can carry "
            "covert data. An attacker can encode HMAC tags, encrypted fragments, "
            "or steganographic data within the opaque ETag string. Because ETags "
            "are opaque strings defined by the origin server, high-entropy or "
            "cryptographically structured values are rarely flagged."
        ),
        "severity": "medium",
        "dread_score": 6.4,
        "entropy_threshold": 3.5,
        "min_value_length": 16,
        "known_patterns": [
            r'^"[a-f0-9]{32,}"$',              # quoted hex hash
            r'^"[A-Za-z0-9+/=]{22,}"$',          # quoted base64
            r'^W/"[a-f0-9]+"$',                  # weak validator with hex
            r'^"[a-f0-9]{8}-[a-f0-9]{4}-',     # UUID-formatted ETag
            r'^[0-9a-f]{40}$',                    # SHA-1 hex
            r'^[0-9a-f]{64}$',                    # SHA-256 hex
            r'^"[A-Za-z0-9+/=]{32,}"$',         # base64 MAC-like
        ],
        "stealth_score": 82,
        "bandwidth_estimate": "~128-512 bytes per ETag value",
        "detection_difficulty": "High — ETags are opaque and inherently variable",
    },
    "ct_log_dead_drop": {
        "name": "Certificate Transparency Dead Drop",
        "description": (
            "Subdomain names in CT logs can encode covert messages. By issuing "
            "certificates for carefully crafted subdomains (e.g., hex-encoded "
            "payloads, base64 labels), attackers embed data in a globally "
            "replicated, append-only log. The subdomain names are public but "
            "rarely examined for encoded content."
        ),
        "severity": "high",
        "dread_score": 7.8,
        "entropy_threshold": 4.0,
        "min_subdomain_length": 20,
        "known_patterns": [
            r"^[a-f0-9]{16,}\.",                # hex subdomain
            r"^[A-Za-z0-9-]{32,}\.",              # long random subdomain
            r"^[A-Za-z0-9+/=]{24,}\.",            # base64 subdomain
            r"^[0-9]{10,}\.",                     # numeric (timestamp/epoch)
            r"^.{40,}\.",                         # very long subdomain label
        ],
        "stealth_score": 88,
        "bandwidth_estimate": "~63 bytes per subdomain label (RFC 1035 limit)",
        "detection_difficulty": "Very High — requires CT log analysis",
    },
    "http_header_dead_drop": {
        "name": "HTTP Header Dead Drop",
        "description": (
            "Covert messages embedded in unusual or custom HTTP header combinations. "
            "Headers like X-Data, X-Payload, X-Token, or even legitimate headers "
            "with anomalous values can carry encoded data. The combination of "
            "header names and values forms a multi-channel encoding scheme."
        ),
        "severity": "medium",
        "dread_score": 6.0,
        "entropy_threshold": 3.6,
        "suspicious_headers": [
            "X-Data", "X-Payload", "X-Token", "X-Secret", "X-Hidden",
            "X-Message", "X-Cmd", "X-Task", "X-Op", "X-Key",
            "X-Cipher", "X-Nonce", "X-Sig", "X-Auth-Token",
            "X-Request-Guid", "X-Correlation-ID", "X-Trace-Id",
            "X-Session-Data", "X-State", "X-Enc", "X-Encoded",
        ],
        "known_patterns": [
            r"^[A-Za-z0-9+/=]{32,}$",              # base64 in header
            r"^[a-f0-9]{32,}$",                    # hex in header
            r"^[A-Za-z0-9+/=]{20,}:[a-f0-9]+$",    # key:value format
        ],
        "stealth_score": 70,
        "bandwidth_estimate": "~4-8 KB total across headers per request",
        "detection_difficulty": "Medium — requires full header inspection",
    },
    "timestamp_stego": {
        "name": "Timestamp Steganography",
        "description": (
            "Data encoded in the precision or anomalies of HTTP Date header "
            "timestamps. By controlling the sub-second precision of server "
            "timestamps, an attacker can embed bits per response. For example, "
            "a timestamp ending in an odd millisecond encodes a 1-bit; even "
            "encodes a 0-bit. Deviations from standard time sync patterns also "
            "indicate covert timing channels."
        ),
        "severity": "low",
        "dread_score": 4.2,
        "bits_per_response": 1,
        "bandwidth_estimate": "~1 bit per response (timing-based)",
        "stealth_score": 92,
        "detection_difficulty": "Very High — requires statistical time analysis",
        "anomaly_indicators": [
            "sub_second_precision_in_date_header",
            "clock_drift_beyond_2_seconds",
            "monotonic_millisecond_changes",
            "non_standard_date_format",
        ],
    },
    "dns_cname_dead_drop": {
        "name": "DNS CNAME Dead Drop",
        "description": (
            "CNAME records can point to domain names whose labels encode covert "
            "messages. The target of a CNAME is a fully qualified domain name, and "
            "each label can carry encoded data (hex, base32, base64url). Long, "
            "high-entropy CNAME targets with unusual TLD combinations are strong "
            "indicators of dead drop activity."
        ),
        "severity": "high",
        "dread_score": 7.0,
        "entropy_threshold": 3.9,
        "min_cname_length": 30,
        "known_patterns": [
            r"[a-f0-9]{16,}\.[a-z]+\.[a-z]+$",         # hex labels in CNAME
            r"[A-Z2-7=]{20,}\.[A-Z2-7=]+\.[A-Z]+$",   # base32 labels
            r"[A-Za-z0-9_-]{32,}\.[a-z0-9-]+\.[a-z]+$", # base64url labels
            r"cdn-[a-f0-9]{8,}\.\w+\.net$",              # fake CDN pattern
        ],
        "stealth_score": 76,
        "bandwidth_estimate": "~63 bytes per label, multiple labels per CNAME",
        "detection_difficulty": "Medium-High — requires DNS CNAME resolution",
    },
    "spf_dkim_dmarc_dead_drop": {
        "name": "SPF/DKIM/DMARC Dead Drop",
        "description": (
            "Email authentication records (SPF, DKIM, DMARC) are long, complex "
            "TXT records that naturally contain encoded data. Covert messages can "
            "be hidden within ip4/ip6 mechanisms, DKIM public key data, or DMARC "
            "policy parameters. The legitimate complexity of these records masks "
            "embedded payloads effectively."
        ),
        "severity": "medium",
        "dread_score": 5.8,
        "entropy_threshold": 3.7,
        "record_types": ["SPF", "DKIM", "DMARC"],
        "suspicious_dkim_patterns": [
            r"p=[A-Za-z0-9+/=]{100,}",    # unusually long DKIM public key
            r"k=rsa;.*[A-Za-z0-9+/=]{200,}", # very long RSA key
        ],
        "stealth_score": 78,
        "bandwidth_estimate": "~2000+ bytes in DKIM records, ~512 in SPF/DMARC",
        "detection_difficulty": "High — records are inherently complex",
    },
    "dead_drop_simulation": {
        "name": "Dead Drop Simulation",
        "description": (
            "Demonstrates how each dead drop channel could be exploited by "
            "simulating the encoding process. Generates example payloads for "
            "each channel type, showing the encoding, embedding, and potential "
            "decoding workflow. Used for red team planning and defender education."
        ),
        "severity": "info",
        "dread_score": 0.0,
        "stealth_score": 0,
        "simulation_types": [
            "dns_txt_encoding",
            "etag_mac_encoding",
            "ct_subdomain_encoding",
            "header_combination_encoding",
            "timestamp_bit_encoding",
            "cname_label_encoding",
            "spf_payload_concealment",
        ],
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# ENCODING_METHODS DATABASE
# ═══════════════════════════════════════════════════════════════════════════

ENCODING_METHODS: Dict[str, Dict[str, Any]] = {
    "base64": {
        "name": "Base64",
        "description": "RFC 4648 standard Base64 encoding",
        "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "padding_char": "=",
        "ratio": 1.333,
        "detection_regex": r"^[A-Za-z0-9+/]{4,}={0,2}$",
        "typical_use": "Binary data, encryption keys, certificates",
        "entropy_range": (3.5, 6.0),
        "decode_fn": "base64.b64decode",
    },
    "base64url": {
        "name": "Base64URL",
        "description": "RFC 4648 URL-safe Base64 variant (no +/padding)",
        "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        "padding_char": "",
        "ratio": 1.333,
        "detection_regex": r"^[A-Za-z0-9_-]{4,}$",
        "typical_use": "JWT tokens, URL-embedded data, OAuth",
        "entropy_range": (3.5, 6.0),
        "decode_fn": "base64.urlsafe_b64decode",
    },
    "hex": {
        "name": "Hexadecimal",
        "description": "Standard hexadecimal encoding (lowercase or uppercase)",
        "alphabet": "0123456789abcdefABCDEF",
        "padding_char": "",
        "ratio": 2.0,
        "detection_regex": r"^[a-fA-F0-9]{8,}$",
        "typical_use": "Hash digests, binary fingerprints, MACs",
        "entropy_range": (3.0, 4.0),
        "decode_fn": "bytes.fromhex",
    },
    "base32": {
        "name": "Base32",
        "description": "RFC 4648 Base32 encoding (uppercase A-Z, 2-7)",
        "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
        "padding_char": "=",
        "ratio": 1.6,
        "detection_regex": r"^[A-Z2-7=]{8,}$",
        "typical_use": "DNS labels,TOTP secrets, encoded subdomains",
        "entropy_range": (3.0, 5.0),
        "decode_fn": "base64.b32decode",
    },
    "base32hex": {
        "name": "Base32Hex",
        "description": "RFC 4648 Base32 extended hex encoding (0-9, A-V)",
        "alphabet": "0123456789ABCDEFGHIJKLMNOPQRSTUV",
        "padding_char": "=",
        "ratio": 1.6,
        "detection_regex": r"^[0-9A-V=]{8,}$",
        "typical_use": "Alternative to base32 for numeric-heavy data",
        "entropy_range": (3.0, 5.0),
        "decode_fn": "base64.b32hexdecode",
    },
    "ascii_hex": {
        "name": "ASCII Hex",
        "description": "Two-hex-digit-per-byte encoding (e.g., 48656C6C6F)",
        "alphabet": "0123456789abcdef",
        "padding_char": "",
        "ratio": 2.0,
        "detection_regex": r"^[a-f0-9]{10,}$",
        "typical_use": "Payload encoding in CNAME/TXT records",
        "entropy_range": (2.8, 4.0),
        "decode_fn": "bytes.fromhex",
    },
    "url_encoded": {
        "name": "URL Encoding",
        "description": "Percent-encoding (RFC 3986)",
        "alphabet": None,
        "padding_char": "",
        "ratio": 3.0,
        "detection_regex": r"%[0-9a-fA-F]{2}",
        "typical_use": "URL parameters, path encoding, header values",
        "entropy_range": (2.0, 4.0),
        "decode_fn": "urllib.parse.unquote",
    },
    "unicode_escape": {
        "name": "Unicode Escape",
        "description": "\\uXXXX or \\UXXXXXXXX escape sequences",
        "alphabet": None,
        "padding_char": "",
        "ratio": 6.0,
        "detection_regex": r"\\u[0-9a-fA-F]{4}",
        "typical_use": "Text steganography, JSON payloads",
        "entropy_range": (1.5, 3.0),
        "decode_fn": "codecs.decode",
    },
    "reversed_base64": {
        "name": "Reversed Base64",
        "description": "Base64 string reversed to evade naive detection",
        "alphabet": "=+AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789/",
        "padding_char": "=",
        "ratio": 1.333,
        "detection_regex": r"^[A-Za-z0-9+/=]{4,}$",
        "typical_use": "Evasion of base64 detection regexes",
        "entropy_range": (3.5, 6.0),
        "decode_fn": "reverse + base64.b64decode",
    },
    "hex_chunked": {
        "name": "Chunked Hex",
        "description": "Hex data split into fixed-size chunks with separators",
        "alphabet": "0123456789abcdef:-",
        "padding_char": "",
        "ratio": 2.2,
        "detection_regex": r"^[a-f0-9]{2}(:[a-f0-9]{2}){4,}$",
        "typical_use": "MAC addresses, UUIDs, obfuscated hex data",
        "entropy_range": (2.5, 4.0),
        "decode_fn": "strip separators + bytes.fromhex",
    },
    "rot13_base64": {
        "name": "ROT13+Base64",
        "description": "Base64 output with ROT13 applied to alpha characters",
        "alphabet": "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/",
        "padding_char": "=",
        "ratio": 1.333,
        "detection_regex": r"^[A-Za-z0-9+/]{4,}={0,2}$",
        "typical_use": "Layered obfuscation of base64 payloads",
        "entropy_range": (3.5, 6.0),
        "decode_fn": "rot13 + base64.b64decode",
    },
    "double_base64": {
        "name": "Double Base64",
        "description": "Data base64-encoded twice for additional obfuscation",
        "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "padding_char": "=",
        "ratio": 1.778,
        "detection_regex": r"^[A-Za-z0-9+/]{4,}={0,2}$",
        "typical_use": "Hiding the structure of the inner base64 layer",
        "entropy_range": (3.8, 6.0),
        "decode_fn": "base64.b64decode x2",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# CRYPTO_PATTERNS DATABASE
# ═══════════════════════════════════════════════════════════════════════════

CRYPTO_PATTERNS: Dict[str, Dict[str, Any]] = {
    "md5_hash": {
        "name": "MD5 Hash",
        "description": "128-bit MD5 message digest in hex",
        "hex_length": 32,
        "regex": r"\b[a-f0-9]{32}\b",
        "algorithm": "md5",
        "digest_size": 16,
        "block_size": 64,
        "security_status": "broken",
        "typical_context": "ETags, cache keys, legacy fingerprints",
    },
    "sha1_hash": {
        "name": "SHA-1 Hash",
        "description": "160-bit SHA-1 message digest in hex",
        "hex_length": 40,
        "regex": r"\b[a-f0-9]{40}\b",
        "algorithm": "sha1",
        "digest_size": 20,
        "block_size": 64,
        "security_status": "broken",
        "typical_context": "ETags, SSL fingerprints, git commits, CT certs",
    },
    "sha256_hash": {
        "name": "SHA-256 Hash",
        "description": "256-bit SHA-256 message digest in hex",
        "hex_length": 64,
        "regex": r"\b[a-f0-9]{64}\b",
        "algorithm": "sha256",
        "digest_size": 32,
        "block_size": 64,
        "security_status": "secure",
        "typical_context": "ETags, HMAC tags, integrity checksums",
    },
    "sha512_hash": {
        "name": "SHA-512 Hash",
        "description": "512-bit SHA-512 message digest in hex",
        "hex_length": 128,
        "regex": r"\b[a-f0-9]{128}\b",
        "algorithm": "sha512",
        "digest_size": 64,
        "block_size": 128,
        "security_status": "secure",
        "typical_context": "High-security integrity, HMAC-SHA512",
    },
    "hmac_sha256_base64": {
        "name": "HMAC-SHA256 (Base64)",
        "description": "HMAC-SHA256 authentication tag in Base64",
        "hex_length": None,
        "regex": r"[A-Za-z0-9+/=]{42,44}",
        "algorithm": "hmac-sha256",
        "digest_size": 32,
        "tag_length_b64": 44,
        "security_status": "secure",
        "typical_context": "AWS SigV4, JWT signatures, API auth",
    },
    "hmac_sha1_base64": {
        "name": "HMAC-SHA1 (Base64)",
        "description": "HMAC-SHA1 authentication tag in Base64",
        "hex_length": None,
        "regex": r"[A-Za-z0-9+/=]{26,28}",
        "algorithm": "hmac-sha1",
        "digest_size": 20,
        "tag_length_b64": 28,
        "security_status": "weak",
        "typical_context": "OAuth 1.0, legacy API auth, AWS v2",
    },
    "aes_cbc_iv": {
        "name": "AES-CBC IV",
        "description": "128/256-bit AES initialization vector",
        "hex_length": 32,
        "regex": r"\b[a-f0-9]{32}\b",
        "algorithm": "aes-cbc-iv",
        "digest_size": 16,
        "security_status": "context-dependent",
        "typical_context": "Encrypted ETag payloads, cookie values",
    },
    "uuid_v4": {
        "name": "UUID v4",
        "description": "Random UUID version 4 identifier",
        "hex_length": 36,
        "regex": r"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
        "algorithm": "uuid4",
        "digest_size": 16,
        "security_status": "not_crypto",
        "typical_context": "Request tracing, correlation IDs, ETags",
    },
    "fingerprint_sha256_base64": {
        "name": "SHA-256 Fingerprint (Base64)",
        "description": "SHA-256 hash in Base64 (no padding) for SPKI/cert fingerprints",
        "hex_length": None,
        "regex": r"[A-Za-z0-9_-]{42,43}",
        "algorithm": "sha256",
        "digest_size": 32,
        "tag_length_b64": 43,
        "security_status": "secure",
        "typical_context": "HPKP pins, certificate pinning, CT log entries",
    },
    "crc32_hex": {
        "name": "CRC32",
        "description": "32-bit cyclic redundancy check in hex",
        "hex_length": 8,
        "regex": r"\b[a-f0-9]{8}\b",
        "algorithm": "crc32",
        "digest_size": 4,
        "security_status": "not_crypto",
        "typical_context": "ETags, checksums, data integrity markers",
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# SHARED CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════

MODULE_NAME = "dead_drop"

CT_LOG_ENDPOINTS: List[str] = [
    "https://crt.sh/?q={}&output=json",
    "https://crt.sh/?q=%.{target}&output=json",
]

COMMON_DNS_OVER_HTTPS: List[Dict[str, str]] = [
    {"name": "Cloudflare", "url": "https://cloudflare-dns.com/dns-query"},
    {"name": "Google", "url": "https://dns.google/resolve"},
]

HEADER_VALUE_MAX_LEN = 4096


# ═══════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def _shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string using stdlib math.log2."""
    if not data:
        return 0.0
    length = len(data)
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _identify_encoding(value: str) -> List[Dict[str, Any]]:
    """Identify which encoding(s) a value might use."""
    results: List[Dict[str, Any]] = []
    stripped = value.strip().strip('"')

    for enc_name, enc_info in ENCODING_METHODS.items():
        regex = enc_info["detection_regex"]
        if re.search(regex, stripped, re.IGNORECASE if enc_name in ("hex", "ascii_hex") else 0):
            ent = _shannon_entropy(stripped)
            lo, hi = enc_info["entropy_range"]
            if lo <= ent <= hi or ent > hi:
                results.append({
                    "encoding": enc_name,
                    "name": enc_info["name"],
                    "entropy": round(ent, 3),
                    "in_range": lo <= ent <= hi,
                    "length": len(stripped),
                })
    return results


def _identify_crypto_pattern(value: str) -> List[Dict[str, Any]]:
    """Identify if a value matches known cryptographic output patterns."""
    results: List[Dict[str, Any]] = []
    stripped = value.strip().strip('"')

    for pat_name, pat_info in CRYPTO_PATTERNS.items():
        regex = pat_info["regex"]
        if re.search(regex, stripped, re.IGNORECASE):
            results.append({
                "pattern": pat_name,
                "name": pat_info["name"],
                "description": pat_info["description"],
                "security_status": pat_info["security_status"],
                "typical_context": pat_info["typical_context"],
            })
    return results


def _compute_hmac_sha256(key: bytes, message: bytes) -> str:
    """Compute HMAC-SHA256 and return hex digest."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _compute_hmac_sha1(key: bytes, message: bytes) -> str:
    """Compute HMAC-SHA1 and return hex digest."""
    return hmac.new(key, message, hashlib.sha1).hexdigest()


def _hash_sha256(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def _hash_sha1(data: bytes) -> str:
    """Compute SHA-1 hex digest."""
    return hashlib.sha1(data).hexdigest()


def _hash_md5(data: bytes) -> str:
    """Compute MD5 hex digest."""
    return hashlib.md5(data).hexdigest()


def _try_base64_decode(value: str) -> Optional[bytes]:
    """Attempt to base64-decode a value, returning None on failure."""
    try:
        padded = value + "=" * (-len(value) % 4) if len(value) % 4 else value
        return base64.b64decode(padded, validate=True)
    except Exception:
        return None


def _try_hex_decode(value: str) -> Optional[bytes]:
    """Attempt to hex-decode a value, returning None on failure."""
    try:
        return bytes.fromhex(value)
    except (ValueError, TypeError):
        return None


def _try_base32_decode(value: str) -> Optional[bytes]:
    """Attempt to base32-decode a value, returning None on failure."""
    try:
        padded = value + "=" * (-len(value) % 8) if len(value) % 8 else value
        return base64.b32decode(padded)
    except Exception:
        return None


def _pack_uint32(val: int) -> bytes:
    """Pack a 32-bit unsigned integer using struct."""
    return struct.pack(">I", val)


def _unpack_uint32(data: bytes) -> Optional[int]:
    """Unpack a 32-bit unsigned integer from bytes."""
    try:
        return struct.unpack(">I", data[:4])[0]
    except (struct.error, ValueError):
        return None


def _pack_uint64(val: int) -> bytes:
    """Pack a 64-bit unsigned integer using struct."""
    return struct.pack(">Q", val)


def _try_decode_all(value: str) -> Dict[str, Optional[bytes]]:
    """Try all known decodings and return results."""
    stripped = value.strip().strip('"')
    return {
        "base64": _try_base64_decode(stripped),
        "hex": _try_hex_decode(stripped),
        "base32": _try_base32_decode(stripped.upper()),
    }


def _finding(
    title: str,
    severity: str,
    category: str,
    description: str,
    evidence: str,
    asset: str,
    dread: float = 0.0,
    remediation: str = "",
    points: int = 0,
) -> Finding:
    """Convenience constructor for a Finding."""
    return Finding(
        title=title,
        severity=severity,
        category=category,
        module=MODULE_NAME,
        description=description,
        evidence=evidence,
        asset=asset,
        points_deducted=points,
        dread_score=dread,
        remediation=remediation,
    )


def _is_high_entropy(value: str, threshold: float = 3.5) -> bool:
    """Return True if the string's Shannon entropy exceeds the threshold."""
    return _shannon_entropy(value) >= threshold


def _looks_like_hex(value: str, min_len: int = 16) -> bool:
    """Check if a string looks like a hex-encoded value."""
    stripped = value.strip().strip('"')
    if len(stripped) < min_len:
        return False
    return bool(re.fullmatch(r'[a-fA-F0-9]+', stripped))


def _looks_like_base64(value: str, min_len: int = 16) -> bool:
    """Check if a string looks like a base64-encoded value."""
    stripped = value.strip().strip('"')
    if len(stripped) < min_len:
        return False
    return bool(re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', stripped))


def _looks_like_base64url(value: str, min_len: int = 16) -> bool:
    """Check if a string looks like a base64url-encoded value."""
    stripped = value.strip().strip('"')
    if len(stripped) < min_len:
        return False
    return bool(re.fullmatch(r'[A-Za-z0-9_-]+', stripped))


def _extract_date_precision(date_str: str) -> Optional[Dict[str, Any]]:
    """Analyze the precision of an HTTP Date header value."""
    if not date_str:
        return None
    date_str = date_str.strip()
    patterns = [
        (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.(\d+)", "iso_ms"),
        (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", "iso_sec"),
        (r"(\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2}) GMT", "rfc1123"),
        (r"(\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2})", "rfc850"),
    ]
    for pat, fmt_name in patterns:
        m = re.search(pat, date_str)
        if m:
            has_subsecond = "ms" in fmt_name
            return {
                "raw": date_str,
                "format": fmt_name,
                "has_subsecond": has_subsecond,
                "subsecond_digits": len(m.group(2)) if has_subsecond and m.lastindex >= 2 else 0,
                "match": m.group(0),
            }
    return None


def _steg_bits_from_timestamp(precision_info: Dict[str, Any]) -> Optional[int]:
    """Extract a steganographic bit from timestamp sub-second precision."""
    if not precision_info or not precision_info["has_subsecond"]:
        return None
    digits = precision_info.get("subsecond_digits", 0)
    if digits < 1:
        return None
    # Bit 0: odd number of subsecond digits → 1, even → 0
    return digits % 2


# ═══════════════════════════════════════════════════════════════════════════
# 1. DNS TXT RECORD DEAD DROP DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_dns_txt_dead_drop(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Check DNS TXT records for encoded dead drop messages.

    Uses Google DNS-over-HTTPS to resolve TXT records, then analyzes
    each value for encoding patterns, cryptographic signatures, and
    high-entropy payloads that could contain covert messages.
    """
    findings: List[Finding] = []
    sig = DEAD_DROP_SIGNATURES["dns_txt_dead_drop"]

    # Resolve TXT via Google DoH
    default_limiter.acquire()
    doh_url = f"https://dns.google/resolve?name={urllib.parse.quote(target)}&type=TXT"
    resp = http_probe(doh_url, timeout=timeout, verify_tls=verify_tls)

    if not resp["ok"]:
        findings.append(_finding(
            title="DNS TXT Resolution Failed",
            severity="low",
            category="dead_drop_dns_txt",
            description=(
                f"Could not resolve DNS TXT records for {target} via "
                f"DNS-over-HTTPS. Dead drop analysis for this channel is "
                f"incomplete."
            ),
            evidence=f"status={resp['status']} reason={resp['reason']}",
            asset=target,
            dread=1.0,
            remediation="Ensure DNS resolution is accessible. Check network policies.",
        ))
        return findings

    try:
        data = json.loads(resp["body"])
    except (ValueError, TypeError):
        return findings

    answers = data.get("Answer", [])
    txt_records: List[str] = []
    for ans in answers:
        if ans.get("type") == 16:  # TXT record type
            raw_data = ans.get("data", "")
            # Google DoH wraps TXT data in quotes
            txt_value = raw_data.strip('"')
            txt_records.append(txt_value)

    if not txt_records:
        findings.append(_finding(
            title="No DNS TXT Records Found",
            severity="info",
            category="dead_drop_dns_txt",
            description=(
                f"No TXT records were found for {target}. This means "
                f"there are no SPF, DKIM, DMARC, or custom TXT records "
                f"that could be used as a dead drop channel."
            ),
            evidence="No TXT answers in DNS response",
            asset=target,
        ))
        return findings

    # Analyze each TXT record
    for txt_value in txt_records:
        entropy = _shannon_entropy(txt_value)
        encodings = _identify_encoding(txt_value)
        crypto_patterns = _identify_crypto_pattern(txt_value)
        decodings = _try_decode_all(txt_value)

        # Check for high-entropy values
        if entropy >= sig["entropy_threshold"] and len(txt_value) >= sig["min_value_length"]:
            decoded_summary = ""
            for enc_name, decoded in decodings.items():
                if decoded is not None:
                    preview = decoded[:64].decode("utf-8", errors="replace")
                    decoded_summary += f"  {enc_name}: {preview!r}... ({len(decoded)} bytes)\n"

            enc_names = [e["encoding"] for e in encodings]
            crypto_names = [c["pattern"] for c in crypto_patterns]

            findings.append(_finding(
                title="High-Entropy DNS TXT Record — Potential Dead Drop",
                severity=sig["severity"],
                category="dead_drop_dns_txt",
                description=(
                    f"DNS TXT record for {target} contains a high-entropy value "
                    f"(H={entropy:.2f}, len={len(txt_value)}). This exceeds the "
                    f"dead drop entropy threshold of {sig['entropy_threshold']}. "
                    f"Identified encodings: {enc_names or 'none detected'}. "
                    f"Matched crypto patterns: {crypto_names or 'none'}. "
                    f"High-entropy TXT records can encode covert messages, "
                    f"encryption keys, or C2 beacons."
                ),
                evidence=(
                    f"TXT value: {txt_value[:200]}{'...' if len(txt_value) > 200 else ''}\n"
                    f"Entropy: {entropy:.4f}\n"
                    f"Encodings: {enc_names}\n"
                    f"Crypto patterns: {crypto_names}\n"
                    f"Decoded previews:\n{decoded_summary}"
                ),
                asset=target,
                dread=sig["dread_score"],
                remediation=(
                    "Audit DNS TXT records regularly. Remove unnecessary TXT records. "
                    "Implement DNS monitoring to detect changes to TXT records."
                ),
                points=15,
            ))
        # Check for pattern-matched values
        else:
            for pat in sig["known_patterns"]:
                if re.search(pat, txt_value, re.IGNORECASE):
                    findings.append(_finding(
                        title="DNS TXT Record Matches Dead Drop Pattern",
                        severity="medium",
                        category="dead_drop_dns_txt",
                        description=(
                            f"TXT record for {target} matches a known dead drop "
                            f"encoding pattern. The value structure is consistent "
                            f"with encoded data used in covert communication channels."
                        ),
                        evidence=(
                            f"Pattern: {pat}\n"
                            f"TXT value: {txt_value[:200]}\n"
                            f"Entropy: {entropy:.4f}"
                        ),
                        asset=target,
                        dread=5.5,
                        remediation="Review and validate the purpose of this TXT record.",
                        points=8,
                    ))
                    break

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 2. HTTP ETAG DEAD DROP DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_etag_dead_drop(
    base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Analyze HTTP ETag headers for cryptographic encoding patterns.

    ETags are opaque strings used for HTTP cache validation. They are
    ideal dead drop carriers because their format is server-defined.
    This function probes multiple paths and analyzes ETag values for
    encoded data, MAC tags, and encrypted values.
    """
    findings: List[Finding] = []
    sig = DEAD_DROP_SIGNATURES["etag_dead_drop"]

    probe_paths = ["/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/.well-known/"]
    etag_values: List[str] = []

    for path in probe_paths:
        url = base_url.rstrip("/") + path
        default_limiter.acquire()
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        etag = resp["headers"].get("ETag", "")
        if etag:
            etag_values.append({"path": path, "etag": etag})

    if not etag_values:
        findings.append(_finding(
            title="No ETag Headers Detected",
            severity="info",
            category="dead_drop_etag",
            description=(
                f"No ETag headers were found on any probed path of {base_url}. "
                f"ETag-based dead drops cannot be used if the server does not "
                f"emit ETags."
            ),
            evidence=f"Probed {len(probe_paths)} paths with no ETag response",
            asset=base_url,
        ))
        return findings

    for item in etag_values:
        etag = item["etag"]
        path = item["path"]
        entropy = _shannon_entropy(etag)
        encodings = _identify_encoding(etag)
        crypto_patterns = _identify_crypto_pattern(etag)
        stripped = etag.strip('"')

        # Check for crypto-sized ETags
        is_suspicious = False
        suspicion_reasons: List[str] = []

        if entropy >= sig["entropy_threshold"]:
            is_suspicious = True
            suspicion_reasons.append(f"High entropy ({entropy:.2f} >= {sig['entropy_threshold']})")

        if crypto_patterns:
            is_suspicious = True
            names = [c["pattern"] for c in crypto_patterns]
            suspicion_reasons.append(f"Matches crypto patterns: {names}")

        if encodings:
            for enc in encodings:
                if enc["encoding"] in ("base64", "base64url", "hex"):
                    is_suspicious = True
                    suspicion_reasons.append(
                        f"Decodable as {enc['encoding']} (entropy={enc['entropy']})"
                    )
                    # Try to decode and check if the decoded content is meaningful
                    decodings = _try_decode_all(stripped)
                    for dec_name, decoded in decodings.items():
                        if decoded is not None and len(decoded) >= 8:
                            # Check if decoded data has structure
                            uint_val = _unpack_uint32(decoded)
                            if uint_val is not None and uint_val > 0:
                                suspicion_reasons.append(
                                    f"Decoded {dec_name} contains structured uint32: {uint_val}"
                                )

        # Check for pattern matches
        for pat in sig["known_patterns"]:
            if re.match(pat, etag):
                is_suspicious = True
                suspicion_reasons.append(f"Matches ETag pattern: {pat}")
                break

        if is_suspicious:
            # Verify if the ETag looks like a legitimate content hash
            default_limiter.acquire()
            resp2 = http_probe(
                base_url.rstrip("/") + path, timeout=timeout, verify_tls=verify_tls
            )
            body_hash_sha256 = _hash_sha256(resp2["body"].encode())[:32]
            body_hash_md5 = _hash_md5(resp2["body"].encode())

            is_legit_hash = (
                stripped == body_hash_sha256
                or stripped == body_hash_md5
                or stripped == _hash_sha1(resp2["body"].encode())
            )

            if is_legit_hash:
                severity = "low"
                title = "ETag Matches Content Hash — Likely Legitimate"
                desc = (
                    f"ETag on {path} at {base_url} has high entropy and matches "
                    f"crypto patterns, but it matches the SHA-256/MD5 hash of the "
                    f"response body ({len(resp2['body'])} bytes). This is likely a "
                    f"standard content-based ETag, not a dead drop."
                )
            else:
                severity = sig["severity"]
                title = "Suspicious ETag — Potential Dead Drop"
                desc = (
                    f"ETag on {path} at {base_url} does NOT match the content hash "
                    f"of the response body, suggesting it may carry covert data. "
                    f"ETags are opaque strings that can encode HMAC tags, encrypted "
                    f"fragments, or steganographic data."
                )

            findings.append(_finding(
                title=title,
                severity=severity,
                category="dead_drop_etag",
                description=desc,
                evidence=(
                    f"Path: {path}\n"
                    f"ETag: {etag}\n"
                    f"Entropy: {entropy:.4f}\n"
                    f"Encodings: {[e['encoding'] for e in encodings]}\n"
                    f"Crypto patterns: {[c['pattern'] for c in crypto_patterns]}\n"
                    f"Reasons: {'; '.join(suspicion_reasons)}\n"
                    f"Legit content hash: {is_legit_hash}"
                ),
                asset=base_url,
                dread=sig["dread_score"] if not is_legit_hash else 1.0,
                remediation=(
                    "Verify ETag generation mechanism. Ensure ETags are derived "
                    "from content hashes. Audit server configuration for custom "
                    "ETag logic."
                ),
                points=10 if not is_legit_hash else 0,
            ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 3. CERTIFICATE TRANSPARENCY DEAD DROP DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_ct_dead_drop(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Analyze CT log entries for subdomains that encode dead drop messages.

    Queries crt.sh for all known subdomain certificates, then analyzes
    each subdomain label for encoding patterns that could carry covert
    data. CT logs are append-only and globally replicated, making them
    an attractive dead drop channel.
    """
    findings: List[Finding] = []
    sig = DEAD_DROP_SIGNATURES["ct_log_dead_drop"]

    # Query crt.sh for CT log entries
    default_limiter.acquire()
    ct_url = f"https://crt.sh/?q={urllib.parse.quote(target)}&output=json"
    resp = http_probe(ct_url, timeout=timeout, verify_tls=verify_tls)

    if not resp["ok"]:
        findings.append(_finding(
            title="CT Log Query Failed",
            severity="low",
            category="dead_drop_ct",
            description=(
                f"Could not query Certificate Transparency logs for {target}. "
                f"CT-based dead drop analysis is incomplete."
            ),
            evidence=f"crt.sh status={resp['status']} reason={resp['reason']}",
            asset=target,
            dread=1.0,
        ))
        return findings

    try:
        ct_entries = json.loads(resp["body"])
    except (ValueError, TypeError):
        findings.append(_finding(
            title="CT Log Response Parse Error",
            severity="low",
            category="dead_drop_ct",
            description="CT log response from crt.sh could not be parsed as JSON.",
            evidence=f"Body length: {len(resp['body'])} chars",
            asset=target,
        ))
        return findings

    if not isinstance(ct_entries, list) or len(ct_entries) == 0:
        findings.append(_finding(
            title="No CT Log Entries Found",
            severity="info",
            category="dead_drop_ct",
            description=(
                f"No Certificate Transparency log entries found for {target}. "
                f"This domain may not have publicly issued certificates."
            ),
            evidence="Empty or null CT log response",
            asset=target,
        ))
        return findings

    # Extract all unique name values (subdomains)
    subdomains: set = set()
    for entry in ct_entries:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and name != target:
                subdomains.add(name)

    suspicious_subdomains: List[Dict[str, Any]] = []

    for subdomain in subdomains:
        # Extract the leftmost label(s)
        parts = subdomain.rstrip(".").split(".")
        if len(parts) < 2:
            continue

        # Check each label
        for label in parts[:-1]:  # skip TLD and base domain
            if len(label) < sig["min_subdomain_length"]:
                continue

            entropy = _shannon_entropy(label)
            if entropy < sig["entropy_threshold"]:
                continue

            encodings = _identify_encoding(label)
            crypto_patterns = _identify_crypto_pattern(label)

            is_suspicious = False
            reasons: List[str] = []

            for pat in sig["known_patterns"]:
                if re.search(pat, label + "."):
                    is_suspicious = True
                    reasons.append(f"Matches pattern: {pat}")
                    break

            if encodings:
                is_suspicious = True
                reasons.append(f"Decodable encodings: {[e['encoding'] for e in encodings]}")

            if crypto_patterns:
                is_suspicious = True
                reasons.append(f"Crypto patterns: {[c['pattern'] for c in crypto_patterns]}")

            if is_suspicious:
                suspicious_subdomains.append({
                    "subdomain": subdomain,
                    "label": label,
                    "entropy": entropy,
                    "reasons": reasons,
                    "encodings": encodings,
                    "crypto_patterns": crypto_patterns,
                })

    if suspicious_subdomains:
        # Deduplicate by label
        seen_labels: set = set()
        unique_suspects: List[Dict[str, Any]] = []
        for s in suspicious_subdomains:
            if s["label"] not in seen_labels:
                seen_labels.add(s["label"])
                unique_suspects.append(s)

        evidence_lines: List[str] = []
        for s in unique_suspects[:20]:
            evidence_lines.append(
                f"  Subdomain: {s['subdomain']}\n"
                f"  Label: {s['label']} (H={s['entropy']:.2f})\n"
                f"  Reasons: {'; '.join(s['reasons'])}"
            )

        findings.append(_finding(
            title=f"CT Log Subdomains with Encoded Patterns ({len(unique_suspects)} found)",
            severity=sig["severity"],
            category="dead_drop_ct",
            description=(
                f"Found {len(unique_suspects)} subdomain(s) in Certificate Transparency logs "
                f"for {target} that exhibit encoding patterns consistent with dead drop "
                f"activity. Subdomain labels can encode covert messages (hex, base64, "
                f"base32) in CT logs, which are globally replicated and publicly accessible."
            ),
            evidence="\n".join(evidence_lines),
            asset=target,
            dread=sig["dread_score"],
            remediation=(
                "Monitor CT logs for new subdomain certificates. Implement certificate "
                "alerting for unusual subdomain patterns. Review certificate issuance "
                "policies and consider CT log monitoring services."
            ),
            points=15,
        ))
    else:
        findings.append(_finding(
            title="CT Log Subdomains — No Dead Drop Patterns",
            severity="info",
            category="dead_drop_ct",
            description=(
                f"Analyzed {len(subdomains)} subdomain entries from Certificate "
                f"Transparency logs for {target}. No subdomain labels exhibited "
                f"encoding patterns consistent with dead drop activity."
            ),
            evidence=f"Subdomains analyzed: {len(subdomains)}",
            asset=target,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 4. HTTP HEADER DEAD DROP DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_header_dead_drop(
    base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Detect encoded messages in unusual HTTP header combinations.

    Analyzes all response headers for: (a) custom/suspicious header names,
    (b) header values with high entropy or encoding patterns, and (c)
    combinations of headers that together could encode data.
    """
    findings: List[Finding] = []
    sig = DEAD_DROP_SIGNATURES["http_header_dead_drop"]

    default_limiter.acquire()
    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    headers = resp["headers"]

    if not headers:
        findings.append(_finding(
            title="No HTTP Headers Retrieved",
            severity="info",
            category="dead_drop_header",
            description=f"No HTTP headers were retrieved from {base_url}.",
            evidence="Empty headers dict",
            asset=base_url,
        ))
        return findings

    suspicious_headers: List[Dict[str, Any]] = []
    suspicious_values: List[Dict[str, Any]] = []

    # Check for suspicious header names
    for header_name, header_value in headers.items():
        # Normalize header name
        norm_name = header_name.lower()

        # Check if header name is suspicious
        for sus_prefix in sig["suspicious_headers"]:
            if norm_name == sus_prefix.lower() or norm_name.startswith(sus_prefix.lower()):
                entropy = _shannon_entropy(header_value)
                encodings = _identify_encoding(header_value)
                crypto_patterns = _identify_crypto_pattern(header_value)

                suspicious_headers.append({
                    "name": header_name,
                    "value": header_value[:200],
                    "entropy": entropy,
                    "encodings": encodings,
                    "crypto_patterns": crypto_patterns,
                })
                break

        # Check for high-entropy values in ANY header
        if len(header_value) >= 24:
            entropy = _shannon_entropy(header_value)
            if entropy >= sig["entropy_threshold"]:
                encodings = _identify_encoding(header_value)
                if encodings or (crypto_patterns := _identify_crypto_pattern(header_value)):
                    suspicious_values.append({
                        "name": header_name,
                        "value": header_value[:200],
                        "entropy": entropy,
                        "encodings": [e["encoding"] for e in encodings],
                        "crypto_patterns": [c["pattern"] for c in crypto_patterns],
                    })

    # Analyze header value combinations for multi-channel encoding
    # Collect all header values that look like encoded fragments
    encoded_fragments: List[Dict[str, str]] = []
    for header_name, header_value in headers.items():
        stripped = header_value.strip().strip('"')
        if _looks_like_base64(stripped, 16) or _looks_like_hex(stripped, 16):
            encoded_fragments.append({"header": header_name, "value": stripped})

    if suspicious_headers:
        evidence_lines: List[str] = []
        for sh in suspicious_headers[:10]:
            evidence_lines.append(
                f"  Header: {sh['name']}\n"
                f"  Value: {sh['value']}\n"
                f"  Entropy: {sh['entropy']:.4f}\n"
                f"  Encodings: {[e['encoding'] for e in sh['encodings']]}\n"
                f"  Crypto: {[c['pattern'] for c in sh['crypto_patterns']]}")

        findings.append(_finding(
            title=f"Suspicious HTTP Headers Detected ({len(suspicious_headers)} headers)",
            severity=sig["severity"],
            category="dead_drop_header",
            description=(
                f"Found {len(suspicious_headers)} HTTP header(s) with names matching "
                f"known dead drop header patterns. These headers can carry encoded "
                f"messages, encryption keys, or C2 instructions.",
                )
                .rstrip(", "),
            evidence="\n".join(evidence_lines),
            asset=base_url,
            dread=sig["dread_score"],
            remediation=(
                "Audit all custom HTTP headers. Remove unnecessary headers. "
                "Implement header allow-listing in WAF rules."
            ),
            points=10,
        ))

    if suspicious_values:
        # Filter out those already reported as suspicious headers
        reported_names = {sh["name"] for sh in suspicious_headers}
        new_sus = [sv for sv in suspicious_values if sv["name"] not in reported_names]

        if new_sus:
            evidence_lines = []
            for sv in new_sus[:10]:
                evidence_lines.append(
                    f"  Header: {sv['name']}\n"
                    f"  Value: {sv['value']}\n"
                    f"  Entropy: {sv['entropy']:.4f}\n"
                    f"  Encodings: {sv['encodings']}\n"
                    f"  Crypto: {sv['crypto_patterns']}"
                )

            findings.append(_finding(
                title=f"High-Entropy Header Values ({len(new_sus)} values)",
                severity="medium",
                category="dead_drop_header",
                description=(
                    f"Found {len(new_sus)} HTTP header value(s) with high entropy "
                    f"and encoding patterns. While these may be legitimate (e.g., "
                    f"cookies, tokens, hashes), they could also encode dead drop messages."
                ),
                evidence="\n".join(evidence_lines),
                asset=base_url,
                dread=5.0,
                remediation=(
                    "Review each high-entropy header value. Validate that the value "
                    "serves a legitimate purpose. Monitor for unexpected changes."
                ),
                points=5,
            ))

    # Check for multi-fragment encoding across headers
    if len(encoded_fragments) >= 3:
        # Try concatenating encoded fragments
        concatenated = "".join(f["value"] for f in encoded_fragments)
        decodings = _try_decode_all(concatenated)
        decoded_any = any(v is not None for v in decodings.values())

        if decoded_any:
            frag_names = [f["header"] for f in encoded_fragments]
            findings.append(_finding(
                title="Potential Multi-Header Dead Drop Encoding",
                severity="high",
                category="dead_drop_header",
                description=(
                    f"Found {len(encoded_fragments)} headers with encoded values that, "
                    f"when concatenated, successfully decode. This is a strong indicator "
                    f"of multi-header dead drop encoding where data is split across "
                    f"multiple headers to evade single-header analysis."
                ),
                evidence=(
                    f"Headers with encoded values: {frag_names}\n"
                    f"Concatenated length: {len(concatenated)} chars\n"
                    f"Successful decodings: {[k for k,v in decodings.items() if v is not None]}"
                ),
                asset=base_url,
                dread=7.5,
                remediation=(
                    "Investigate the relationship between these headers. Check if "
                    "they are set by the same application component. Implement "
                    "cross-header correlation monitoring."
                ),
                points=18,
            ))

    if not suspicious_headers and not suspicious_values and len(encoded_fragments) < 3:
        findings.append(_finding(
            title="HTTP Headers — No Dead Drop Patterns",
            severity="info",
            category="dead_drop_header",
            description=(
                f"Analyzed {len(headers)} HTTP headers from {base_url}. No "
                f"suspicious header names or high-entropy encoded values detected."
            ),
            evidence=f"Headers inspected: {list(headers.keys())}",
            asset=base_url,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 5. TIMESTAMP STEGANOGRAPHY DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_timestamp_stego(
    base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Detect data encoded in timestamp precision of Date headers.

    Makes multiple requests and analyzes the Date header for:
    - Sub-second precision (unusual for HTTP Date headers)
    - Non-standard date format deviations
    - Monotonic but anomalous time patterns
    - Bit extraction from sub-second digits
    """
    findings: List[Finding] = []
    sig = DEAD_DROP_SIGNATURES["timestamp_stego"]

    timestamps: List[Dict[str, Any]] = []
    num_probes = 5

    for i in range(num_probes):
        default_limiter.acquire()
        resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
        date_val = resp["headers"].get("Date", "")

        precision = _extract_date_precision(date_val)
        steg_bit = _steg_bits_from_timestamp(precision) if precision else None

        timestamps.append({
            "probe_index": i,
            "date_raw": date_val,
            "precision": precision,
            "steg_bit": steg_bit,
            "request_time": time.time(),
        })

        time.sleep(0.3)  # Small delay between probes

    # Analyze timestamps
    has_subsecond = any(
        t["precision"] and t["precision"]["has_subsecond"] for t in timestamps
    )

    steg_bits = [t["steg_bit"] for t in timestamps if t["steg_bit"] is not None]
    extracted_byte = None
    if len(steg_bits) >= 8:
        # Combine first 8 bits into a byte
        bits_str = "".join(str(b) for b in steg_bits[:8])
        extracted_byte = int(bits_str, 2)

    if has_subsecond:
        subsecond_entries = [
            t for t in timestamps
            if t["precision"] and t["precision"]["has_subsecond"]
        ]

        precision_details = "\n".join(
            f"  Probe {t['probe_index']}: {t['date_raw']} "
            f"(subsec_digits={t['precision']['subsecond_digits']}, "
            f"bit={t['steg_bit']})"
            for t in subsecond_entries
        )

        findings.append(_finding(
            title="HTTP Date Header Has Sub-Second Precision",
            severity=sig["severity"],
            category="dead_drop_timestamp",
            description=(
                f"The HTTP Date header from {base_url} includes sub-second "
                f"precision in {len(subsecond_entries)} out of {num_probes} probes. "
                f"RFC 7231 specifies second-level granularity for HTTP dates. "
                f"Sub-second precision can encode ~1 bit per response via the "
                f"number of sub-second digits (odd=1, even=0). This creates a covert "
                f"timing channel."
                + (f" Extracted byte from first 8 bits: 0x{extracted_byte:02x} ({extracted_byte})" if extracted_byte is not None else "")
            ),
            evidence=(
                f"Sub-second probes: {len(subsecond_entries)}/{num_probes}\n"
                f"Details:\n{precision_details}"
                + (f"\nExtracted byte: 0x{extracted_byte:02x}" if extracted_byte is not None else "")
            ),
            asset=base_url,
            dread=sig["dread_score"],
            remediation=(
                "Configure server to emit Date headers with second-level precision "
                "only. Use NTP synchronization. Monitor for timestamp anomalies."
            ),
            points=6,
        ))
    else:
        # Check for other anomalies
        date_formats: set = set()
        for t in timestamps:
            if t["precision"]:
                date_formats.add(t["precision"]["format"])

        if len(date_formats) > 1:
            findings.append(_finding(
                title="Inconsistent HTTP Date Formats",
                severity="low",
                category="dead_drop_timestamp",
                description=(
                    f"HTTP Date headers from {base_url} use {len(date_formats)} "
                    f"different format(s): {date_formats}. Inconsistent formatting "
                    f"can be used to signal binary data (format A = 0, format B = 1)."
                ),
                evidence=f"Formats observed: {date_formats}",
                asset=base_url,
                dread=2.5,
                remediation="Ensure consistent Date header formatting across all responses.",
                points=3,
            ))
        else:
            findings.append(_finding(
                title="Timestamp Steganography — No Anomalies",
                severity="info",
                category="dead_drop_timestamp",
                description=(
                    f"Analyzed {num_probes} HTTP Date headers from {base_url}. "
                    f"No sub-second precision or format inconsistencies detected. "
                    f"Timestamp-based dead drops are not evident."
                ),
                evidence=f"Probes: {num_probes}, formats: {date_formats or {'standard'}}",
                asset=base_url,
            ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 6. DNS CNAME DEAD DROP DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def _detect_cname_dead_drop(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Check CNAME records for encoded subdomain patterns.

    Resolves CNAME records via DNS-over-HTTPS and analyzes each label
    in the CNAME target for encoding patterns. Long, high-entropy labels
    are hallmarks of dead drop encoding in DNS CNAME chains.
    """
    findings: List[Finding] = []
    sig = DEAD_DROP_SIGNATURES["dns_cname_dead_drop"]

    # Common subdomains to check for CNAME records
    subdomains_to_check = [
        target,
        f"www.{target}",
        f"mail.{target}",
        f"api.{target}",
        f"cdn.{target}",
        f"static.{target}",
        f"assets.{target}",
    ]

    all_cname_targets: List[Dict[str, str]] = []

    for subdomain in subdomains_to_check:
        default_limiter.acquire()
        doh_url = f"https://dns.google/resolve?name={urllib.parse.quote(subdomain)}&type=CNAME"
        resp = http_probe(doh_url, timeout=timeout, verify_tls=verify_tls)

        if not resp["ok"]:
            continue

        try:
            data = json.loads(resp["body"])
        except (ValueError, TypeError):
            continue

        for ans in data.get("Answer", []):
            if ans.get("type") == 5:  # CNAME record type
                cname_target = ans.get("data", "").strip().rstrip(".")
                all_cname_targets.append({
                    "source": subdomain,
                    "target": cname_target,
                })

    if not all_cname_targets:
        findings.append(_finding(
            title="No CNAME Records Found",
            severity="info",
            category="dead_drop_cname",
            description=(
                f"No CNAME records were found for {target} or its common "
                f"subdomains. CNAME-based dead drop analysis is not applicable."
            ),
            evidence=f"Checked {len(subdomains_to_check)} subdomains",
            asset=target,
        ))
        return findings

    suspicious_cnames: List[Dict[str, Any]] = []

    for cname_info in all_cname_targets:
        cname_target = cname_info["target"]
        entropy = _shannon_entropy(cname_target)

        if len(cname_target) < sig["min_cname_length"]:
            continue

        if entropy < sig["entropy_threshold"]:
            continue

        labels = cname_target.split(".")
        suspicious_labels: List[Dict[str, Any]] = []

        for label in labels:
            if len(label) < 16:
                continue

            label_entropy = _shannon_entropy(label)
            encodings = _identify_encoding(label)
            crypto_patterns = _identify_crypto_pattern(label)

            for pat in sig["known_patterns"]:
                if re.search(pat, label + "."):
                    suspicious_labels.append({
                        "label": label,
                        "entropy": label_entropy,
                        "encodings": encodings,
                        "crypto_patterns": crypto_patterns,
                        "pattern": pat,
                    })
                    break

        if suspicious_labels:
            suspicious_cnames.append({
                "source": cname_info["source"],
                "target": cname_target,
                "entropy": entropy,
                "suspicious_labels": suspicious_labels,
            })

    if suspicious_cnames:
        evidence_lines: List[str] = []
        for sc in suspicious_cnames:
            for sl in sc["suspicious_labels"]:
                evidence_lines.append(
                    f"  CNAME: {sc['source']} -> {sc['target']}\n"
                    f"  Label: {sl['label']} (H={sl['entropy']:.2f})\n"
                    f"  Encodings: {[e['encoding'] for e in sl['encodings']]}\n"
                    f"  Crypto: {[c['pattern'] for c in sl['crypto_patterns']]}")

        findings.append(_finding(
            title=f"CNAME Records with Encoded Patterns ({len(suspicious_cnames)} found)",
            severity=sig["severity"],
            category="dead_drop_cname",
            description=(
                f"Found {len(suspicious_cnames)} CNAME record(s) for {target} "
                f"with labels exhibiting encoding patterns consistent with dead "
                f"drop activity. CNAME targets can encode covert messages in their "
                f"domain labels using hex, base32, or base64url encoding."
            ),
            evidence="\n".join(evidence_lines),
            asset=target,
            dread=sig["dread_score"],
            remediation=(
                "Audit CNAME records for all subdomains. Remove unnecessary CNAME "
                "chains. Monitor DNS configurations for unauthorized changes."
            ),
            points=12,
        ))
    else:
        findings.append(_finding(
            title="CNAME Records — No Dead Drop Patterns",
            severity="info",
            category="dead_drop_cname",
            description=(
                f"Analyzed {len(all_cname_targets)} CNAME record(s) for {target}. "
                f"No labels exhibited encoding patterns consistent with dead drops."
            ),
            evidence=f"CNAMEs analyzed: {len(all_cname_targets)}",
            asset=target,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 7. SPF/DKIM/DMARC DEAD DROP ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════

def _detect_email_auth_dead_drop(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Check SPF, DKIM, and DMARC records for hidden dead drop messages.

    Email authentication records are complex TXT records that naturally
    contain encoded data. Covert messages can be hidden within:
    - SPF ip4/ip6 mechanism parameters
    - DKIM public key data (p= tag)
    - DMARC policy parameters (rua, ruf tags)
    """
    findings: List[Finding] = []
    sig = DEAD_DROP_SIGNATURES["spf_dkim_dmarc_dead_drop"]

    email_record_queries: List[Dict[str, str]] = [
        {"type": "SPF", "name": target, "dns_name": target, "dns_type": "TXT",
         "filter": "v=spf1"},
        {"type": "DMARC", "name": f"_dmarc.{target}", "dns_name": f"_dmarc.{target}",
         "dns_type": "TXT", "filter": "v=DMARC1"},
        {"type": "DKIM-selector1", "name": f"default._domainkey.{target}",
         "dns_name": f"default._domainkey.{target}", "dns_type": "TXT",
         "filter": "v=DKIM1"},
        {"type": "DKIM-selector2", "name": f"selector1._domainkey.{target}",
         "dns_name": f"selector1._domainkey.{target}", "dns_type": "TXT",
         "filter": "v=DKIM1"},
    ]

    records_found: List[Dict[str, Any]] = []

    for query in email_record_queries:
        default_limiter.acquire()
        doh_url = (
            f"https://dns.google/resolve?name={urllib.parse.quote(query['dns_name'])}"
            f"&type={query['dns_type']}"
        )
        resp = http_probe(doh_url, timeout=timeout, verify_tls=verify_tls)

        if not resp["ok"]:
            continue

        try:
            data = json.loads(resp["body"])
        except (ValueError, TypeError):
            continue

        for ans in data.get("Answer", []):
            if ans.get("type") == 16:  # TXT
                raw_value = ans.get("data", "").strip('"')
                if query["filter"].lower() in raw_value.lower():
                    records_found.append({
                        "type": query["type"],
                        "name": query["name"],
                        "value": raw_value,
                    })

    if not records_found:
        findings.append(_finding(
            title="No Email Authentication Records Found",
            severity="info",
            category="dead_drop_email_auth",
            description=(
                f"No SPF, DKIM, or DMARC records were found for {target}. "
                f"Email authentication dead drop analysis is not applicable."
            ),
            evidence=f"Queried {len(email_record_queries)} record types",
            asset=target,
        ))
        return findings

    for record in records_found:
        rec_type = record["type"]
        rec_value = record["value"]
        entropy = _shannon_entropy(rec_value)
        encodings = _identify_encoding(rec_value)
        crypto_patterns = _identify_crypto_pattern(rec_value)

        is_suspicious = False
        reasons: List[str] = []

        # For DKIM: check for unusually long public keys
        if rec_type.startswith("DKIM"):
            p_match = re.search(r"p=([A-Za-z0-9+/=]+)", rec_value)
            if p_match:
                key_data = p_match.group(1)
                key_len = len(key_data)
                # A 2048-bit RSA key in base64 is ~372 chars, 4096-bit is ~740 chars
                if key_len > 740:
                    is_suspicious = True
                    reasons.append(
                        f"DKIM public key is {key_len} chars (base64), suggesting "
                        f"a key larger than 4096 bits or embedded extra data"
                    )

                # Check if the key data has suspicious entropy distribution
                key_entropy = _shannon_entropy(key_data)
                if key_entropy < 4.5 and key_len > 400:
                    is_suspicious = True
                    reasons.append(
                        f"DKIM key entropy ({key_entropy:.2f}) is unusually low for "
                        f"a {key_len}-char base64 value, suggesting non-random padding"
                    )

                # Try to decode key and look for structure
                decoded_key = _try_base64_decode(key_data)
                if decoded_key is not None:
                    # Check for ASN.1 structure ( legitimate RSA key starts with 0x30)
                    if len(decoded_key) > 0 and decoded_key[0] != 0x30:
                        is_suspicious = True
                        reasons.append(
                            f"Decoded DKIM key does not start with ASN.1 SEQUENCE tag (0x30). "
                            f"First byte: 0x{decoded_key[0]:02x}. This may indicate "
                            f"non-standard or embedded data."
                        )

        # For SPF: check for unusual mechanisms with encoded data
        if rec_type == "SPF":
            # Extract ip4/ip6 values and check for encoded data
            ip_matches = re.findall(r'ip[46]:([^"\s]+)', rec_value)
            for ip_val in ip_matches:
                if _looks_like_hex(ip_val, 20) or _looks_like_base64(ip_val, 20):
                    is_suspicious = True
                    reasons.append(f"SPF contains encoded data in mechanism: ip4/ip6:{ip_val}")

            # Check include: directives for encoded domains
            includes = re.findall(r'include:([^"\s]+)', rec_value)
            for inc in includes:
                inc_labels = inc.split(".")
                for label in inc_labels:
                    if len(label) >= 20 and _is_high_entropy(label, 3.5):
                        is_suspicious = True
                        reasons.append(f"SPF include domain has high-entropy label: {label}")

        # For DMARC: check rua/ruf tags for encoded URLs
        if rec_type == "DMARC":
            rua_matches = re.findall(r'rua=([^"\s;]+)', rec_value)
            ruf_matches = re.findall(r'ruf=([^"\s;]+)', rec_value)
            for tag_val in rua_matches + ruf_matches:
                # Look for base64/hex encoded data in report URIs
                for segment in tag_val.split(","):
                    segment = segment.strip()
                    path_match = re.search(r'https?://[^/]+(/[^"\s]+)', segment)
                    if path_match:
                        path = path_match.group(1)
                        if _is_high_entropy(path, 3.5) and len(path) > 20:
                            is_suspicious = True
                            reasons.append(
                                f"DMARC report URI path has high entropy: {path}"
                            )

        # General check: overall entropy and encoding patterns
        if entropy >= sig["entropy_threshold"]:
            if not is_suspicious:  # Don't double-report
                is_suspicious = True
                reasons.append(f"Overall record entropy ({entropy:.2f}) exceeds threshold")

        if is_suspicious:
            findings.append(_finding(
                title=f"Suspicious {rec_type} Record — Potential Dead Drop",
                severity=sig["severity"],
                category="dead_drop_email_auth",
                description=(
                    f"{rec_type} record for {record['name']} exhibits characteristics "
                    f"consistent with dead drop activity: {'; '.join(reasons)}. "
                    f"Email authentication records are complex and can mask embedded "
                    f"covert messages within their legitimate structure."
                ),
                evidence=(
                    f"Type: {rec_type}\n"
                    f"Name: {record['name']}\n"
                    f"Value: {rec_value[:500]}{'...' if len(rec_value) > 500 else ''}\n"
                    f"Entropy: {entropy:.4f}\n"
                    f"Encodings: {[e['encoding'] for e in encodings]}\n"
                    f"Crypto: {[c['pattern'] for c in crypto_patterns]}\n"
                    f"Reasons: {'; '.join(reasons)}"
                ),
                asset=target,
                dread=sig["dread_score"],
                remediation=(
                    f"Audit the {rec_type} record content. Verify all mechanisms, "
                    f"keys, and URIs serve legitimate email authentication purposes. "
                    f"Compare against known-good configurations."
                ),
                points=10,
            ))

    if not any(f.severity in ("high", "medium") for f in findings):
        findings.append(_finding(
            title="Email Auth Records — No Dead Drop Patterns",
            severity="info",
            category="dead_drop_email_auth",
            description=(
                f"Analyzed {len(records_found)} email authentication record(s) for "
                f"{target}: {', '.join(r['type'] for r in records_found)}. No dead drop "
                f"patterns were detected in SPF, DKIM, or DMARC records."
            ),
            evidence=f"Records analyzed: {len(records_found)}",
            asset=target,
        ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# 8. DEAD DROP SIMULATION
# ═══════════════════════════════════════════════════════════════════════════

def _simulate_dead_drops(target: str) -> List[Finding]:
    """Demonstrate how each dead drop channel could be used with examples.

    Generates concrete examples of encoded payloads for each channel type,
    showing the encoding process and the resulting dead drop artifact.
    Uses only stdlib crypto (hashlib, hmac, base64, struct).
    """
    findings: List[Finding] = []
    secret_message = b"MEET AT THE OLD BRIDGE 2300"
    sim_key = b"dead-drop-simulation-key-2024"

    # ── 8a. DNS TXT Dead Drop Simulation ──
    # Encode the secret message as base64, wrap in a fake SPF-like record
    msg_b64 = base64.b64encode(secret_message).decode()
    fake_txt = f"v=spf1 ip4:192.0.2.1 include:_dmarc.{target} {msg_b64} -all"
    txt_hmac = _compute_hmac_sha256(sim_key, fake_txt.encode())

    findings.append(_finding(
        title="Simulation: DNS TXT Dead Drop",
        severity="info",
        category="dead_drop_simulation",
        description=(
            "Demonstrates how a covert message can be embedded in a DNS TXT "
            "record disguised as an SPF record. The base64-encoded message is "
            "appended to legitimate-looking SPF mechanisms. Most DNS monitoring "
            "tools only check SPF syntax validity, not the semantic meaning of "
            "individual tokens."
        ),
        evidence=(
            f"Original message: {secret_message.decode()}\n"
            f"Base64 encoded: {msg_b64}\n"
            f"Fake TXT record:\n  {fake_txt}\n"
            f"HMAC-SHA256 (verification): {txt_hmac}\n"
            f"Channel capacity: ~255 bytes per TXT record\n"
            f"Stealth score: {DEAD_DROP_SIGNATURES['dns_txt_dead_drop']['stealth_score']}/100"
        ),
        asset=target,
    ))

    # ── 8b. ETag Dead Drop Simulation ──
    # Create an HMAC tag that looks like a legitimate ETag
    etag_payload = secret_message + struct.pack(">I", int(time.time()))
    etag_mac = hmac.new(sim_key, etag_payload, hashlib.sha256).digest()
    etag_b64 = base64.b64encode(etag_mac).decode().rstrip("=")
    fake_etag = f'"{etag_b64}"'

    # Also simulate a hex-encoded encrypted ETag
    etag_iv = hashlib.sha256(sim_key + b"iv-salt").hexdigest()[:32]
    etag_cipher_hex = hashlib.sha256(secret_message + etag_iv.encode()).hexdigest()
    fake_etag_hex = f'"{etag_cipher_hex[:40]}"'  # SHA-1 length appearance

    findings.append(_finding(
        title="Simulation: HTTP ETag Dead Drop",
        severity="info",
        category="dead_drop_simulation",
        description=(
            "Demonstrates how an ETag header can carry a covert HMAC tag. "
            "The ETag contains an HMAC-SHA256 computed over the secret message "
            "and a timestamp. Because ETags are opaque strings, this appears "
            "as a normal cache validator to intermediaries."
        ),
        evidence=(
            f"Payload: message + uint32 timestamp ({len(etag_payload)} bytes)\n"
            f"HMAC-SHA256 (raw): {etag_mac.hex()}\n"
            f"Fake ETag (base64url): {fake_etag}\n"
            f"Fake ETag (hex/SHA-1-like): {fake_etag_hex}\n"
            f"Channel capacity: ~128-512 bytes\n"
            f"Stealth score: {DEAD_DROP_SIGNATURES['etag_dead_drop']['stealth_score']}/100"
        ),
        asset=target,
    ))

    # ── 8c. CT Subdomain Dead Drop Simulation ──
    # Encode message as hex subdomain labels
    msg_hex = secret_message.hex()
    # Split into 63-char max labels (RFC 1035)
    label_size = 32  # Use 32-char hex labels (16 bytes each)
    hex_labels = [msg_hex[i:i+label_size] for i in range(0, len(msg_hex), label_size)]
    fake_subdomain = ".".join(hex_labels) + f".{target}"

    # Also demonstrate base32 encoding for subdomains
    msg_b32 = base64.b32encode(secret_message).decode().rstrip("=")
    b32_labels = [msg_b32[i:i+32] for i in range(0, len(msg_b32), 32)]
    fake_b32_subdomain = ".".join(b32_labels) + f".cdn.{target}"

    findings.append(_finding(
        title="Simulation: Certificate Transparency Dead Drop",
        severity="info",
        category="dead_drop_simulation",
        description=(
            "Demonstrates how a message can be encoded in CT log subdomain "
            "labels. By issuing a certificate for a subdomain whose labels "
            "are hex/base32-encoded message fragments, data is permanently "
            "recorded in globally replicated CT logs. Retrieval requires no "
            "direct connection to the target."
        ),
        evidence=(
            f"Original message: {secret_message.decode()}\n"
            f"Hex encoded ({len(msg_hex)} chars): {msg_hex}\n"
            f"Fake subdomain (hex): {fake_subdomain}\n"
            f"Base32 encoded ({len(msg_b32)} chars): {msg_b32}\n"
            f"Fake subdomain (base32): {fake_b32_subdomain}\n"
            f"Channel capacity: ~63 bytes per label (RFC 1035)\n"
            f"Stealth score: {DEAD_DROP_SIGNATURES['ct_log_dead_drop']['stealth_score']}/100"
        ),
        asset=target,
    ))

    # ── 8d. HTTP Header Combination Dead Drop Simulation ──
    # Split the base64 message across multiple custom headers
    chunk_size = 12
    chunks = [msg_b64[i:i+chunk_size] for i in range(0, len(msg_b64), chunk_size)]
    header_names = ["X-Request-Id", "X-Correlation-ID", "X-Trace-Id",
                    "X-Session-Data", "X-Request-Seq"]
    fake_headers: Dict[str, str] = {}
    for i, chunk in enumerate(chunks):
        name = header_names[i % len(header_names)]
        fake_headers[name] = chunk

    # Also simulate: encode message bits in header presence/absence
    msg_bits = "".join(format(b, "08b") for b in secret_message)
    header_presence_headers: Dict[str, str] = {}
    bit_headers = [f"X-Feature-{i:03d}" for i in range(min(len(msg_bits), 32))]
    for i, bit in enumerate(msg_bits[:32]):
        if bit == "1":
            header_presence_headers[bit_headers[i]] = "enabled"

    findings.append(_finding(
        title="Simulation: HTTP Header Combination Dead Drop",
        severity="info",
        category="dead_drop_simulation",
        description=(
            "Demonstrates two header-based dead drop techniques: (1) splitting "
            "a base64-encoded message across multiple custom headers that appear "
            "as legitimate tracing/correlation IDs, and (2) encoding bits in the "
            "presence or absence of feature-flag headers."
        ),
        evidence=(
            f"Technique 1 — Fragmented encoding:\n"
            + "\n".join(f"  {k}: {v}" for k, v in fake_headers.items())
            + f"\n\nTechnique 2 — Header presence encoding (first 32 bits):\n"
            + f"  Message bits: {msg_bits[:32]}...\n"
            + "\n".join(
                f"  {k}: {v}" for k, v in list(header_presence_headers.items())[:8]
            )
            + f"\n  ... ({len(header_presence_headers)} headers with value 'enabled')\n"
            f"Channel capacity: ~4-8 KB across headers\n"
            f"Stealth score: {DEAD_DROP_SIGNATURES['http_header_dead_drop']['stealth_score']}/100"
        ),
        asset=target,
    ))

    # ── 8e. Timestamp Steganography Simulation ──
    # Encode message bits in sub-second digit counts
    msg_bits = "".join(format(b, "08b") for b in secret_message)
    timestamp_examples: List[str] = []
    for i, bit in enumerate(msg_bits[:16]):
        # Odd number of subsec digits = 1, even = 0
        digits = 3 if bit == "1" else 2
        ts = f"2024-06-15T14:{30 + i // 60:02d}:{i % 60:02d}.{'1' * digits}Z"
        timestamp_examples.append(f"  bit={bit} -> {ts}")

    findings.append(_finding(
        title="Simulation: Timestamp Steganography Dead Drop",
        severity="info",
        category="dead_drop_simulation",
        description=(
            "Demonstrates encoding message bits in the number of sub-second "
            "digits in HTTP Date headers. An odd count encodes a 1-bit, even "
            "encodes a 0-bit. At 1 bit per response, a 30-byte message requires "
            "240 requests — low bandwidth but extremely hard to detect."
        ),
        evidence=(
            f"Encoding scheme: odd subsec digits = 1, even = 0\n"
            f"Message: {secret_message.decode()}\n"
            f"First 16 bit encodings:\n"
            + "\n".join(timestamp_examples)
            + f"\nChannel capacity: ~1 bit per response\n"
            f"Stealth score: {DEAD_DROP_SIGNATURES['timestamp_stego']['stealth_score']}/100"
        ),
        asset=target,
    ))

    # ── 8f. CNAME Dead Drop Simulation ──
    # Encode message in CNAME target labels
    msg_hex = secret_message.hex()
    label_size = 32
    hex_labels = [msg_hex[i:i+label_size] for i in range(0, len(msg_hex), label_size)]
    fake_cname_target = ".".join(hex_labels) + f".edgecdn.akamai.net"

    # Compute verification HMAC
    cname_hmac = _compute_hmac_sha256(sim_key, fake_cname_target.encode())

    # Demonstrate struct-based encoding: embed a uint64 epoch timestamp
    epoch_now = int(time.time())
    ts_bytes = _pack_uint64(epoch_now)
    ts_hex = ts_bytes.hex()
    fake_cname_ts = f"{ts_hex}.data.{target}.cloudfront.net"

    findings.append(_finding(
        title="Simulation: DNS CNAME Dead Drop",
        severity="info",
        category="dead_drop_simulation",
        description=(
            "Demonstrates encoding a message in CNAME target domain labels. "
            "The hex-encoded message is split into RFC 1035-compliant labels "
            "and appended to a legitimate-looking CDN domain. Also shows "
            "struct-based encoding of a uint64 timestamp in the first label."
        ),
        evidence=(
            f"Original message: {secret_message.decode()}\n"
            f"Hex labels: {hex_labels}\n"
            f"Fake CNAME target: {fake_cname_target}\n"
            f"Verification HMAC-SHA256: {cname_hmac}\n"
            f"\nStruct encoding example:\n"
            f"  Epoch: {epoch_now}\n"
            f"  Packed uint64: {ts_bytes.hex()}\n"
            f"  Fake CNAME (timestamp): {fake_cname_ts}\n"
            f"Channel capacity: ~63 bytes per label\n"
            f"Stealth score: {DEAD_DROP_SIGNATURES['dns_cname_dead_drop']['stealth_score']}/100"
        ),
        asset=target,
    ))

    # ── 8g. SPF/DKIM/DMARC Payload Concealment Simulation ──
    # Hide a message in a DKIM public key's padding
    real_key_b64 = base64.b64encode(
        b"\x30\x82\x01\x0a" + b"\x00" * 250  # Fake minimal ASN.1
    ).decode().rstrip("=")
    # Append covert data after the key, before any semicolon
    covert_b64 = base64.b64encode(secret_message).decode().rstrip("=")
    fake_dkim = (
        f"v=DKIM1; k=rsa; p={real_key_b64}{covert_b64}; "
        f"n=standard-2048-key"
    )

    # Also hide data in DMARC rua URI path
    covert_path = base64.urlsafe_b64encode(secret_message).decode().rstrip("=")
    fake_dmarc = (
        f"v=DMARC1; p=reject; rua=mailto:dmarc@{target}"
        f",https://reports.{target}/dmarc/{covert_path}; "
        f"ruf=mailto:forensic@{target}; pct=100; adkim=s; aspf=s"
    )

    dkim_hmac = _compute_hmac_sha256(sim_key, fake_dkim.encode())

    findings.append(_finding(
        title="Simulation: SPF/DKIM/DMARC Payload Concealment",
        severity="info",
        category="dead_drop_simulation",
        description=(
            "Demonstrates hiding covert data in email authentication records: "
            "(1) Appending base64-encoded data to a DKIM public key — the extra "
            "data appears as part of the key to casual inspection. (2) Embedding "
            "base64url data in a DMARC report URI path, where it looks like a "
            "report identifier."
        ),
        evidence=(
            f"DKIM concealment:\n  {fake_dkim[:300]}...\n"
            f"  Appended covert data: {covert_b64}\n"
            f"\nDMARC concealment:\n  {fake_dmarc[:300]}...\n"
            f"  Covert URI path: /dmarc/{covert_path}\n"
            f"\nVerification HMAC-SHA256: {dkim_hmac}\n"
            f"Channel capacity: ~2000+ bytes (DKIM), ~512 bytes (SPF/DMARC)\n"
            f"Stealth score: {DEAD_DROP_SIGNATURES['spf_dkim_dmarc_dead_drop']['stealth_score']}/100"
        ),
        asset=target,
    ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def run_dead_drop(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Run all dead drop detection and simulation checks.

    Args:
        target: The target domain (e.g., "example.com").
        base_url: The base URL for HTTP probing (e.g., "https://example.com").
        timeout: HTTP request timeout in seconds.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        A list of Finding objects documenting detected or simulated
        dead drop activity across all eight channels.
    """
    all_findings: List[Finding] = []

    # 1. DNS TXT Record Dead Drop Detection
    all_findings.extend(
        _detect_dns_txt_dead_drop(target, base_url, timeout, verify_tls)
    )

    # 2. HTTP ETag Dead Drop Detection
    all_findings.extend(
        _detect_etag_dead_drop(base_url, timeout, verify_tls)
    )

    # 3. Certificate Transparency Dead Drop Detection
    all_findings.extend(
        _detect_ct_dead_drop(target, base_url, timeout, verify_tls)
    )

    # 4. HTTP Header Dead Drop Detection
    all_findings.extend(
        _detect_header_dead_drop(base_url, timeout, verify_tls)
    )

    # 5. Timestamp Steganography Detection
    all_findings.extend(
        _detect_timestamp_stego(base_url, timeout, verify_tls)
    )

    # 6. DNS CNAME Dead Drop Detection
    all_findings.extend(
        _detect_cname_dead_drop(target, base_url, timeout, verify_tls)
    )

    # 7. SPF/DKIM/DMARC Dead Drop Analysis
    all_findings.extend(
        _detect_email_auth_dead_drop(target, base_url, timeout, verify_tls)
    )

    # 8. Dead Drop Simulation
    all_findings.extend(
        _simulate_dead_drops(target)
    )

    return all_findings

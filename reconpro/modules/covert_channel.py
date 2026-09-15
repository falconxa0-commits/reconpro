"""COVERT_CHANNEL module — Covert data exfiltration channel detection & simulation.

ReconPro v9.2.0

Detects and simulates eight classes of covert data exfiltration channels:
  1. DNS Tunneling Detection
  2. HTTP Header Covert Channel Detection
  3. Timing Channel Detection
  4. ICMP Tunnel Detection Markers
  5. HTTPS Certificate Steganography
  6. URL Path Encoding Channels
  7. Chunked Transfer Encoding Abuse
  8. WebSocket Frame Analysis

Pure stdlib — zero external dependencies.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import http_probe, Finding, default_limiter


# ═══════════════════════════════════════════════════════════════════════════
# CHANNEL_SIGNATURES DATABASE
# ═══════════════════════════════════════════════════════════════════════════

CHANNEL_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "dns_tunneling": {
        "name": "DNS Tunneling",
        "description": (
            "Encodes data in DNS query labels (subdomains). Long, "
            "high-entropy subdomains are hallmarks of tools like dnscat2, "
            "iodine, Cobalt Strike DNS beacon."
        ),
        "max_label_length": 63,       # RFC 1035
        "suspicious_label_min": 24,   # labels this long are rare in legit traffic
        "max_query_length": 253,      # RFC 1035 FQDN limit
        "known_tools": ["dnscat2", "iodine", "DNS2TCP", "Cobalt Strike", "PoshC2"],
        "record_type_indicators": ["TXT", "NULL", "CNAME", "MX", "A"],
        "entropy_threshold": 3.8,
        "bandwidth_estimate": "Low (~1-4 KB/s downstream, ~0.5 KB/s upstream)",
        "stealth_score": 72,
        "dread_score": 7.5,
        "severity": "high",
        "patterns": [
            r"[a-z0-9]{24,}\.",  # long base36 subdomain
            r"[a-f0-9]{32,}\.",  # hex-encoded subdomain (MD5-like)
            r"[A-Za-z0-9+/=]{20,}\.",  # base64 subdomain
            r"[a-z0-9-]{40,}\.",  # very long label with hyphens
        ],
    },
    "http_header_covert": {
        "name": "HTTP Header Covert Channel",
        "description": (
            "Data encoded in HTTP headers via: custom/unusual headers, "
            "header ordering signals, whitespace/padding manipulation, "
            "cookie value encoding, or header value steganography."
        ),
        "suspicious_header_prefixes": [
            "X-", "X-Powered-By", "X-Forwarded", "X-Real-IP",
            "X-Original-URL", "X-Custom", "X-Steg", "X-Data",
            "X-Exfil", "X-C2", "X-Session-Id", "X-Request-Id",
        ],
        "entropy_threshold": 3.6,
        "bandwidth_estimate": "Medium (~50-200 KB/s)",
        "stealth_score": 65,
        "dread_score": 6.8,
        "severity": "medium",
        "patterns": [
            r"^X-[A-Za-z-]+$",
            r"^[A-Za-z-]+: [A-Za-z0-9+/=]{40,}$",
            r"^[A-Za-z-]+: \s*[a-f0-9]{64,}$",  # hex payload in header
        ],
    },
    "timing_channel": {
        "name": "Timing Channel",
        "description": (
            "Encodes data in response timing deltas. Binary (0/1) or "
            "multi-bit encoding where the interval between requests/responses "
            "carries hidden information. Extremely stealthy but low bandwidth."
        ),
        "binary_encoding_delta_ms": 100,
        "multi_bit_levels": 4,        # 0-3 per interval
        "min_observations": 8,
        "std_dev_threshold": 0.05,    # very consistent deltas = suspicious
        "entropy_threshold": 0.9,     # low entropy in timing = encoding
        "bandwidth_estimate": "Very Low (~0.1-2 bits/s)",
        "stealth_score": 88,
        "dread_score": 8.2,
        "severity": "high",
        "patterns": [],
    },
    "icmp_tunnel": {
        "name": "ICMP Tunnel Detection Markers",
        "description": (
            "Data encoded in ICMP echo request/reply payloads. Observed via "
            "HTTP timing side-effects or infrastructure patterns: unusual "
            "packet sizes, high-frequency ICMP, payload-bearing pings."
        ),
        "normal_icmp_size": 64,        # standard ping payload
        "max_icmp_size": 65507,        # max IP payload
        "suspicious_size_min": 512,    # abnormally large
        "entropy_threshold": 3.5,
        "bandwidth_estimate": "Low (~1-10 KB/s)",
        "stealth_score": 78,
        "dread_score": 7.8,
        "severity": "high",
        "patterns": [
            r"icmp.*(tunnel|ping|echo)",
            r"payload.*(size|length).*(\d{3,})",
        ],
    },
    "cert_steganography": {
        "name": "HTTPS Certificate Steganography",
        "description": (
            "Hidden data embedded in TLS certificate fields: unusual OU/O "
            "fields, certificate comment extensions (Netscape Comment), "
            "encoded SAN entries, serial number encoding, or custom X.509 "
            "extensions carrying covert payloads."
        ),
        "max_ou_length": 64,
        "suspicious_ou_min": 20,
        "entropy_threshold": 3.4,
        "bandwidth_estimate": "Negligible (one-time per handshake)",
        "stealth_score": 92,
        "dread_score": 7.0,
        "severity": "medium",
        "patterns": [
            r"OU=[A-Za-z0-9+/=]{20,}",
            r"comment.*[A-Za-z0-9+/=]{32,}",
            r"serialNumber.*[a-f0-9]{40,}",
        ],
    },
    "url_path_encoding": {
        "name": "URL Path Encoding Channel",
        "description": (
            "Data encoded in URL path segments: hex-encoded binary paths, "
            "unusually long paths, base64 segments, or path parameter "
            "steganography. Each path segment can carry encoded bytes."
        ),
        "normal_path_length": 128,
        "suspicious_path_min": 256,
        "max_path_length": 8192,
        "entropy_threshold": 3.7,
        "bandwidth_estimate": "Medium (~10-50 KB/s)",
        "stealth_score": 55,
        "dread_score": 5.5,
        "severity": "medium",
        "patterns": [
            r"/[a-f0-9]{16,}(?:/[a-f0-9]{16,})+",
            r"/[A-Za-z0-9+/=]{20,}(?:/[A-Za-z0-9+/=]{20,})+",
            r"/%[0-9a-fA-F]{2}{8,}",  # heavy URL-encoding
        ],
    },
    "chunked_encoding_abuse": {
        "name": "Chunked Transfer Encoding Abuse",
        "description": (
            "Data encoded in chunk sizes of HTTP chunked transfer encoding. "
            "Each chunk's size value encodes bits, while the chunk body "
            "contains cover traffic. Anomalous chunk size patterns signal abuse."
        ),
        "typical_chunk_sizes": [1024, 4096, 8192, 16384],
        "entropy_threshold": 3.2,
        "bandwidth_estimate": "Medium (~5-20 KB/s of covert data)",
        "stealth_score": 70,
        "dread_score": 6.5,
        "severity": "medium",
        "patterns": [
            r"[0-9a-fA-F]+\r\n",  # chunk size lines
        ],
    },
    "websocket_frame": {
        "name": "WebSocket Frame Analysis",
        "description": (
            "Covert data transfer via WebSocket frames: unusual frame sizes "
            "encoding binary data, timing between frames carrying information, "
            "opcode manipulation (text vs binary), or masked payload patterns."
        ),
        "typical_frame_sizes": [64, 128, 256, 512, 1024, 4096],
        "entropy_threshold": 3.5,
        "bandwidth_estimate": "High (~100 KB/s - 1 MB/s)",
        "stealth_score": 60,
        "dread_score": 7.2,
        "severity": "high",
        "patterns": [
            r"frame.*(size|length).*(\d{3,})",
            r"opcode.*(2|3|8)",  # binary, close, pong
        ],
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# ENTROPY THRESHOLD CALCULATIONS
# ═══════════════════════════════════════════════════════════════════════════

def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string in bits per character.

    Higher entropy means more random/unpredictable data — a strong
    indicator of encoded or encrypted payloads.

    Formula: H(X) = -Σ p(x) * log2(p(x))
    """
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _entropy_for_channel(channel_type: str, data: str) -> Tuple[float, bool]:
    """Calculate entropy and compare against channel-specific threshold.

    Returns (entropy_value, is_above_threshold).
    """
    sig = CHANNEL_SIGNATURES.get(channel_type, {})
    threshold = sig.get("entropy_threshold", 3.5)
    entropy = _shannon_entropy(data)
    return entropy, entropy >= threshold


def _byte_entropy(data: bytes) -> float:
    """Shannon entropy over raw bytes (0-255 alphabet)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _index_of_coincidence(data: str) -> float:
    """Calculate the Index of Coincidence (IoC) for a string.

    English text: ~0.0667. Random: ~0.0385.
    Low IoC with high entropy = strong indicator of encoding.
    """
    if len(data) < 2:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in data.lower():
        if ch.isalnum():
            freq[ch] = freq.get(ch, 0) + 1
    n = sum(freq.values())
    if n < 2:
        return 0.0
    ic = sum(c * (c - 1) for c in freq.values()) / (n * (n - 1))
    return ic


# ═══════════════════════════════════════════════════════════════════════════
# SIMULATION ENGINE — Educational byte-level demonstrations
# ═══════════════════════════════════════════════════════════════════════════

def _simulate_dns_tunneling() -> Dict[str, Any]:
    """Demonstrate DNS tunneling with byte-level encoding."""
    # Simulate encoding "SECRET" in DNS subdomain labels
    secret = b"SECRET DATA"
    # Base32 encode (common in DNS tunneling — case-insensitive, DNS-safe)
    b32 = base64.b32encode(secret).decode().rstrip("=")
    # Split into RFC 1035 compliant labels (max 63 chars each)
    labels = []
    chunk_size = 63
    for i in range(0, len(b32), chunk_size):
        labels.append(b32[i:i + chunk_size])
    # Prepend a counter label for reassembly
    encoded_domain = f"{'.'.join(labels)}.exfil.attacker.com"

    # Byte-level breakdown
    breakdown = []
    for i, label in enumerate(labels):
        breakdown.append({
            "label_index": i,
            "label_value": label,
            "label_length": len(label),
            "decoded_bytes": base64.b32decode(label + "=" * (-len(label) % 8)).hex(),
            "entropy": round(_shannon_entropy(label), 3),
        })

    return {
        "technique": "Base32-encoded subdomain labels",
        "tools": CHANNEL_SIGNATURES["dns_tunneling"]["known_tools"],
        "original_data": secret.decode(),
        "encoded_domain": encoded_domain,
        "domain_length": len(encoded_domain),
        "rfc_compliant": len(encoded_domain) <= 253,
        "label_breakdown": breakdown,
        "encoding_chain": "Plaintext → Base32 → Split into ≤63-char labels → DNS query",
        "bandwidth_note": (
            "Each DNS query carries ~188 bits (base32). At 10 qps upstream limit, "
            "that is ~235 B/s. TXT responses can carry ~512 bytes each."
        ),
    }


def _simulate_header_covert() -> Dict[str, Any]:
    """Demonstrate HTTP header covert channel encoding."""
    secret = b"HIDDEN MESSAGE"
    # Method 1: Base64 in a custom header
    b64_header_val = base64.b64encode(secret).decode()
    # Method 2: Hex encoding across multiple headers
    hex_chunks = [secret[i:i+4].hex() for i in range(0, len(secret), 4)]
    # Method 3: Header ordering (permutation encoding)
    # The order of a set of benign headers encodes bits
    header_set = ["X-Request-Id", "X-Trace-Id", "X-Correlation-Id", "X-Session-Id"]
    # Permutation index = secret bytes interpreted as index
    perm_index = int.from_bytes(secret[:2], "big") % math.factorial(len(header_set))
    ordered_headers = header_set.copy()
    # Simple Fisher-Yates partial shuffle for demo
    for i in range(min(perm_index % 4, len(ordered_headers) - 1)):
        j = (i + 1 + perm_index) % len(ordered_headers)
        ordered_headers[i], ordered_headers[j] = ordered_headers[j], ordered_headers[i]

    # Method 4: Whitespace steganography in header values
    # Trailing spaces/tabs encode binary
    binary_secret = "".join(f"{b:08b}" for b in secret)
    whitespace_encoded = "".join(
        " " if bit == "0" else "\t" for bit in binary_secret
    )

    return {
        "technique": "Multiple HTTP header encoding methods",
        "methods": [
            {
                "name": "Custom Header Base64",
                "example_header": f"X-Custom-Data: {b64_header_val}",
                "encoded_value": b64_header_val,
                "decoded": secret.decode(),
                "entropy": round(_shannon_entropy(b64_header_val), 3),
                "bytes_per_request": len(secret),
            },
            {
                "name": "Hex-Split Across Headers",
                "example_headers": {
                    f"X-Data-Part-{i}": chunk
                    for i, chunk in enumerate(hex_chunks)
                },
                "chunks": hex_chunks,
                "reassembled_hex": "".join(hex_chunks),
                "decoded": secret.decode(),
            },
            {
                "name": "Header Ordering (Permutation)",
                "header_set": header_set,
                "permutation_index": perm_index,
                "ordered_headers": ordered_headers,
                "bits_encodable": int(math.log2(math.factorial(len(header_set)))),
                "note": f"4 headers → log2(4!) = {int(math.log2(math.factorial(len(header_set))))} bits per request",
            },
            {
                "name": "Whitespace Steganography",
                "example": f"X-Nonce: abc123{'[' + ' '.join(['SP' if c == ' ' else 'TAB' for c in whitespace_encoded[:16]]) + '...]'}",
                "binary_length": len(binary_secret),
                "encoded_whitespace_length": len(whitespace_encoded),
                "note": "SP=0, TAB=1 — invisible to most logging",
            },
        ],
        "encoding_chain": "Plaintext → [Base64 | Hex-Split | Permutation | Whitespace] → HTTP header(s)",
    }


def _simulate_timing_channel() -> Dict[str, Any]:
    """Demonstrate timing-based covert channel."""
    secret = b"Hi"  # Simple demo: 2 bytes
    # Binary encoding: 0 = 100ms delay, 1 = 300ms delay
    binary_str = "".join(f"{b:08b}" for b in secret)
    delta_map = {"0": 0.10, "1": 0.30}  # seconds

    deltas = [delta_map[bit] for bit in binary_str]

    # Multi-bit encoding: 4 levels per interval (2 bits each)
    multi_bit_levels = [0.05, 0.15, 0.25, 0.35]
    multi_bit_pairs = []
    for i in range(0, len(binary_str), 2):
        pair = binary_str[i:i+2]
        idx = int(pair, 2) if len(pair) == 2 else int(pair, 2) * 2
        idx = min(idx, 3)
        multi_bit_pairs.append({
            "bits": pair.ljust(2, "0"),
            "decimal": idx,
            "delta_s": multi_bit_levels[idx],
        })

    return {
        "technique": "Response timing encodes binary data",
        "methods": [
            {
                "name": "Binary Timing (1 bit/request)",
                "encoding": "bit 0 → 100ms, bit 1 → 300ms",
                "original_data": secret.decode(),
                "binary": binary_str,
                "delta_sequence_ms": [int(d * 1000) for d in deltas],
                "total_time_s": round(sum(deltas), 2),
                "bandwidth": "1 bit per request pair (req + response)",
            },
            {
                "name": "Multi-bit Timing (2 bits/request)",
                "encoding": "00→50ms, 01→150ms, 10→250ms, 11→350ms",
                "level_map": {"00": 50, "01": 150, "10": 250, "11": 350},
                "symbol_sequence": multi_bit_pairs,
                "total_time_s": round(sum(p["delta_s"] for p in multi_bit_pairs), 2),
                "bandwidth": "2 bits per request pair",
                "note": "More efficient but higher detection risk (4 discrete levels)",
            },
        ],
        "detection_bypass": (
            "Add jitter: δ' = δ + N(0, σ²) where σ = 10-50ms. "
            "Receiver uses thresholding (δ < 200ms → 0, else → 1) to decode."
        ),
        "countermeasure": "Anomaly detection on inter-request timing distributions",
    }


def _simulate_icmp_tunnel() -> Dict[str, Any]:
    """Demonstrate ICMP tunneling concepts."""
    secret = b"ICMP payload data"
    # Standard ICMP echo has 8-byte header + variable payload
    # icmp-python, ptunnel encode data in the payload section
    icmp_header = struct.pack(">BBHHH", 8, 0, 0, 1234, 1)  # type, code, cksum, id, seq
    payload = secret
    # Calculate checksum
    packet = icmp_header + payload
    chksum = _internet_checksum(packet)
    packet = icmp_header[:2] + struct.pack(">H", chksum) + icmp_header[4:] + payload

    return {
        "technique": "Data in ICMP echo payload",
        "icmp_structure": {
            "type": "8 (Echo Request)",
            "code": "0",
            "checksum": f"0x{chksum:04x}",
            "identifier": "0x04D2 (1234)",
            "sequence": "0x0001",
            "payload_hex": payload.hex(),
            "payload_ascii": payload.decode("ascii", errors="replace"),
            "payload_length": len(payload),
            "total_packet_size": len(packet),
        },
        "packet_hex": packet.hex(),
        "encoding_chain": "Plaintext → Raw bytes → ICMP payload → IP packet → Wire",
        "bandwidth_note": (
            "Max payload per ICMP: 65,507 bytes. Practical: ~512-1024 bytes. "
            "Tools: ptunnel, icmpsh, icmptunnel encode in payload + padding."
        ),
        "detection_markers": [
            "ICMP packets > 64 bytes (standard ping size)",
            "High ICMP request rate from single source",
            "ICMP with unusual payload patterns (high entropy)",
            "ICMP responses to requests never sent (L3 beacon)",
        ],
        "known_tools": ["ptunnel", "icmpsh", "icmptunnel", "CNighT", "PowerShellICMP"],
    }


def _internet_checksum(data: bytes) -> int:
    """Calculate the Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def _simulate_cert_stego() -> Dict[str, Any]:
    """Demonstrate certificate steganography."""
    secret = b"STEGO SECRET"
    b64 = base64.b64encode(secret).decode()

    return {
        "technique": "Data hidden in X.509 certificate fields",
        "methods": [
            {
                "name": "OU Field Encoding",
                "example": f"OU={b64}",
                "field": "Subject.OrganizationalUnitName",
                "encoded_value": b64,
                "entropy": round(_shannon_entropy(b64), 3),
                "max_rfc_length": 64,
                "capacity": "~48 bytes of raw data per OU field (base64 overhead)",
            },
            {
                "name": "Netscape Comment Extension",
                "example": f"nsComment = {b64}",
                "oid": "2.16.840.1.113730.1.13",
                "field": "X.509v3 Extension: netscape-comment",
                "capacity": "Virtually unlimited (extension can be large)",
            },
            {
                "name": "Serial Number Encoding",
                "example": f"serialNumber = {int.from_bytes(hashlib.sha256(secret).digest()[:10], 'big')}",
                "field": "Certificate.SerialNumber",
                "capacity": "~20 bytes (160-bit serial number)",
                "note": "CA-generated serials should be random anyway — hard to distinguish",
            },
            {
                "name": "SAN Entry Encoding",
                "example": f"subjectAltName = DNS:{b64.lower()}.attacker.com",
                "field": "X.509v3 Extension: Subject Alternative Name",
                "capacity": "~60 bytes per SAN DNS entry (label length limit)",
            },
        ],
        "encoding_chain": (
            "Plaintext → Base64 → Embed in [OU | nsComment | Serial | SAN] "
            "→ Sign certificate → Deliver via TLS handshake"
        ),
        "extraction": (
            "Target parses cert on TLS handshake, extracts field, base64-decodes. "
            "One-time transfer per new cert, ideal for C2 addresses or keys."
        ),
    }


def _simulate_url_path_encoding() -> Dict[str, Any]:
    """Demonstrate URL path-based covert channel."""
    secret = b"URL_ENCODED_SECRET"
    # Method 1: Hex-encoded path segments
    hex_encoded = secret.hex()
    hex_segments = [hex_encoded[i:i+4] for i in range(0, len(hex_encoded), 4)]
    hex_path = "/" + "/".join(hex_segments)
    # Method 2: Base64 path segments
    b64 = base64.urlsafe_b64encode(secret).decode().rstrip("=")
    b64_segments = [b64[i:i+16] for i in range(0, len(b64), 16)]
    b64_path = "/" + "/".join(b64_segments)
    # Method 3: Double URL-encoding
    double_encoded = urllib.parse.quote(urllib.parse.quote(secret.decode(), safe=""), safe="")

    return {
        "technique": "Data encoded in URL path structure",
        "methods": [
            {
                "name": "Hex Path Segments",
                "example_url": f"https://target.com{hex_path}",
                "path": hex_path,
                "path_length": len(hex_path),
                "segment_count": len(hex_segments),
                "decoded": secret.decode(),
            },
            {
                "name": "Base64 Path Segments",
                "example_url": f"https://target.com{b64_path}",
                "path": b64_path,
                "path_length": len(b64_path),
                "segment_count": len(b64_segments),
                "decoded": secret.decode(),
            },
            {
                "name": "Double URL Encoding",
                "example_url": f"https://target.com/api/{double_encoded}",
                "encoded_path": double_encoded,
                "decoded": secret.decode(),
                "note": "Bypasses WAF URL-decode-once rules",
            },
        ],
        "encoding_chain": "Plaintext → [Hex-Segments | Base64-Segments | Double-Encode] → URL path",
        "bandwidth_note": "URL max ~8KB. Each request can carry ~6KB of encoded data.",
    }


def _simulate_chunked_encoding() -> Dict[str, Any]:
    """Demonstrate chunked transfer encoding abuse."""
    secret = b"CHUNK"
    # Each byte maps to a chunk size: chunk_size = cover_size + (byte_value * N)
    # The covert data is in the SIZE field, not the body
    cover_data = b"A" * 64  # cover traffic
    chunk_multiplier = 16

    chunks = []
    for byte_val in secret:
        covert_size = 64 + (byte_val * chunk_multiplier)
        chunk_line = f"{covert_size:x}\r\n"
        chunks.append({
            "secret_byte": chr(byte_val),
            "byte_hex": f"0x{byte_val:02x}",
            "chunk_size_decimal": covert_size,
            "chunk_size_hex": chunk_line.strip(),
            "covert_delta": byte_val * chunk_multiplier,
            "entropy_of_size": round(_shannon_entropy(chunk_line.strip()), 3),
        })

    # Full chunked response example
    full_response = ""
    for c in chunks:
        size = c["chunk_size_decimal"]
        full_response += f"{size:x}\r\n{cover_data * (size // 64)}\r\n"
    full_response += "0\r\n\r\n"

    return {
        "technique": "Covert data in chunk size fields",
        "methods": [
            {
                "name": "Chunk Size Encoding",
                "description": "Each chunk's size = base_size + (secret_byte * multiplier)",
                "base_size": 64,
                "multiplier": chunk_multiplier,
                "bytes_per_chunk": 1,
                "max_encodable_byte": 0xFF,
                "max_chunk_size": 64 + (255 * 16),  # 4144
            },
        ],
        "chunk_breakdown": chunks,
        "sample_response_prefix": full_response[:200] + "...",
        "encoding_chain": "Plaintext → Map each byte → Anomalous chunk size → HTTP chunked response",
        "detection_note": (
            "Normal servers use power-of-2 chunk sizes (1024, 4096, 8192). "
            "Arbitrary sizes like 4256, 4272, 4288 are anomalous."
        ),
    }


def _simulate_websocket_frame() -> Dict[str, Any]:
    """Demonstrate WebSocket frame covert channel."""
    secret = b"WS SECRET"
    # WebSocket frame format: FIN(1) RSV(3) Opcode(4) MASK(1) LEN(7) [MASK_KEY(32)] PAYLOAD(...)
    # Method 1: Frame length encodes data
    frame_details = []
    for byte_val in secret:
        # FIN=1, RSV=000, Opcode=0001 (text), MASK=0, LEN=7 bits
        # We encode the secret byte in the payload length (after a base offset)
        payload_len = 128 + byte_val
        # Frame header: 0x81 (FIN+text opcode) + payload_len
        header = bytes([0x81, payload_len])
        frame_details.append({
            "secret_byte": chr(byte_val) if 32 <= byte_val < 127 else f"0x{byte_val:02x}",
            "byte_hex": f"0x{byte_val:02x}",
            "frame_header_hex": header.hex(),
            "opcode": "0x1 (text)",
            "payload_length": payload_len,
            "covert_delta": byte_val,
        })

    # Method 2: Opcode switching
    # Opcodes: 0x1=text, 0x2=binary, 0x8=close, 0x9=ping, 0xA=pong
    # Encode 2 bits per frame via opcode selection
    opcode_map = {
        0x1: "00", 0x2: "01", 0x8: "10", 0x9: "11",
    }
    opcode_frames = []
    binary_secret = "".join(f"{b:08b}" for b in secret)
    for i in range(0, len(binary_secret), 2):
        pair = binary_secret[i:i+2].ljust(2, "0")
        for opcode, bits in opcode_map.items():
            if bits == pair:
                opcode_frames.append({
                    "bits": pair,
                    "opcode": f"0x{opcode:x}",
                    "opcode_name": {0x1: "text", 0x2: "binary", 0x8: "close", 0x9: "ping"}[opcode],
                })
                break

    return {
        "technique": "Covert data in WebSocket frame structure",
        "methods": [
            {
                "name": "Frame Length Encoding",
                "description": "Payload length = base_offset + secret_byte",
                "base_offset": 128,
                "bits_per_frame": 8,
                "frame_details": frame_details,
            },
            {
                "name": "Opcode Switching",
                "description": "Frame opcode encodes 2 bits (text=00, binary=01, close=10, ping=11)",
                "opcode_map": {f"0x{k:x}": v for k, v in opcode_map.items()},
                "encoded_sequence": opcode_frames,
                "bits_per_frame": 2,
                "note": "Frequent opcode switching is anomalous in normal WebSocket traffic",
            },
        ],
        "encoding_chain": "Plaintext → [Frame Length | Opcode Switching] → WebSocket frames",
        "bandwidth_note": "WebSocket has no same-origin restrictions. Full-duplex, persistent connection.",
    }


SIMULATORS = {
    "dns_tunneling": _simulate_dns_tunneling,
    "http_header_covert": _simulate_header_covert,
    "timing_channel": _simulate_timing_channel,
    "icmp_tunnel": _simulate_icmp_tunnel,
    "cert_steganography": _simulate_cert_stego,
    "url_path_encoding": _simulate_url_path_encoding,
    "chunked_encoding_abuse": _simulate_chunked_encoding,
    "websocket_frame": _simulate_websocket_frame,
}


# ═══════════════════════════════════════════════════════════════════════════
# DETECTION FUNCTIONS — Real HTTP-based analysis
# ═══════════════════════════════════════════════════════════════════════════

def _detect_dns_tunneling(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Analyze HTTP responses for DNS-tunneling indicators.

    Looks for: references to DNS services, unusual subdomains in
    response body/headers, DNS-over-HTTPS endpoints that could be
    used for tunneling.
    """
    findings: List[Finding] = []
    sig = CHANNEL_SIGNATURES["dns_tunneling"]

    # Probe common DNS-over-HTTPS endpoints
    doh_endpoints = [
        "/dns-query",
        "/dns-query?dns=",
        "/resolve?name=",
        "/api/dns",
    ]

    for ep in doh_endpoints:
        resp = http_probe(
            f"{base_url}{ep}", timeout=timeout, verify_tls=verify_tls,
            limiter=default_limiter,
        )
        if resp["ok"] and resp["status"] == 200:
            body = resp.get("body", "")
            headers = resp.get("headers", {})
            content_type = headers.get("content-type", "")

            # Check for DNS-over-HTTPS response (application/dns-message)
            if "dns" in content_type.lower():
                # Analyze response for tunneling indicators
                entropy, is_high = _entropy_for_channel("dns_tunneling", body)
                if is_high:
                    findings.append(Finding(
                        title="DNS-over-HTTPS Endpoint with High-Entropy Response",
                        severity=sig["severity"],
                        category="covert_channel",
                        module="covert_channel",
                        description=(
                            f"DNS-over-HTTPS endpoint {ep} returns high-entropy data "
                            f"(H={entropy:.2f} bits, threshold={sig['entropy_threshold']}). "
                            f"This could indicate active DNS tunneling or a DoH service "
                            f"that could be abused for data exfiltration."
                        ),
                        evidence=f"Endpoint: {ep}, Content-Type: {content_type}, Entropy: {entropy:.2f}",
                        asset=target,
                        points_deducted=15,
                        dread_score=sig["dread_score"],
                        remediation=(
                            "Restrict DNS-over-HTTPS to authorized resolvers. Monitor DNS "
                            "query patterns for unusually long/numerous subdomain queries. "
                            "Implement DNS query logging and anomaly detection."
                        ),
                    ))

    # Check response body for references to DNS tunneling tools/infrastructure
    probe_resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    if probe_resp["ok"]:
        body = probe_resp.get("body", "")
        for tool in sig["known_tools"]:
            tool_lower = tool.lower()
            if tool_lower in body.lower():
                findings.append(Finding(
                    title=f"DNS Tunneling Tool Reference: {tool}",
                    severity="high",
                    category="covert_channel",
                    module="covert_channel",
                    description=(
                        f"Response body contains reference to known DNS tunneling tool '{tool}'. "
                        f"This may indicate compromised infrastructure or a red team engagement."
                    ),
                    evidence=f"Tool name '{tool}' found in response body",
                    asset=target,
                    points_deducted=20,
                    dread_score=8.0,
                    remediation=f"Investigate the presence of {tool} on this system.",
                ))

    return findings


def _detect_http_header_covert(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Analyze HTTP response headers for covert channel indicators."""
    findings: List[Finding] = []
    sig = CHANNEL_SIGNATURES["http_header_covert"]

    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    headers = resp.get("headers", {})

    suspicious_headers_found = []
    high_entropy_headers = []

    for header_name, header_value in headers.items():
        # Check for suspicious custom headers
        for prefix in sig["suspicious_header_prefixes"]:
            if header_name.lower().startswith(prefix.lower()):
                entropy, is_high = _entropy_for_channel("http_header_covert", header_value)
                suspicious_headers_found.append({
                    "name": header_name,
                    "value_preview": header_value[:80] + ("..." if len(header_value) > 80 else ""),
                    "value_length": len(header_value),
                    "entropy": round(entropy, 3),
                    "high_entropy": is_high,
                })
                if is_high:
                    high_entropy_headers.append(header_name)
                break

        # Check for unusually long header values (potential base64/hex payloads)
        if len(header_value) > 100:
            entropy = _shannon_entropy(header_value)
            if entropy >= sig["entropy_threshold"]:
                if header_name not in [h["name"] for h in suspicious_headers_found]:
                    high_entropy_headers.append(header_name)

    if high_entropy_headers:
        findings.append(Finding(
            title="High-Entropy Values in Custom HTTP Headers",
            severity=sig["severity"],
            category="covert_channel",
            module="covert_channel",
            description=(
                f"Found {len(high_entropy_headers)} HTTP header(s) with high-entropy values "
                f"that could encode covert data: {', '.join(high_entropy_headers)}. "
                f"Normal header values have entropy < {sig['entropy_threshold']}. "
                f"High entropy suggests encoded or encrypted payloads."
            ),
            evidence=json.dumps(suspicious_headers_found, indent=2),
            asset=target,
            points_deducted=10,
            dread_score=sig["dread_score"],
            remediation=(
                "Audit custom HTTP headers for legitimate purpose. Remove unnecessary headers. "
                "Implement header allowlisting at the WAF/reverse proxy level. "
                "Monitor for headers with entropy > 3.5 bits."
            ),
        ))

    if suspicious_headers_found and not high_entropy_headers:
        findings.append(Finding(
            title="Custom HTTP Headers Present (Potential Covert Channel Vector)",
            severity="low",
            category="covert_channel",
            module="covert_channel",
            description=(
                f"Found {len(suspicious_headers_found)} custom HTTP header(s). While not "
                f"currently carrying high-entropy payloads, these headers could be "
                f"abused for covert data exfiltration if the server reflects or processes them."
            ),
            evidence=json.dumps(suspicious_headers_found, indent=2),
            asset=target,
            points_deducted=3,
            dread_score=3.5,
            remediation=(
                "Review custom headers for necessity. Implement strict header policies."
            ),
        ))

    # Check for cookie manipulation vectors
    cookies = headers.get("set-cookie", "")
    if cookies:
        cookie_entropy = _shannon_entropy(cookies)
        if cookie_entropy >= sig["entropy_threshold"]:
            findings.append(Finding(
                title="High-Entropy Cookie Value (Potential Covert Channel)",
                severity="low",
                category="covert_channel",
                module="covert_channel",
                description=(
                    f"Set-Cookie header contains high-entropy value (H={cookie_entropy:.2f}). "
                    f"Cookies can be used as a covert channel if the server reflects "
                    f"or logs cookie values for later exfiltration."
                ),
                evidence=f"Cookie entropy: {cookie_entropy:.2f}, Cookie: {cookies[:80]}...",
                asset=target,
                points_deducted=5,
                dread_score=4.0,
                remediation=(
                    "Ensure cookies use standard, audited values. Implement HttpOnly and "
                    "Secure flags. Monitor cookie value patterns for anomalies."
                ),
            ))

    return findings


def _detect_timing_channel(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Analyze response timing for timing-channel indicators.

    Sends multiple requests and measures inter-response time deltas.
    Consistent, non-natural timing patterns indicate encoding.
    """
    findings: List[Finding] = []
    sig = CHANNEL_SIGNATURES["timing_channel"]

    # Collect timing samples
    num_samples = 10
    timings: List[float] = []

    for i in range(num_samples):
        start = time.monotonic()
        resp = http_probe(
            f"{base_url}/?_t={int(time.time() * 1000)}_{i}",
            timeout=timeout, verify_tls=verify_tls, limiter=default_limiter,
        )
        elapsed = time.monotonic() - start
        timings.append(elapsed)

    if len(timings) < sig["min_observations"]:
        return findings

    # Calculate timing statistics
    deltas = [timings[i+1] - timings[i] for i in range(len(timings) - 1)]
    mean_delta = sum(deltas) / len(deltas)
    variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
    std_dev = math.sqrt(variance)

    if std_dev == 0:
        coeff_of_var = 0.0
    else:
        coeff_of_var = std_dev / mean_delta if mean_delta > 0 else float("inf")

    # Very consistent timing is suspicious (indicates server-side encoding)
    # Check if deltas cluster around specific values (discrete levels)
    quantized_deltas = [round(d * 100) / 100 for d in deltas]  # quantize to 10ms
    unique_deltas = set(quantized_deltas)

    # If we see very few unique delta values relative to samples, that's suspicious
    delta_diversity = len(unique_deltas) / len(quantized_deltas) if quantized_deltas else 0

    is_suspicious = False
    indicators = []

    if coeff_of_var < sig["std_dev_threshold"] and mean_delta > 0.01:
        is_suspicious = True
        indicators.append(
            f"Extremely consistent timing (CV={coeff_of_var:.4f}, "
            f"mean={mean_delta*1000:.1f}ms, σ={std_dev*1000:.2f}ms)"
        )

    if delta_diversity < 0.4 and len(deltas) >= 5:
        is_suspicious = True
        indicators.append(
            f"Low timing diversity ({len(unique_deltas)} unique values in "
            f"{len(quantized_deltas)} deltas = {delta_diversity:.2f})"
        )

    if is_suspicious:
        findings.append(Finding(
            title="Suspicious Response Timing Patterns (Timing Channel Indicator)",
            severity=sig["severity"],
            category="covert_channel",
            module="covert_channel",
            description=(
                f"Response timing analysis reveals patterns consistent with "
                f"timing-based covert channels. {'; '.join(indicators)}. "
                f"Timing channels encode data in inter-request/response delays."
            ),
            evidence=(
                f"Timings (ms): {[f'{t*1000:.1f}' for t in timings]}\n"
                f"Deltas (ms): {[f'{d*1000:.1f}' for d in deltas]}\n"
                f"Mean delta: {mean_delta*1000:.1f}ms, StdDev: {std_dev*1000:.2f}ms, "
                f"CV: {coeff_of_var:.4f}, Diversity: {delta_diversity:.2f}"
            ),
            asset=target,
            points_deducted=12,
            dread_score=sig["dread_score"],
            remediation=(
                "Implement request jitter/randomization. Monitor inter-request timing "
                "distributions for anomalies. Use network flow analysis to detect "
                "periodic or clustered timing patterns."
            ),
        ))
    else:
        findings.append(Finding(
            title="Timing Channel Analysis (No Anomalies Detected)",
            severity="info",
            category="covert_channel",
            module="covert_channel",
            description=(
                f"Analyzed {num_samples} response timings. Mean delta: "
                f"{mean_delta*1000:.1f}ms, CV: {coeff_of_var:.4f}. "
                f"No suspicious patterns detected."
            ),
            evidence=f"CV: {coeff_of_var:.4f}, Diversity: {delta_diversity:.2f}",
            asset=target,
            points_deducted=0,
            dread_score=0.0,
        ))

    return findings


def _detect_icmp_tunnel_markers(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Detect infrastructure patterns consistent with ICMP tunneling.

    Since we are HTTP-based, we look for:
    - References to ICMP/ping services in responses
    - Network diagnostic endpoints that could facilitate tunneling
    - Timing patterns that suggest ICMP-based side channels
    """
    findings: List[Finding] = []
    sig = CHANNEL_SIGNATURES["icmp_tunnel"]

    # Probe for network diagnostic endpoints
    diag_paths = [
        "/ping", "/api/ping", "/api/health/ping",
        "/icmp", "/api/icmp", "/network/ping",
        "/api/v1/ping", "/diagnostics/ping",
        "/trace", "/api/traceroute", "/api/trace",
    ]

    icmp_endpoints_found = []

    for path in diag_paths:
        resp = http_probe(
            f"{base_url}{path}", timeout=timeout, verify_tls=verify_tls,
            limiter=default_limiter,
        )
        if resp["ok"] and resp["status"] == 200:
            body = resp.get("body", "")
            headers = resp.get("headers", {})

            # Check if endpoint actually performs ICMP-like operations
            icmp_indicators = []
            body_lower = body.lower()
            for keyword in ["icmp", "ping", "echo", "ttl", "rtt", "latency", "packet"]:
                if keyword in body_lower:
                    icmp_indicators.append(keyword)

            if icmp_indicators:
                icmp_endpoints_found.append({
                    "path": path,
                    "indicators": icmp_indicators,
                    "response_size": len(body),
                })

    if icmp_endpoints_found:
        paths_str = ", ".join(ep["path"] for ep in icmp_endpoints_found)
        findings.append(Finding(
            title="ICMP-Related Endpoints Discovered (Potential Tunneling Vector)",
            severity=sig["severity"],
            category="covert_channel",
            module="covert_channel",
            description=(
                f"Found {len(icmp_endpoints_found)} endpoint(s) related to ICMP/ping "
                f"functionality: {paths_str}. If these endpoints allow arbitrary "
                f"ICMP operations or accept user-controlled payload data, they could "
                f"facilitate ICMP tunneling for covert exfiltration."
            ),
            evidence=json.dumps(icmp_endpoints_found, indent=2),
            asset=target,
            points_deducted=15,
            dread_score=sig["dread_score"],
            remediation=(
                "Restrict access to network diagnostic endpoints. Ensure they do not "
                "accept user-controlled payload data. Implement network-level ICMP "
                "monitoring for unusual packet sizes and frequencies."
            ),
        ))

    # Check main response for ICMP tunnel tool references
    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    if resp["ok"]:
        body = resp.get("body", "")
        for tool in ["ptunnel", "icmpsh", "icmptunnel", "cnighT"]:
            if tool.lower() in body.lower():
                findings.append(Finding(
                    title=f"ICMP Tunneling Tool Reference: {tool}",
                    severity="high",
                    category="covert_channel",
                    module="covert_channel",
                    description=(
                        f"Response body references ICMP tunneling tool '{tool}'. "
                        f"This indicates the system may be configured for or compromised "
                        f"by ICMP tunneling capabilities."
                    ),
                    evidence=f"Tool '{tool}' found in response body",
                    asset=target,
                    points_deducted=20,
                    dread_score=8.5,
                    remediation=f"Investigate {tool} presence and remove if unauthorized.",
                ))

    return findings


def _detect_cert_steganography(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Analyze TLS certificate fields for steganographic indicators.

    Uses the TLS connection from http_probe to observe certificate-derived
    information available in HTTP responses.
    """
    findings: List[Finding] = []
    sig = CHANNEL_SIGNATURES["cert_steganography"]

    # Make a request and examine response for certificate-related info
    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    headers = resp.get("headers", {})
    body = resp.get("body", "")

    # Check for certificate-related information in headers
    cert_headers = {}
    for h_name, h_value in headers.items():
        h_lower = h_name.lower()
        if any(k in h_lower for k in ["ssl", "tls", "cert", "certificate"]):
            cert_headers[h_name] = h_value

    # Analyze any certificate-related headers for stego indicators
    for h_name, h_value in cert_headers.items():
        entropy, is_high = _entropy_for_channel("cert_steganography", h_value)
        if is_high:
            findings.append(Finding(
                title=f"High-Entropy Certificate-Related Header: {h_name}",
                severity=sig["severity"],
                category="covert_channel",
                module="covert_channel",
                description=(
                    f"Header '{h_name}' contains certificate-related data with high "
                    f"entropy (H={entropy:.2f}, threshold={sig['entropy_threshold']}). "
                    f"This could indicate steganographic data embedded in TLS certificate fields."
                ),
                evidence=f"Header: {h_name}, Entropy: {entropy:.2f}, Value: {h_value[:100]}",
                asset=target,
                points_deducted=12,
                dread_score=sig["dread_score"],
                remediation=(
                    "Audit certificate generation for unusual field values. Ensure OU, O, "
                    "and CN fields contain expected organizational data. Monitor certificate "
                    "transparency logs for anomalous certificates."
                ),
            ))

    # Check response body for certificate details (API endpoints that expose cert info)
    cert_patterns = [
        (r"OU[=:]\s*([^,\n]+)", "OU field"),
        (r"organizationUnit[=:]\s*([^,\n]+)", "organizationalUnit field"),
        (r"serialNumber[=:]\s*([^,\n]+)", "serialNumber field"),
        (r"nsComment[=:]\s*([^,\n]+)", "nsComment extension"),
        (r"subjectAltName[=:]\s*([^,\n]+)", "SAN extension"),
    ]

    for pattern, field_name in cert_patterns:
        matches = re.findall(pattern, body, re.IGNORECASE)
        for match in matches:
            match_stripped = match.strip()
            if len(match_stripped) > sig["suspicious_ou_min"]:
                entropy = _shannon_entropy(match_stripped)
                if entropy >= sig["entropy_threshold"]:
                    findings.append(Finding(
                        title=f"Suspicious Certificate Field: {field_name}",
                        severity=sig["severity"],
                        category="covert_channel",
                        module="covert_channel",
                        description=(
                            f"Certificate {field_name} contains unusually long, "
                            f"high-entropy value (length={len(match_stripped)}, "
                            f"H={entropy:.2f}). This is consistent with certificate "
                            f"steganography where covert data is embedded in X.509 fields."
                        ),
                        evidence=f"Field: {field_name}, Value: {match_stripped[:80]}, Entropy: {entropy:.2f}",
                        asset=target,
                        points_deducted=12,
                        dread_score=sig["dread_score"],
                        remediation=(
                            f"Audit certificate {field_name} values. Legitimate values should be "
                            f"short, human-readable organizational identifiers."
                        ),
                    ))

    return findings


def _detect_url_path_encoding(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Detect URL path patterns consistent with data encoding."""
    findings: List[Finding] = []
    sig = CHANNEL_SIGNATURES["url_path_encoding"]

    # Test various encoded path patterns against the target
    test_paths = [
        # Hex-encoded path segments
        "/" + "/".join(["a1b2c3d4e5f6"] * 3),
        # Base64 path segments
        "/" + "/".join(["SGVsbG8gV29ybGQ="] * 2),
        # Long path with encoded data
        "/" + "a" * 300,
        # URL-encoded heavy path
        "/api/%41%42%43%44%45%46%47%48%49%4a%4b%4c%4d%4e%4f%50",
        # Mixed encoding
        "/" + "/".join([f"seg{i:04x}" for i in range(5)]),
    ]

    for path in test_paths:
        resp = http_probe(
            f"{base_url}{path}", timeout=timeout, verify_tls=verify_tls,
            limiter=default_limiter,
        )

        # If the server accepts (200/404) unusually long/encoded paths, it's a vector
        if resp["status"] in (200, 301, 302, 404, 405):
            path_len = len(path)
            if path_len > sig["suspicious_path_min"]:
                # Check if server echoes back the path (reflection = amplification vector)
                body = resp.get("body", "")
                path_echoes = any(seg in body for seg in path.split("/")[1:4] if seg)

                if path_echoes:
                    findings.append(Finding(
                        title="URL Path Reflection with Encoded Data (Covert Channel Vector)",
                        severity=sig["severity"],
                        category="covert_channel",
                        module="covert_channel",
                        description=(
                            f"Server accepts and reflects long/encoded URL paths "
                            f"(length={path_len}). Path data is echoed in the response, "
                            f"confirming it as a viable covert channel for data exfiltration."
                        ),
                        evidence=f"Path length: {path_len}, Status: {resp['status']}",
                        asset=target,
                        points_deducted=10,
                        dread_score=sig["dread_score"],
                        remediation=(
                            "Implement maximum URL length restrictions. Normalize and "
                            "validate all URL paths. Do not reflect user-supplied path data."
                        ),
                    ))
                else:
                    findings.append(Finding(
                        title=f"Server Accepts Unusually Long URL Paths ({path_len} chars)",
                        severity="low",
                        category="covert_channel",
                        module="covert_channel",
                        description=(
                            f"Server processes URL paths of {path_len} characters without "
                            f"rejection. Long URL paths can encode covert data in hex, "
                            f"base64, or raw binary segments."
                        ),
                        evidence=f"Path: {path[:100]}..., Status: {resp['status']}",
                        asset=target,
                        points_deducted=3,
                        dread_score=3.0,
                        remediation=(
                            "Set maximum URL length (recommend ≤2048 chars). Reject paths with "
                            "high entropy or unusual encoding patterns."
                        ),
                    ))
                break  # One finding per category is sufficient

    # Check response body for long encoded URLs/paths in links
    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    if resp["ok"]:
        body = resp.get("body", "")
        url_pattern = r'href=["\']([^"\']{256,})["\']'
        long_urls = re.findall(url_pattern, body)
        for url in long_urls[:5]:
            entropy = _shannon_entropy(url)
            if entropy >= sig["entropy_threshold"]:
                parsed = urllib.parse.urlparse(url)
                if len(parsed.path) > sig["suspicious_path_min"]:
                    findings.append(Finding(
                        title="High-Entropy Long URL in Response Body",
                        severity="medium",
                        category="covert_channel",
                        module="covert_channel",
                        description=(
                            f"Response contains a link with high-entropy, unusually long path "
                            f"(path length={len(parsed.path)}, H={entropy:.2f}). This could be "
                            f"a covert channel for data exfiltration via URL paths."
                        ),
                        evidence=f"URL: {url[:120]}..., Path entropy: {entropy:.2f}",
                        asset=target,
                        points_deducted=8,
                        dread_score=5.0,
                        remediation="Audit link generation for security. Validate URL patterns.",
                    ))

    return findings


def _detect_chunked_encoding_abuse(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Detect anomalous chunked transfer encoding patterns."""
    findings: List[Finding] = []
    sig = CHANNEL_SIGNATURES["chunked_encoding_abuse"]

    # Request with Accept-Encoding to potentially trigger chunked responses
    resp = http_probe(
        base_url,
        headers={"Accept-Encoding": "identity"},  # force unchunked if possible
        timeout=timeout, verify_tls=verify_tls, limiter=default_limiter,
    )
    headers = resp.get("headers", {})
    body = resp.get("body", "")

    transfer_encoding = headers.get("transfer-encoding", "").lower()

    if "chunked" in transfer_encoding:
        # Analyze the body for chunk size patterns
        # In our case http_probe already decodes chunked, so we analyze the raw
        # response characteristics
        findings.append(Finding(
            title="Chunked Transfer Encoding Detected (Potential Covert Channel)",
            severity=sig["severity"],
            category="covert_channel",
            module="covert_channel",
            description=(
                f"Server uses chunked transfer encoding. While legitimate, chunked "
                f"encoding can be abused to encode covert data in chunk size fields. "
                f"Normal servers use power-of-2 chunk sizes; anomalous sizes indicate abuse."
            ),
            evidence=f"Transfer-Encoding: {transfer_encoding}, Body size: {len(body)}",
            asset=target,
            points_deducted=5,
            dread_score=sig["dread_score"],
            remediation=(
                "Prefer Content-Length over chunked encoding where possible. Monitor "
                "chunk size distributions for anomalies. Implement middleware that "
                "normalizes chunk sizes."
            ),
        ))
    else:
        # Check if server supports chunked encoding via HEAD/conditional request
        resp2 = http_probe(
            f"{base_url}/?chunked-test=1",
            headers={
                "Accept-Encoding": "identity",
                "TE": "chunked",
            },
            timeout=timeout, verify_tls=verify_tls, limiter=default_limiter,
        )
        te_header = resp2.get("headers", {}).get("transfer-encoding", "").lower()
        if "chunked" in te_header:
            findings.append(Finding(
                title="Server Supports Chunked TE (When Explicitly Requested)",
                severity="info",
                category="covert_channel",
                module="covert_channel",
                description=(
                    "Server emits chunked transfer encoding when TE: chunked is requested. "
                    "This confirms chunked encoding support, which is a prerequisite "
                    "for chunked encoding abuse."
                ),
                evidence=f"TE header triggered chunked response",
                asset=target,
                points_deducted=2,
                dread_score=2.0,
            ))

    # Check body for chunk-size-like patterns (hex strings on their own lines)
    chunk_pattern = re.findall(r"\b([0-9a-fA-F]{1,4})\s*$", body, re.MULTILINE)
    if len(chunk_pattern) > 10:
        # Lots of hex numbers on their own lines = possibly chunked data in body
        non_power_of_two = []
        for s in chunk_pattern:
            val = int(s, 16)
            if val > 0 and (val & (val - 1)) != 0:  # not power of 2
                non_power_of_two.append(val)

        if non_power_of_two:
            findings.append(Finding(
                title="Anomalous Chunk-Size Patterns in Response Body",
                severity="medium",
                category="covert_channel",
                module="covert_channel",
                description=(
                    f"Response body contains {len(chunk_pattern)} hex values on separate lines, "
                    f"of which {len(non_power_of_two)} are non-power-of-2. This pattern is "
                    f"consistent with chunked encoding abuse where chunk sizes encode data."
                ),
                evidence=(
                    f"Total hex values: {len(chunk_pattern)}, "
                    f"Non-power-of-2: {non_power_of_two[:10]}"
                ),
                asset=target,
                points_deducted=8,
                dread_score=5.5,
                remediation=(
                    "Investigate why response body contains chunk-like hex patterns. "
                    "If this is application data, consider encoding it differently."
                ),
            ))

    return findings


def _detect_websocket_frame_anomalies(
    target: str, base_url: str, timeout: int, verify_tls: bool
) -> List[Finding]:
    """Detect WebSocket endpoints and analyze for covert channel potential."""
    findings: List[Finding] = []
    sig = CHANNEL_SIGNATURES["websocket_frame"]

    # Probe for WebSocket upgrade endpoints
    ws_paths = [
        "/ws", "/websocket", "/socket", "/live",
        "/api/ws", "/api/websocket", "/api/socket",
        "/chat/ws", "/realtime", "/stream",
        "/api/v1/ws", "/notifications/ws",
    ]

    ws_endpoints_found = []

    for path in ws_paths:
        resp = http_probe(
            f"{base_url}{path}",
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": base64.b64encode(b"reconpro-covert-scan").decode(),
                "Sec-WebSocket-Version": "13",
            },
            timeout=timeout, verify_tls=verify_tls, limiter=default_limiter,
        )

        if resp["status"] == 101:
            # Successful WebSocket upgrade
            ws_endpoints_found.append({
                "path": path,
                "status": 101,
                "headers": dict(resp.get("headers", {})),
            })
        elif resp["status"] in (400, 403, 426) or resp["ok"]:
            # 426 = Upgrade Required, indicates WS support
            if resp["status"] == 426:
                ws_endpoints_found.append({
                    "path": path,
                    "status": 426,
                    "note": "Server indicates upgrade required (WS supported)",
                })

    if ws_endpoints_found:
        paths_str = ", ".join(ep["path"] for ep in ws_endpoints_found)
        # Determine severity based on whether upgrade succeeded
        has_upgrade = any(ep["status"] == 101 for ep in ws_endpoints_found)
        severity = "high" if has_upgrade else "medium"
        points = 15 if has_upgrade else 8

        findings.append(Finding(
            title=f"WebSocket Endpoint(s) Discovered: {paths_str}",
            severity=severity,
            category="covert_channel",
            module="covert_channel",
            description=(
                f"Found {len(ws_endpoints_found)} WebSocket endpoint(s). WebSocket "
                f"connections are persistent, full-duplex, and bypass same-origin "
                f"policies — making them ideal for covert data exfiltration. Frame "
                f"sizes, opcodes, and inter-frame timing can all encode covert data."
            ),
            evidence=json.dumps(ws_endpoints_found, indent=2),
            asset=target,
            points_deducted=points,
            dread_score=sig["dread_score"] if has_upgrade else 5.0,
            remediation=(
                "Authenticate WebSocket connections (token in handshake). Implement "
                "rate limiting per connection. Monitor frame sizes and inter-frame "
                f"timing. Restrict WebSocket to specific paths. Log all WS traffic."
            ),
        ))

    # Check for WebSocket-related JavaScript in response body
    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    if resp["ok"]:
        body = resp.get("body", "")
        ws_js_indicators = []
        for pattern in [
            r"new\s+WebSocket\s*",
            r"\.onmessage\s*=",
            r'wss?://[^"]+',
            r"socket\.io",
            r"SockJS",
        ]:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                ws_js_indicators.append({"pattern": pattern, "count": len(matches)})

        if ws_js_indicators:
            total_ws_refs = sum(ind["count"] for ind in ws_js_indicators)
            findings.append(Finding(
                title=f"WebSocket Client-Side Code Detected ({total_ws_refs} references)",
                severity="info",
                category="covert_channel",
                module="covert_channel",
                description=(
                    f"Response body contains {total_ws_refs} WebSocket-related code references. "
                    f"This confirms active WebSocket usage on the target, which is a potential "
                    f"covert channel vector if not properly secured."
                ),
                evidence=json.dumps(ws_js_indicators, indent=2),
                asset=target,
                points_deducted=2,
                dread_score=2.0,
            ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

# Detector functions registry
_DETECTORS: List[Tuple[str, callable]] = [
    ("dns_tunneling", _detect_dns_tunneling),
    ("http_header_covert", _detect_http_header_covert),
    ("timing_channel", _detect_timing_channel),
    ("icmp_tunnel", _detect_icmp_tunnel_markers),
    ("cert_steganography", _detect_cert_steganography),
    ("url_path_encoding", _detect_url_path_encoding),
    ("chunked_encoding_abuse", _detect_chunked_encoding_abuse),
    ("websocket_frame", _detect_websocket_frame_anomalies),
]


def run_covert_channel(
    target: str, base_url: str, timeout: int = 8, verify_tls: bool = True
) -> List[Finding]:
    """Run all covert channel detection checks against a target.

    Detects and simulates eight classes of covert data exfiltration channels:
      1. DNS Tunneling Detection
      2. HTTP Header Covert Channel Detection
      3. Timing Channel Detection
      4. ICMP Tunnel Detection Markers
      5. HTTPS Certificate Steganography
      6. URL Path Encoding Channels
      7. Chunked Transfer Encoding Abuse
      8. WebSocket Frame Analysis

    Each detection produces a Finding with severity, evidence, and remediation.
    Educational simulations demonstrate byte-level encoding for each channel.

    Args:
        target: Human-readable target identifier (e.g. 'example.com').
        base_url: Base URL for HTTP probes (e.g. 'https://example.com').
        timeout: Per-request timeout in seconds.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        List of Finding objects, one per detection result or simulation.
    """
    all_findings: List[Finding] = []

    # ── Phase 1: Run all detectors ─────────────────────────────────────
    for channel_name, detector_fn in _DETECTORS:
        try:
            results = detector_fn(target, base_url, timeout, verify_tls)
            all_findings.extend(results)
        except Exception:
            # Individual detector failures must not crash the entire module
            continue

    # ── Phase 2: Generate educational simulations ──────────────────────
    simulation_summary: Dict[str, Any] = {}
    for channel_name, simulator_fn in SIMULATORS.items():
        try:
            sim = simulator_fn()
            simulation_summary[channel_name] = sim
        except Exception:
            continue

    # Add a simulation summary finding
    if simulation_summary:
        sim_channels = list(simulation_summary.keys())
        sim_evidence_parts = []
        for ch_name, sim_data in simulation_summary.items():
            sig = CHANNEL_SIGNATURES[ch_name]
            technique = sim_data.get("technique", "N/A")
            sim_evidence_parts.append(
                f"[{sig['name']}] {technique} | "
                f"Bandwidth: {sig['bandwidth_estimate']} | "
                f"Stealth: {sig['stealth_score']}/100 | "
                f"DREAD: {sig['dread_score']}"
            )

        all_findings.append(Finding(
            title="Covert Channel Simulation Summary (Educational)",
            severity="info",
            category="covert_channel_simulation",
            module="covert_channel",
            description=(
                f"Generated byte-level encoding simulations for {len(sim_channels)} covert "
                f"channel types. These simulations demonstrate how each channel can be "
                f"exploited for data exfiltration. Channels analyzed: "
                f"{', '.join(sig['name'] for sig in [CHANNEL_SIGNATURES[s] for s in sim_channels])}. "
                f"Full simulation data available in evidence."
            ),
            evidence="\n".join(sim_evidence_parts),
            asset=target,
            points_deducted=0,
            dread_score=0.0,
            remediation=(
                "Review simulations to understand each channel's encoding method, "
                "bandwidth, and stealth characteristics. Implement corresponding "
                "detection and mitigation strategies."
            ),
        ))

    # ── Phase 3: Overall risk assessment ───────────────────────────────
    high_sev_count = sum(1 for f in all_findings if f.severity in ("critical", "high"))
    total_dread = sum(f.dread_score for f in all_findings if f.dread_score > 0)
    max_dread = len(CHANNEL_SIGNATURES) * 10.0
    risk_pct = min(100, (total_dread / max_dread * 100)) if max_dread > 0 else 0

    risk_level = (
        "CRITICAL" if risk_pct > 75 else
        "HIGH" if risk_pct > 50 else
        "MEDIUM" if risk_pct > 25 else
        "LOW"
    )

    all_findings.append(Finding(
        title=f"Covert Channel Risk Assessment: {risk_level} ({risk_pct:.1f}%)",
        severity=(
            "critical" if risk_pct > 75 else
            "high" if risk_pct > 50 else
            "medium" if risk_pct > 25 else
            "low"
        ),
        category="covert_channel_assessment",
        module="covert_channel",
        description=(
            f"Comprehensive covert channel analysis complete. Scanned {len(_DETECTORS)} "
            f"channel types against {target}. Found {high_sev_count} high-severity findings. "
            f"Aggregate DREAD score: {total_dread:.1f}/{max_dread:.1f} ({risk_pct:.1f}%). "
            f"Risk level: {risk_level}."
        ),
        evidence=(
            f"Channels scanned: {len(_DETECTORS)}\n"
            f"High-severity findings: {high_sev_count}\n"
            f"Total findings: {len(all_findings)}\n"
            f"Aggregate DREAD: {total_dread:.1f}/{max_dread:.1f}\n"
            f"Risk: {risk_level} ({risk_pct:.1f}%)\n"
            f"Simulations generated: {len(simulation_summary)}"
        ),
        asset=target,
        points_deducted=high_sev_count * 5,
        dread_score=round(total_dread, 1),
        remediation=(
            "Implement defense-in-depth: network-level monitoring (DNS, ICMP flow analysis), "
            "application-level header/path validation, TLS certificate auditing, and "
            "timing anomaly detection. Deploy IDS/IPS rules for known tunneling signatures."
        ),
    ))

    return all_findings

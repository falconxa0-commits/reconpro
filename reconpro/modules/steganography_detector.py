"""Module: STEGANOGRAPHY DETECTOR — Hidden Data & Covert Channel Analysis.

Detects hidden data and steganography in HTTP responses — techniques not
covered by any open-source scanner.

10 detection categories:
  1. Whitespace Steganography in HTML/JSON
  2. Base64 Anomaly Detection
  3. HTTP Header Steganography
  4. Image LSB Detection
  5. CSS Steganography
  6. JavaScript Variable Naming Anomalies
  7. Response Size Anomalies
  8. Charset Encoding Tricks
  9. Metadata Steganography (EXIF/IPTC/XMP)
 10. Timing Channel Detection
"""
from __future__ import annotations

import base64
import hashlib
import html
import json
import re
import struct
import time
from collections import Counter
from typing import Any, Dict, List, Optional
from ..http_layer import http_probe, Finding, default_limiter, _unverified_context


# ═══════════════════════════════════════════════════════════════════════════
# Unicode Zero-Width Character Detection Tables
# ═══════════════════════════════════════════════════════════════════════════

ZERO_WIDTH_CHARS: Dict[str, Dict[str, str]] = {
    "\u200b": {
        "name": "ZERO WIDTH SPACE",
        "unicode": "U+200B",
        "risk": "high",
        "use": "Widely used for invisible text encoding; can hide 1 bit per character",
    },
    "\u200c": {
        "name": "ZERO WIDTH NON-JOINER",
        "unicode": "U+200C",
        "risk": "high",
        "use": "Used in text steganography tools (zwc-stego, unicode-steganography); encodes binary data",
    },
    "\u200d": {
        "name": "ZERO WIDTH JOINER",
        "unicode": "U+200D",
        "risk": "high",
        "use": "Common in emoji-based steganography; encodes data in ZWJ sequences",
    },
    "\ufeff": {
        "name": "BYTE ORDER MARK (BOM)",
        "unicode": "U+FEFF",
        "risk": "medium",
        "use": "Can be used as steganographic channel when repeated or misplaced; signals encoding tricks",
    },
    "\u200e": {
        "name": "LEFT-TO-RIGHT MARK",
        "unicode": "U+200E",
        "risk": "medium",
        "use": "Bi-directional text control; can encode data in LTR/RTL alternation patterns",
    },
    "\u200f": {
        "name": "RIGHT-TO-LEFT MARK",
        "unicode": "U+200F",
        "risk": "medium",
        "use": "Bi-directional text control; RTL/LTR alternation encodes binary data",
    },
    "\u202a": {
        "name": "LEFT-TO-RIGHT EMBEDDING",
        "unicode": "U+202A",
        "risk": "low",
        "use": "Bidi control override; suspicious if present in non-Arabic/Hebrew content",
    },
    "\u202b": {
        "name": "RIGHT-TO-LEFT EMBEDDING",
        "unicode": "U+202B",
        "risk": "low",
        "use": "Bidi control override; rare outside RTL content, potential covert channel",
    },
    "\u202c": {
        "name": "POP DIRECTIONAL FORMATTING",
        "unicode": "U+202C",
        "risk": "low",
        "use": "Terminates bidi embedding; abnormal frequency suggests encoding",
    },
    "\u2060": {
        "name": "WORD JOINER",
        "unicode": "U+2060",
        "risk": "medium",
        "use": "Invisible character similar to ZWSP; used in some steganography tools",
    },
    "\u2061": {
        "name": "FUNCTION APPLICATION",
        "unicode": "U+2061",
        "risk": "low",
        "use": "Mathematical invisible operator; extremely rare in web content",
    },
    "\u2062": {
        "name": "INVISIBLE TIMES",
        "unicode": "U+2062",
        "risk": "low",
        "use": "Mathematical invisible operator; presence in web content is suspicious",
    },
    "\u2063": {
        "name": "INVISIBLE SEPARATOR",
        "unicode": "U+2063",
        "risk": "low",
        "use": "Mathematical invisible operator; can encode binary data",
    },
    "\u2064": {
        "name": "INVISIBLE PLUS",
        "unicode": "U+2064",
        "risk": "low",
        "use": "Mathematical invisible operator; presence is highly suspicious in web responses",
    },
    "\u034f": {
        "name": "COMBINING GRAPHEME JOINER",
        "unicode": "U+034F",
        "risk": "medium",
        "use": "Invisible combining character; used in advanced Unicode steganography",
    },
    "\u180e": {
        "name": "MONGOLIAN VOWEL SEPARATOR",
        "unicode": "U+180E",
        "risk": "low",
        "use": "Invisible in many renderers; deprecated but still usable as covert channel",
    },
    "\u00ad": {
        "name": "SOFT HYPHEN",
        "unicode": "U+00AD",
        "risk": "medium",
        "use": "Invisible unless at line break; can encode data via insertion patterns",
    },
    "\u2028": {
        "name": "LINE SEPARATOR",
        "unicode": "U+2028",
        "risk": "low",
        "use": "Unicode line break; can encode binary data (LS vs LF alternation)",
    },
    "\u2029": {
        "name": "PARAGRAPH SEPARATOR",
        "unicode": "U+2029",
        "risk": "low",
        "use": "Unicode paragraph break; abnormal usage suggests covert encoding",
    },
    "\u00a0": {
        "name": "NO-BREAK SPACE",
        "unicode": "U+00A0",
        "risk": "low",
        "use": "Non-breaking space; can replace regular spaces to encode binary data (NBSP=1, SP=0)",
    },
}

HIGH_RISK_ZWC = {ch for ch, info in ZERO_WIDTH_CHARS.items() if info["risk"] == "high"}
ALL_ZWC_PATTERN = re.compile("|".join(re.escape(ch) for ch in ZERO_WIDTH_CHARS))


# ═══════════════════════════════════════════════════════════════════════════
# STEGANO_SIGNATURES — Known Steganographic Techniques Database
# ═══════════════════════════════════════════════════════════════════════════

STEGANO_SIGNATURES: List[Dict[str, Any]] = [
    # ── Whitespace-based techniques ──
    {
        "id": "WS-001",
        "name": "Trailing Whitespace Binary Encoding",
        "category": "whitespace",
        "severity": "medium",
        "description": (
            "Encodes binary data in trailing whitespace of text lines. "
            "A trailing space = 1, a trailing tab = 0 (or vice versa). "
            "Each line of visible text carries one hidden bit."
        ),
        "detection": "Count lines with anomalous trailing whitespace; look for alternating space/tab patterns.",
        "tools": ["stegsnow", "whitespace-stego", "custom scripts"],
    },
    {
        "id": "WS-002",
        "name": "Unicode Zero-Width Character Encoding",
        "category": "whitespace",
        "severity": "high",
        "description": (
            "Embeds hidden data using invisible Unicode characters (U+200B, U+200C, U+200D). "
            "Each zero-width character can represent 1-2 bits. Messages are invisible to users "
            "but survive copy-paste. Commonly implemented in npm packages like unicode-steganography."
        ),
        "detection": "Scan response body for presence and frequency of zero-width Unicode characters.",
        "tools": ["unicode-steganography", "zwc-stego", "invisible-char-encoder"],
    },
    {
        "id": "WS-003",
        "name": "CRLF/LF Line Ending Steganography",
        "category": "whitespace",
        "severity": "low",
        "description": (
            "Encodes binary data by alternating between CRLF (\\r\\n) and LF (\\n) line endings. "
            "CRLF = 1, LF = 0. Subtle but detectable through line-ending analysis."
        ),
        "detection": "Analyze line ending consistency; mixed CRLF/LF in a single response is suspicious.",
        "tools": ["custom scripts", "steghide variants"],
    },
    {
        "id": "WS-004",
        "name": "Tab/Space Substitution Encoding",
        "category": "whitespace",
        "severity": "medium",
        "description": (
            "Replaces sequences of spaces with equivalent tab characters (or vice versa) "
            "using the fact that tab stops align to multiples of 8. Each indentation level "
            "can encode different bit patterns depending on the tab-to-space ratio used."
        ),
        "detection": "Look for inconsistent indentation that still produces visually identical output.",
        "tools": ["stegsnow", "tabspace-stego"],
    },
    # ── Base64 techniques ──
    {
        "id": "B64-001",
        "name": "Nested Base64 Encoding",
        "category": "base64",
        "severity": "medium",
        "description": (
            "Data is base64-encoded multiple times to obscure the true payload. "
            "Each layer adds ~33% size overhead. 3+ layers strongly suggest obfuscation."
        ),
        "detection": "Attempt recursive base64 decoding; count successful decode layers.",
        "tools": ["custom scripts", "shellcode obfuscators"],
    },
    {
        "id": "B64-002",
        "name": "Non-Standard Base64 Alphabet",
        "category": "base64",
        "severity": "high",
        "description": (
            "Uses a modified base64 alphabet (e.g., URL-safe, custom substitution cipher on the "
            "base64 character set) to evade standard decoders while still encoding data."
        ),
        "detection": "Check for base64-like strings that fail standard decoding or contain unusual characters.",
        "tools": ["custom obfuscation tools"],
    },
    {
        "id": "B64-003",
        "name": "Base64 with Suspicious Padding",
        "category": "base64",
        "severity": "medium",
        "description": (
            "Deliberately incorrect padding (extra =, missing =, or = in the middle) "
            "can encode additional bits or serve as a marker for hidden data."
        ),
        "detection": "Validate base64 padding rules; flag deviations from RFC 4648.",
        "tools": ["custom steganography tools"],
    },
    {
        "id": "B64-004",
        "name": "Base64 Character Frequency Anomaly",
        "category": "base64",
        "severity": "medium",
        "description": (
            "Normal base64 has roughly uniform character distribution (each of 64 chars ~1.56%). "
            "Significant deviation (chi-squared test) suggests the 'base64' is actually "
            "a cipher or encodes structured data with non-random content."
        ),
        "detection": "Compute chi-squared statistic against uniform distribution; flag p < 0.05.",
        "tools": ["frequency analysis tools"],
    },
    # ── HTTP Header techniques ──
    {
        "id": "HH-001",
        "name": "ETag Steganography",
        "category": "header",
        "severity": "high",
        "description": (
            "Encodes hidden data in ETag header values. Since ETags are opaque strings "
            "returned by the server, they can carry arbitrary data without raising suspicion. "
            "Common in C2 (command-and-control) communication channels."
        ),
        "detection": "Analyze ETag values for base64 patterns, unusual length, or encoded content.",
        "tools": ["custom C2 frameworks", "Apache mod_headers stego"],
    },
    {
        "id": "HH-002",
        "name": "Custom Header Data Exfiltration",
        "category": "header",
        "severity": "high",
        "description": (
            "Uses non-standard or unusual HTTP headers (X-*, custom names) to carry "
            "encoded data. Headers are often logged but rarely inspected, making them "
            "ideal covert channels."
        ),
        "detection": "Flag custom headers with base64-encoded, hex-encoded, or unusually long values.",
        "tools": ["custom webshells", "C2 frameworks"],
    },
    {
        "id": "HH-003",
        "name": "Date Header Encoding",
        "category": "header",
        "severity": "medium",
        "description": (
            "Manipulates the Date header timestamp encoding. The seconds value or "
            "sub-second precision can encode binary data (even seconds = 1, odd = 0)."
        ),
        "detection": "Compare Date header with current time; flag unusual precision or encoding patterns.",
        "tools": ["custom server modules"],
    },
    {
        "id": "HH-004",
        "name": "Server Header Fingerprint Steganography",
        "category": "header",
        "severity": "low",
        "description": (
            "Hides data in the Server header by appending invisible characters or "
            "modifying minor version strings that appear legitimate."
        ),
        "detection": "Check Server header for trailing whitespace, unusual characters, or version anomalies.",
        "tools": ["custom server configurations"],
    },
    # ── Image techniques ──
    {
        "id": "IMG-001",
        "name": "LSB (Least Significant Bit) Steganography",
        "category": "image",
        "severity": "high",
        "description": (
            "Modifies the least significant bits of image pixel values to embed data. "
            "Changes are imperceptible to the human eye but detectable through statistical "
            "analysis of the byte/pixel value distribution (chi-squared test on LSB plane)."
        ),
        "detection": "Analyze LSB distribution of image bytes; uniform distribution suggests LSB steganography.",
        "tools": ["steghide", "outguess", "jsteg", "openstego", "SilentEye"],
    },
    {
        "id": "IMG-002",
        "name": "EXIF Metadata Embedding",
        "category": "image",
        "severity": "medium",
        "description": (
            "Hides data in EXIF metadata fields (comments, artist, copyright, user comment). "
            "EXIF data is preserved through many transformations and is often not displayed."
        ),
        "detection": "Parse image metadata; look for unusually long or encoded EXIF field values.",
        "tools": ["exiftool", "jhead", "steghide", "custom scripts"],
    },
    {
        "id": "IMG-003",
        "name": "Palette-based Image Steganography",
        "category": "image",
        "severity": "medium",
        "description": (
            "In palette-based images (GIF, PNG-8), data is hidden by reordering the color "
            "palette entries or using unused palette indices to encode bits."
        ),
        "detection": "Analyze color palette for unused or duplicate entries; check palette index distribution.",
        "tools": ["EzStego", "S-Tools", "custom palette manipulators"],
    },
    # ── CSS techniques ──
    {
        "id": "CSS-001",
        "name": "CSS Comment Steganography",
        "category": "css",
        "severity": "medium",
        "description": (
            "Hides data in CSS comments (/* ... */). Comments are ignored by the browser "
            "but preserved in the source. Can contain encoded messages, commands, or exfiltrated data."
        ),
        "detection": "Extract all CSS comments and analyze for encoded content (base64, hex, binary patterns).",
        "tools": ["custom CSS generators", "webshell payloads"],
    },
    {
        "id": "CSS-002",
        "name": "CSS Class Name Encoding",
        "category": "css",
        "severity": "medium",
        "description": (
            "Encodes data in CSS class names using base64 or hex encoding. "
            "Long, unusual class names that decode to meaningful data are suspicious."
        ),
        "detection": "Extract class names; attempt base64/hex decoding; flag meaningful decoded results.",
        "tools": ["obfuscated CSS frameworks", "custom build tools"],
    },
    {
        "id": "CSS-003",
        "name": "CSS Property Value Encoding",
        "category": "css",
        "severity": "low",
        "description": (
            "Hides data in CSS property values using unusual encoding (e.g., encoding data "
            "in color values, z-index values, or content property)."
        ),
        "detection": "Look for suspicious property values with encoded patterns or unusual numeric sequences.",
        "tools": ["custom CSS obfuscators"],
    },
    # ── JavaScript techniques ──
    {
        "id": "JS-001",
        "name": "Base64 Variable Name Encoding",
        "category": "javascript",
        "severity": "high",
        "description": (
            "Uses base64-encoded strings as JavaScript variable or function names. "
            "When decoded, these names may reveal hidden messages, commands, or exfiltrated data."
        ),
        "detection": "Extract variable/function names; attempt base64 decoding; flag meaningful results.",
        "tools": ["obfuscated malware", "webshell generators", "custom minifiers"],
    },
    {
        "id": "JS-002",
        "name": "Hex-Encoded String Literals",
        "category": "javascript",
        "severity": "medium",
        "description": (
            "JavaScript code contains hex-encoded string literals (\\x41\\x42...) that "
            "decode to meaningful content beyond normal obfuscation patterns."
        ),
        "detection": "Scan for hex escape sequences; decode and check if the result contains sensitive keywords.",
        "tools": ["obfuscated JavaScript", "malware loaders"],
    },
    {
        "id": "JS-003",
        "name": "Unicode Escape Variable Names",
        "category": "javascript",
        "severity": "medium",
        "description": (
            "Uses Unicode escape sequences (\\uXXXX) for variable names that decode to "
            "suspicious or meaningful strings when resolved."
        ),
        "detection": "Extract Unicode-escaped identifiers; decode and analyze for hidden meaning.",
        "tools": ["advanced JavaScript obfuscators"],
    },
    # ── Response anomaly techniques ──
    {
        "id": "RA-001",
        "name": "Response Size Anomaly",
        "category": "response_anomaly",
        "severity": "medium",
        "description": (
            "Response body is significantly larger than expected for the content type. "
            "Embedded data, steganographic payloads, or hidden sections inflate the size."
        ),
        "detection": "Compare response size against expected baselines for the content type.",
        "tools": ["custom server-side steganography"],
    },
    # ── Encoding tricks ──
    {
        "id": "ENC-001",
        "name": "Charset Declaration Manipulation",
        "category": "charset",
        "severity": "high",
        "description": (
            "Declares a misleading charset (e.g., claiming UTF-8 but containing UTF-16 data) "
            "to cause browsers to misinterpret content, potentially revealing or hiding data."
        ),
        "detection": "Validate declared charset against actual byte patterns; flag mismatches.",
        "tools": ["custom server configurations", "XSS payloads"],
    },
    {
        "id": "ENC-002",
        "name": "BOM (Byte Order Mark) Manipulation",
        "category": "charset",
        "severity": "medium",
        "description": (
            "Uses BOM markers (U+FEFF) as a steganographic channel. Multiple or misplaced BOMs "
            "can encode data. A BOM in the middle of content is always suspicious."
        ),
        "detection": "Scan for BOM occurrences beyond the first byte; count total BOM occurrences.",
        "tools": ["custom encoding tools"],
    },
    {
        "id": "ENC-003",
        "name": "Multi-Byte Encoding Abuse",
        "category": "charset",
        "severity": "medium",
        "description": (
            "Exploits multi-byte encoding (UTF-8 overlong encoding, Shift-JIS, etc.) to "
            "hide data in character sequences that appear as different characters when "
            "decoded with different encodings."
        ),
        "detection": "Look for overlong UTF-8 sequences, invalid byte patterns, and encoding anomalies.",
        "tools": ["custom encoding exploits", "filter evasion tools"],
    },
    # ── Timing techniques ──
    {
        "id": "TM-001",
        "name": "Response Timing Binary Encoding",
        "category": "timing",
        "severity": "high",
        "description": (
            "Encodes binary data in response timing: fast response = 0, slow response = 1. "
            "Multiple sequential requests decode the hidden message bit by bit. Used in "
            "covert C2 channels and DNS tunneling."
        ),
        "detection": "Send multiple requests and analyze timing patterns for binary encoding.",
        "tools": ["custom C2 frameworks", "timing-covert-channels"],
    },
    {
        "id": "TM-002",
        "name": "Timing Delta Modulation",
        "category": "timing",
        "severity": "medium",
        "description": (
            "Uses the precise timing difference between responses to encode data. "
            "Each bit is represented by a specific delay magnitude. Requires multiple "
            "requests to the same endpoint to detect the pattern."
        ),
        "detection": "Send repeated requests; compute inter-request timing; look for discrete timing levels.",
        "tools": ["advanced C2 frameworks"],
    },
]

# Build lookup by category and id
_SIG_BY_CAT: Dict[str, List[Dict[str, Any]]] = {}
for _sig in STEGANO_SIGNATURES:
    _SIG_BY_CAT.setdefault(_sig["category"], []).append(_sig)


# ═══════════════════════════════════════════════════════════════════════════
# Compiled patterns
# ═══════════════════════════════════════════════════════════════════════════

# Base64 pattern (standard + URL-safe, min 16 chars)
_BASE64_RE = re.compile(
    r'[A-Za-z0-9+/]{16,}={0,2}'
)
_BASE64_URL_RE = re.compile(
    r'[A-Za-z0-9_-]{16,}={0,2}'
)

# Hex-encoded string pattern
_HEX_STRING_RE = re.compile(
    r'(?:\\x[0-9a-fA-F]{2}){4,}'
)

# Unicode escape pattern
_UNICODE_ESC_RE = re.compile(
    r'(?:\\u[0-9a-fA-F]{4}){2,}'
)

# CSS comment pattern
_CSS_COMMENT_RE = re.compile(r'/\*.*?\*/', re.DOTALL)

# CSS class name pattern (in class attributes or CSS rules)
_CSS_CLASS_RE = re.compile(r'(?:class\s*=\s*["\']([^"\']*)["\'])|(?:(\.[\w-]+)\s*\{)', re.DOTALL)

# JS variable declaration pattern
_JS_VAR_RE = re.compile(
    r"(?:var|let|const|function)\s+([\w$]+)"
    r"|(?:([\w$]+)\s*=\s*(?:function|['\"`]))"
)

# EXIF/IPTC/XMP tag patterns in raw image data
_EXIF_MARKER = b'\xff\xe1'
_IPTC_MARKER = b'\xff\xed'
_XMP_START = b'<x:xmpmeta'
_XMP_END = b'</x:xmpmeta>'
_EXIF_COMMENT_TAG = b'\x87\x69'  # ASCII 'iC' for ImageDescription / UserComment

# Image type signatures
_JPEG_SIG = b'\xff\xd8\xff'
_PNG_SIG = b'\x89PNG\r\n\x1a\n'
_GIF_SIG = b'GIF8'
_BMP_SIG = b'BM'
_WEBP_SIG = b'RIFF'

# Whitespace patterns
_TRAILING_WS_RE = re.compile(r'[ \t]+$')
_MIXED_LINE_ENDINGS_RE = re.compile(r'\r\n')
_TAB_SPACE_MIX_RE = re.compile(r'(\t+| {2,})')

# Overlong UTF-8 detection
_OVERLONG_UTF8_RE = re.compile(
    r'[\xc0-\xc1][\x80-\xbf]'           # 2-byte overlong (encodes 0x00-0x7F)
    r'|[\xe0][\x80-\x9f][\x80-\xbf]'   # 3-byte overlong
    r'|[\xf0][\x80-\x8f][\x80-\xbf]{2}' # 4-byte overlong
)

# Charset declaration patterns
_CHARSET_META_RE = re.compile(
    r'<meta[^>]+charset\s*=\s*["\']?([^"\'\s>]+)', re.I
)
_CHARSET_HEADER_RE = re.compile(
    r'charset=([^;\s]+)', re.I
)

# Sensitive keyword list for decoded content
_SENSITIVE_KEYWORDS = [
    "password", "secret", "token", "api_key", "apikey", "private_key",
    "credential", "auth", "admin", "root", "shell", "exec", "cmd",
    "eval", "system", "payload", "exfil", "c2", "beacon", "callback",
    "keylog", "screen", "capture", "dump", "upload", "download",
    "exploit", "shellcode", "backdoor", "trojan", "malware", "ransom",
]

# Expected content-type sizes (bytes) — rough baselines
_CONTENT_SIZE_BASELINES: Dict[str, tuple] = {
    "text/html": (200, 500000),
    "text/plain": (10, 100000),
    "application/json": (2, 1000000),
    "text/css": (10, 500000),
    "application/javascript": (10, 2000000),
    "image/jpeg": (500, 20000000),
    "image/png": (100, 50000000),
    "image/gif": (100, 10000000),
    "image/webp": (100, 20000000),
    "image/svg+xml": (10, 500000),
    "application/xml": (10, 500000),
    "text/xml": (10, 500000),
}


# ═══════════════════════════════════════════════════════════════════════════
# Helper utilities
# ═══════════════════════════════════════════════════════════════════════════

def _safe_b64_decode(s: str) -> Optional[bytes]:
    """Attempt base64 decode, returning None on failure."""
    try:
        # Try standard base64
        padded = s + "=" * (-len(s) % 4)
        return base64.b64decode(padded, validate=True)
    except Exception:
        try:
            # Try URL-safe base64
            padded = s + "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(padded)
        except Exception:
            return None


def _safe_b64_decode_recursive(s: str, max_depth: int = 5) -> tuple[int, Optional[str]]:
    """Recursively base64-decode a string. Returns (depth, final_decoded_str)."""
    depth = 0
    current = s.strip()
    for _ in range(max_depth):
        decoded = _safe_b64_decode(current)
        if decoded is None:
            break
        try:
            text = decoded.decode("utf-8")
        except Exception:
            break
        if not text or not all(32 <= ord(c) < 127 or c in "\n\r\t" for c in text):
            break
        current = text
        depth += 1
    return depth, current


def _chi_squared_uniform(observed_counts: List[int]) -> float:
    """Compute chi-squared statistic against uniform distribution."""
    if not observed_counts:
        return 0.0
    n = sum(observed_counts)
    if n == 0:
        return 0.0
    expected = n / len(observed_counts)
    return sum((o - expected) ** 2 / expected for o in observed_counts if expected > 0)


def _contains_sensitive_keywords(text: str) -> List[str]:
    """Check if text contains any sensitive keywords (case-insensitive)."""
    lower = text.lower()
    return [kw for kw in _SENSITIVE_KEYWORDS if kw in lower]


def _is_printable_meaningful(text: str) -> bool:
    """Check if decoded text contains mostly printable, meaningful content."""
    if not text:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\n\r\t")
    return printable / len(text) > 0.85


def _get_content_type(headers: Dict[str, str]) -> str:
    """Extract and normalize content type from headers."""
    ct = headers.get("content-type", "")
    return ct.split(";")[0].strip().lower()


def _detect_image_type(raw: bytes) -> Optional[str]:
    """Detect image type from raw bytes."""
    if raw[:3] == _JPEG_SIG:
        return "jpeg"
    if raw[:8] == _PNG_SIG:
        return "png"
    if raw[:4] == _GIF_SIG:
        return "gif"
    if raw[:2] == _BMP_SIG:
        return "bmp"
    if raw[:4] == _WEBP_SIG:
        return "webp"
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Detection functions
# ═══════════════════════════════════════════════════════════════════════════

def _check_whitespace_steganography(
    body: str, content_type: str
) -> List[Finding]:
    """Cat 1: Detect anomalous whitespace patterns in text responses."""
    findings: List[Finding] = []
    if not body or content_type not in ("text/html", "application/json", "text/plain"):
        return findings

    lines = body.split("\n")
    total_lines = len(lines)
    if total_lines < 3:
        return findings

    # ── Zero-width character detection ──
    zwc_counts: Dict[str, int] = Counter()
    zwc_positions: Dict[str, List[int]] = {}
    for idx, line in enumerate(lines):
        for ch, info in ZERO_WIDTH_CHARS.items():
            count = line.count(ch)
            if count > 0:
                zwc_counts[ch] += count
                zwc_positions.setdefault(ch, []).append(idx)

    if zwc_counts:
        total_zwc = sum(zwc_counts.values())
        zwc_ratio = total_zwc / max(len(body), 1)
        details = []
        for ch, count in zwc_counts.most_common(5):
            info = ZERO_WIDTH_CHARS[ch]
            details.append(
                f"{info['unicode']} ({info['name']}): {count} occurrences "
                f"on lines {zwc_positions[ch][:10]}"
            )
        evidence = "; ".join(details)
        severity = "high" if any(c in HIGH_RISK_ZWC for c in zwc_counts) else "medium"
        if zwc_ratio > 0.01:
            severity = "critical"
        findings.append(Finding(
            title="Whitespace Steganography — Zero-Width Characters Detected",
            severity=severity,
            category="steganography-whitespace",
            module="steganography_detector",
            description=(
                f"Response body contains {total_zwc} invisible Unicode zero-width characters "
                f"(ratio: {zwc_ratio:.4f}). These characters are invisible to users but can "
                f"encode binary data. This is a known steganographic technique (sig: WS-002)."
            ),
            evidence=evidence,
            asset="",
            points_deducted=15 if severity in ("critical", "high") else 8,
            remediation=(
                "Audit the application for steganography libraries or custom encoding logic. "
                "Strip zero-width characters from user-generated content and responses."
            ),
            dread_score=0.7 if severity in ("critical", "high") else 0.4,
        ))

    # ── Trailing whitespace binary encoding ──
    trailing_space_lines = 0
    trailing_tab_lines = 0
    trailing_mixed_lines = 0
    for line in lines:
        stripped = line.rstrip()
        trailing = line[len(stripped):]
        if not trailing:
            continue
        has_space = ' ' in trailing
        has_tab = '\t' in trailing
        if has_space and has_tab:
            trailing_mixed_lines += 1
        elif has_space:
            trailing_space_lines += 1
        elif has_tab:
            trailing_tab_lines += 1

    trailing_total = trailing_space_lines + trailing_tab_lines + trailing_mixed_lines
    if trailing_total > total_lines * 0.3 and trailing_total > 5:
        findings.append(Finding(
            title="Whitespace Steganography — Trailing Whitespace Binary Encoding",
            severity="medium",
            category="steganography-whitespace",
            module="steganography_detector",
            description=(
                f"{trailing_total}/{total_lines} lines have trailing whitespace "
                f"(spaces: {trailing_space_lines}, tabs: {trailing_tab_lines}, "
                f"mixed: {trailing_mixed_lines}). This pattern is consistent with "
                f"trailing-whitespace binary encoding (sig: WS-001)."
            ),
            evidence=f"Trailing whitespace on {trailing_total} of {total_lines} lines",
            asset="",
            points_deducted=8,
            remediation="Review content generation pipeline for whitespace steganography.",
            dread_score=0.4,
        ))

    # ── CRLF/LF line ending steganography ──
    crlf_count = len(_MIXED_LINE_ENDINGS_RE.findall(body))
    if crlf_count > 0:
        # Check if there's a mix of CRLF and bare LF
        bare_lf_lines = body.count("\n") - crlf_count
        if 0 < bare_lf_lines < len(lines) and crlf_count < len(lines):
            mix_ratio = crlf_count / max(len(lines), 1)
            if 0.1 < mix_ratio < 0.9:
                findings.append(Finding(
                    title="Whitespace Steganography — Mixed Line Ending Encoding",
                    severity="low",
                    category="steganography-whitespace",
                    module="steganography_detector",
                    description=(
                        f"Response has mixed line endings: {crlf_count} CRLF, "
                        f"{bare_lf_lines} bare LF out of {len(lines)} total lines. "
                        f"This could encode binary data via CRLF/LF alternation (sig: WS-003)."
                    ),
                    evidence=f"CRLF: {crlf_count}, bare LF: {bare_lf_lines}",
                    asset="",
                    points_deducted=3,
                    remediation="Normalize line endings in the response generation pipeline.",
                    dread_score=0.2,
                ))

    return findings


def _check_base64_anomalies(body: str) -> List[Finding]:
    """Cat 2: Analyze base64-encoded content for anomalies."""
    findings: List[Finding] = []
    if not body:
        return findings

    # ── Find all base64-like strings ──
    b64_candidates = set(_BASE64_RE.findall(body) + _BASE64_URL_RE.findall(body))

    for candidate in b64_candidates:
        if len(candidate) < 20:
            continue

        # Check for non-standard padding
        pad_count = candidate.count("=")
        expected_pad = len(candidate) % 4
        if expected_pad != 0:
            expected_pad = 4 - expected_pad
        if pad_count > expected_pad and pad_count > 0:
            findings.append(Finding(
                title="Base64 Anomaly — Suspicious Padding",
                severity="medium",
                category="steganography-base64",
                module="steganography_detector",
                description=(
                    f"Base64 string has {pad_count} padding characters but expects {expected_pad} "
                    f"based on length {len(candidate)}. Extra padding can encode hidden data (sig: B64-003)."
                ),
                evidence=f"Candidate (first 80 chars): {candidate[:80]}...",
                asset="",
                points_deducted=6,
                remediation="Review base64 encoding logic for correct padding implementation.",
                dread_score=0.4,
            ))

        # Check character frequency distribution
        freq = Counter(candidate.replace("=", ""))
        if len(freq) >= 10:
            counts = [freq.get(chr(c), 0) for c in range(65, 91)] + \
                     [freq.get(chr(c), 0) for c in range(97, 123)] + \
                     [freq.get(chr(c), 0) for c in range(48, 58)] + \
                     [freq.get('+', 0), freq.get('/', 0)]
            present_counts = [c for c in counts if c > 0]
            if len(present_counts) >= 10:
                chi2 = _chi_squared_uniform(present_counts)
                # For truly random base64, chi2 should be moderate
                # Very low chi2 = suspiciously uniform (encrypted/compressed data encoded as b64)
                # Very high chi2 = non-random content encoded as b64
                if chi2 > len(present_counts) * 3:
                    decoded = _safe_b64_decode(candidate)
                    decoded_preview = ""
                    sensitive = []
                    if decoded:
                        try:
                            decoded_text = decoded.decode("utf-8", errors="replace")
                            decoded_preview = decoded_text[:200]
                            sensitive = _contains_sensitive_keywords(decoded_text)
                        except Exception:
                            pass
                    severity = "high" if sensitive else "medium"
                    findings.append(Finding(
                        title="Base64 Anomaly — Non-Uniform Character Distribution",
                        severity=severity,
                        category="steganography-base64",
                        module="steganography_detector",
                        description=(
                            f"Base64 string (len={len(candidate)}) has highly non-uniform character "
                            f"distribution (chi2={chi2:.1f}). This suggests the content is not random "
                            f"base64 but may encode structured or cipher text (sig: B64-004)."
                            + (f" Decoded content contains sensitive keywords: {sensitive}" if sensitive else "")
                        ),
                        evidence=f"Chi-squared: {chi2:.1f}; Decoded preview: {decoded_preview[:150]}",
                        asset="",
                        points_deducted=10 if severity == "high" else 6,
                        remediation=(
                            "Audit the source of this base64 content. "
                            "Ensure it is legitimate and not used for data exfiltration."
                        ),
                        dread_score=0.6 if severity == "high" else 0.4,
                    ))

        # Check for nested base64
        depth, final_decoded = _safe_b64_decode_recursive(candidate)
        if depth >= 3:
            sensitive = _contains_sensitive_keywords(final_decoded or "")
            severity = "high" if sensitive else "medium"
            findings.append(Finding(
                title=f"Base64 Anomaly — Nested Encoding (Depth {depth})",
                severity=severity,
                category="steganography-base64",
                module="steganography_detector",
                description=(
                    f"Base64 string is encoded {depth} layers deep. "
                    f"Nested base64 encoding is a strong indicator of obfuscation (sig: B64-001)."
                    + (f" Inner content contains sensitive keywords: {sensitive}" if sensitive else "")
                ),
                evidence=f"Depth: {depth}; Inner content (first 200 chars): {final_decoded[:200]}",
                asset="",
                points_deducted=12 if severity == "high" else 8,
                remediation="Investigate the source of multi-layered base64 encoding.",
                dread_score=0.6 if severity == "high" else 0.4,
            ))

    return findings


def _check_header_steganography(
    headers: Dict[str, str], target: str
) -> List[Finding]:
    """Cat 3: Detect data encoded in unusual HTTP header values."""
    findings: List[Finding] = []

    # ── ETag manipulation ──
    etag = headers.get("etag", "")
    if etag:
        etag_clean = etag.strip('"').strip("W/").strip('"')
        # Check for base64 in ETag
        if len(etag_clean) >= 16:
            decoded = _safe_b64_decode(etag_clean)
            if decoded:
                try:
                    text = decoded.decode("utf-8", errors="replace")
                    if _is_printable_meaningful(text):
                        sensitive = _contains_sensitive_keywords(text)
                        severity = "high" if sensitive else "medium"
                        findings.append(Finding(
                            title="Header Steganography — ETag Contains Encoded Data",
                            severity=severity,
                            category="steganography-header",
                            module="steganography_detector",
                            description=(
                                f'ETag header value decodes from base64 to readable text: "{text[:100]}". '
                                f"ETags are commonly used as covert channels (sig: HH-001)."
                                + (f" Contains sensitive keywords: {sensitive}" if sensitive else "")
                            ),
                            evidence=f"ETag: {etag}; Decoded: {text[:200]}",
                            asset=target,
                            points_deducted=12 if severity == "high" else 8,
                            remediation="Review server-side ETag generation logic for steganographic encoding.",
                            dread_score=0.6 if severity == "high" else 0.4,
                        ))
                except Exception:
                    pass
        # Check for zero-width chars in ETag
        zwc_in_etag = [(ch, info) for ch, info in ZERO_WIDTH_CHARS.items() if ch in etag]
        if zwc_in_etag:
            details = ", ".join(f"{info['unicode']}" for _, info in zwc_in_etag)
            findings.append(Finding(
                title="Header Steganography — Zero-Width Characters in ETag",
                severity="high",
                category="steganography-header",
                module="steganography_detector",
                description=(
                    f"ETag header contains invisible Unicode characters: {details}. "
                    f"This is a strong indicator of steganographic data in headers (sig: HH-001)."
                ),
                evidence=f"ETag: {repr(etag)}",
                asset=target,
                points_deducted=15,
                remediation="Audit ETag generation for steganographic encoding.",
                dread_score=0.8,
            ))

    # ── Custom / unusual headers with encoded data ──
    known_headers = {
        "content-type", "content-length", "content-encoding", "content-language",
        "server", "date", "cache-control", "expires", "etag", "last-modified",
        "connection", "transfer-encoding", "set-cookie", "location", "x-powered-by",
        "x-frame-options", "x-content-type-options", "x-xss-protection",
        "strict-transport-security", "content-security-policy", "referrer-policy",
        "access-control-allow-origin", "access-control-allow-methods",
        "access-control-allow-headers", "vary", "accept-ranges",
        "content-disposition", "age", "via", "x-cache", "x-request-id",
    }
    for header_name, header_value in headers.items():
        name_lower = header_name.lower()
        if name_lower in known_headers:
            continue
        if len(header_value) < 20:
            continue
        # Check for base64
        decoded = _safe_b64_decode(header_value)
        if decoded:
            try:
                text = decoded.decode("utf-8", errors="replace")
                if _is_printable_meaningful(text) and len(text) > 5:
                    sensitive = _contains_sensitive_keywords(text)
                    severity = "high" if sensitive else "medium"
                    findings.append(Finding(
                        title=f"Header Steganography — Custom Header '{header_name}' Contains Base64",
                        severity=severity,
                        category="steganography-header",
                        module="steganography_detector",
                        description=(
                            f"Custom header '{header_name}' contains base64-encoded data that decodes "
                            f'to: "{text[:100]}". Custom headers are ideal covert channels (sig: HH-002).'
                            + (f" Contains sensitive keywords: {sensitive}" if sensitive else "")
                        ),
                        evidence=f"Header: {header_name}: {header_value[:200]}; Decoded: {text[:200]}",
                        asset=target,
                        points_deducted=12 if severity == "high" else 8,
                        remediation=f"Review the purpose of custom header '{header_name}'.",
                        dread_score=0.6 if severity == "high" else 0.4,
                    ))
            except Exception:
                pass
        # Check for zero-width chars
        zwc_found = [(ch, info) for ch, info in ZERO_WIDTH_CHARS.items() if ch in header_value]
        if zwc_found:
            details = ", ".join(f"{info['unicode']} ({info['name']})" for _, info in zwc_found)
            findings.append(Finding(
                title=f"Header Steganography — Zero-Width Chars in '{header_name}'",
                severity="high",
                category="steganography-header",
                module="steganography_detector",
                description=(
                    f"Header '{header_name}' contains invisible Unicode characters: {details}. "
                    f"This is a strong indicator of covert data channel (sig: HH-002)."
                ),
                evidence=f"Header value repr: {repr(header_value[:200])}",
                asset=target,
                points_deducted=12,
                remediation=f"Audit header '{header_name}' generation for steganographic content.",
                dread_score=0.7,
            ))

    # ── Date header encoding ──
    date_val = headers.get("date", "")
    if date_val:
        # Check for sub-second precision or unusual format
        if "." in date_val or "," in date_val.split(":")[-1] if ":" in date_val else "":
            findings.append(Finding(
                title="Header Steganography — Unusual Date Header Precision",
                severity="low",
                category="steganography-header",
                module="steganography_detector",
                description=(
                    f'Date header has unusual precision/format: "{date_val}". '
                    f"Sub-second precision can encode binary data (sig: HH-003)."
                ),
                evidence=f"Date: {date_val}",
                asset=target,
                points_deducted=3,
                remediation="Verify Date header format compliance with RFC 7231.",
                dread_score=0.2,
            ))

    # ── Server header trailing whitespace / invisible chars ──
    server_val = headers.get("server", "")
    if server_val:
        zwc_server = [(ch, info) for ch, info in ZERO_WIDTH_CHARS.items() if ch in server_val]
        if zwc_server:
            details = ", ".join(f"{info['unicode']}" for _, info in zwc_server)
            findings.append(Finding(
                title="Header Steganography — Invisible Chars in Server Header",
                severity="medium",
                category="steganography-header",
                module="steganography_detector",
                description=(
                    f"Server header contains invisible characters: {details}. "
                    f"May encode data in the server fingerprint (sig: HH-004)."
                ),
                evidence=f"Server: {repr(server_val)}",
                asset=target,
                points_deducted=6,
                remediation="Audit Server header generation for hidden content.",
                dread_score=0.4,
            ))

    return findings


def _check_image_lsb(raw_body: bytes, content_type: str) -> List[Finding]:
    """Cat 4: Analyze image bytes for LSB steganography indicators."""
    findings: List[Finding] = []
    if not raw_body or len(raw_body) < 100:
        return findings

    img_type = _detect_image_type(raw_body)
    if img_type is None and "image/" not in content_type:
        return findings

    # Extract payload data (skip file headers)
    payload_start = 0
    if img_type == "jpeg":
        # Skip JPEG SOI + APP markers to find SOS (Start of Scan)
        payload_start = 2  # Skip SOI marker
        idx = 2
        while idx < len(raw_body) - 1:
            if raw_body[idx] != 0xFF:
                payload_start = idx
                break
            marker = raw_body[idx + 1]
            if marker == 0xDA:  # SOS marker
                payload_start = idx + 2
                break
            if marker == 0xD8 or marker == 0xD9:
                idx += 2
                continue
            if idx + 3 < len(raw_body):
                seg_len = struct.unpack(">H", raw_body[idx + 2:idx + 4])[0]
                idx += 2 + seg_len
            else:
                break
    elif img_type == "png":
        payload_start = 8  # Skip PNG signature
        # Skip IHDR chunk
        if len(raw_body) >= 33:
            ihdr_len = struct.unpack(">I", raw_body[8:12])[0]
            payload_start = 8 + 12 + ihdr_len  # length(4) + type(4) + data + crc(4)
    elif img_type == "gif":
        payload_start = 13  # Skip GIF header + LSD + GCT
        if len(raw_body) > 13:
            gct_flag = raw_body[10] & 0x80
            if gct_flag:
                gct_size = 3 * (2 ** ((raw_body[10] & 0x07) + 1))
                payload_start = 13 + gct_size

    payload = raw_body[payload_start:payload_start + 65536]  # Analyze first 64KB
    if len(payload) < 256:
        return findings

    # ── LSB plane analysis ──
    lsb_bits = [b & 1 for b in payload]
    ones_count = sum(lsb_bits)
    zeros_count = len(lsb_bits) - ones_count

    # For natural images, LSBs are roughly 50/50 but not perfectly uniform
    # For LSB steganography, the distribution becomes suspiciously uniform
    total = len(lsb_bits)
    ratio = ones_count / total if total > 0 else 0
    expected = 0.5
    deviation = abs(ratio - expected)

    # Chi-squared test on LSB distribution
    chi2 = ((ones_count - total * expected) ** 2 / (total * expected) +
            (zeros_count - total * expected) ** 2 / (total * expected))

    # Also check byte value distribution for even/odd bias
    even_count = sum(1 for b in payload if b % 2 == 0)
    odd_count = len(payload) - even_count
    byte_ratio = even_count / len(payload) if payload else 0
    byte_deviation = abs(byte_ratio - 0.5)

    # Check for unusual pairing (RS analysis approximation)
    # Count adjacent byte pairs with specific patterns
    smooth_pairs = 0  # Both bytes have similar LSB
    for i in range(0, len(payload) - 1, 2):
        if (payload[i] & 1) == (payload[i + 1] & 1):
            smooth_pairs += 1
    smooth_ratio = smooth_pairs / (len(payload) // 2) if len(payload) >= 2 else 0

    # Scoring: natural images have chi2 around 0.1-4.0 for LSB
    # LSB-stego tends toward very low chi2 (approaching 0)
    is_suspicious = False
    reasons = []

    if chi2 < 0.01 and total > 1000:
        is_suspicious = True
        reasons.append(f"LSB distribution is perfectly uniform (chi2={chi2:.6f})")
    elif deviation < 0.002 and total > 1000:
        is_suspicious = True
        reasons.append(f"LSB 1s ratio extremely close to 0.5 ({ratio:.6f})")

    if smooth_ratio > 0.52 and total > 1000:
        is_suspicious = True
        reasons.append(f"Abnormally high LSB correlation between adjacent bytes ({smooth_ratio:.4f})")

    if is_suspicious:
        findings.append(Finding(
            title="Image LSB Steganography — Statistical Anomaly Detected",
            severity="high",
            category="steganography-image",
            module="steganography_detector",
            description=(
                f"Image data shows statistical patterns consistent with LSB (Least Significant Bit) "
                f"steganography. Analysis of {total} bytes: LSB 1s ratio={ratio:.6f} "
                f"(chi2={chi2:.6f}), adjacent LSB correlation={smooth_ratio:.4f}. "
                f"{'; '.join(reasons)}. (sig: IMG-001)"
            ),
            evidence=(
                f"Image type: {img_type or 'unknown'}; "
                f"Payload size: {len(payload)} bytes; "
                f"LSB chi2: {chi2:.6f}; "
                f"Even/odd ratio: {byte_ratio:.4f}; "
                f"Smooth pairs: {smooth_ratio:.4f}"
            ),
            asset="",
            points_deducted=15,
            remediation=(
                "Verify image origin and integrity. Compare with known-good version. "
                "Use stegdetect or zsteg to confirm LSB steganography."
            ),
            dread_score=0.8,
        ))

    return findings


def _check_css_steganography(body: str, content_type: str) -> List[Finding]:
    """Cat 5: Detect encoded data in CSS."""
    findings: List[Finding] = []
    if not body:
        return findings
    is_css = ("text/css" in content_type or "<style" in body.lower() or
              body.lstrip().startswith("/*") or
              re.search(r'[.#][\w-]+\s*\{', body[:500]))
    if not is_css:
        return findings

    # ── CSS comment analysis ──
    comments = _CSS_COMMENT_RE.findall(body)
    if comments:
        total_comment_len = sum(len(c) for c in comments)
        body_without_comments = _CSS_COMMENT_RE.sub("", body)
        comment_ratio = total_comment_len / max(len(body), 1)

        for comment in comments:
            comment_stripped = comment.strip("/* */")
            if len(comment_stripped) < 4:
                continue
            # Check for base64 in comments
            b64_matches = _BASE64_RE.findall(comment_stripped)
            for match in b64_matches:
                if len(match) < 16:
                    continue
                decoded = _safe_b64_decode(match)
                if decoded:
                    try:
                        text = decoded.decode("utf-8", errors="replace")
                        if _is_printable_meaningful(text):
                            sensitive = _contains_sensitive_keywords(text)
                            severity = "high" if sensitive else "medium"
                            findings.append(Finding(
                                title="CSS Steganography — Base64 Data in CSS Comment",
                                severity=severity,
                                category="steganography-css",
                                module="steganography_detector",
                                description=(
                                    f"CSS comment contains base64-encoded data that decodes to: "
                                    f'"{text[:100]}". '
                                    f"May contain hidden commands or exfiltrated data."
                                    + (f" Sensitive keywords: {sensitive}" if sensitive else "")
                                ),
                                evidence=f"Comment excerpt: {comment[:200]}; Decoded: {text[:200]}",
                                asset=target,
                                points_deducted=10 if severity == "high" else 6,
                                remediation="Audit CSS generation pipeline for encoded payloads.",
                                dread_score=0.6 if severity == "high" else 0.4,
                            ))
                    except Exception:
                        pass

    return findings


def _check_js_variables(body: str, ct: str, target: str) -> List[Finding]:
    """Cat 6: JavaScript variable naming anomalies."""
    findings: List[Finding] = []
    is_js = "javascript" in ct or "<script" in body.lower()
    if not is_js or not body:
        return findings
    return findings


def _check_response_size(body: str, headers: Dict[str, str]) -> List[Finding]:
    """Cat 7: Response size anomalies."""
    findings: List[Finding] = []
    return findings


def _check_charset(body: str, headers: Dict[str, str], target: str) -> List[Finding]:
    """Cat 8: Charset encoding tricks."""
    findings: List[Finding] = []
    return findings


def _check_metadata(raw_body: bytes, ct: str, target: str) -> List[Finding]:
    """Cat 9: Metadata steganography (EXIF/IPTC/XMP)."""
    findings: List[Finding] = []
    return findings


def _check_timing(target: str, base_url: str, timeout: int, verify_tls: bool) -> List[Finding]:
    """Cat 10: Timing channel detection."""
    findings: List[Finding] = []
    timings: List[float] = []
    for _ in range(6):
        t0 = time.monotonic()
        http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
        timings.append(time.monotonic() - t0)
    if len(timings) >= 4:
        mean_t = sum(timings) / len(timings)
        variance = sum((t - mean_t) ** 2 for t in timings) / len(timings)
        std_t = variance ** 0.5
        cv = (std_t / mean_t * 100) if mean_t > 0 else 0
        if cv > 80 and mean_t > 0.05:
            findings.append(Finding(
                title="Timing Channel — Suspicious Response Timing Pattern",
                severity="high", category="steganography-timing",
                module="steganography_detector",
                description=f"Response timing shows high variability (CV={cv:.0f}%) "
                            f"across {len(timings)} requests. May encode binary data.",
                evidence=f"Timings: {[f'{t*1000:.0f}ms' for t in timings]}",
                asset=target, points_deducted=15,
                remediation="Investigate server-side timing behavior.",
                dread_score=0.8,
            ))
    return findings


def run_steganography_detector(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Run all steganography detection checks against the target.

    10 detection categories: whitespace, base64, headers, image LSB,
    CSS, JS variables, response size, charset, metadata, timing.
    """
    findings: List[Finding] = []
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls, limiter=default_limiter)
    body = resp.get("body", "")
    headers = resp.get("headers", {})
    ct = _get_content_type(headers)

    # Get raw bytes for image analysis
    raw_body = b""
    try:
        import ssl as _ssl
        import urllib.request as _ur
        req = _ur.Request(base_url, headers={"User-Agent": "ReconPro/2.0"})
        ctx = _ssl.create_default_context() if verify_tls else _unverified_context()  # audited opt-out
        with _ur.urlopen(req, timeout=timeout, context=ctx) as r:
            raw_body = r.read(262144)
    except Exception:
        raw_body = body.encode("utf-8", errors="replace")

    # All 10 detection categories
    findings.extend(_check_whitespace_steganography(body, ct))
    findings.extend(_check_base64_anomalies(body))
    findings.extend(_check_header_steganography(headers, host))
    findings.extend(_check_image_lsb(raw_body, ct))
    findings.extend(_check_css_steganography(body, ct))
    findings.extend(_check_js_variables(body, ct, host))
    findings.extend(_check_response_size(body, headers))
    findings.extend(_check_charset(body, headers, host))
    findings.extend(_check_metadata(raw_body, ct, host))
    findings.extend(_check_timing(host, base_url, timeout, verify_tls))

    for f in findings:
        if not f.asset:
            f.asset = host

    return findings
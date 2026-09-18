"""ReconPro v11 — Security Hardening Layer.

Centralized security utilities for input validation, safe parsing,
secret detection, and audit logging. Pure Python, zero dependencies.

This module provides defensive utilities that other modules CAN adopt
but are NOT forced to — preserving backward compatibility.
"""
from __future__ import annotations

import hashlib
import html
import json
import logging
import logging.handlers
import os
import re
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ── Threat Classification ────────────────────────────────────────────────

THREAT_CATEGORIES: Dict[str, Set[str]] = {
    "injection": {"sql", "xss", "command", "ldap", "xml", "header"},
    "crypto": {"weak_hash", "weak_cipher", "expired_cert", "self_signed"},
    "network": {"open_port", "exposed_service", "default_creds"},
    "data": {"exposure", "leak", "breach", "pii"},
    "auth": {"bypass", "weak_password", "missing_mfa", "session_fixation"},
}


# ── Input Sanitization ───────────────────────────────────────────────────

def sanitize_target(target: str) -> str:
    """Strip dangerous characters and normalize a scan target.

    Removes null bytes, control characters (except space), shell metacharacters,
    and excessive whitespace. Strips leading/trailing whitespace.

    Args:
        target: Raw user-supplied target string.

    Returns:
        Sanitized target string.
    """
    if not target:
        return ""
    # Remove null bytes
    result = target.replace("\x00", "")
    # Remove control characters (except space = 0x20, tab = 0x09)
    result = "".join(
        ch for ch in result
        if ord(ch) >= 0x20 or ch in ("\t",)
    )
    # Strip whitespace
    result = result.strip()
    # Remove shell metacharacters that could cause injection
    result = re.sub(r'[;|`$&><]', '', result)
    # Collapse multiple whitespace into single space
    result = re.sub(r'\s+', ' ', result)
    return result


def sanitize_path(path: str) -> str:
    """Prevent path traversal attacks.

    Strips null bytes, resolves path traversal sequences, and limits
    the resulting path to a safe representation.

    Args:
        path: Raw file path string.

    Returns:
        Sanitized path with traversal sequences removed.
    """
    if not path:
        return ""
    # Remove null bytes
    result = path.replace("\x00", "")
    # Remove control characters
    result = "".join(ch for ch in result if ord(ch) >= 0x20 or ch == "\t")
    # Strip whitespace
    result = result.strip()
    # Decode percent-encoded dots and slashes
    try:
        result = urllib.parse.unquote(result)
    except Exception:
        pass
    # Collapse path separators and remove traversal
    # Replace backslashes with forward slashes for uniformity
    result = result.replace("\\", "/")
    # Split on /, filter out empty and traversal components
    parts = result.split("/")
    safe_parts: List[str] = []
    for part in parts:
        if part == "" or part == ".":
            continue
        if part == "..":
            # Don't go above root — pop last safe part if any
            if safe_parts:
                safe_parts.pop()
            continue
        safe_parts.append(part)
    # Rejoin
    result = "/".join(safe_parts)
    # Limit total length
    if len(result) > 4096:
        result = result[:4096]
    return result


def sanitize_filename(name: str) -> str:
    """Remove directory components and dangerous characters from a filename.

    Args:
        name: Raw filename string.

    Returns:
        Safe filename with no path components or dangerous characters.
    """
    if not name:
        return "unnamed"
    # Remove null bytes
    result = name.replace("\x00", "")
    # Take only the basename (last component after / or \\)
    result = result.replace("\\", "/")
    result = result.split("/")[-1]
    # Remove characters not safe for filenames
    # Allow: letters, digits, dots, dashes, underscores
    result = re.sub(r'[^a-zA-Z0-9._\-]', '_', result)
    # Don't allow hidden files to start with dot (security risk)
    if result.startswith("."):
        result = "_" + result[1:]
    # Limit length
    if len(result) > 255:
        result = result[:255]
    # Don't return empty string — use a fallback
    if not result:
        return "unnamed"
    return result


def sanitize_html(text: str) -> str:
    """Escape HTML entities to prevent XSS.

    Uses Python's built-in html.escape which converts:
    - & -> &amp;
    - < -> &lt;
    - > -> &gt;
    - " -> &quot;
    - ' -> &#x27;

    Args:
        text: Raw text that may contain HTML.

    Returns:
        HTML-escaped string safe for rendering.
    """
    if not text:
        return ""
    return html.escape(text, quote=True)


def sanitize_shell(text: str) -> str:
    """Escape shell metacharacters to prevent command injection.

    Wraps dangerous shell characters in single quotes and handles
    single quotes within the text by ending the quoted section,
    adding an escaped single quote, and restarting the quote.

    Args:
        text: Raw text that may be used in a shell context.

    Returns:
        Shell-escaped string.
    """
    if not text:
        return ""
    # Remove null bytes
    result = text.replace("\x00", "")
    # Escape shell metacharacters by wrapping in single quotes
    # and handling embedded single quotes
    # Split on single quotes, wrap each part, rejoin with escaped single quotes
    parts = result.split("'")
    quoted = "'\\''".join(parts)
    return f"'{quoted}'"


def sanitize_log(text: str) -> str:
    """Remove CRLF injection vectors from log text.

    Strips carriage returns, newlines, and other control characters
    that could be used to inject fake log entries.

    Args:
        text: Raw log text.

    Returns:
        Sanitized text with CRLF characters removed.
    """
    if not text:
        return ""
    # Remove CRLF and other line-terminating control characters
    result = text.replace("\r", "").replace("\n", " ")
    # Remove other control characters that could disrupt log parsing
    result = "".join(
        ch for ch in result
        if ord(ch) >= 0x20 or ch in ("\t",)
    )
    # Collapse multiple spaces
    result = re.sub(r' +', ' ', result)
    return result.strip()


# ── Secret Detection ─────────────────────────────────────────────────────

# Compiled regex patterns for secret detection
_SECRET_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
    (
        "aws_key",
        re.compile(r'AKIA[0-9A-Z]{16}'),
        "high",
    ),
    (
        # AWS STS temporary credentials (same shape as AKIA, ASIA prefix)
        "aws_key_temporary",
        re.compile(r'ASIA[0-9A-Z]{16}'),
        "high",
    ),
    (
        # AWS secret access key in an assignment context (40 base64 chars)
        "aws_secret_access_key",
        re.compile(
            r'aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?',
            re.IGNORECASE,
        ),
        "critical",
    ),
    (
        "github_token",
        re.compile(r'ghp_[A-Za-z0-9]{36}'),
        "high",
    ),
    (
        # GitHub OAuth / user / server / refresh tokens share ghp_'s shape
        "github_token_variant",
        re.compile(r'gh[ousr]_[A-Za-z0-9]{36,45}'),
        "high",
    ),
    (
        "github_token_fine_grained",
        re.compile(r'github_pat_[A-Za-z0-9_]{22,}'),
        "high",
    ),
    (
        "gitlab_token",
        re.compile(r'glpat-[A-Za-z0-9_\-]{20,}'),
        "high",
    ),
    (
        "openai_api_key",
        re.compile(r'sk-(?:proj-)?[A-Za-z0-9_\-]{40,}'),
        "high",
    ),
    (
        "anthropic_api_key",
        re.compile(r'sk-ant-[A-Za-z0-9_\-]{20,}'),
        "high",
    ),
    (
        "vault_token",
        re.compile(r'hvs\.[A-Za-z0-9_\-]{20,}'),
        "medium",
    ),
    (
        # NOTE: bare "key" removed from the alternation — it matched every
        # JSON/dict entry ("key": "value") and was the #1 false-positive
        # source.  A \b boundary prevents "monkey=" matching "key=".
        "generic_api_key",
        re.compile(r'\b(?:api[_-]?key|apikey|token|secret|password)\b\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?', re.IGNORECASE),
        "medium",
    ),
    (
        "private_key_rsa",
        re.compile(r'-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----'),
        "critical",
    ),
    (
        "private_key_ec",
        re.compile(r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----'),
        "critical",
    ),
    (
        "private_key_generic",
        re.compile(r'-----BEGIN\s+PRIVATE\s+KEY-----'),
        "critical",
    ),
    (
        "private_key_openssh",
        re.compile(r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----'),
        "critical",
    ),
    (
        "password_in_url",
        re.compile(r'https?://[^:]+:([^@]{3,})@[^\s]+'),
        "high",
    ),
    (
        "db_connection_string",
        re.compile(r'(?:mongodb(?:\+srv)?|mysql|postgres|postgresql|redis|amqp|mssql|oracle)://[^\s"\']+[:@][^\s"\']+', re.IGNORECASE),
        "high",
    ),
    (
        "jwt_token",
        re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        "medium",
    ),
]


def detect_secrets_in_text(text: str) -> List[Dict[str, Any]]:
    """Detect secrets and credentials in text using regex patterns.

    Scans the provided text for known secret patterns including AWS keys,
    GitHub tokens, API keys, private keys, passwords in URLs, database
    connection strings, and JWT tokens.

    Args:
        text: The text content to scan for secrets.

    Returns:
        List of dicts with keys: type, match, line, offset, confidence.
        Each dict represents a detected secret.
    """
    if not text:
        return []

    findings: List[Dict[str, Any]] = []
    lines = text.split("\n")

    for secret_type, pattern, confidence in _SECRET_PATTERNS:
        for line_num, line in enumerate(lines, start=1):
            for match in pattern.finditer(line):
                matched_text = match.group(0)
                findings.append({
                    "type": secret_type,
                    "match": matched_text,
                    "line": line_num,
                    "offset": match.start(),
                    "confidence": confidence,
                })

    return findings


# ── Safe Parsing ─────────────────────────────────────────────────────────

# Parsing limits
_MAX_JSON_SIZE = 1_048_576  # 1 MB
_MAX_JSON_DEPTH = 20
_MAX_JSON_KEYS = 10_000
_MAX_URL_LENGTH = 2048
_ALLOWED_SCHEMES = {"http", "https"}


def safe_json_parse(text: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Safely parse JSON with size, depth, and key count limits.

    Args:
        text: JSON string to parse.

    Returns:
        Tuple of (parsed_dict_or_None, error_message_or_None).
        On success: (dict, None)
        On failure: (None, error_description)
    """
    if not text:
        return None, "Empty input"

    # Size check
    if len(text) > _MAX_JSON_SIZE:
        return None, f"JSON input exceeds maximum size of {_MAX_JSON_SIZE} bytes"

    # Try parsing
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"
    except Exception as e:
        return None, f"JSON parse error: {e}"

    # Must be a dict at top level
    if not isinstance(data, dict):
        return None, "JSON root must be an object (dict)"

    # Check key count
    key_count = _count_keys(data)
    if key_count > _MAX_JSON_KEYS:
        return None, f"JSON has {key_count} keys, exceeding limit of {_MAX_JSON_KEYS}"

    # Check depth
    depth = _measure_depth(data)
    if depth > _MAX_JSON_DEPTH:
        return None, f"JSON has depth {depth}, exceeding limit of {_MAX_JSON_DEPTH}"

    return data, None


def _count_keys(obj: Any) -> int:
    """Recursively count all keys in a JSON-like structure."""
    if isinstance(obj, dict):
        count = len(obj)
        for v in obj.values():
            count += _count_keys(v)
        return count
    elif isinstance(obj, list):
        count = 0
        for item in obj:
            count += _count_keys(item)
        return count
    return 0


def _measure_depth(obj: Any, current: int = 1) -> int:
    """Measure the maximum nesting depth of a JSON-like structure."""
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_measure_depth(v, current + 1) for v in obj.values())
    elif isinstance(obj, list):
        if not obj:
            return current
        return max(_measure_depth(item, current + 1) for item in obj)
    return current


# DEAD CODE: consider removal
def safe_url_parse(url: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Safely parse a URL with scheme whitelist and length limits.

    Only allows http and https schemes. Enforces a maximum URL length.

    Args:
        url: URL string to parse.

    Returns:
        Tuple of (parsed_components_or_None, error_message_or_None).
        On success: (dict with scheme, netloc, path, params, query, fragment, None)
        On failure: (None, error_description)
    """
    if not url:
        return None, "Empty URL"

    # Length check
    if len(url) > _MAX_URL_LENGTH:
        return None, f"URL exceeds maximum length of {_MAX_URL_LENGTH} characters"

    # Parse
    try:
        parsed = urllib.parse.urlparse(url.strip())
    except Exception as e:
        return None, f"URL parse error: {e}"

    # Scheme whitelist
    scheme = parsed.scheme.lower()
    if not scheme:
        return None, "URL must include a scheme (http or https)"
    if scheme not in _ALLOWED_SCHEMES:
        return None, f"URL scheme '{scheme}' is not allowed. Allowed: {', '.join(sorted(_ALLOWED_SCHEMES))}"

    # Must have a netloc (hostname)
    if not parsed.netloc:
        return None, "URL must include a hostname"

    return {
        "scheme": scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "params": parsed.params,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }, None


# DEAD CODE: consider removal
def safe_xml_parse(text: str) -> Tuple[Optional[str], Optional[str]]:
    """Safely parse XML with entity expansion prevention.

    Uses Python's xml.etree.ElementTree with security limits to prevent
    billion laughs (XML bomb) attacks.

    Args:
        text: XML string to parse.

    Returns:
        Tuple of (root_tag_or_None, error_message_or_None).
        On success: (root_element_tag_name, None)
        On failure: (None, error_description)
    """
    if not text:
        return None, "Empty input"

    # Size limit
    if len(text) > _MAX_JSON_SIZE:  # Reuse 1MB limit
        return None, f"XML input exceeds maximum size of {_MAX_JSON_SIZE} bytes"

    # Define a custom parser that disables entity expansion
    class _SafeXMLParser(ET.XMLParser):
        """XML parser that blocks entity declarations."""
        pass

    try:
        parser = _SafeXMLParser()
        # Block DTD loading and entity declarations
        if hasattr(parser, 'parser'):
            parser.parser.EntityDeclHandler = lambda *args: (_ for _ in ()).throw(ValueError("Entity declarations are blocked"))  # type: ignore[attr-defined]
        root = ET.fromstring(text, parser=parser)
        return root.tag, None
    except ET.ParseError as e:
        return None, f"XML parse error: {e}"
    except ValueError as e:
        return None, f"XML security violation: {e}"
    except Exception as e:
        return None, f"XML error: {e}"


# ── Audit Logger ─────────────────────────────────────────────────────────

class SecurityAuditLogger:
    """Structured security audit logging.

    Logs security events with consistent format:
    - timestamp (ISO 8601)
    - level (INFO, WARN, ALERT)
    - event_type (SCAN_START, FINDING, PLUGIN_LOAD, etc.)
    - module
    - target
    - details (dict)

    Outputs to ~/.reconpro/audit.log with rotation (10MB max, 5 backups).
    Pure Python implementation using logging.handlers.RotatingFileHandler.
    """

    _MAX_BYTES = 10 * 1024 * 1024  # 10 MB
    _BACKUP_COUNT = 5
    _LOG_DIR_NAME = ".reconpro"
    _LOG_FILENAME = "audit.log"

    def __init__(
        self,
        log_dir: Optional[str] = None,
        module_name: str = "security",
    ) -> None:
        """Initialize the audit logger.

        Args:
            log_dir: Override directory for log files. Defaults to ~/.reconpro/
            module_name: Name of the module using this logger (for the 'module' field).
        """
        self.module_name = module_name
        if log_dir is None:
            log_dir = os.path.join(os.path.expanduser("~"), self._LOG_DIR_NAME)
        self.log_dir = log_dir
        self._log_path = os.path.join(log_dir, self._LOG_FILENAME)

        # Ensure directory exists
        os.makedirs(log_dir, exist_ok=True)

        # Set up rotating file handler
        self._handler = logging.handlers.RotatingFileHandler(
            self._log_path,
            maxBytes=self._MAX_BYTES,
            backupCount=self._BACKUP_COUNT,
            encoding="utf-8",
        )
        self._handler.setFormatter(logging.Formatter("%(message)s"))

        self._logger = logging.getLogger(f"reconpro.audit.{module_name}")
        self._logger.setLevel(logging.DEBUG)
        # Avoid duplicate handlers if logger already configured
        if not self._logger.handlers:
            self._logger.addHandler(self._handler)

    def _emit(self, level: str, event_type: str, target: str = "", details: Optional[Dict[str, Any]] = None) -> None:
        """Emit a structured audit log entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "event_type": event_type,
            "module": self.module_name,
            "target": sanitize_log(target),
            "details": details or {},
        }
        msg = json.dumps(entry, default=str)
        if level == "ALERT":
            self._logger.critical(msg)
        elif level == "WARN":
            self._logger.warning(msg)
        else:
            self._logger.info(msg)

    def info(self, event_type: str, target: str = "", details: Optional[Dict[str, Any]] = None) -> None:
        """Log an INFO-level audit event."""
        self._emit("INFO", event_type, target, details)

    def warn(self, event_type: str, target: str = "", details: Optional[Dict[str, Any]] = None) -> None:
        """Log a WARN-level audit event."""
        self._emit("WARN", event_type, target, details)

    def alert(self, event_type: str, target: str = "", details: Optional[Dict[str, Any]] = None) -> None:
        """Log an ALERT-level audit event."""
        self._emit("ALERT", event_type, target, details)

    @property
    def log_path(self) -> str:
        """Return the path to the audit log file."""
        return self._log_path

    # DEAD CODE: consider removal
    def close(self) -> None:
        """Close the logger and release resources."""
        self._handler.close()
        self._logger.removeHandler(self._handler)


# ── Signature Verification ───────────────────────────────────────────────

# DEAD CODE: consider removal
def compute_file_hash(filepath: str, algorithm: str = "sha256") -> str:
    """Compute the hash of a file.

    Args:
        filepath: Path to the file to hash.
        algorithm: Hash algorithm (sha256, sha512, md5, sha1).

    Returns:
        Hex-encoded hash string, or empty string on error.
    """
    if not os.path.isfile(filepath):
        return ""
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)  # 64 KB chunks
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (ValueError, OSError, IOError):
        return ""


# DEAD CODE: consider removal
def verify_module_signature(module_name: str, source_hash: str) -> bool:
    """Placeholder for future code-signing verification.

    Currently always returns True. In a future version, this will:
    1. Locate the module source file
    2. Compute its hash
    3. Compare against a known-good hash store

    Args:
        module_name: Dotted module name (e.g., 'reconpro.scanner').
        source_hash: Expected hash of the module source.

    Returns:
        True (placeholder — always trusts).
    """
    # Placeholder: future implementation will verify actual hashes
    return True


# ── Supply Chain ─────────────────────────────────────────────────────────

# DEAD CODE: consider removal
def check_dependency_integrity() -> Dict[str, Any]:
    """Check that reconpro has no unexpected dependencies.

    Scans the reconpro package for import statements and reports
    which external (non-stdlib) packages are imported.

    Returns:
        Dict with keys:
        - "status": "ok" or "warning"
        - "stdlib_imports": set of stdlib module names found
        - "external_imports": set of non-stdlib module names found
        - "details": human-readable summary
    """
    stdlib_modules = {
        "os", "sys", "re", "json", "hashlib", "html", "logging",
        "urllib", "xml", "datetime", "pathlib", "typing", "math",
        "collections", "itertools", "functools", "time", "socket",
        "ssl", "http", "subprocess", "threading", "asyncio",
        "io", "struct", "unittest", "argparse", "copy", "csv",
        "base64", "hmac", "secrets", "shutil", "tempfile",
        "importlib", "pkgutil", "traceback", "warnings", "contextlib",
        "dataclasses", "enum", "abc", "operator", "statistics",
        "textwrap", "difflib", "fileinput", "fnmatch", "glob",
        "linecache", "posixpath", "ntpath", "genericpath",
        "codecs", "binascii", "mimetypes", "email", "html",
        "xmlrpc", "multiprocessing", "concurrent", "queue",
        "smtplib", "ftplib", "poplib", "imaplib", "nntplib",
        "telnetlib", "uuid", "string", "random", "numbers",
        "decimal", "fractions", "array", "weakref",
        "types", "pdb", "profile", "cProfile", "timeit",
        "pprint", "reprlib", "enum", "numbers",
    }

    # Read all Python files in the reconpro package
    reconpro_dir = os.path.dirname(os.path.abspath(__file__))
    external_imports: Set[str] = set()
    stdlib_imports: Set[str] = set()

    import_pattern = re.compile(
        r'^(?:from|import)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
        re.MULTILINE,
    )

    for root, _dirs, files in os.walk(reconpro_dir):
        # Skip __pycache__
        if "__pycache__" in root:
            continue
        for fname in files:
            if not fname.endswith(".py"):
                continue
            filepath = os.path.join(root, fname)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue

            for m in import_pattern.finditer(content):
                mod = m.group(1)
                # Skip relative imports and reconpro internal imports
                if mod.startswith(".") or mod == "reconpro":
                    continue
                if mod in stdlib_modules:
                    stdlib_imports.add(mod)
                elif mod not in ("__future__", "__main__"):
                    external_imports.add(mod)

    status = "ok" if not external_imports else "warning"
    details = (
        f"Found {len(stdlib_imports)} stdlib imports, "
        f"{len(external_imports)} external imports."
    )

    return {
        "status": status,
        "stdlib_imports": stdlib_imports,
        "external_imports": external_imports,
        "details": details,
    }


def get_security_profile() -> Dict[str, Any]:
    """Return a summary of the security configuration.

    Returns:
        Dict describing current security settings and capabilities.
    """
    return {
        "version": "1.0.0",
        "module": "security",
        "sanitization": {
            "sanitize_target": True,
            "sanitize_path": True,
            "sanitize_filename": True,
            "sanitize_html": True,
            "sanitize_shell": True,
            "sanitize_log": True,
        },
        "secret_detection": {
            "patterns": len(_SECRET_PATTERNS),
            "types": [p[0] for p in _SECRET_PATTERNS],
        },
        "safe_parsing": {
            "json_max_size_bytes": _MAX_JSON_SIZE,
            "json_max_depth": _MAX_JSON_DEPTH,
            "json_max_keys": _MAX_JSON_KEYS,
            "url_max_length": _MAX_URL_LENGTH,
            "allowed_url_schemes": sorted(_ALLOWED_SCHEMES),
        },
        "audit_logging": {
            "max_log_size_bytes": SecurityAuditLogger._MAX_BYTES,
            "backup_count": SecurityAuditLogger._BACKUP_COUNT,
            "log_dir": os.path.join(os.path.expanduser("~"), ".reconpro"),
        },
        "threat_categories": THREAT_CATEGORIES,
    }


# ── Threat Classification ────────────────────────────────────────────────

def classify_threat(finding: Dict[str, Any]) -> str:
    """Map a finding dict to a threat category.

    Looks at the finding's 'type', 'category', 'severity', and 'description'
    fields to determine the most appropriate threat category.

    Args:
        finding: A dict with at least 'type' or 'category' key.

    Returns:
        Threat category string (e.g., "injection", "crypto", "network", "data", "auth")
        or "unknown" if no match is found.
    """
    if not finding:
        return "unknown"

    # Collect all text to search through
    search_fields: List[str] = []
    for key in ("type", "category", "subtype", "name"):
        if key in finding:
            search_fields.append(str(finding[key]).lower())
    if "description" in finding:
        search_fields.append(str(finding["description"]).lower())
    if "severity" in finding:
        search_fields.append(str(finding["severity"]).lower())

    combined = " ".join(search_fields)

    # Check each category for keyword matches
    for category, keywords in THREAT_CATEGORIES.items():
        for keyword in keywords:
            if keyword in combined:
                return category

    # Additional heuristic mappings
    # SQL-related patterns
    sql_indicators = {"sql", "query", "select", "inject", "sqli"}
    if any(ind in combined for ind in sql_indicators):
        return "injection"

    # XSS-related patterns
    xss_indicators = {"xss", "cross-site", "script", "javascript", "dom"}
    if any(ind in combined for ind in xss_indicators):
        return "injection"

    # Crypto-related patterns
    crypto_indicators = {"tls", "ssl", "certificate", "cipher", "encrypt", "hash"}
    if any(ind in combined for ind in crypto_indicators):
        return "crypto"

    # Network patterns
    network_indicators = {"port", "service", "open", "exposed", "firewall"}
    if any(ind in combined for ind in network_indicators):
        return "network"

    # Data patterns
    data_indicators = {"data", "leak", "exposure", "pii", "personal", "gdpr"}
    if any(ind in combined for ind in data_indicators):
        return "data"

    # Auth patterns
    auth_indicators = {"auth", "login", "password", "session", "token", "mfa", "credential"}
    if any(ind in combined for ind in auth_indicators):
        return "auth"

    return "unknown"

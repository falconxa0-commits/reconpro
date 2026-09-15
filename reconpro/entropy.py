"""Granular Secret Entropy Scoring for ReconPro v8.0.

Uses Shannon entropy analysis combined with contextual signals (variable names,
file paths, surrounding code comments, known prefix patterns, and format validation)
to distinguish real secrets from random-looking-but-innocent strings.

Exports: shannon_entropy, SecretMatch, SecretClassifier, ContextAnalyzer,
         scan_string, scan_file, scan_directory
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# 1. Shannon Entropy
# ──────────────────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of *s* in bits.

    Returns 0.0 for empty or single-character strings.
    Formula: H = -sum(p_i * log2(p_i) for each unique character frequency p_i).
    """
    if not s or len(s) <= 1:
        return 0.0

    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


# ──────────────────────────────────────────────────────────────────────────────
# 2. Known Secret Prefixes
# ──────────────────────────────────────────────────────────────────────────────

# Maps prefix pattern (plain str treated as literal start; tuples are (prefix, regex_flag))
# to (secret_type, base_confidence).  The classifier combines this with entropy & context.
KNOWN_PREFIXES: Dict[str, Dict[str, str | float]] = {
    # ── AWS ──
    "AKIA":  {"type": "AWS Access Key",      "confidence": 0.95},
    "ASIA":  {"type": "AWS Temporary Key",    "confidence": 0.92},
    "ABIA":  {"type": "AWS ABIA Key",         "confidence": 0.90},
    "ACAA":  {"type": "AWS ACAA Key",         "confidence": 0.90},
    "AGPA":  {"type": "AWS AGPA Key",         "confidence": 0.90},
    "AIDA":  {"type": "AWS AIDA Key",         "confidence": 0.90},
    "AIPA":  {"type": "AWS AIPA Key",         "confidence": 0.90},
    "ANPA":  {"type": "AWS ANPA Key",         "confidence": 0.90},
    "ANVA":  {"type": "AWS ANVA Key",         "confidence": 0.90},
    "APKA":  {"type": "AWS APKA Key",         "confidence": 0.90},
    "ARPA":  {"type": "AWS ARPA Key",         "confidence": 0.90},
    "AROA":  {"type": "AWS AROA Key",         "confidence": 0.90},
    # ── GitHub ──
    "ghp_":  {"type": "GitHub PAT",            "confidence": 0.97},
    "gho_":  {"type": "GitHub OAuth Token",    "confidence": 0.97},
    "ghu_":  {"type": "GitHub User Token",     "confidence": 0.97},
    "ghs_":  {"type": "GitHub App Token",      "confidence": 0.97},
    "ghr_":  {"type": "GitHub Refresh Token",  "confidence": 0.97},
    # ── GitLab ──
    "glpat-": {"type": "GitLab PAT",           "confidence": 0.96},
    "glptt-": {"type": "GitLab Trigger Token",  "confidence": 0.96},
    # ── Slack ──
    "xoxb-": {"type": "Slack Bot Token",       "confidence": 0.96},
    "xoxp-": {"type": "Slack User Token",      "confidence": 0.96},
    "xoxo-": {"type": "Slack Org Token",       "confidence": 0.96},
    # ── Stripe ──
    "sk_live_":  {"type": "Stripe Secret Key",      "confidence": 0.98},
    "pk_live_":  {"type": "Stripe Publishable Key",  "confidence": 0.95},
    "rk_live_":  {"type": "Stripe Restricted Key",   "confidence": 0.95},
    # ── Twilio ──
    "SK":  {"type": "Twilio API Key",       "confidence": 0.75},
    # ── Google ──
    "AIza":  {"type": "Google API Key",       "confidence": 0.93},
    "ya29.": {"type": "Google OAuth Token",    "confidence": 0.93},
    # ── Azure ──
    "DEFAULTAZURE":  {"type": "Azure Default Cred",  "confidence": 0.90},
    "AZURE_CLIENT":   {"type": "Azure Client Cred",   "confidence": 0.90},
    # ── JWT ──
    "eyJ":  {"type": "JWT Token",            "confidence": 0.85},
    # ── Generic (case-insensitive matching handled in classifier) ──
    "password":   {"type": "Password",             "confidence": 0.80},
    "secret":     {"type": "Secret",               "confidence": 0.80},
    "token":      {"type": "Token",                "confidence": 0.75},
    "api_key":    {"type": "API Key",              "confidence": 0.80},
    "private_key":{"type": "Private Key",           "confidence": 0.85},
    "access_key": {"type": "Access Key",            "confidence": 0.80},
}


# ──────────────────────────────────────────────────────────────────────────────
# 4. SecretMatch dataclass
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class SecretMatch:
    """Result of classifying a potential secret."""
    value: str
    secret_type: str
    severity: str                 # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: float             # 0.0 – 1.0
    entropy: float
    matched_prefix: Optional[str] = None
    context_signals: List[str] = field(default_factory=list)
    recommendation: str = ""

    def __str__(self) -> str:
        masked = self.value[:6] + "..." + self.value[-4:] if len(self.value) > 12 else "***"
        return (
            f"[{self.severity}] {self.secret_type} (entropy={self.entropy:.2f}, "
            f"conf={self.confidence:.0%}) prefix={self.matched_prefix or 'none'} "
            f"value={masked}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# 5. ContextAnalyzer
# ──────────────────────────────────────────────────────────────────────────────

class ContextAnalyzer:
    """Extract contextual signals from variable names, file paths, and code."""

    SECRET_KEYWORDS: List[str] = [
        "password", "passwd", "pass",
        "secret", "token", "apikey", "api_key", "api-key",
        "access_key", "accesskey", "private_key", "privatekey",
        "credentials", "creds", "credential",
        "auth", "authorization", "authenticate",
        "private", "cert", "certificate",
    ]

    SENSITIVE_FILENAMES: List[str] = [
        ".env", ".env.local", ".env.production", ".env.development",
        ".env.staging", ".env.test", ".env.backup",
        "credentials", "credential", "creds",
        "config", "configuration", "settings", "settings.local",
        "secrets", "secret",
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
        ".netrc", ".pgpass", ".my.cnf",
    ]

    TEMPORARY_COMMENTS: List[str] = [
        "todo: remove", "fixme", "temporary", "hack", "workaround",
        "remove before", "delete this", "not for production",
        "debug only", "testing only", "do not commit", "don't commit",
        "wip", "xxx",
    ]

    def analyze_variable_name(self, name: str) -> List[str]:
        """Return signal strings found in *name* (e.g. 'contains:password')."""
        signals: List[str] = []
        lower = name.lower().replace("-", "_").replace(" ", "_")
        for kw in self.SECRET_KEYWORDS:
            if kw in lower:
                signals.append(f"var:{kw}")
        return signals

    def analyze_file_path(self, path: str) -> List[str]:
        """Return signal strings for sensitive file/directory names in *path*."""
        signals: List[str] = []
        lower = path.lower().replace(os.sep, "/")
        parts = lower.split("/")
        for part in parts:
            for sf in self.SENSITIVE_FILENAMES:
                if part == sf or part.startswith(sf + "."):
                    signals.append(f"file:{sf}")
                    break
        return signals

    def analyze_surrounding_code(self, code: str) -> List[str]:
        """Return signal strings for temporary / debug comments in *code*."""
        signals: List[str] = []
        upper = code.upper()
        for tc in self.TEMPORARY_COMMENTS:
            if tc.upper() in upper:
                signals.append(f"comment:{tc.lower()}")
        return signals


# ──────────────────────────────────────────────────────────────────────────────
# 3. SecretClassifier
# ──────────────────────────────────────────────────────────────────────────────

class SecretClassifier:
    """Classify a string as a real secret, weak secret, or benign."""

    def __init__(self) -> None:
        self._ctx = ContextAnalyzer()
        self._prefix_lookup = self._build_prefix_lookup()

    # -- prefix lookup is ordered longest-prefix-first so substrings don't
    # -- steal matches from longer, more specific prefixes (e.g. sk_live_ before s)
    @staticmethod
    def _build_prefix_lookup() -> List[tuple[str, str, float]]:
        items = [(prefix, info["type"], float(info["confidence"]))
                 for prefix, info in KNOWN_PREFIXES.items()]
        items.sort(key=lambda x: len(x[0]), reverse=True)
        return items

    # ── public API ──────────────────────────────────────────────────────────

    def classify(
        self,
        value: str,
        variable_name: str = "",
        file_path: str = "",
        surrounding_code: str = "",
    ) -> SecretMatch:
        """Classify *value* and return a :class:`SecretMatch`.

        Parameters
        ----------
        value : str
            The candidate secret string.
        variable_name : str
            Name of the variable/field holding the value (e.g. "AWS_SECRET_KEY").
        file_path : str
            Path of the file where the value was found.
        surrounding_code : str
            A few lines of code around the match for comment analysis.
        """
        entropy = shannon_entropy(value)

        # --- a) Match known prefix (longest first) ---
        matched_prefix: Optional[str] = None
        prefix_type = ""
        prefix_confidence = 0.0
        value_upper = value.upper()
        for pfx, ptype, pconf in self._prefix_lookup:
            if value.startswith(pfx) or value_upper.startswith(pfx.upper()):
                matched_prefix = pfx
                prefix_type = ptype
                prefix_confidence = pconf
                break

        # --- b) Context signals ---
        context_signals: List[str] = []
        context_signals.extend(self._ctx.analyze_variable_name(variable_name))
        context_signals.extend(self._ctx.analyze_file_path(file_path))
        context_signals.extend(self._ctx.analyze_surrounding_code(surrounding_code))

        has_secret_var = any(s.startswith("var:") for s in context_signals)
        has_sensitive_file = any(s.startswith("file:") for s in context_signals)
        has_temp_comment = any(s.startswith("comment:") for s in context_signals)

        # --- c) Format validation ---
        format_valid = self._validate_format(value, matched_prefix)

        # --- d) Classification matrix ---
        severity, confidence, recommendation = self._classify_matrix(
            entropy=entropy,
            has_prefix=bool(matched_prefix),
            prefix_confidence=prefix_confidence,
            has_secret_var=has_secret_var,
            has_sensitive_file=has_sensitive_file,
            has_temp_comment=has_temp_comment,
            format_valid=format_valid,
        )

        secret_type = prefix_type if prefix_type else self._infer_type(context_signals, value)

        # Downgrade confidence slightly if marked as temporary
        if has_temp_comment and confidence > 0.3:
            confidence *= 0.6

        return SecretMatch(
            value=value,
            secret_type=secret_type,
            severity=severity,
            confidence=round(confidence, 3),
            entropy=round(entropy, 3),
            matched_prefix=matched_prefix,
            context_signals=context_signals,
            recommendation=recommendation,
        )

    # ── internal helpers ────────────────────────────────────────────────────

    def _classify_matrix(
        self,
        entropy: float,
        has_prefix: bool,
        prefix_confidence: float,
        has_secret_var: bool,
        has_sensitive_file: bool,
        has_temp_comment: bool,
        format_valid: bool,
    ) -> tuple[str, float, str]:
        """Apply the classification rules and return (severity, confidence, rec)."""

        # Known prefix + high entropy + secret variable name → CRITICAL
        if has_prefix and entropy > 3.5 and has_secret_var:
            return (
                "CRITICAL",
                min(prefix_confidence * 1.04, 0.99),  # cap at 99%
                "Real secret detected with high confidence. Rotate immediately.",
            )

        # Known prefix + high entropy → HIGH
        if has_prefix and entropy > 3.5:
            conf = prefix_confidence if format_valid else prefix_confidence * 0.85
            return (
                "HIGH",
                conf,
                "Likely a real secret based on known prefix and high entropy."
                + (" Format is valid." if format_valid else " Format is unexpected."),
            )

        # High entropy + secret variable name → HIGH
        if entropy >= 3.5 and has_secret_var:
            return (
                "HIGH",
                0.85,
                "High-entropy value assigned to a secret-related variable. Likely a real secret.",
            )

        # High entropy + sensitive file → HIGH
        if entropy >= 3.5 and has_sensitive_file:
            return (
                "HIGH",
                0.80,
                "High-entropy value found in a sensitive file. Likely a real secret.",
            )

        # High entropy + no context → MEDIUM (could be UUID, session ID, hash)
        if entropy >= 3.5:
            return (
                "MEDIUM",
                0.50,
                "High-entropy string but no secret-related context. Could be a UUID, hash, or session ID.",
            )

        # Low entropy + known prefix (e.g. password123) → HIGH (weak but real)
        if has_prefix and entropy <= 3.5:
            return (
                "HIGH",
                prefix_confidence * 0.7,
                "Known secret prefix with low entropy — likely a weak or placeholder secret. Still a real leak.",
            )

        # Low entropy + secret variable name → MEDIUM
        if entropy < 3.5 and has_secret_var:
            return (
                "MEDIUM",
                0.55,
                "Secret-related variable holds a low-entropy value. Could be a weak or default credential.",
            )

        # Low entropy + no context → INFO
        return (
            "INFO",
            0.10,
            "Low entropy with no secret context. Probably not a secret.",
        )

    def _validate_format(self, value: str, prefix: Optional[str]) -> bool:
        """Check value format against expectations for its prefix type."""
        if not prefix:
            return self._validate_generic_api_key(value)

        pu = prefix.upper()

        # AWS access key: exactly 20 chars uppercase+digits after AKIA/ASIA
        if pu in ("AKIA", "ASIA"):
            suffix = value[len(prefix):]
            return len(suffix) == 16 and suffix.isalnum() and suffix.isupper()

        # GitHub tokens: exactly 36 hex chars after prefix
        if pu in ("GHP_", "GHO_", "GHU_", "GHS_", "GHR_"):
            suffix = value[len(prefix):]
            return len(suffix) == 36 and all(c in "0123456789abcdefABCDEF" for c in suffix)

        # GitLab PAT
        if pu in ("GLPAT-", "GLPTT-"):
            suffix = value[len(prefix):]
            return len(suffix) >= 20 and bool(re.match(r"^[\w-]+$", suffix))

        # Slack tokens
        if pu in ("XOXB-", "XOXP-", "XOXO-"):
            suffix = value[len(prefix):]
            return len(suffix) >= 10 and bool(re.match(r"^[\w-]+$", suffix))

        # Stripe keys
        if pu in ("SK_LIVE_", "PK_LIVE_", "RK_LIVE_"):
            suffix = value[len(prefix):]
            return len(suffix) >= 20 and bool(re.match(r"^[\w]+$", suffix))

        # Twilio: SK followed by hex
        if pu == "SK" and len(prefix) == 2 and len(value) > 2:
            suffix = value[2:]
            return suffix and all(c in "0123456789abcdef" for c in suffix)

        # Google API key: AIza + 33 chars
        if prefix == "AIza":
            suffix = value[4:]
            return len(suffix) == 33 and bool(re.match(r"^[\w-]+$", suffix))

        # Google OAuth: ya29. + token chars
        if value.startswith("ya29."):
            suffix = value[5:]
            return len(suffix) >= 10 and bool(re.match(r"^[\w._-]+$", suffix))

        # JWT: three base64url segments
        if prefix == "eyJ":
            parts = value.split(".")
            if len(parts) != 3:
                return False
            b64_pattern = re.compile(r"^[A-Za-z0-9_-]+$")
            return all(b64_pattern.match(p) for p in parts)

        # Azure prefixes
        if pu in ("DEFAULTAZURE", "AZURE_CLIENT"):
            return len(value) > len(prefix)

        return self._validate_generic_api_key(value)

    @staticmethod
    def _validate_generic_api_key(value: str) -> bool:
        """Generic API key heuristic: 20-100 chars, mix of upper + lower + digit."""
        if not (20 <= len(value) <= 100):
            return False
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        return has_upper and has_lower and has_digit

    @staticmethod
    # DEAD CODE: consider removal
    def _infer_type(signals: List[str], value: str) -> str:
        """Guess the secret type from context signals when no prefix matched."""
        for sig in signals:
            kw = sig.split(":", 1)[1] if ":" in sig else sig
            kw = kw.replace("_", " ").title()
        # Use the first variable signal if present
        for sig in signals:
            if sig.startswith("var:"):
                kw = sig[4:].replace("_", " ").title()
                return f"Potential {kw}"
        return "Unknown Secret"


# ──────────────────────────────────────────────────────────────────────────────
# 7 & 8. Convenience scanning functions
# ──────────────────────────────────────────────────────────────────────────────

# Regex to extract string literals from source files (covers Python, JS, TS, etc.)
_STRING_LITERAL_RE = re.compile(
    r'"""(?:[^"\\]|\\.)*?"""'
    r"|'''(?:[^'\\]|\\.)*?'''"
    r'|"(?:[^"\\]|\\.)*"'
    r"|'(?:[^'\\]|\\.)*'"
    r'|`(?:[^`\\]|\\.)*`',
)

# Regex to extract variable = "value" or KEY = value patterns from config/env files
# Uses \x5c for backslash to avoid quoting issues inside character classes.
_ASSIGNMENT_RE = re.compile(
    r'(?:^|(?<=[\s,;{]))'
    r'([A-Za-z_][\w]*)'
    r'\s*(?:=|:)\s*'
    r'(["\x27](?:[^"\x27\x5c]|\x5c.)*["\x27])',
    re.MULTILINE,
)

# Minimum entropy to even bother classifying (below this, classify returns INFO anyway)
_ENTROPY_FLOOR = 2.5


# DEAD CODE: consider removal
def scan_string(
    value: str,
    variable_name: str = "",
    file_path: str = "",
    surrounding_code: str = "",
) -> Optional[SecretMatch]:
    """Classify a single candidate string.

    Returns ``None`` when the value is clearly not a secret (very low entropy,
    too short, empty, or classified as INFO).
    """
    if not value or len(value) < 6:
        return None

    classifier = SecretClassifier()
    result = classifier.classify(
        value=value,
        variable_name=variable_name,
        file_path=file_path,
        surrounding_code=surrounding_code,
    )

    if result.severity == "INFO":
        return None

    return result


# DEAD CODE: consider removal
def scan_file(path: str) -> List[SecretMatch]:
    """Read a file, extract string literals, and classify each as a potential secret.

    Skips binary files and files larger than 256 KB.
    """
    results: List[SecretMatch] = []
    classifier = SecretClassifier()

    try:
        file_size = os.path.getsize(path)
        if file_size > 256 * 1024 or file_size == 0:
            return results
    except OSError:
        return results

    try:
        with open(path, errors="replace") as fh:
            content = fh.read()
    except OSError:
        return results

    # Quick binary detection: if >5% of first 4 KB are null bytes, skip
    sample = content[:4096]
    if sample.count("\x00") > len(sample) * 0.05:
        return results

    seen_values: set[str] = set()
    lines = content.splitlines()

    # Strategy 1: Extract assignment patterns (VAR = "value")
    for m in _ASSIGNMENT_RE.finditer(content):
        var_name = m.group(1)
        raw_val = m.group(2)
        # Strip surrounding quotes
        if (raw_val.startswith('"') and raw_val.endswith('"')) or \
           (raw_val.startswith("'") and raw_val.endswith("'")):
            val = raw_val[1:-1]
        else:
            val = raw_val

        if len(val) < 6 or val in seen_values:
            continue
        seen_values.add(val)

        # Get surrounding code (3 lines before and after the match)
        start_line = content[:m.start()].count("\n")
        ctx_start = max(0, start_line - 3)
        ctx_end = min(len(lines), start_line + 4)
        surrounding = "\n".join(lines[ctx_start:ctx_end])

        match = classifier.classify(
            value=val,
            variable_name=var_name,
            file_path=path,
            surrounding_code=surrounding,
        )
        if match.severity != "INFO":
            results.append(match)

    # Strategy 2: Extract bare string literals that look high-entropy
    for m in _STRING_LITERAL_RE.finditer(content):
        raw_val = m.group(0)
        # Strip quotes
        if (raw_val.startswith('"""') and raw_val.endswith('"""')) or \
           (raw_val.startswith("'''") and raw_val.endswith("'''")):
            val = raw_val[3:-3]
        elif raw_val and raw_val[0] in ("'", '"', '`') and raw_val[-1] == raw_val[0]:
            val = raw_val[1:-1]
        else:
            val = raw_val

        if len(val) < 8 or val in seen_values:
            continue

        # Quick entropy pre-filter to avoid classifying every string
        ent = shannon_entropy(val)
        if ent < _ENTROPY_FLOOR:
            continue

        seen_values.add(val)

        start_line = content[:m.start()].count("\n")
        ctx_start = max(0, start_line - 2)
        ctx_end = min(len(lines), start_line + 3)
        surrounding = "\n".join(lines[ctx_start:ctx_end])

        match = classifier.classify(
            value=val,
            file_path=path,
            surrounding_code=surrounding,
        )
        if match.severity != "INFO":
            results.append(match)

    return results


def scan_directory(
    path: str,
    extensions: Optional[List[str]] = None,
) -> List[SecretMatch]:
    """Recursively scan a directory for secrets in files.

    Parameters
    ----------
    path : str
        Root directory to scan.
    extensions : list[str] | None
        File extensions to include (e.g. [".py", ".js"]).
        Defaults to common source/config extensions if *None*.
    """
    if extensions is None:
        extensions = [
            ".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs",
            ".rb", ".go", ".rs", ".java", ".php", ".c", ".cpp", ".h",
            ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini",
            ".env", ".sh", ".bash", ".zsh", ".ps1",
            ".tf", ".hcl",                      # Terraform
            ".properties", ".xml", ".conf",     # Java / Nginx
            ".sql",                                # DB scripts
            ".gradle", ".cmake",                  # Build files
        ]

    # Normalise extensions to lowercase with dot
    ext_set = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions}

    root = Path(path)
    if not root.is_dir():
        return []

    results: List[SecretMatch] = []
    # Directories to skip
    skip_dirs = {
        "node_modules", ".venv", "venv", "env", ".git", "__pycache__",
        ".tox", ".mypy_cache", ".pytest_cache", ".next", "dist", "build",
        ".cache", ".idea", ".vscode", "target", "vendor", ".bundle",
        "coverage", ".nyc_output", ".turbo",
    }

    for filepath in root.rglob("*"):
        # Skip directories
        if filepath.is_dir():
            continue
        # Skip blacklisted directories
        if any(part in skip_dirs for part in filepath.parts):
            continue
        # Skip symlinks
        if filepath.is_symlink():
            continue
        # Check extension
        if ext_set and filepath.suffix.lower() not in ext_set:
            # Also allow extensionless sensitive filenames like .env, Dockerfile
            basename_lower = filepath.name.lower()
            if not any(basename_lower.startswith(sf) for sf in [".env", "dockerfile", "makefile", "credentials", "id_rsa"]):
                continue

        results.extend(scan_file(str(filepath)))

    return results


# ── File Entropy Analysis ─────────────────────────────────────────────────

# DEAD CODE: consider removal
def file_entropy(filepath: str) -> Dict[str, Any]:
    """Calculate Shannon entropy of a file. Returns {entropy, bits_per_byte, size, path, assessment}."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        if not data:
            return {"entropy": 0.0, "bits_per_byte": 0.0, "size": 0, "path": filepath, "assessment": "empty"}
        ent = shannon_entropy(data.decode("latin-1"))
        return {
            "entropy": round(ent, 4),
            "bits_per_byte": round(ent / 8.0 * 100, 2),
            "size": len(data),
            "path": filepath,
            "assessment": "high_entropy" if ent > 7.0 else "medium_entropy" if ent > 5.0 else "low_entropy",
        }
    except Exception as e:
        return {"entropy": 0.0, "bits_per_byte": 0.0, "size": 0, "path": filepath, "assessment": f"error: {e}"}


# DEAD CODE: consider removal
def directory_entropy_scan(directory: str, extensions: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Scan all files in a directory for high entropy (potential encrypted/compiled secrets)."""
    results = []
    exts = set(extensions) if extensions else None
    for root, dirs, files in os.walk(directory):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            if exts:
                _, ext = os.path.splitext(fname)
                if ext.lstrip(".").lower() not in exts:
                    continue
            info = file_entropy(fpath)
            if info["entropy"] > 5.0:
                results.append(info)
    return sorted(results, key=lambda x: -x["entropy"])


def crypto_material_detector(data: str, context: str = "") -> List[Dict[str, Any]]:
    """Detect cryptographic material (keys, certs, tokens) using entropy + patterns."""
    from .entropy import KNOWN_PREFIXES
    findings = []
    lines = data.split("\n")
    for i, line in enumerate(lines):
        stripped = line.strip()
        for prefix, info in KNOWN_PREFIXES.items():
            if stripped.startswith(prefix):
                ent = shannon_entropy(stripped)
                findings.append({
                    "line": i + 1,
                    "prefix": prefix,
                    "type": info["type"],
                    "entropy": round(ent, 4),
                    "value_preview": stripped[:20] + "..." if len(stripped) > 20 else stripped,
                    "confidence": info["confidence"],
                    "context": context,
                })
    return findings


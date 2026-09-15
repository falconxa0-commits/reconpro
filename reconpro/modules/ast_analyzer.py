"""AST-based static code vulnerability scanner.

Parses Python source files using the stdlib ``ast`` module and
walks the tree looking for common security anti-patterns.
JavaScript / TypeScript files are analysed with targeted regexes
(no extra dependency).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import List, Tuple

from ..http_layer import Finding


# ── Supported extensions ─────────────────────────────────────────────

PY_EXT = {".py"}
JS_EXT = {".js", ".jsx", ".ts", ".tsx"}
ALL_EXT = PY_EXT | JS_EXT


# ── Regex helpers for JS/TS ─────────────────────────────────────────

_JS_PATTERNS: List[Tuple[str, re.Pattern, str, str, str, str, str, int]] = [
    (
        "Hardcoded Password",
        re.compile(r"(?:password|passwd|secret|token|api_key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I),
        "hardcoded_secret", "high", "ast_analyzer",
        "Potential hardcoded password or secret detected.",
        "Use environment variables or a secrets manager.",
        15,
    ),
    (
        "eval() Usage",
        re.compile(r"\beval\s*\("),
        "dangerous_eval", "critical", "ast_analyzer",
        "Use of eval() can lead to arbitrary code execution.",
        "Avoid eval(). Use JSON.parse() or explicit parsing.",
        20,
    ),
    (
        "innerHTML Assignment",
        re.compile(r"\.innerHTML\s*=", re.I),
        "xss", "high", "ast_analyzer",
        "Direct innerHTML assignment can lead to XSS.",
        "Use textContent or DOMPurify to sanitise input.",
        15,
    ),
    (
        "document.write",
        re.compile(r"document\.write\s*\("),
        "xss", "high", "ast_analyzer",
        "document.write() is vulnerable to injection attacks.",
        "Use DOM manipulation methods instead.",
        15,
    ),
    (
        "HTTP URL",
        re.compile(r"(?:fetch|axios|XMLHttpRequest)\s*\(\s*[\"']http://"),
        "cleartext_http", "medium", "ast_analyzer",
        "Insecure HTTP URL detected; data may be sent in cleartext.",
        "Switch to HTTPS endpoints.",
        8,
    ),
    (
        "SQL String Concatenation",
        re.compile(r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*[\"']", re.I),
        "sql_injection", "critical", "ast_analyzer",
        "SQL keyword detected in string concatenation — likely SQL injection.",
        "Use parameterized queries.",
        20,
    ),
    (
        "Weak Crypto (MD5)",
        re.compile(r"(?:createHash|crypto)\.?(?:md5|sha1)", re.I),
        "weak_crypto", "medium", "ast_analyzer",
        "Weak hashing algorithm detected (MD5/SHA1).",
        "Use SHA-256 or stronger algorithms.",
        10,
    ),
    (
        "Debug Mode",
        re.compile(r"(?:DEBUG|debug)\s*[:=]\s*true", re.I),
        "debug_mode", "low", "ast_analyzer",
        "Debug mode appears to be enabled.",
        "Disable debug mode in production.",
        3,
    ),
    (
        "CORS Wildcard",
        re.compile(r"(?:Access-Control-Allow-Origin|allowOrigin|cors)\s*[:=]\s*[\"']*\*[\"']", re.I),
        "cors_wildcard", "medium", "ast_analyzer",
        "CORS wildcard origin allows any domain.",
        "Restrict CORS to known trusted origins.",
        8,
    ),
    (
        "Disabled CSRF",
        re.compile(r"(?:csrf|xsrf)\s*[:=]\s*false", re.I),
        "csrf_disabled", "high", "ast_analyzer",
        "CSRF protection appears to be disabled.",
        "Enable CSRF protection for all state-changing endpoints.",
        12,
    ),
    (
        "Weak Random",
        re.compile(r"Math\.random\("),
        "weak_random", "medium", "ast_analyzer",
        "Math.random() is not cryptographically secure.",
        "Use crypto.getRandomValues() for security-sensitive contexts.",
        8,
    ),
    (
        "Sensitive Data Logging",
        re.compile(r"console\.(?:log|warn|error|info)\([^)]*(?:password|secret|token|key|ssn|credit)", re.I),
        "sensitive_logging", "medium", "ast_analyzer",
        "Sensitive data may be logged to the console.",
        "Never log passwords, tokens, or PII.",
        10,
    ),
    (
        "Child Process Execution",
        re.compile(r"(?:child_process|execSync|spawn)\s*\("),
        "command_injection", "high", "ast_analyzer",
        "Child process execution detected — possible command injection.",
        "Avoid shell execution; use strict argument arrays.",
        15,
    ),
    (
        "JWT Without Verification",
        re.compile(r"jwt\.decode\s*\(\s*[^,]+\s*\)\s*[,;]"),
        "jwt_no_verify", "high", "ast_analyzer",
        "JWT decode without verification or secret key.",
        "Always verify JWT signatures with a secret/public key.",
        12,
    ),
    (
        "Path Traversal in File Operation",
        re.compile(r"(?:readFile|writeFile|createReadStream)\([^)]*(?:\+|\$\{)", re.I),
        "path_traversal", "high", "ast_analyzer",
        "File operation with concatenated path — possible path traversal.",
        "Validate and sanitise file paths; use path.basename().",
        15,
    ),
]


# ── Severity order for sorting ──────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── AST Node Visitors ────────────────────────────────────────────────


class _SecurityVisitor(ast.NodeVisitor):
    """Walks a single Python AST and collects Findings."""

    def __init__(self, filepath: str, source_lines: List[str]) -> None:
        self.filepath = filepath
        self.lines = source_lines
        self.findings: List[Finding] = []
        self._imported: set = set()

    # -- helpers --------------------------------------------------------

    def _line(self, node: ast.AST) -> str:
        """Return the source line for *node*, or empty string."""
        ln = getattr(node, "lineno", 0) or 0
        if 1 <= ln <= len(self.lines):
            return self.lines[ln - 1].strip()
        return ""

    def _add(self, title: str, sev: str, cat: str, desc: str,
             node: ast.AST, remediation: str = "", pts: int = 0) -> None:
        evidence = self._line(node)
        self.findings.append(Finding(
            title=title, severity=sev, category=cat,
            module="ast_analyzer", description=desc,
            evidence=evidence, asset=self.filepath,
            points_deducted=pts, remediation=remediation,
        ))

    # -- import tracking -------------------------------------------------

    def _track_imports(self, module_name: str) -> None:
        base = module_name.split(".")[0]
        self._imported.add(base)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._track_imports(alias.name)
        self._check_weak_import_line(node)
        self._check_weak_random_import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._track_imports(node.module)
        self._check_weak_import_line(node)
        self._check_weak_random_import(node)
        self.generic_visit(node)

    # ── Check 1: Hardcoded passwords / secrets ─────────────────────────

    _SECRET_PATTERNS = [
        re.compile(
            r"(?:password|passwd|secret|token|api_key|apikey|private_key)"
            r"\s*=\s*['\"][^'\"]{6,}['\"]",
            re.I,
        ),
    ]

    def visit_Assign(self, node: ast.Assign) -> None:
        line = self._line(node)
        for pat in self._SECRET_PATTERNS:
            if pat.search(line):
                self._add(
                    "Hardcoded Secret",
                    "high", "hardcoded_secret",
                    "A password, token, or secret is hardcoded in source.",
                    node,
                    remediation="Use environment variables or a vault.", pts=15,
                )
                break
        self.generic_visit(node)

    # ── Check 2 & 3: eval / exec ───────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        fname = ""
        if isinstance(func, ast.Name):
            fname = func.id
        elif isinstance(func, ast.Attribute):
            fname = func.attr

        # Check 2: eval
        if fname == "eval" and isinstance(func, ast.Name):
            self._add(
                "eval() Usage", "critical", "dangerous_eval",
                "eval() allows arbitrary code execution.", node,
                remediation="Never use eval(). Use ast.literal_eval() or explicit parsing.",
                pts=20,
            )

        # Check 3: exec
        if fname == "exec" and isinstance(func, ast.Name):
            self._add(
                "exec() Usage", "critical", "dangerous_exec",
                "exec() allows arbitrary code execution.", node,
                remediation="Never use exec(). Restrict to whitelisted callables.",
                pts=20,
            )

        # Check 4: subprocess with shell=True
        if fname in ("run", "call", "Popen", "check_output", "check_call"):
            if "subprocess" in self._imported or isinstance(func, ast.Attribute):
                for kw in node.keywords:
                    if kw.arg == "shell":
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self._add(
                                "subprocess shell=True",
                                "high", "command_injection",
                                "subprocess called with shell=True enables shell injection.",
                                node,
                                remediation="Pass arguments as a list without shell=True.", pts=15,
                            )
                            break

        # Check 5: Unsafe deserialization — pickle.loads / yaml.load
        if fname == "loads" and isinstance(func, ast.Attribute):
            attr_value = ""
            if isinstance(func.value, ast.Name):
                attr_value = func.value.id
            elif isinstance(func.value, ast.Attribute):
                attr_value = func.value.attr

            if attr_value in ("pickle", "marshal", "shelve"):
                self._add(
                    "Unsafe Deserialization (pickle)",
                    "critical", "unsafe_deserialization",
                    f"{attr_value}.loads() can execute arbitrary code.",
                    node,
                    remediation="Use safe formats: JSON, msgpack, or signed payloads.", pts=20,
                )

            if attr_value == "yaml":
                self._add(
                    "Unsafe YAML Load",
                    "high", "unsafe_deserialization",
                    "yaml.load() without Loader=yaml.SafeLoader is dangerous.",
                    node,
                    remediation="Use yaml.safe_load() or Loader=yaml.SafeLoader.", pts=15,
                )

        # Check 13: SQL keywords in .format() calls
        if fname == "format" and isinstance(func, ast.Attribute):
            if isinstance(func.value, (ast.Constant,)):
                val = func.value.value
                if isinstance(val, str) and self._SQL_KW.search(val):
                    self._add(
                        "SQL via .format()",
                        "critical", "sql_injection",
                        "SQL query built with .format() — vulnerable to injection.",
                        node,
                        remediation="Use parameterized queries (cursor.execute(q, params)).",
                        pts=20,
                    )

        # Check 14: os.system()
        if fname == "system" and isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                self._add(
                    "os.system() Call", "high", "command_injection",
                    "os.system() passes commands to the shell unsanitised.", node,
                    remediation="Use subprocess.run() with a list of arguments.", pts=15,
                )

        # Check 19: os.popen
        if fname == "popen" and isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name) and func.value.id == "os":
                self._add(
                    "os.popen() Call", "high", "command_injection",
                    "os.popen() is vulnerable to command injection.", node,
                    remediation="Use subprocess.run() with explicit arguments.", pts=15,
                )

        # Check 20: Path traversal in open()
        if fname == "open" and isinstance(func, ast.Name):
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, (ast.BinOp, ast.JoinedStr)):
                    self._add(
                        "Potential Path Traversal",
                        "high", "path_traversal",
                        "open() called with a dynamically constructed path.", node,
                        remediation="Validate paths and restrict to a safe directory.",
                        pts=15,
                    )

        self.generic_visit(node)

    # ── Check 6: SQL keywords in f-strings ─────────────────────────────

    _SQL_KW = re.compile(
        r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b", re.I,
    )

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Check f-strings for SQL keywords (Check 13 cont.)."""
        parts: list = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                parts.append(str(val.value))
            elif isinstance(val, ast.FormattedValue):
                parts.append("{}")
        combined = " ".join(parts)
        if self._SQL_KW.search(combined):
            self._add(
                "SQL in f-string",
                "critical", "sql_injection",
                "SQL query built with f-string — vulnerable to injection.", node,
                remediation="Use parameterized queries.", pts=20,
            )
        self.generic_visit(node)

    # ── Check 7: Weak crypto imports ───────────────────────────────────

    _WEAK_IMPORT_RE = re.compile(
        r"(?:Crypto\.Cipher\.DES|from\s+Crypto\.Cipher\s+import\s+DES"
        r"|from\s+Cryptography.*?(?:DES|RC4|Blowfish))",
        re.I,
    )

    def _check_weak_import_line(self, node: ast.AST) -> None:
        line = self._line(node)
        if self._WEAK_IMPORT_RE.search(line):
            self._add(
                "Weak Cipher Import (DES/RC4/Blowfish)",
                "medium", "weak_crypto",
                "A weak encryption algorithm is being imported.",
                node,
                remediation="Use AES-256-GCM or ChaCha20.", pts=10,
            )

    # ── Check 7b: Weak hash calls ──────────────────────────────────────

    _WEAK_HASH_CALL_RE = re.compile(r"hashlib\.new\s*\(\s*['\"](?:md5|sha1)", re.I)

    def visit_Call_extra(self, node: ast.Call) -> None:
        """Additional call-site checks (called from generic_visit)."""
        line = self._line(node)
        if self._WEAK_HASH_CALL_RE.search(line):
            self._add(
                "Weak Hash Algorithm", "medium", "weak_crypto",
                "MD5 or SHA1 is cryptographically broken.", node,
                remediation="Use hashlib.sha256 or hashlib.sha3_256.", pts=10,
            )

    # ── Line-based checks (runs on every statement) ────────────────────

    _DEBUG_RE = re.compile(r"(?:FLASK_DEBUG|DEBUG)\s*=\s*True", re.I)
    _CORS_RE = re.compile(r"(?:allow_origin|Access-Control-Allow-Origin)\s*=\s*['\"]\*['\"]", re.I)
    _CSRF_RE = re.compile(r"(?:WTF_CSRF_ENABLED|CSRF_ENABLED)\s*=\s*False", re.I)
    _HTTP_RE = re.compile(r'http://[^\'"\s]+', re.I)
    _MKTEMP_RE = re.compile(r"(?:tempfile|os)\.mktemp\s*\(", re.I)
    _B64_SECRET_RE = re.compile(r"(?:password|secret|token|key)\s*=\s*base64\.b64decode\(", re.I)
    _JWT_NO_VERIFY_RE = re.compile(r"jwt\.decode\s*\(\s*\w+\s*\)", re.I)
    _SENSITIVE_LOG_RE = re.compile(
        r"(?:logger|logging|log)\.\w+\(.*?(?:password|secret|token|api_key|ssn|credit_card)",
        re.I,
    )

    def _check_weak_random_import(self, node: ast.AST) -> None:
        """Check 12: Weak random module import."""
        line = self._line(node)
        if re.search(r"(?:^import\s+random\b|^from\s+random\s+import)", line):
            self._add(
                "Weak Random (random module)", "medium", "weak_random",
                "The random module is not cryptographically secure.", node,
                remediation="Use secrets or os.urandom() for security contexts.", pts=8,
            )

    def _line_based_checks(self, node: ast.stmt) -> None:
        """Run regex-based checks on the source line of a statement node."""
        line = self._line(node)
        if not line:
            return

        # Check 8: Debug mode
        if self._DEBUG_RE.search(line):
            self._add(
                "Debug Mode Enabled", "low", "debug_mode",
                "Debug mode is enabled in production code.", node,
                remediation="Disable debug mode in production.", pts=3,
            )

        # Check 9: CORS wildcard
        if self._CORS_RE.search(line):
            self._add(
                "CORS Wildcard Origin", "medium", "cors_wildcard",
                "CORS allows all origins (Access-Control-Allow-Origin: *).", node,
                remediation="Restrict to trusted origins.", pts=8,
            )

        # Check 10: Disabled CSRF
        if self._CSRF_RE.search(line):
            self._add(
                "CSRF Protection Disabled", "high", "csrf_disabled",
                "CSRF protection has been disabled.", node,
                remediation="Enable CSRF protection.", pts=12,
            )

        # Check 11: HTTP instead of HTTPS
        stripped = line.lstrip()
        if not stripped.startswith("#") and self._HTTP_RE.search(line):
            self._add(
                "HTTP (Cleartext) URL", "medium", "cleartext_http",
                "An insecure HTTP URL was detected.", node,
                remediation="Use HTTPS for all network communication.", pts=8,
            )

        # Check 15: mktemp
        if self._MKTEMP_RE.search(line):
            self._add(
                "Insecure Temp File (mktemp)", "high", "temp_file_race",
                "tempfile.mktemp() is vulnerable to race conditions.", node,
                remediation="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile().", pts=12,
            )

        # Check 16: Base64 encoded secrets
        if self._B64_SECRET_RE.search(line):
            self._add(
                "Base64-Encoded Secret", "medium", "hardcoded_secret",
                "A secret is stored as a base64-encoded string.", node,
                remediation="Use a proper secrets manager; base64 is encoding, not encryption.",
                pts=10,
            )

        # Check 17: JWT without verification
        if self._JWT_NO_VERIFY_RE.search(line):
            self._add(
                "JWT Decode Without Verification", "high", "jwt_no_verify",
                "JWT decoded without signature verification.", node,
                remediation="Use jwt.decode(token, key, algorithms=[...]) with a verification key.",
                pts=12,
            )

        # Check 18: Sensitive data logging
        if self._SENSITIVE_LOG_RE.search(line):
            self._add(
                "Sensitive Data Logging", "medium", "sensitive_logging",
                "A logger call may expose sensitive data (passwords, tokens, PII).", node,
                remediation="Never log secrets or PII. Use structured redaction.", pts=10,
            )

    # -- Hook into generic_visit for line-based and extra call checks ---

    def generic_visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.stmt):
            self._line_based_checks(node)
        if isinstance(node, ast.Call):
            self.visit_Call_extra(node)
        super().generic_visit(node)


# ── JS/TS regex scanner ─────────────────────────────────────────────


def _scan_js_file(filepath: str, source: str) -> List[Finding]:
    """Scan a JavaScript/TypeScript file with regex patterns."""
    findings: List[Finding] = []
    for line in source.splitlines():
        for title, pattern, cat, sev, mod, desc, rem, pts in _JS_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    title=title, severity=sev, category=cat,
                    module=mod, description=desc,
                    evidence=line.strip(), asset=filepath,
                    points_deducted=pts, remediation=rem,
                ))
    return findings


# ── Public API ──────────────────────────────────────────────────────


class ASTAnalyzer:
    """Static analysis scanner for Python, JavaScript, and TypeScript files.

    Usage::

        analyzer = ASTAnalyzer()
        findings = analyzer.analyze_file("app.py")
        all_findings = analyzer.analyze_directory("src/")
    """

    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def analyze_file(self, path: str) -> List[Finding]:
        """Analyse a single source file and return a list of Findings."""
        p = Path(path)
        if not p.is_file():
            return []

        ext = p.suffix.lower()
        if ext not in ALL_EXT:
            return []

        try:
            source = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        file_findings: List[Finding] = []

        if ext in PY_EXT:
            file_findings = self._analyze_python(p, source)
        elif ext in JS_EXT:
            file_findings = _scan_js_file(str(p), source)

        self.findings.extend(file_findings)
        return file_findings

    def analyze_directory(self, path: str) -> List[Finding]:
        """Recursively analyse all supported files in a directory."""
        root = Path(path)
        if not root.is_dir():
            return []

        all_findings: List[Finding] = []
        for p in sorted(root.rglob("*")):
            if p.suffix.lower() in ALL_EXT and p.is_file():
                all_findings.extend(self.analyze_file(str(p)))

        return all_findings

    @staticmethod
    def _analyze_python(filepath: Path, source: str) -> List[Finding]:
        """Parse Python source with ast and run security visitors."""
        try:
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError:
            return []

        lines = source.splitlines()
        visitor = _SecurityVisitor(str(filepath), lines)
        visitor.visit(tree)
        return visitor.findings

    def clear(self) -> None:
        """Reset accumulated findings."""
        self.findings = []

    def summary(self) -> dict:
        """Return a quick summary dict of accumulated findings."""
        counts: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            s = f.severity.lower()
            if s in counts:
                counts[s] += 1
        return {
            "total": len(self.findings),
            "by_severity": counts,
            "categories": list({f.category for f in self.findings}),
        }

"""DEV module — Developer security tools.

Scans for developer-focused security issues:
- Dependency vulnerability scanning (package.json, requirements.txt, Pipfile, go.mod, Cargo.toml)
- Git security (exposed secrets, branch protection, .gitconfig)
- .env file detection & secret scanning
- Port conflict detection
- Docker Compose security
- API key/secret detection in codebase
- Outdated dependency detection
- Hardcoded credentials in source code
- Sensitive file detection (.pem, .key, .p12, credentials)
- Pre-commit hook presence
- Lockfile CVE scanning (package-lock.json, yarn.lock, Pipfile.lock)
- Go/Rust/Cargo audit (go.mod, Cargo.toml)
- Git config credential leak detection
- Terraform/TFVars secret scanning
- GitHub Actions token exposure
- Dependency confusion detection
"""

from __future__ import annotations

import os
import re
import json
import glob
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import Finding


def _scan_dir(base_dir: str = ".") -> str:
    """Get absolute path of directory to scan."""
    return os.path.abspath(base_dir)


def _find_files(patterns: List[str], base: str) -> List[str]:
    """Find files matching patterns in base directory."""
    found = []
    for pattern in patterns:
        found.extend(glob.glob(os.path.join(base, "**", pattern), recursive=True))
    return found


def _read_file(path: str, max_size: int = 65536) -> str:
    """Read file contents safely."""
    try:
        size = os.path.getsize(path)
        if size > max_size:
            return f"[file too large: {size} bytes]"
        with open(path, errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _check_package_json(base: str) -> List[Finding]:
    """Scan package.json for security issues."""
    findings: List[Finding] = []
    asset = base

    pkg_files = _find_files(["package.json"], base)
    for pkg_path in pkg_files:
        # Skip node_modules
        if "node_modules" in pkg_path:
            continue

        try:
            with open(pkg_path) as f:
                pkg = json.load(f)
        except Exception:
            continue

        deps = {}
        deps.update(pkg.get("dependencies", {}))
        deps.update(pkg.get("devDependencies", {}))

        if not deps:
            continue

        # Check for known vulnerable/outdated patterns
        risky_pkgs = {
            "lodash": ("low", "Consider replacing individual lodash imports with native JS"),
            "express": ("info", "Ensure Express is >= 4.18.0"),
            "jsonwebtoken": ("medium", "Ensure jsonwebtoken is >= 9.0.0"),
            "react": ("info", "Keep React updated"),
            "next": ("info", "Keep Next.js updated"),
            "mongoose": ("info", "Ensure Mongoose is latest"),
            "minimist": ("low", "minimist had prototype pollution CVEs"),
            "uglify-js": ("low", "uglify-js had ReDoS vulnerabilities"),
            "event-stream": ("high", "event-stream was compromised in 2018"),
        }

        for pkg_name, (sev, note) in risky_pkgs.items():
            if pkg_name in deps:
                findings.append(Finding(
                    title=f"{pkg_name}@{deps[pkg_name]} in {os.path.basename(os.path.dirname(pkg_path))}",
                    severity=sev, category="dependencies",
                    module="dev",
                    description=f"{note}.",
                    evidence=f"{pkg_name}: {deps[pkg_name]}",
                    asset=asset, points_deducted=3 if sev == "medium" else (8 if sev == "high" else 1),
                    remediation=f"Run: npm audit fix && npm update {pkg_name}",
                ))

        # Check for scripts that might run untrusted code
        scripts = pkg.get("scripts", {})
        risky_scripts = {"preinstall", "postinstall", "prestart", "poststart"}
        for script_name in risky_scripts:
            if script_name in scripts:
                findings.append(Finding(
                    title=f"Lifecycle script '{script_name}' in {os.path.basename(os.path.dirname(pkg_path))}/package.json",
                    severity="medium", category="supply_chain",
                    module="dev",
                    description="Package lifecycle scripts can run arbitrary code during npm install. Review the script content.",
                    evidence=f"{script_name}: {scripts[script_name][:100]}",
                    asset=asset, points_deducted=4,
                    remediation="Review and minimize lifecycle scripts. Avoid curl | bash patterns.",
                ))

    return findings


def _check_requirements(base: str) -> List[Finding]:
    """Scan requirements.txt / Pipfile for security issues."""
    findings: List[Finding] = []
    asset = base

    req_files = _find_files(["requirements.txt", "Pipfile", "pyproject.toml"], base)
    for req_path in req_files:
        if "node_modules" in req_path or ".venv" in req_path or "venv/" in req_path:
            continue

        content = _read_file(req_path)
        if not content:
            continue

        risky_py_pkgs = {
            "django": ("info", "Keep Django updated (check for CVEs)"),
            "flask": ("info", "Keep Flask updated"),
            "requests": ("info", "Ensure requests >= 2.31.0"),
            "pyjwt": ("medium", "Ensure PyJWT >= 2.8.0"),
            "cryptography": ("info", "Keep cryptography updated"),
            "sqlalchemy": ("info", "Keep SQLAlchemy updated"),
            "paramiko": ("medium", "Ensure Paramiko is latest"),
            "pickle": ("high", "pickle is unsafe for untrusted data"),
        }

        for pkg, (sev, note) in risky_py_pkgs.items():
            # Match package name at start of line or after common separators
            if re.search(rf'^{re.escape(pkg)}[=<>!\[]', content, re.MULTILINE | re.IGNORECASE):
                findings.append(Finding(
                    title=f"{pkg} in {os.path.basename(os.path.dirname(req_path))}/{os.path.basename(req_path)}",
                    severity=sev, category="dependencies",
                    module="dev",
                    description=note,
                    evidence=f"Found in {req_path}",
                    asset=asset, points_deducted=3 if sev == "medium" else (8 if sev == "high" else 1),
                    remediation=f"Run: pip audit && pip install --upgrade {pkg}",
                ))

    return findings


def _check_env_files(base: str) -> List[Finding]:
    """Find .env files and scan for secrets."""
    findings: List[Finding] = []
    asset = base

    env_files = _find_files([
        ".env", ".env.local", ".env.production", ".env.development",
        ".env.staging", ".env.test", ".env.backup",
    ], base)

    for env_path in env_files:
        if "node_modules" in env_path or ".venv" in env_path:
            continue

        content = _read_file(env_path)
        if not content:
            continue

        # Check if .env is in .gitignore
        parent = os.path.dirname(env_path)
        gitignore = os.path.join(parent, ".gitignore")
        gitignored = False
        if os.path.exists(gitignore):
            gi_content = _read_file(gitignore)
            if ".env" in gi_content:
                gitignored = True

        if not gitignored:
            findings.append(Finding(
                title=f".env file not in .gitignore: {env_path}",
                severity="critical", category="env_files",
                module="dev",
                description=f"{os.path.basename(env_path)} exists but .env is not in .gitignore. This file may be committed to git.",
                evidence=f"File: {env_path}",
                asset=asset, points_deducted=15,
                remediation=f"Add '.env' and '.env.*' to .gitignore in {parent}",
            ))

        # Scan for actual secrets in .env
        secret_count = 0
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key = line.split("=", 1)[0].upper()
            val = line.split("=", 1)[1].strip()

            secret_keywords = [
                "KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD",
                "CREDENTIAL", "PRIVATE", "CERT", "API_KEY", "AUTH",
            ]
            if any(kw in key for kw in secret_keywords) and val and val != '""' and val != "''":
                secret_count += 1
                if secret_count <= 5:
                    masked = val[:8] + "..." if len(val) > 8 else "***"
                    findings.append(Finding(
                        title=f"Secret in {os.path.basename(env_path)}: {key}",
                        severity="high", category="env_secrets",
                        module="dev",
                        description="Potential secret found in .env file.",
                        evidence=f"{key}={masked}",
                        asset=asset, points_deducted=6,
                        remediation="Use a secrets manager for production. Never commit .env files.",
                    ))

    return findings


def _check_git_security(base: str) -> List[Finding]:
    """Check git configuration and security."""
    findings: List[Finding] = []
    asset = base

    # Find git repos
    git_dirs = _find_files([".git"], base)
    git_repos = [os.path.dirname(d) for d in git_dirs if os.path.isdir(d)]

    for repo in git_repos[:10]:  # Limit to 10 repos
        repo_name = os.path.basename(repo)

        # Check for committed secrets in git log
        try:
            r = subprocess.run(
                ["git", "-C", repo, "log", "--all", "--oneline", "-20"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode == 0 and r.stdout.strip():
                findings.append(Finding(
                    title=f"Git repo: {repo_name} ({len(r.stdout.strip().splitlines())} recent commits)",
                    severity="info", category="git",
                    module="dev",
                    description=f"Found git repository at {repo}.",
                    evidence=repo,
                    asset=asset, points_deducted=0,
                    remediation="",
                ))
        except Exception:
            pass

        # Check for pre-commit hooks
        precommit = os.path.join(repo, ".git", "hooks", "pre-commit")
        if os.path.exists(precommit):
            pass  # pre-commit exists, good
        else:
            findings.append(Finding(
                title=f"No pre-commit hooks in {repo_name}",
                severity="low", category="git",
                module="dev",
                description="No pre-commit hooks found. Consider adding pre-commit for secret scanning and linting.",
                evidence=f"No .git/hooks/pre-commit in {repo}",
                asset=asset, points_deducted=2,
                remediation="Install pre-commit: pip install pre-commit && pre-commit install",
            ))

        # Check for .gitconfig issues
        gitconfig = os.path.expanduser("~/.gitconfig")
        if os.path.exists(gitconfig):
            gc = _read_file(gitconfig)
            if "credential" in gc.lower() and "store" in gc.lower():
                findings.append(Finding(
                    title="Git credential store is enabled",
                    severity="medium", category="git",
                    module="dev",
                    description="Git credentials are stored in plaintext on disk.",
                    evidence="credential helper = store in ~/.gitconfig",
                    asset=asset, points_deducted=5,
                    remediation="Use git-credential-manager or cache instead of store.",
                ))

    return findings


def _check_sensitive_files(base: str) -> List[Finding]:
    """Find sensitive files in the project."""
    findings: List[Finding] = []
    asset = base

    sensitive_patterns = [
        ("*.pem", "high", "PEM certificate/key file"),
        ("*.p12", "high", "PKCS12 certificate file"),
        ("*.pfx", "high", "PFX certificate file"),
        ("*.key", "high", "Private key file"),
        ("*.jks", "high", "Java keystore"),
        ("*.keystore", "high", "Keystore file"),
        ("id_rsa*", "critical", "SSH private key"),
        ("id_ed25519*", "critical", "SSH Ed25519 private key"),
        ("*.credentials", "high", "Credentials file"),
        ("*.htpasswd", "medium", "Apache password file"),
        ("*.sql", "medium", "SQL dump file (may contain data)"),
        ("*.dump", "medium", "Database dump file"),
        ("*.bak", "low", "Backup file"),
        (".DS_Store", "info", "macOS metadata file"),
        ("Thumbs.db", "info", "Windows thumbnail cache"),
    ]

    for pattern, sev, desc in sensitive_patterns:
        files = _find_files([pattern], base)
        # Skip common non-sensitive locations
        for f in files:
            if any(skip in f for skip in ["node_modules", ".venv", "venv/", ".git/objects"]):
                continue
            findings.append(Finding(
                title=f"Sensitive file: {f}",
                severity=sev, category="sensitive_files",
                module="dev",
                description=f"{desc} found in project. Ensure this is not committed to version control.",
                evidence=f"File: {f}",
                asset=asset, points_deducted=8 if sev in ("critical", "high") else (4 if sev == "medium" else 1),
                remediation="Add to .gitignore. Move secrets to a secure vault.",
            ))

    return findings


def _check_hardcoded_secrets(base: str) -> List[Finding]:
    """Scan source code for hardcoded secrets."""
    findings: List[Finding] = []
    asset = base

    # File extensions to scan
    code_exts = [".js", ".ts", ".tsx", ".jsx", ".py", ".rb", ".go", ".rs",
                ".java", ".php", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini"]

    secret_patterns = [
        (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']([\w\-]{20,})', "Hardcoded API key"),
        (r'(?i)(?:secret[_-]?key|secretkey)\s*[:=]\s*["\']([\w\-]{20,})', "Hardcoded secret key"),
        (r'(?i)password\s*[:=]\s*["\']([^"\']{6,})', "Hardcoded password"),
        (r'(?i)token\s*[:=]\s*["\']([\w\-\.=]{20,})', "Hardcoded token"),
        (r'(?i)aws_access_key_id\s*[:=]\s*["\'](AKIA[\w]{16})', "Hardcoded AWS Access Key"),
        (r'(?i)aws_secret_access_key\s*[:=]\s*["\']([\w/+=]{40})', "Hardcoded AWS Secret Key"),
        (r'ghp_[\w]{36}', "Hardcoded GitHub PAT"),
        (r'gho_[\w]{36}', "Hardcoded GitHub OAuth token"),
        (r'ghs_[\w]{36}', "Hardcoded GitHub App token"),
        (r'glpat-[\w\-]{20,}', "Hardcoded GitLab PAT"),
        (r'xox[bposa]-[\w\-]{10,}', "Hardcoded Slack token"),
        (r'np\.[\w]{36}', "Hardcoded npm token"),
        (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', "Hardcoded private key"),
    ]

    for ext in code_exts:
        files = _find_files([f"*{ext}"], base)
        for filepath in files[:50]:  # Limit scan
            if any(skip in filepath for skip in ["node_modules", ".venv", "venv/", ".git/", "dist/", "build/", ".next/"]):
                continue

            content = _read_file(filepath, max_size=32768)
            if not content:
                continue

            for pattern, title in secret_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    for match in matches[:2]:
                        if isinstance(match, tuple):
                            match = match[0] if match else "***"
                        masked = match[:8] + "..." + match[-4:] if len(str(match)) > 12 else "***"
                        findings.append(Finding(
                            title=f"{title} in {os.path.basename(filepath)}",
                            severity="critical", category="hardcoded_secrets",
                            module="dev",
                            description=f"Secret detected in source code: {title}",
                            evidence=f"Match: {masked}",
                            asset=asset, points_deducted=15,
                            remediation="Move secrets to environment variables or a secrets manager. Never commit secrets to source code.",
                        ))
                    break  # One match per pattern per file

    return findings


def _check_docker_compose(base: str) -> List[Finding]:
    """Check Docker Compose files for security issues."""
    findings: List[Finding] = []
    asset = base

    compose_files = _find_files(["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"], base)

    for cf in compose_files:
        if "node_modules" in cf:
            continue

        content = _read_file(cf)
        if not content:
            continue

        # Check for privileged mode
        if re.search(r'privileged\s*:\s*true', content):
            findings.append(Finding(
                title=f"Privileged container in {os.path.basename(cf)}",
                severity="high", category="docker",
                module="dev",
                description="A container is running in privileged mode, giving it full host access.",
                evidence=f"privileged: true found in {cf}",
                asset=asset, points_deducted=10,
                remediation="Remove privileged: true. Use specific capabilities instead.",
            ))

        # Check for exposed sensitive ports
        exposed_ports = re.findall(r'(\d{4,5})\s*:\s*\d{4,5}', content)
        sensitive_exposed = []
        for port in exposed_ports:
            p = int(port)
            if p in (22, 3306, 5432, 6379, 27017, 9200):
                sensitive_exposed.append(str(p))

        if sensitive_exposed:
            findings.append(Finding(
                title=f"Sensitive ports exposed in {os.path.basename(cf)}: {', '.join(sensitive_exposed[:5])}",
                severity="medium", category="docker",
                module="dev",
                description="Database or admin ports are exposed to the host network.",
                evidence=f"Ports: {', '.join(sensitive_exposed[:5])}",
                asset=asset, points_deducted=5,
                remediation="Only expose necessary ports. Bind databases to internal networks only.",
            ))

        # Check for env vars with secrets
        env_vars = re.findall(r'([A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z_]*)\s*:\s*(.+)', content)
        for var_name, val in env_vars[:5]:
            val = val.strip()
            if val and val not in ('""', "''", '${', 'false', 'true'):
                findings.append(Finding(
                    title=f"Secret in {os.path.basename(cf)}: {var_name}",
                    severity="medium", category="docker",
                    module="dev",
                    description="Secret value found directly in compose file.",
                    evidence=f"{var_name}={val[:15]}...",
                    asset=asset, points_deducted=4,
                    remediation="Use .env file or Docker secrets instead of inline values.",
                ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 1: Lockfile CVE Scan
# ---------------------------------------------------------------------------

# Static list of top 50 known vulnerable packages (name -> CVE, affected versions, severity)
_LOCKFILE_CVE_DB: List[Dict[str, str]] = [
    {"pkg": "lodash", "cve": "CVE-2021-23337", "max_ver": "4.17.20", "severity": "high",
     "desc": "Command Injection in lodash"},
    {"pkg": "lodash", "cve": "CVE-2020-8203", "max_ver": "4.17.12", "severity": "high",
     "desc": "ReDoS in lodash"},
    {"pkg": "minimist", "cve": "CVE-2020-7598", "max_ver": "0.0.8", "severity": "high",
     "desc": "Prototype Pollution in minimist"},
    {"pkg": "minimist", "cve": "CVE-2021-44906", "max_ver": "1.2.5", "severity": "high",
     "desc": "Prototype Pollution in minimist"},
    {"pkg": "express", "cve": "CVE-2024-29041", "max_ver": "4.18.3", "severity": "medium",
     "desc": "Open redirect in express"},
    {"pkg": "node-forge", "cve": "CVE-2022-24771", "max_ver": "1.3.0", "severity": "high",
     "desc": "SSRF via improper URL sanitization in node-forge"},
    {"pkg": "node-forge", "cve": "CVE-2022-24772", "max_ver": "1.3.0", "severity": "high",
     "desc": "Improper verification of JWS signatures in node-forge"},
    {"pkg": "jsonwebtoken", "cve": "CVE-2022-23529", "max_ver": "8.5.1", "severity": "high",
     "desc": "Insecure default algorithm in jsonwebtoken"},
    {"pkg": "express", "cve": "CVE-2022-24999", "max_ver": "4.17.3", "severity": "medium",
     "desc": "Open redirect in express res.redirect"},
    {"pkg": "axios", "cve": "CVE-2023-45857", "max_ver": "1.6.0", "severity": "medium",
     "desc": "CSRF via cookie leak in axios"},
    {"pkg": "semver", "cve": "CVE-2022-25883", "max_ver": "7.3.7", "severity": "medium",
     "desc": "ReDoS in semver"},
    {"pkg": "path-to-regexp", "cve": "CVE-2024-45296", "max_ver": "0.1.12", "severity": "high",
     "desc": "ReDoS in path-to-regexp"},
    {"pkg": "qs", "cve": "CVE-2022-24999", "max_ver": "6.10.3", "severity": "medium",
     "desc": "Prototype Pollution in qs"},
    {"pkg": "yargs-parser", "cve": "CVE-2020-15366", "max_ver": "18.1.3", "severity": "medium",
     "desc": "Prototype Pollution in yargs-parser"},
    {"pkg": "webpack-dev-server", "cve": "CVE-2024-29180", "max_ver": "4.15.2", "severity": "high",
     "desc": "Path traversal in webpack-dev-server"},
    {"pkg": "protobufjs", "cve": "CVE-2023-36665", "max_ver": "6.11.3", "severity": "high",
     "desc": "Prototype Pollution in protobufjs"},
    {"pkg": "vue", "cve": "CVE-2023-44489", "max_ver": "3.3.8", "severity": "medium",
     "desc": "XSS in Vue.js"},
    {"pkg": "angular", "cve": "CVE-2021-23364", "max_ver": "11.2.10", "severity": "high",
     "desc": "XSS in Angular"},
    {"pkg": "d3", "cve": "CVE-2022-31124", "max_ver": "7.0.0", "severity": "medium",
     "desc": "ReDoS in d3-color"},
    {"pkg": "uglify-js", "cve": "CVE-2023-37466", "max_ver": "3.17.3", "severity": "medium",
     "desc": "ReDoS in uglify-js"},
    # Python packages
    {"pkg": "requests", "cve": "CVE-2023-32681", "max_ver": "2.31.0", "severity": "medium",
     "desc": "Unintended leak of Proxy-Authorization header in requests"},
    {"pkg": "pyjwt", "cve": "CVE-2022-39227", "max_ver": "2.4.0", "severity": "high",
     "desc": "JWT algorithm confusion in PyJWT"},
    {"pkg": "cryptography", "cve": "CVE-2023-49083", "max_ver": "41.0.5", "severity": "medium",
     "desc": "Null pointer dereference in cryptography"},
    {"pkg": "django", "cve": "CVE-2024-27351", "max_ver": "4.2.7", "severity": "high",
     "desc": "DoS via large username in Django"},
    {"pkg": "flask", "cve": "CVE-2023-30861", "max_ver": "2.3.2", "severity": "medium",
     "desc": "Open redirect in Flask"},
    {"pkg": "jinja2", "cve": "CVE-2024-22195", "max_ver": "3.1.3", "severity": "medium",
     "desc": "ReDoS in Jinja2"},
    {"pkg": "pillow", "cve": "CVE-2023-44271", "max_ver": "10.0.1", "severity": "high",
     "desc": "DoS via large PNG in Pillow"},
    {"pkg": "urllib3", "cve": "CVE-2023-45803", "max_ver": "2.0.7", "severity": "medium",
     "desc": "Request body not stripped after redirect in urllib3"},
    {"pkg": "sqlalchemy", "cve": "CVE-2023-44271", "max_ver": "2.0.20", "severity": "medium",
     "desc": "SQL injection in SQLAlchemy"},
    # More high-impact npm packages
    {"pkg": "tar", "cve": "CVE-2021-32803", "max_ver": "4.4.18", "severity": "high",
     "desc": "Arbitrary file creation via archive in tar"},
    {"pkg": "tar", "cve": "CVE-2021-32804", "max_ver": "4.4.18", "severity": "high",
     "desc": "Arbitrary file overwrite via symlink in tar"},
    {"pkg": "async", "cve": "CVE-2021-43138", "max_ver": "2.6.4", "severity": "high",
     "desc": "Prototype Pollution in async"},
    {"pkg": "got", "cve": "CVE-2022-33987", "max_ver": "11.8.5", "severity": "high",
     "desc": "Bypass of unsafe REMOTE_URL in got"},
    {"pkg": "ws", "cve": "CVE-2021-32640", "max_ver": "7.5.4", "severity": "medium",
     "desc": "ReDoS in ws"},
    {"pkg": "cacheable-request", "cve": "CVE-2022-24769", "max_ver": "7.0.2", "severity": "medium",
     "desc": "SSRF via exposed .headers property in cacheable-request"},
    {"pkg": "shell-quote", "cve": "CVE-2022-29047", "max_ver": "1.7.3", "severity": "high",
     "desc": "Command Injection in shell-quote"},
    {"pkg": "cross-spawn", "cve": "CVE-2022-33660", "max_ver": "7.0.3", "severity": "medium",
     "desc": "Regular Expression DoS in cross-spawn"},
    {"pkg": "ws", "cve": "CVE-2023-44287", "max_ver": "8.13.0", "severity": "medium",
     "desc": "Buffer overflow in ws"},
    {"pkg": "cookie", "cve": "CVE-2022-25490", "max_ver": "0.5.0", "severity": "medium",
     "desc": "Cookie order manipulation in cookie"},
    {"pkg": "vite", "cve": "CVE-2023-34092", "max_ver": "4.3.9", "severity": "medium",
     "desc": "SSRF in Vite dev server"},
    {"pkg": "next", "cve": "CVE-2024-34351", "max_ver": "14.1.0", "severity": "high",
     "desc": "DoS via malformed URL in Next.js"},
    {"pkg": "dompurify", "cve": "CVE-2023-43783", "max_ver": "3.0.6", "severity": "medium",
     "desc": "Mutation XSS in DOMPurify"},
    {"pkg": "engine.io", "cve": "CVE-2024-22436", "max_ver": "6.4.2", "severity": "medium",
     "desc": "DoS via long poll in engine.io"},
    {"pkg": "socket.io", "cve": "CVE-2024-22435", "max_ver": "4.6.2", "severity": "medium",
     "desc": "DoS in socket.io"},
    {"pkg": "xml2js", "cve": "CVE-2023-30590", "max_ver": "0.6.2", "severity": "medium",
     "desc": "Prototype Pollution in xml2js"},
    {"pkg": "highlight.js", "cve": "CVE-2024-37375", "max_ver": "11.9.0", "severity": "medium",
     "desc": "ReDoS in highlight.js"},
    {"pkg": "postcss", "cve": "CVE-2023-44270", "max_ver": "8.4.31", "severity": "high",
     "desc": "ReDoS in postcss"},
]


def _version_gte(installed: str, minimum: str) -> bool:
    """Check if installed version >= minimum (both semver-ish strings)."""
    def _parse(v: str) -> Tuple[int, ...]:
        parts = []
        for p in re.split(r'[.\-]', v)[:3]:
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return tuple(parts)
    return _parse(installed) >= _parse(minimum)


def _check_lockfile_cves(base: str) -> List[Finding]:
    """Parse lockfiles for known vulnerable packages."""
    findings: List[Finding] = []
    asset = base

    # Collect all (package, version) pairs from lockfiles
    pkg_versions: Dict[str, List[str]] = {}  # pkg_name -> [version strings]

    # package-lock.json
    lock_files = _find_files(["package-lock.json"], base)
    for lf in lock_files:
        if "node_modules" in lf:
            continue
        try:
            with open(lf) as f:
                data = json.load(f)
            _extract_npm_lockfile(data, pkg_versions, lf)
        except Exception:
            pass

    # yarn.lock
    yarn_files = _find_files(["yarn.lock"], base)
    for yf in yarn_files:
        if "node_modules" in yf:
            continue
        try:
            content = _read_file(yf)
            _extract_yarn_lockfile(content, pkg_versions, yf)
        except Exception:
            pass

    # Pipfile.lock
    pipfile_locks = _find_files(["Pipfile.lock"], base)
    for pf in pipfile_locks:
        if ".venv" in pf:
            continue
        try:
            with open(pf) as f:
                data = json.load(f)
            for section in ("develop", "default"):
                for pkg_name, pkg_info in data.get(section, {}).items():
                    if isinstance(pkg_info, dict) and "version" in pkg_info:
                        ver = pkg_info["version"].lstrip("=")
                        pkg_versions.setdefault(pkg_name.lower(), []).append(ver)
        except Exception:
            pass

    # Check collected packages against CVE database
    for pkg_name, versions in pkg_versions.items():
        for cve in _LOCKFILE_CVE_DB:
            if cve["pkg"].lower() == pkg_name.lower():
                for ver in versions:
                    if not _version_gte(ver, cve["max_ver"]):
                        findings.append(Finding(
                            title=f"{cve['pkg']}@{ver} vulnerable to {cve['cve']}",
                            severity=cve["severity"], category="lockfile_cve",
                            module="dev",
                            description=f"{cve['desc']}. Installed version {ver} is below fixed version {cve['max_ver']}.",
                            evidence=f"{cve['pkg']}=={ver}, {cve['cve']}",
                            asset=asset, points_deducted=10 if cve["severity"] == "high" else 5,
                            remediation=f"Update {cve['pkg']} to >= {cve['max_ver']}",
                        ))
                        break  # One finding per package
                break  # One CVE match per package

    return findings


def _extract_npm_lockfile(data: Any, pkg_versions: Dict[str, List[str]], source: str) -> None:
    """Recursively extract package versions from package-lock.json."""
    packages = data.get("packages", data.get("dependencies", {}))
    if isinstance(packages, dict):
        for pkg_path, info in packages.items():
            if isinstance(info, dict) and "version" in info:
                # Extract package name from path like "node_modules/lodash"
                name = pkg_path.split("/")[-1] if "/" in pkg_path else pkg_path
                # Handle scoped packages like "@scope/pkg"
                if pkg_path.startswith("@"):
                    name = pkg_path
                pkg_versions.setdefault(name.lower(), []).append(info["version"])


def _extract_yarn_lockfile(content: str, pkg_versions: Dict[str, List[str]], source: str) -> None:
    """Extract package versions from yarn.lock format."""
    # yarn.lock format: "pkg_name@version:" followed by version "version X.Y.Z"
    blocks = re.split(r'\n(?=\S)', content)
    for block in blocks:
        header_match = re.match(r'^([^"\s]+|"[^"]+")@', block)
        if not header_match:
            continue
        pkg_name = header_match.group(1).strip('"')
        ver_match = re.search(r'version\s+"([^"]+)"', block)
        if ver_match:
            pkg_versions.setdefault(pkg_name.lower(), []).append(ver_match.group(1))


# ---------------------------------------------------------------------------
# NEW CHECK 2: Go/Rust/Cargo Audit
# ---------------------------------------------------------------------------

# Known risky Go and Rust packages
_GO_RISKY_PKGS = {
    "github.com/spf13/viper": {"cve": "CVE-2023-43178", "max_ver": "1.16.0", "severity": "medium",
                                 "desc": "Session fixation in Viper"},
    "github.com/gin-gonic/gin": {"cve": "CVE-2020-28483", "max_ver": "1.7.0", "severity": "medium",
                                  "desc": "Open redirect in Gin"},
    "github.com/valyala/fasthttp": {"cve": "CVE-2023-39325", "max_ver": "1.51.0", "severity": "high",
                                     "desc": "HTTP/2 rapid reset DoS in Go net/http (affects fasthttp users)"},
    "golang.org/x/crypto": {"cve": "CVE-2024-29857", "max_ver": "0.17.0", "severity": "medium",
                              "desc": "Memory allocation failure in golang.org/x/crypto/ssh"},
    "golang.org/x/net": {"cve": "CVE-2023-44487", "max_ver": "0.19.0", "severity": "high",
                            "desc": "HTTP/2 rapid reset attack"},
    "github.com/json-iterator/go": {"cve": "CVE-2022-3108", "max_ver": "1.1.12", "severity": "medium",
                                     "desc": "ReDoS in json-iterator"},
    "github.com/containers/podman": {"cve": "CVE-2023-30544", "max_ver": "4.4.0", "severity": "high",
                                        "desc": "Privilege escalation in Podman"},
}

_RUST_RISKY_PKGS = {
    "regex": {"cve": "CVE-2022-24713", "max_ver": "1.5.4", "severity": "medium",
               "desc": "ReDoS in Rust regex crate"},
    "time": {"cve": "CVE-2020-26235", "max_ver": "0.2.26", "severity": "medium",
              "desc": "Potential segfault in time crate"},
    "chrono": {"cve": "CVE-2023-32324", "max_ver": "0.4.25", "severity": "medium",
                "desc": "Segmentation fault in chrono parsing"},
    "hyper": {"cve": "CVE-2023-44487", "max_ver": "0.14.25", "severity": "high",
               "desc": "HTTP/2 rapid reset DoS in hyper"},
    "rustls": {"cve": "CVE-2023-43641", "max_ver": "0.21.8", "severity": "medium",
                "desc": "Memory usage bug in rustls"},
}


def _check_go_rust_cargo(base: str) -> List[Finding]:
    """Scan go.mod and Cargo.toml for known risky packages."""
    findings: List[Finding] = []
    asset = base

    # Scan go.mod files
    go_mods = _find_files(["go.mod"], base)
    for gm in go_mods:
        if "vendor" in gm:
            continue
        content = _read_file(gm)
        if not content:
            continue

        # Parse require blocks: e.g., "github.com/pkg v1.2.3"
        requires = re.findall(r'^\s*(\S+)\s+(v?[\d.]+)', content, re.MULTILINE)
        for pkg, ver in requires:
            ver = ver.lstrip("v")
            if pkg in _GO_RISKY_PKGS:
                cve_info = _GO_RISKY_PKGS[pkg]
                if not _version_gte(ver, cve_info["max_ver"]):
                    findings.append(Finding(
                        title=f"Go {pkg}@{ver} vulnerable to {cve_info['cve']}",
                        severity=cve_info["severity"], category="go_rust_audit",
                        module="dev",
                        description=f"{cve_info['desc']}. Version {ver} is below fix {cve_info['max_ver']}.",
                        evidence=f"{pkg}@{ver} in {gm}",
                        asset=asset, points_deducted=8 if cve_info["severity"] == "high" else 4,
                        remediation=f"Update: go get {pkg}@{cve_info['max_ver']}",
                    ))

    # Scan Cargo.toml files
    cargo_files = _find_files(["Cargo.toml"], base)
    for cf in cargo_files:
        if "target/" in cf or "registry/" in cf:
            continue
        content = _read_file(cf)
        if not content:
            continue

        # Parse [dependencies] and [dev-dependencies]
        in_deps = False
        for line in content.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith("[dependencies]") and "dev-" not in line_stripped:
                in_deps = True
                continue
            if line_stripped.startswith("["):
                in_deps = False
            if not in_deps:
                continue

            # Parse: pkg_name = "1.2.3" or pkg_name = { version = "1.2.3" }
            match = re.match(r'^([\w-]+)\s*=\s*["{]', line_stripped)
            if not match:
                continue
            pkg_name = match.group(1)
            ver_match = re.search(r'version\s*=\s*["\']([^"\'\s]+)', line_stripped)
            if not ver_match:
                ver_match = re.search(r'["\']([\d.]+)["\']', line_stripped)
            if ver_match:
                ver = ver_match.group(1)
                if pkg_name in _RUST_RISKY_PKGS:
                    cve_info = _RUST_RISKY_PKGS[pkg_name]
                    if not _version_gte(ver, cve_info["max_ver"]):
                        findings.append(Finding(
                            title=f"Rust {pkg_name}@{ver} vulnerable to {cve_info['cve']}",
                            severity=cve_info["severity"], category="go_rust_audit",
                            module="dev",
                            description=f"{cve_info['desc']}. Version {ver} is below fix {cve_info['max_ver']}.",
                            evidence=f"{pkg_name}@{ver} in {cf}",
                            asset=asset, points_deducted=8 if cve_info["severity"] == "high" else 4,
                            remediation=f"Update: cargo update -p {pkg_name}",
                        ))

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 3: Git Config Credential Leak
# ---------------------------------------------------------------------------

def _check_git_config_credential_leak(base: str) -> List[Finding]:
    """Check .git/config for embedded credentials in remote URLs."""
    findings: List[Finding] = []
    asset = base

    # Find all .git/config files
    git_dirs = _find_files([".git"], base)
    git_repos = [os.path.dirname(d) for d in git_dirs if os.path.isdir(d)]

    for repo in git_repos[:10]:
        config_path = os.path.join(repo, ".git", "config")
        if not os.path.isfile(config_path):
            continue

        try:
            with open(config_path, errors="replace") as f:
                content = f.read()
        except Exception:
            continue

        # Check remote URLs for embedded credentials
        # Patterns: https://user:pass@host, ssh://user:pass@host, git://user:pass@host
        cred_patterns = [
            (r'https?://[^\s]+:[^\s]+@[^\s]+', "HTTPS URL with embedded credentials"),
            (r'ssh://[^\s]+:[^\s]+@[^\s]+', "SSH URL with embedded credentials"),
            (r'git://[^\s]+:[^\s]+@[^\s]+', "Git protocol URL with embedded credentials"),
        ]

        for pattern, description in cred_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                # Mask the actual credential
                masked = re.sub(r':([^@]+)@', ':***@', matches[0])
                findings.append(Finding(
                    title=f"Credential in .git/config remote URL: {os.path.basename(repo)}",
                    severity="critical", category="git_credential_leak",
                    module="dev",
                    description=f"{description} found in .git/config. Credentials should not be embedded in remote URLs.",
                    evidence=f"Remote URL: {masked}",
                    asset=asset, points_deducted=15,
                    remediation="Remove credentials from the URL. Use SSH keys or a credential helper: git remote set-url origin <clean-url>",
                ))
                break  # One finding per repo

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 4: Terraform/TFVars Secret Scan
# ---------------------------------------------------------------------------

_TF_SECRET_PATTERNS = [
    (r'(?i)(?:password|passwd|secret|token|api_key|access_key)\s*=\s*["\']([^"\']{4,})', "Hardcoded secret in Terraform"),
    (r'(?i)(?:aws_access_key_id)\s*=\s*["\'](AKIA[\w]{16})', "AWS Access Key in Terraform"),
    (r'(?i)(?:aws_secret_access_key)\s*=\s*["\']([\w/+=]{40})', "AWS Secret Key in Terraform"),
    (r'(?i)(?:private_key|tls_private_key|rsa_private_key)\s*=\s*["\']-----BEGIN', "Private key in Terraform"),
    (r'(?i)(?:db_password|database_password|redis_password)\s*=\s*["\']([^"\']{4,})', "Database password in Terraform"),
    (r'(?i)(?:slack_webhook|discord_webhook)\s*=\s*["\'](https://hooks\.[^"\']{10,})', "Webhook URL in Terraform"),
    (r'(?i)(?:connection_string|mongodb_uri|postgres_url)\s*=\s*["\']([^"\']{10,})', "Database connection string in Terraform"),
]


def _check_terraform_secrets(base: str) -> List[Finding]:
    """Scan .tf and .tfvars files for hardcoded secrets."""
    findings: List[Finding] = []
    asset = base

    tf_files = _find_files(["*.tf", "*.tfvars", "*.tf.json"], base)
    for tf in tf_files:
        if any(skip in tf for skip in [".terraform/", ".terragrunt-cache/", "node_modules"]):
            continue

        content = _read_file(tf)
        if not content:
            continue

        for pattern, description in _TF_SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                for match in matches[:2]:
                    if isinstance(match, tuple):
                        match = match[0] if match else "***"
                    masked = match[:8] + "..." + match[-4:] if len(str(match)) > 12 else "***"
                    findings.append(Finding(
                        title=f"{description}: {os.path.basename(tf)}",
                        severity="critical", category="terraform_secrets",
                        module="dev",
                        description=f"Hardcoded secret found in Terraform file: {description}",
                        evidence=f"Match: {masked}",
                        asset=asset, points_deducted=15,
                        remediation="Use Terraform variables, vault, or cloud secret managers (AWS SSM, GCP Secret Manager). Never hardcode secrets in .tf files.",
                    ))
                break  # One match per pattern per file

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 5: GitHub Actions Token Exposure
# ---------------------------------------------------------------------------

_ACTIONS_SECRET_PATTERNS = [
    (r'(?i)(?:secrets|env)\s*:\s*\n(?:[^\n]*\n)*?(?:([A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*)\s*:\s*([^\n]+))',
     "Secret exposed in workflow env/secrets"),
    (r'(?i)GH_TOKEN\s*:\s*["\']?([\w]{20,})', "GH_TOKEN exposed in workflow"),
    (r'(?i)ACTIONS_DEPLOY_KEY\s*:\s*["\']?([\w\-]{20,})', "Deploy key exposed in workflow"),
    (r'(?i)NPM_TOKEN\s*:\s*["\']?([\w\.]{20,})', "npm token exposed in workflow"),
    (r'(?i)SLACK_WEBHOOK\s*:\s*["\']?(https://hooks\.[^"\'\s]+)', "Slack webhook exposed in workflow"),
]


def _check_github_actions_tokens(base: str) -> List[Finding]:
    """Check .github/workflows/ for secrets exposed in env vars."""
    findings: List[Finding] = []
    asset = base

    workflow_dir = os.path.join(base, ".github", "workflows")
    if not os.path.isdir(workflow_dir):
        return findings

    workflow_files = _find_files(["*.yml", "*.yaml"], workflow_dir)
    for wf in workflow_files:
        content = _read_file(wf)
        if not content:
            continue

        # Check for secrets in env: blocks that use plain values instead of ${{ secrets.X }}
        # Look for env: sections with hardcoded values
        env_sections = re.finditer(r'^\s*env:\s*$', content, re.MULTILINE)
        for env_match in env_sections:
            start = env_match.end()
            # Read until next top-level key (same or less indentation)
            env_text = ""
            for line in content[start:].splitlines():
                if line and not line[0].isspace() and line.strip():
                    break
                env_text += line + "\n"

            # Check for secret-like keys with non-${{ }} values
            for line in env_text.splitlines():
                kv_match = re.match(r'^\s+([A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|WEBHOOK|API)[A-Z_]*)\s*:\s*(.+)', line)
                if kv_match:
                    key_name = kv_match.group(1)
                    val = kv_match.group(2).strip()
                    # If value is NOT a GitHub secret reference
                    if val and "${{ secrets." not in val and val not in ('""', "''", '"""', "'''", 'true', 'false', 'null'):
                        masked = val[:10] + "..." if len(val) > 10 else "***"
                        findings.append(Finding(
                            title=f"Potential secret exposed in env: {key_name} in {os.path.basename(wf)}",
                            severity="high", category="github_actions",
                            module="dev",
                            description=f"Environment variable '{key_name}' in workflow has a hardcoded value. Use ${{{{ secrets.{key_name} }}}} instead.",
                            evidence=f"{key_name}={masked}",
                            asset=asset, points_deducted=10,
                            remediation=f"Use GitHub Secrets: Set {key_name} in Settings > Secrets and use ${{{{ secrets.{key_name} }}}} in the workflow.",
                        ))

        # Also check for tokens in run: steps
        for pattern, description in _ACTIONS_SECRET_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                for match in matches[:1]:
                    if isinstance(match, tuple):
                        match_str = match[-1] if match else "***"
                    else:
                        match_str = match
                    masked = match_str[:10] + "..." if len(str(match_str)) > 10 else "***"
                    findings.append(Finding(
                        title=f"{description}: {os.path.basename(wf)}",
                        severity="high", category="github_actions",
                        module="dev",
                        description=f"Potential secret or token found directly in GitHub Actions workflow.",
                        evidence=f"Match: {masked}",
                        asset=asset, points_deducted=10,
                        remediation="Move to GitHub Secrets and reference via ${{{{ secrets.NAME }}}}",
                    ))
                break  # One per pattern per file

    return findings


# ---------------------------------------------------------------------------
# NEW CHECK 6: Dependency Confusion Detection
# ---------------------------------------------------------------------------

# Popular public npm packages that are commonly used as internal/private names
# This helps detect when a private package shadows a popular public one
_PUBLIC_PACKAGE_NAMES = {
    "lodash", "underscore", "moment", "axios", "express", "react", "react-dom",
    "vue", "angular", "jquery", "bootstrap", "tailwindcss", "next", "nuxt",
    "webpack", "babel", "eslint", "prettier", "jest", "mocha", "chai",
    "mongoose", "prisma", "sequelize", "typeorm", "knex", "bookshelf",
    "passport", "bcrypt", "jsonwebtoken", "joi", "yup", "zod", "dotenv",
    "cors", "helmet", "compression", "morgan", "body-parser", "multer",
    "socket.io", "ws", "redis", "ioredis", "pg", "mysql", "mysql2",
    "mongoose", "mongodb", "amqplib", "kafkajs", "bull", "agenda",
    "nodemailer", "sendgrid", "stripe", "twilio", "aws-sdk", "firebase",
    "google-cloud", "azure", "@google/cloud", "@azure/storage",
    "uuid", "nanoid", "date-fns", "dayjs", "chalk", "ora", "inquirer",
    "commander", "yargs", "inquirer", "prompt", "figlet", "cli-table",
    "winston", "pino", "bunyan", "morgan", "log4js", "debug",
    "sharp", "jimp", "canvas", "pdfkit", "docx", "xlsx", "csv-parser",
    "cron", "node-cron", "agenda", "bree", "toad-scheduler",
    "config", "convict", "dotenv-flow", "rc", "nconf",
    "request", "got", "node-fetch", "ky", "undici", "superagent",
    "typeorm", "objection", "mikro-orm", "drizzle-orm", "kysely",
}


def _check_dependency_confusion(base: str) -> List[Finding]:
    """Check if private packages are named the same as popular public packages."""
    findings: List[Finding] = []
    asset = base

    # Check for .npmrc with registry config indicating private registry
    npmrc_paths = _find_files([".npmrc"], base)
    private_registry = None
    for npmrc in npmrc_paths:
        if "node_modules" in npmrc:
            continue
        content = _read_file(npmrc)
        if content:
            reg_match = re.search(r'registry\s*=\s*(https?://[^\s]+)', content)
            if reg_match:
                reg_url = reg_match.group(1)
                # If it's NOT the default npm registry, it's a private registry
                if "registry.npmjs.org" not in reg_url:
                    private_registry = reg_url

    # Check for private packages in package.json
    pkg_files = _find_files(["package.json"], base)
    for pkg_path in pkg_files:
        if "node_modules" in pkg_path:
            continue
        try:
            with open(pkg_path) as f:
                pkg = json.load(f)
        except Exception:
            continue

        all_deps = {}
        all_deps.update(pkg.get("dependencies", {}))
        all_deps.update(pkg.get("devDependencies", {}))

        for dep_name in all_deps:
            # Strip @scope/ prefix for comparison
            clean_name = dep_name.split("/")[-1] if "/" in dep_name else dep_name
            if clean_name.lower() in {n.lower() for n in _PUBLIC_PACKAGE_NAMES} and private_registry:
                findings.append(Finding(
                    title=f"Dependency confusion risk: '{dep_name}' on private registry",
                    severity="high", category="dependency_confusion",
                    module="dev",
                    description=f"Package '{dep_name}' is named the same as a popular public npm package, but you're using a private registry ({private_registry}). An attacker could publish a malicious version on the public registry with a higher version number.",
                    evidence=f"Package: {dep_name}, Registry: {private_registry}",
                    asset=asset, points_deducted=8,
                    remediation=f"1) Use scoped packages (e.g., @yourcompany/{clean_name}). 2) Configure .npmrc to always prefer your private registry for this package scope.",
                ))

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_dev(target: str = ".", base_url: str = "", timeout: int = 8,
            verify_tls: bool = True) -> List[Finding]:
    """Developer security audit.

    Args:
        target: Directory to scan (default: current directory).
    """
    base = _scan_dir(target)
    findings: List[Finding] = []

    findings.extend(_check_package_json(base))
    findings.extend(_check_requirements(base))
    findings.extend(_check_env_files(base))
    findings.extend(_check_git_security(base))
    findings.extend(_check_sensitive_files(base))
    findings.extend(_check_hardcoded_secrets(base))
    findings.extend(_check_docker_compose(base))

    # New checks
    findings.extend(_check_lockfile_cves(base))
    findings.extend(_check_go_rust_cargo(base))
    findings.extend(_check_git_config_credential_leak(base))
    findings.extend(_check_terraform_secrets(base))
    findings.extend(_check_github_actions_tokens(base))
    findings.extend(_check_dependency_confusion(base))

    return findings

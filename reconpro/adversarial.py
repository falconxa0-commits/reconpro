"""Adversarial self-play security remediation loop.

Three-agent system:
  HACKER   - Deep scans the target, discovers vulnerabilities.
  CODER    - Generates concrete fix commands for each finding.
  GUARDIAN - Re-scans / rule-checks whether fixes would close the gap.

The loop repeats until the GUARDIAN is satisfied or max_rounds is hit.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .scanner import scan, audit_scan
from .http_layer import Finding
from .utils import compute_grade


# -- ANSI helpers --------------------------------------------------------------

def _c(code: str, text: str) -> str:
    """Wrap *text* in an ANSI escape sequence."""
    return f"\033[{code}m{text}\033[0m"

RED = "91"
GREEN = "92"
YELLOW = "93"
BRIGHT_RED = "91;1"
BRIGHT_GREEN = "92;1"
BRIGHT_CYAN = "96"
BRIGHT_WHITE = "97;1"
DIM = "2"
BOLD = "1"

def red(t: str) -> str:   return _c(RED, t)
def green(t: str) -> str: return _c(GREEN, t)
def yellow(t: str) -> str: return _c(YELLOW, t)
def cyan(t: str) -> str:   return _c(BRIGHT_CYAN, t)
def white(t: str) -> str:  return _c(BRIGHT_WHITE, t)
def dim(t: str) -> str:   return _c(DIM, t)
def bold(t: str) -> str:  return _c(BOLD, t)


# -- Remediation Rule-Book ------------------------------------------------------

REMEDIATION_RULES: Dict[str, Dict[str, Any]] = {
    # 1 - Security headers
    "security_headers": {
        "description": "Missing HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)",
        "fix_commands": [
            "# -- Nginx ------------------------------------------",
            "add_header X-Frame-Options 'SAMEORIGIN' always;",
            "add_header X-Content-Type-Options 'nosniff' always;",
            "add_header X-XSS-Protection '1; mode=block' always;",
            "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;",
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'\" always;",
            "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;",
            "add_header Permissions-Policy 'camera=(), microphone=(), geolocation=()' always;",
            "",
            "# -- Apache (.htaccess or vhost) --------------------",
            "Header always set X-Frame-Options 'SAMEORIGIN'",
            "Header always set X-Content-Type-Options 'nosniff'",
            "Header always set X-XSS-Protection '1; mode=block'",
            "Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'",
            "Header always set Content-Security-Policy \"default-src 'self';\"",
            "Header always set Referrer-Policy 'strict-origin-when-cross-origin'",
        ],
        "verification_keys": ["x-frame-options", "x-content-type-options", "strict-transport-security",
                              "content-security-policy", "referrer-policy"],
        "confidence": 0.90,
    },
    # 2 - Open ports / services
    "open_ports": {
        "description": "Unnecessary network ports exposed to the public",
        "fix_commands": [
            "# -- UFW --------------------------------------------",
            "ufw default deny incoming",
            "ufw default allow outgoing",
            "ufw allow 22/tcp     # SSH (change port if non-standard)",
            "ufw allow 80/tcp     # HTTP",
            "ufw allow 443/tcp    # HTTPS",
            "ufw --force enable",
            "",
            "# -- iptables fallback -----------------------------",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
            "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            "iptables -A INPUT -j DROP",
            "iptables-save > /etc/iptables/rules.v4",
        ],
        "verification_keys": ["ufw", "iptables", "deny incoming"],
        "confidence": 0.85,
    },
    # 3 - Weak passwords / authentication
    "weak_passwords": {
        "description": "Weak password policy detected",
        "fix_commands": [
            "# -- /etc/security/pwquality.conf ------------------",
            "minlen = 14",
            "minclass = 3",
            "dcredit = -1",
            "ucredit = -1",
            "lcredit = -1",
            "ocredit = -1",
            "maxrepeat = 3",
            "enforcing = 1",
            "",
            "# -- /etc/login.defs -------------------------------",
            "PASS_MAX_DAYS   90",
            "PASS_MIN_DAYS   1",
            "PASS_MIN_LEN   14",
            "PASS_WARN_AGE   14",
        ],
        "verification_keys": ["minlen", "minclass", "pwquality"],
        "confidence": 0.80,
    },
    # 4 - Missing encryption at rest
    "missing_encryption": {
        "description": "Data at rest is not encrypted (no LUKS / FileVault)",
        "fix_commands": [
            "# -- LUKS (Linux) ----------------------------------",
            "# WARNING: Back up data first!",
            "cryptsetup luksFormat /dev/sdX",
            "cryptsetup luksOpen /dev/sdX encrypted_data",
            "mkfs.ext4 /dev/mapper/encrypted_data",
            "mount /dev/mapper/encrypted_data /mnt/secure",
            "",
            "# -- FileVault (macOS) ------------------------------",
            "fdesetup enable",
            "",
            "# -- BitLocker (Windows) ----------------------------",
            "manage-bde -on C: -RecoveryPassword",
        ],
        "verification_keys": ["luksFormat", "cryptsetup", "fdesetup", "bitlocker"],
        "confidence": 0.70,
    },
    # 5 - Secrets in environment / code
    "env_secrets": {
        "description": "Secrets or API keys found in environment variables or source code",
        "fix_commands": [
            "# -- HashiCorp Vault migration ---------------------",
            "vault kv put secret/app DB_PASSWORD=$(echo -n 'xxx' | base64)",
            "vault kv put secret/app API_KEY=$(echo -n 'yyy' | base64)",
            "",
            "# -- AWS Secrets Manager ---------------------------",
            "aws secretsmanager create-secret --name /app/db-password --secret-string REDACTED",
            "aws secretsmanager create-secret --name /app/api-key     --secret-string REDACTED",
            "",
            "# -- Application code change -----------------------",
            "# Replace:  os.environ['DB_PASSWORD']",
            "# With:     vault.read('secret/data/app')['data']['data']['DB_PASSWORD']",
            "",
            "# -- .env hardening ---------------------------------",
            "chmod 600 .env",
            "echo '.env' >> .gitignore",
        ],
        "verification_keys": ["vault kv put", "secretsmanager", ".gitignore", "chmod 600"],
        "confidence": 0.85,
    },
    # 6 - Outdated software / packages
    "outdated_software": {
        "description": "Running outdated software with known CVEs",
        "fix_commands": [
            "# -- Debian / Ubuntu --------------------------------",
            "apt update && apt upgrade -y",
            "apt autoremove -y",
            "",
            "# -- RHEL / CentOS / Fedora -------------------------",
            "dnf upgrade --refresh -y",
            "",
            "# -- Enable automatic security updates ------------",
            "apt install -y unattended-upgrades",
            "dpkg-reconfigure -plow unattended-upgrades",
            "",
            "# -- NPM ecosystem ----------------------------------",
            "npm audit --production",
            "npm audit fix",
            "",
            "# -- Python ecosystem -------------------------------",
            "pip install --upgrade pip && pip-audit --fix",
        ],
        "verification_keys": ["apt upgrade", "dnf upgrade", "npm audit", "pip-audit"],
        "confidence": 0.90,
    },
    # 7 - Insecure file permissions
    "file_permissions": {
        "description": "World-readable / world-writable files or directories",
        "fix_commands": [
            "# -- Common sensitive file lockdown ----------------",
            "chmod 600 /etc/shadow",
            "chmod 640 /etc/passwd",
            "chmod 600 /etc/ssh/sshd_config",
            "chmod 700 /root",
            "chmod 750 /home/*",
            "chmod 600 ~/.ssh/authorized_keys",
            "chmod 600 ~/.ssh/id_rsa",
            "chmod 644 ~/.ssh/id_rsa.pub",
            "",
            "# -- Fix world-writable files -----------------------",
            "find / -xdev -type f -perm -0002 -exec chmod o-w {} +",
            "find / -xdev -type d -perm -0002 -exec chmod o-w {} +",
            "",
            "# -- SUID/SGID audit --------------------------------",
            r"find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls",
        ],
        "verification_keys": ["chmod 600", "chmod 640", "chmod 750", "o-w"],
        "confidence": 0.88,
    },
    # 8 - SSH misconfiguration
    "ssh_misconfig": {
        "description": "SSH daemon configured insecurely (root login, weak ciphers, etc.)",
        "fix_commands": [
            "# -- /etc/ssh/sshd_config hardening -----------------",
            "PermitRootLogin no",
            "PasswordAuthentication no",
            "PubkeyAuthentication yes",
            "Protocol 2",
            "MaxAuthTries 3",
            "LoginGraceTime 30",
            "AllowUsers deploy admin",
            "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
            "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com",
            "",
            "systemctl restart sshd",
        ],
        "verification_keys": ["PermitRootLogin no", "PasswordAuthentication no",
                              "MaxAuthTries 3", "PubkeyAuthentication yes"],
        "confidence": 0.92,
    },
    # 9 - Docker security issues
    "docker_issues": {
        "description": "Insecure Docker daemon or container configuration",
        "fix_commands": [
            "# -- /etc/docker/daemon.json -----------------------",
            '{"userns-remap": "default", "live-restore": true, '
            '"no-new-privileges": true, "userland-proxy": false}',
            "",
            "# -- Container hardening flags ---------------------",
            "docker run --rm --cap-drop ALL --cap-add CHOWN --read-only --security-opt no-new-privileges ...",
            "docker run --rm --network=none --pid=host ...",  # if needed
            "",
            "# -- Enable user namespaces -----------------------",
            '# echo > /etc/subuid  {"subuid": "100000:65536", "subgid": "100000:65536"}',
            "",
            "# -- Restrict Docker API --------------------------",
            "# DO NOT expose 2375/tcp without TLS",
            "systemctl edit docker.service",  # add --tlsverify --tlscacert=...
        ],
        "verification_keys": ["userns-remap", "no-new-privileges", "cap-drop ALL", "read-only"],
        "confidence": 0.85,
    },
    # 10 - TLS / SSL misconfiguration
    "tls_misconfig": {
        "description": "Weak TLS configuration (old protocols, weak ciphers)",
        "fix_commands": [
            "# -- Nginx SSL hardening ---------------------------",
            "ssl_protocols TLSv1.2 TLSv1.3;",
            "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';",
            "ssl_prefer_server_ciphers on;",
            "ssl_session_cache shared:SSL:10m;",
            "ssl_session_timeout 10m;",
            "",
            "# -- Apache SSL hardening --------------------------",
            "SSLProtocol -all +TLSv1.2 +TLSv1.3",
            "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
            "SSLHonorCipherOrder on",
        ],
        "verification_keys": ["TLSv1.2", "TLSv1.3", "ssl_protocols", "ssl_ciphers"],
        "confidence": 0.90,
    },
    # 11 - Information disclosure
    "info_disclosure": {
        "description": "Server version, framework, or technology stack leaked in headers/body",
        "fix_commands": [
            "# -- Nginx -----------------------------------------",
            "server_tokens off;",
            "",
            "# -- Apache ----------------------------------------",
            "ServerTokens Prod",
            "ServerSignature Off",
            "",
            "# -- PHP -------------------------------------------",
            "expose_php = Off",  # php.ini
            "",
            "# -- Remove X-Powered-By / X-AspNet-Version -------",
            "# Framework-specific: set display_errors=Off, debug=false",
        ],
        "verification_keys": ["server_tokens off", "ServerTokens Prod", "expose_php", "display_errors"],
        "confidence": 0.85,
    },
    # 12 - Cross-Site Scripting (XSS)
    "xss": {
        "description": "Reflected or stored XSS vulnerabilities detected",
        "fix_commands": [
            "# -- Content Security Policy (primary defense) ----",
            "Content-Security-Policy: default-src 'self'; script-src 'self';",
            "",
            "# -- Output encoding (application layer) ----------",
            "# Python:  |escape or markupsafe.escape(user_input)",
            "# Node.js:  encodeURIComponent(user_input)",
            "# Go:       html.EscapeString(user_input)",
            "",
            "# -- HTTPOnly + Secure cookie flags ---------------",
            "Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict",
        ],
        "verification_keys": ["Content-Security-Policy", "HttpOnly", "escape", "encodeURIComponent"],
        "confidence": 0.80,
    },
    # 13 - SQL Injection
    "sql_injection": {
        "description": "SQL injection vectors found in input parameters",
        "fix_commands": [
            "# -- Parameterized queries (the ONLY real fix) ----",
            "# Python (sqlite3):  cursor.execute('SELECT * FROM t WHERE id=?', (uid,))",
            "# Python (psycopg2): cursor.execute('SELECT * FROM t WHERE id=%s', (uid,))",
            "# Node.js (pg):      client.query('SELECT * FROM t WHERE id=$1', [uid])",
            "# Java (JDBC):       PreparedStatement ps = conn.prepareStatement('SELECT * FROM t WHERE id=?');",
            "",
            "# -- ORM usage ------------------------------------",
            "# Use SQLAlchemy, Django ORM, Hibernate, Sequelize -- never concatenate SQL.",
            "",
            "# -- WAF as defense-in-depth ----------------------",
            "# ModSecurity: SecRule ARGS '@@contains' SELECT 'id:1001,phase:2,deny'",
        ],
        "verification_keys": ["parameterized", "prepared statement", "ORM", "placeholder"],
        "confidence": 0.88,
    },
    # 14 - Clickjacking
    "clickjacking": {
        "description": "Page can be framed -- no X-Frame-Options or CSP frame-ancestors",
        "fix_commands": [
            "# -- X-Frame-Options header ------------------------",
            "X-Frame-Options: DENY   # or SAMEORIGIN if framing is needed",
            "",
            "# -- CSP frame-ancestors (modern) ------------------",
            "Content-Security-Policy: frame-ancestors 'self';",
        ],
        "verification_keys": ["X-Frame-Options", "frame-ancestors"],
        "confidence": 0.95,
    },
    # 15 - CSRF
    "csrf": {
        "description": "Cross-Site Request Forgery -- no anti-CSRF token found",
        "fix_commands": [
            "# -- Framework-built-in CSRF protection -----------",
            "# Django:  {% csrf_token %} in every form",
            "# Flask:   @app.before_request + session-based token",
            "# Rails:   rails_ujs auto-injects authenticity_token",
            "# Express: csurf middleware",
            "",
            "# -- SameSite cookie attribute --------------------",
            "Set-Cookie: session=abc; SameSite=Strict; Secure; HttpOnly",
        ],
        "verification_keys": ["csrf_token", "SameSite", "authenticity_token", "csurf"],
        "confidence": 0.82,
    },
    # 16 - Subdomain takeover
    "subdomain_takeover": {
        "description": "Dangling DNS record pointing to a deprovisioned cloud service",
        "fix_commands": [
            "# -- Remove dangling CNAME / A records -----------",
            "# AWS Route 53:  aws route53 change-resource-record-sets --hosted-zone-id ZID --change-batch file://remove.json",
            "# Cloudflare:   Delete the DNS record via dashboard or API",
            "",
            "# -- Audit all subdomains periodically ------------",
            "# python3 reconpro subdomain-audit example.com",
        ],
        "verification_keys": ["change-resource-record-sets", "delete", "remove"],
        "confidence": 0.78,
    },
    # 17 - Rate limiting absent
    "no_rate_limit": {
        "description": "No rate limiting on authentication or API endpoints",
        "fix_commands": [
            "# -- Nginx -----------------------------------------",
            "limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;",
            "limit_req zone=login burst=5 nodelay;",
            "",
            "# -- Fail2Ban --------------------------------------",
            "apt install -y fail2ban",
            "systemctl enable --now fail2ban",
            "echo '[sshd]' > /etc/fail2ban/jail.local",
            "echo 'enabled = true' >> /etc/fail2ban/jail.local",
            "echo 'maxretry = 3' >> /etc/fail2ban/jail.local",
            "echo 'bantime = 3600' >> /etc/fail2ban/jail.local",
            "",
            "# -- Application-level (example: Flask-Limiter) --",
            "# @limiter.limit('5/minute')  # per-IP on login endpoint",
        ],
        "verification_keys": ["limit_req_zone", "fail2ban", "rate", "limiter"],
        "confidence": 0.85,
    },
    # 18 - Cookie security
    "cookie_security": {
        "description": "Cookies missing Secure / HttpOnly / SameSite flags",
        "fix_commands": [
            "# -- Application code changes ----------------------",
            "# Set-Cookie: sid=abc; Secure; HttpOnly; SameSite=Strict; Path=/",
            "",
            "# -- Python (Flask) --------------------------------",
            "app.config['SESSION_COOKIE_SECURE'] = True",
            "app.config['SESSION_COOKIE_HTTPONLY'] = True",
            "app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'",
        ],
        "verification_keys": ["Secure", "HttpOnly", "SameSite"],
        "confidence": 0.90,
    },
    # 19 - CORS misconfiguration
    "cors_misconfig": {
        "description": "Overly permissive CORS policy (wildcard origin reflected)",
        "fix_commands": [
            "# -- Restrict allowed origins ---------------------",
            "Access-Control-Allow-Origin: https://trusted.example.com   # NOT *",
            "Access-Control-Allow-Credentials: true",
            "Access-Control-Allow-Methods: GET, POST, OPTIONS",
            "Access-Control-Allow-Headers: Content-Type, Authorization",
            "",
            "# -- Django (django-cors-headers) -------------------",
            "CORS_ALLOWED_ORIGINS = ['https://trusted.example.com']",
            "CORS_ALLOW_CREDENTIALS = True",
        ],
        "verification_keys": ["Access-Control-Allow-Origin", "CORS_ALLOWED_ORIGINS", "not *"],
        "confidence": 0.87,
    },
    # 20 - Sensitive paths exposed
    "sensitive_paths": {
        "description": "Sensitive files or directories accessible (.git, .env, admin panels)",
        "fix_commands": [
            "# -- Nginx block rules -----------------------------",
            r"location ~ /\.git { deny all; return 404; }",
            r"location ~ /\.env { deny all; return 404; }",
            "location ~ /wp-admin { allow 10.0.0.0/8; deny all; }",
            "location ~ /phpmyadmin { deny all; return 404; }",
            r"location ~ /backup\.sql { deny all; return 404; }",
            r"location ~ /\.DS_Store { deny all; return 404; }",
            "",
            "# -- Ensure .git is not web-accessible ------------",
            r"RedirectMatch 404 /\.git",
        ],
        "verification_keys": ["deny all", "return 404", ".git", ".env", "location ~"],
        "confidence": 0.88,
    },
    # 21 - Directory listing enabled
    "directory_listing": {
        "description": "Directory listing is enabled, exposing file structure",
        "fix_commands": [
            "# -- Nginx -----------------------------------------",
            "autoindex off;",
            "",
            "# -- Apache ----------------------------------------",
            "Options -Indexes",
        ],
        "verification_keys": ["autoindex off", "Options -Indexes"],
        "confidence": 0.95,
    },
    # 22 - Unpatched kernel / OS
    "unpatched_kernel": {
        "description": "Running a kernel or OS version with known vulnerabilities",
        "fix_commands": [
            "# -- Debian / Ubuntu --------------------------------",
            "apt update && apt dist-upgrade -y",
            "reboot",
            "",
            "# -- RHEL / CentOS ----------------------------------",
            "dnf update -y && reboot",
            "",
            "# -- Check current kernel --------------------------",
            "uname -r  # verify after reboot",
        ],
        "verification_keys": ["dist-upgrade", "dnf update", "reboot", "uname"],
        "confidence": 0.92,
    },
    # 23 - Debug mode enabled
    "debug_mode": {
        "description": "Application running in debug/development mode in production",
        "fix_commands": [
            "# -- Django ----------------------------------------",
            "DEBUG = False  # settings.py",
            "ALLOWED_HOSTS = ['example.com']  # restrict to real hostnames",
            "",
            "# -- Flask -----------------------------------------",
            "app.config['DEBUG'] = False",
            "app.config['TESTING'] = False",
            "",
            "# -- Node.js / Express -----------------------------",
            "NODE_ENV=production  # set in environment or process manager",
        ],
        "verification_keys": ["DEBUG = False", "NODE_ENV", "production"],
        "confidence": 0.95,
    },
    # 24 - Default credentials
    "default_credentials": {
        "description": "Default or hardcoded credentials detected (admin/admin, root/toor)",
        "fix_commands": [
            "# -- Change all default passwords immediately ------",
            "# MySQL:  ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongP@ss!2024';",
            "# PostgreSQL: ALTER USER postgres WITH PASSWORD 'StrongP@ss!2024';",
            "# Redis:   echo 'requirepass YourStr0ngP@ss' >> /etc/redis/redis.conf",
            "# MongoDB: use admin; db.changeUserPassword('root', 'StrongP@ss!2024')",
            "",
            "# -- Remove hardcoded credentials from source ------",
            "# Replace with environment variable lookups or secret managers.",
        ],
        "verification_keys": ["ALTER USER", "IDENTIFIED BY", "requirepass", "changeUserPassword"],
        "confidence": 0.85,
    },
    # 25 - Unnecessary services / daemons
    "unnecessary_services": {
        "description": "Unneeded services running, expanding attack surface",
        "fix_commands": [
            "# -- Disable & mask unneeded services --------------",
            "systemctl disable --now telnet.socket",
            "systemctl disable --now rsh.socket",
            "systemctl disable --now ftpd.service",
            "systemctl mask avahi-daemon.service",
            "systemctl mask cups.service",
            "",
            "# -- Audit running services ------------------------",
            "systemctl list-units --type=service --state=running",
        ],
        "verification_keys": ["systemctl disable", "systemctl mask", "--now"],
        "confidence": 0.85,
    },
}


# -- Category fuzzy matcher -----------------------------------------------------

# Maps substrings in finding categories / titles to the rule-book keys above.
_CATEGORY_ALIAS: Dict[str, str] = {
    "header": "security_headers",
    "hsts": "security_headers",
    "csp": "security_headers",
    "x-frame": "security_headers",
    "x-content-type": "security_headers",
    "port": "open_ports",
    "service": "open_ports",
    "password": "weak_passwords",
    "auth": "weak_passwords",
    "credential": "default_credentials",
    "default": "default_credentials",
    "encrypt": "missing_encryption",
    "luks": "missing_encryption",
    "secret": "env_secrets",
    "api_key": "env_secrets",
    "env": "env_secrets",
    "outdated": "outdated_software",
    "cve": "outdated_software",
    "version": "outdated_software",
    "permission": "file_permissions",
    "chmod": "file_permissions",
    "ssh": "ssh_misconfig",
    "sshd": "ssh_misconfig",
    "docker": "docker_issues",
    "container": "docker_issues",
    "tls": "tls_misconfig",
    "ssl": "tls_misconfig",
    "certificate": "tls_misconfig",
    "disclosure": "info_disclosure",
    "leak": "info_disclosure",
    "xss": "xss",
    "cross-site script": "xss",
    "sqli": "sql_injection",
    "sql injection": "sql_injection",
    "clickjack": "clickjacking",
    "frame": "clickjacking",
    "csrf": "csrf",
    "subdomain": "subdomain_takeover",
    "dangling": "subdomain_takeover",
    "rate": "no_rate_limit",
    "brute": "no_rate_limit",
    "cookie": "cookie_security",
    "cors": "cors_misconfig",
    "sensitive_path": "sensitive_paths",
    ".git": "sensitive_paths",
    ".env": "sensitive_paths",
    "directory list": "directory_listing",
    "autoindex": "directory_listing",
    "kernel": "unpatched_kernel",
    "debug": "debug_mode",
    "unnecessary": "unnecessary_services",
    "daemon": "unnecessary_services",
}


def _match_category(finding_title: str, finding_category: str) -> Optional[str]:
    """Try to map a finding to a remediation rule key."""
    combined = f"{finding_category} {finding_title}".lower()
    best_key: Optional[str] = None
    best_len = 0
    for alias, rule_key in _CATEGORY_ALIAS.items():
        if alias.lower() in combined:
            if len(alias) > best_len:
                best_len = len(alias)
                best_key = rule_key
    return best_key


# -- Data classes --------------------------------------------------------------

@dataclass
class RemediationAction:
    """A single fix generated by the CODER."""
    finding_title: str
    finding_category: str
    severity: str
    rule_key: Optional[str]
    rule_description: str
    fix_commands: List[str]
    confidence: float
    verified: bool = False
    verification_note: str = ""
    round_applied: int = 0


@dataclass
class RoundSummary:
    """Summary of one HACKER -> CODER -> GUARDIAN round."""
    round_num: int
    hacker_findings: int
    hacker_new: int
    coder_fixes: int
    guardian_verified_fixed: int
    guardian_still_vulnerable: int
    total_open: int
    score_before: int
    score_after: int
    grade_before: str
    grade_after: str
    elapsed_seconds: float
    actions: List[RemediationAction] = field(default_factory=list)
    remaining_titles: List[str] = field(default_factory=list)


@dataclass
class AdversarialResult:
    """Complete result of the adversarial self-play loop."""
    target: str
    max_rounds: int
    rounds: List[RoundSummary] = field(default_factory=list)
    total_findings_initial: int = 0
    total_findings_final: int = 0
    findings_fixed: int = 0
    findings_unfixed: int = 0
    remediation_report: str = ""
    final_score: int = 0
    final_grade: str = ""
    initial_score: int = 0
    initial_grade: str = ""
    converged: bool = False
    modules_run: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "max_rounds": self.max_rounds,
            "total_findings_initial": self.total_findings_initial,
            "total_findings_final": self.total_findings_final,
            "findings_fixed": self.findings_fixed,
            "findings_unfixed": self.findings_unfixed,
            "final_score": self.final_score,
            "final_grade": self.final_grade,
            "initial_score": self.initial_score,
            "initial_grade": self.initial_grade,
            "converged": self.converged,
            "rounds": [
                {
                    "round": r.round_num,
                    "hacker_findings": r.hacker_findings,
                    "hacker_new": r.hacker_new,
                    "coder_fixes": r.coder_fixes,
                    "guardian_verified_fixed": r.guardian_verified_fixed,
                    "guardian_still_vulnerable": r.guardian_still_vulnerable,
                    "total_open": r.total_open,
                    "score_before": r.score_before,
                    "score_after": r.score_after,
                    "grade_before": r.grade_before,
                    "grade_after": r.grade_after,
                    "elapsed_seconds": round(r.elapsed_seconds, 2),
                }
                for r in self.rounds
            ],
            "remediation_report": self.remediation_report,
        }


# -- Adversarial Loop ----------------------------------------------------------

class AdversarialLoop:
    """Runs HACKER vs CODER vs GUARDIAN in an iterative remediation loop."""

    def __init__(
        self,
        target: str,
        max_rounds: int = 3,
        modules: Optional[List[str]] = None,
        is_local: bool = False,
    ) -> None:
        self.target = target
        self.max_rounds = max_rounds
        self.modules = modules
        self.is_local = is_local
        self._all_actions: List[RemediationAction] = []
        self._fixed_titles: set = set()
        self._failed_titles: set = set()
        self._feedback_context: Dict[str, List[str]] = {}
        self._converged = False

    # -- HACKER phase ---------------------------------------------------------

    def _run_hacker(self) -> Tuple[List[Dict[str, Any]], int, str]:
        """Run a deep scan and return (findings, score, grade)."""
        print(f"  {red('>>  HACKER')}  Scanning {white(self.target)} ...")
        try:
            if self.is_local:
                result = audit_scan(target=self.target, modules=self.modules)
            else:
                result = scan(target=self.target, modules=self.modules, all_modules=False)
            findings = result.findings
            score = result.total_score
            grade = result.grade
        except Exception as exc:
            print(f"    {dim(f'Scan error: {exc}')}")
            return [], 100, "A"
        print(f"    {red(str(len(findings)))} finding(s) discovered")
        return findings, score, grade

    # -- CODER phase ----------------------------------------------------------

    def _run_coder(
        self,
        findings: List[Dict[str, Any]],
        round_num: int,
    ) -> List[RemediationAction]:
        """Generate remediation actions for each finding."""
        print(f"  {green('>>  CODER')}  Generating fixes ...")
        actions: List[RemediationAction] = []
        for f in findings:
            title = f.get("title", "")
            category = f.get("category", "")
            severity = f.get("severity", "info")

            # Skip already-fixed or already-attempted findings
            if title in self._fixed_titles:
                continue
            if title in self._failed_titles:
                continue

            rule_key = _match_category(title, category)
            if rule_key and rule_key in REMEDIATION_RULES:
                rule = REMEDIATION_RULES[rule_key]
                # Enrich with feedback from previous rounds if available
                fix_cmds = list(rule["fix_commands"])
                if title in self._feedback_context:
                    prior_notes = self._feedback_context[title]
                    fix_cmds.append("")
                    fix_cmds.append("# -- GUARDIAN feedback from prior round(s) --")
                    for note in prior_notes:
                        fix_cmds.append(f"#   > {note}")
                    fix_cmds.append("#   Ensure the above commands are applied before re-verification.")

                action = RemediationAction(
                    finding_title=title,
                    finding_category=category,
                    severity=severity,
                    rule_key=rule_key,
                    rule_description=rule["description"],
                    fix_commands=fix_cmds,
                    confidence=rule["confidence"],
                    round_applied=round_num,
                )
            else:
                # Generic remediation for unmapped categories
                action = RemediationAction(
                    finding_title=title,
                    finding_category=category,
                    severity=severity,
                    rule_key=None,
                    rule_description=f"Manual remediation needed for category '{category}'",
                    fix_commands=[
                        f"# Manual investigation required:",
                        f"#   Finding : {title}",
                        f"#   Category: {category}",
                        f"#   Severity: {severity}",
                        f"# Review the evidence and apply appropriate fixes.",
                        f"# Re-scan after fixing to verify closure.",
                    ],
                    confidence=0.30,
                    round_applied=round_num,
                )
            actions.append(action)
        print(f"    {green(str(len(actions)))} fix(es) generated")
        return actions

    # -- GUARDIAN phase --------------------------------------------------------

    def _run_guardian(
        self,
        actions: List[RemediationAction],
        all_findings: List[Dict[str, Any]],
        round_num: int,
    ) -> Tuple[int, int, List[str]]:
        """Rule-based verification of proposed fixes.

        Returns (verified_fixed_count, still_vulnerable_count, remaining_titles).
        """
        print(f"  {yellow('>>  GUARDIAN')} Verifying fixes ...")
        verified = 0
        still_open = 0
        remaining: List[str] = []

        # Build a lookup of current finding titles
        finding_titles = {f.get("title", "") for f in all_findings}

        for action in actions:
            title = action.finding_title
            rule_key = action.rule_key

            if rule_key and rule_key in REMEDIATION_RULES:
                rule = REMEDIATION_RULES[rule_key]
                verif_keys = rule.get("verification_keys", [])
                confidence = rule.get("confidence", 0.5)

                # Check severity and confidence for auto-verification
                if confidence >= 0.90:
                    action.verified = True
                    action.verification_note = (
                        f"High-confidence rule ({confidence:.0%}) -- "
                        f"fix commands should resolve '{title}'."
                    )
                    verified += 1
                    self._fixed_titles.add(title)
                    self._failed_titles.discard(title)
                elif confidence >= 0.80:
                    # Medium-high confidence: verify if the finding is still present
                    if title in finding_titles:
                        # Still present after fix -- mark as still vulnerable
                        action.verified = False
                        action.verification_note = (
                            f"Finding '{title}' still present after remediation attempt. "
                            f"Commands target: {', '.join(verif_keys[:3])}."
                        )
                        still_open += 1
                        remaining.append(title)
                        self._failed_titles.add(title)
                        # Feed back context for next round
                        self._feedback_context.setdefault(title, []).append(
                            f"Round {round_num}: Fix not effective. Try applying all commands."
                        )
                    else:
                        action.verified = True
                        action.verification_note = f"Finding '{title}' no longer detected."
                        verified += 1
                        self._fixed_titles.add(title)
                        self._failed_titles.discard(title)
                else:
                    # Lower confidence -- always flag as needing verification
                    action.verified = False
                    action.verification_note = (
                        f"Rule confidence {confidence:.0%} is below threshold. "
                        f"Manual verification required for '{title}'."
                    )
                    still_open += 1
                    remaining.append(title)
                    self._feedback_context.setdefault(title, []).append(
                        f"Round {round_num}: Low confidence rule. Escalate to manual review."
                    )
            else:
                # No matching rule
                action.verified = False
                action.verification_note = (
                    f"No verification rule for category '{action.finding_category}'. "
                    f"Manual review required."
                )
                still_open += 1
                remaining.append(title)

        print(f"    {green(str(verified))} verified fixed  |  "
              f"{red(str(still_open))} still vulnerable")
        return verified, still_open, remaining

    # -- Progress bar ---------------------------------------------------------

    @staticmethod
    def _progress_bar(fixed: int, total: int, width: int = 30) -> str:
        if total == 0:
            return green("#" * width) + " 100%"
        ratio = fixed / total
        filled = int(width * ratio)
        bar = green("#" * filled) + dim("." * (width - filled))
        return f"{bar} {ratio:.0%}"

    # -- Round display --------------------------------------------------------

    @staticmethod
    def _print_round_banner(round_num: int, max_rounds: int) -> None:
        print()
        print(f"{white('=' * 60)}")
        print(f"{bold(f'  ROUND {round_num} / {max_rounds}')}")
        print(f"{white('=' * 60)}")

    # -- Main loop ------------------------------------------------------------

    def run(self) -> AdversarialResult:
        """Execute the full adversarial loop and return an AdversarialResult."""
        print()
        print(f"{bold(cyan('  +==========================================+'))}")
        print(f"{bold(cyan('  |   ADVERSARIAL  SELF-PLAY  REMEDIATION   |'))}")
        print(f"{bold(cyan('  |   HACKER -> CODER -> GUARDIAN  (loop)  |'))}")
        print(f"{bold(cyan('  +==========================================+'))}")
        print(f"  Target: {white(self.target)}")
        print(f"  Max rounds: {white(str(self.max_rounds))}")
        print(f"  Mode: {white('LOCAL AUDIT' if self.is_local else 'REMOTE SCAN')}")

        result = AdversarialResult(
            target=self.target,
            max_rounds=self.max_rounds,
        )

        initial_findings: List[Dict[str, Any]] = []
        initial_score = 100
        initial_grade = "A"

        for rnd in range(1, self.max_rounds + 1):
            t0 = time.monotonic()
            self._print_round_banner(rnd, self.max_rounds)

            # -- HACKER ---------------------------------------------------------
            findings, score_before, grade_before = self._run_hacker()
            if rnd == 1:
                initial_findings = list(findings)
                initial_score = score_before
                initial_grade = grade_before

            # Track new vs already-known findings
            known_titles = self._fixed_titles | self._failed_titles
            new_findings = [f for f in findings if f.get("title", "") not in known_titles]
            hacker_new = len(new_findings)
            hacker_total = len(findings)

            # -- CODER ----------------------------------------------------------
            actions = self._run_coder(findings, round_num=rnd)
            self._all_actions.extend(actions)

            # -- GUARDIAN -------------------------------------------------------
            verified_fixed, still_vulnerable, remaining_titles = self._run_guardian(
                actions, findings, round_num=rnd,
            )
            elapsed = time.monotonic() - t0

            # Compute projected score after fixes
            projected_score = min(100, 100 - sum(
                f.get("points_deducted", 0)
                for f in findings
                if f.get("title", "") not in self._fixed_titles
            ))
            projected_grade = compute_grade(projected_score)

            # Open issues: findings not yet fixed
            open_titles = {
                f.get("title", "") for f in findings
            } - self._fixed_titles
            total_open = len(open_titles)

            progress_str = self._progress_bar(
                len(self._fixed_titles),
                len(initial_findings) if initial_findings else 1,
            )

            round_summary = RoundSummary(
                round_num=rnd,
                hacker_findings=hacker_total,
                hacker_new=hacker_new,
                coder_fixes=len(actions),
                guardian_verified_fixed=verified_fixed,
                guardian_still_vulnerable=still_vulnerable,
                total_open=total_open,
                score_before=score_before,
                score_after=projected_score,
                grade_before=grade_before,
                grade_after=projected_grade,
                elapsed_seconds=elapsed,
                actions=actions,
                remaining_titles=remaining_titles,
            )
            result.rounds.append(round_summary)

            # -- Round summary output -------------------------------------------
            print()
            print(f"  {dim('--- Round Summary ------------------------------------')}")
            print(f"  Findings scanned    : {red(str(hacker_total))}  (new: {red(str(hacker_new))})")
            print(f"  Fixes generated     : {green(str(len(actions)))}")
            print(f"  Verified fixed      : {green(str(verified_fixed))}")
            print(f"  Still vulnerable    : {red(str(still_vulnerable))}")
            print(f"  Open issues         : {yellow(str(total_open))}")
            print(f"  Progress            : {progress_str}")
            print(f"  Score               : {grade_before} ({score_before}) -> {projected_grade} ({projected_score})")
            print(f"  Elapsed             : {dim(f'{elapsed:.1f}s')}")

            # -- Show individual fixes ------------------------------------------
            if actions:
                print()
                print(f"  {dim('--- Fixes Applied -----------------------------------')}")
                for act in actions:
                    status_icon = green("[OK]") if act.verified else red("[!!]")
                    sev_color = {
                        "critical": BRIGHT_RED, "high": RED,
                        "medium": YELLOW, "low": DIM, "info": DIM,
                    }.get(act.severity, DIM)
                    print(f"    {status_icon} {_c(sev_color, act.severity.upper().ljust(8))} "
                          f"{act.finding_title[:60]}")
                    if act.rule_key:
                        print(f"      {dim(f'Rule: {act.rule_key} (confidence {act.confidence:.0%})')}")

            # -- Check convergence ----------------------------------------------
            if total_open == 0:
                self._converged = True
                print()
                print(f"  {green(bold('  >> ALL FINDINGS REMEDIATED -- loop converged!'))}")
                break

            if rnd < self.max_rounds and still_vulnerable == 0 and hacker_new == 0:
                # No new findings and no new fixes -- likely converged
                self._converged = True
                print()
                print(f"  {yellow(bold('  !! No new findings or fixes -- loop stalled. Stopping early.'))}")
                break

        # -- Build final report ------------------------------------------------
        initial_title_set = {f.get("title", "") for f in initial_findings}
        result.total_findings_initial = len(initial_findings)
        result.total_findings_final = len(initial_title_set - self._fixed_titles)
        result.findings_fixed = len(self._fixed_titles & initial_title_set)
        result.findings_unfixed = result.total_findings_initial - result.findings_fixed
        result.final_score = result.rounds[-1].score_after if result.rounds else 100
        result.final_grade = compute_grade(result.final_score)
        result.initial_score = initial_score
        result.initial_grade = initial_grade
        result.converged = self._converged
        result.remediation_report = self._build_remediation_report(result)

        # -- Final scorecard ---------------------------------------------------
        self._print_scorecard(result)

        return result

    # -- Remediation report builder --------------------------------------------

    def _build_remediation_report(self, result: AdversarialResult) -> str:
        lines: List[str] = []
        lines.append("RECONPRO ADVERSARIAL REMEDIATION REPORT")
        lines.append("=" * 50)
        lines.append(f"Target          : {result.target}")
        lines.append(f"Initial findings: {result.total_findings_initial}")
        lines.append(f"Fixed           : {result.findings_fixed}")
        lines.append(f"Unfixed         : {result.findings_unfixed}")
        lines.append(f"Score           : {result.initial_grade} ({result.initial_score}) -> "
                      f"{result.final_grade} ({result.final_score})")
        lines.append(f"Converged       : {result.converged}")
        lines.append(f"Rounds played   : {len(result.rounds)}")
        lines.append("")

        for rnd in result.rounds:
            lines.append(f"--- Round {rnd.round_num} ---")
            lines.append(f"  HACKER:   {rnd.hacker_findings} findings ({rnd.hacker_new} new)")
            lines.append(f"  CODER:    {rnd.coder_fixes} fixes generated")
            lines.append(f"  GUARDIAN: {rnd.guardian_verified_fixed} fixed, {rnd.guardian_still_vulnerable} still open")
            lines.append("")

            for act in rnd.actions:
                status = "FIXED" if act.verified else "OPEN"
                lines.append(f"  [{status}] {act.finding_title}")
                lines.append(f"    Category: {act.finding_category}  |  Severity: {act.severity}")
                if act.rule_key:
                    lines.append(f"    Rule: {act.rule_key} (confidence {act.confidence:.0%})")
                lines.append(f"    Fix commands:")
                for cmd in act.fix_commands:
                    lines.append(f"      {cmd}")
                lines.append(f"    Note: {act.verification_note}")
                lines.append("")

        # Unfixed findings detail
        unfixed_actions = [a for a in self._all_actions if not a.verified]
        if unfixed_actions:
            lines.append("=== REMAINING VULNERABILITIES ===")
            for act in unfixed_actions:
                lines.append(f"  - {act.finding_title} ({act.severity})")
                lines.append(f"    {act.verification_note}")
            lines.append("")

        return "\n".join(lines)

    # -- Scorecard -------------------------------------------------------------

    @staticmethod
    def _print_scorecard(result: AdversarialResult) -> None:
        print()
        print(f"{white('=' * 60)}")
        print(f"{bold(cyan('  FINAL SCORECARD'))}")
        print(f"{white('=' * 60)}")
        print(f"  Target          : {white(result.target)}")
        print(f"  Initial findings: {red(str(result.total_findings_initial))}")
        print(f"  Fixed           : {green(str(result.findings_fixed))}")
        print(f"  Unfixed         : {red(str(result.findings_unfixed))}")
        print(f"  Score change    : {result.initial_grade} ({result.initial_score}) -> "
              f"{result.final_grade} ({result.final_score})")
        print(f"  Converged       : {green('YES') if result.converged else red('NO')}")
        print(f"  Rounds played   : {len(result.rounds)}")

        if result.findings_unfixed == 0:
            print()
            print(f"  {green(bold('  >> ALL VULNERABILITIES REMEDIATED SUCCESSFULLY'))}")
        else:
            pct = (result.findings_fixed / result.total_findings_initial * 100
                   if result.total_findings_initial > 0 else 100)
            print(f"  Remediation rate: {yellow(f'{pct:.0f}%')}")
            print()
            print(f"  {red(bold('  !! Some vulnerabilities remain -- review the report above.'))}")

        print(f"{white('=' * 60)}")
        print()


# -- Public entry point --------------------------------------------------------

def run_adversarial(
    target: str,
    max_rounds: int = 3,
    modules: Optional[List[str]] = None,
    is_local: bool = False,
) -> AdversarialResult:
    """Run the adversarial self-play loop against a target.

    Args:
        target:      Domain/URL for remote scan, or directory for local audit.
        max_rounds:  Maximum HACKER->CODER->GUARDIAN iterations (default 3).
        modules:     Optional list of module IDs to use during scans.
        is_local:    If True, run audit_scan instead of scan.

    Returns:
        AdversarialResult with all round summaries, remediation report, and scores.
    """
    loop = AdversarialLoop(
        target=target,
        max_rounds=max_rounds,
        modules=modules,
        is_local=is_local,
    )
    return loop.run()

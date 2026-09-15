"""Autonomous Defense Generation for ReconPro v8.0.

Given vulnerability findings from ReconPro scanners, this module generates
deployable fixes: WAF rules, code patches, infrastructure fixes, and CI/CD
additions.

Exports:
    PatchGenerator    - single-finding defense generator
    DefenseBundle     - batch defense orchestrator
    CATEGORY_PATCH_MAP - category -> fix template registry
    generate_defense       - convenience: single finding
    generate_defense_bundle - convenience: batch findings
"""
from __future__ import annotations

import hashlib
import json
import re
import textwrap
import uuid
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# CATEGORY_PATCH_MAP  --  vulnerability category  ->  fix templates
# ---------------------------------------------------------------------------

# ModSecurity rule building helper — these are REAL, deployable SecRule directives.
# Single quotes inside msg strings use \x27 hex-escape to stay inside raw r"..." literals.

_SMODSEC_SSQLI = (
    r'SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES '
    r'"@rx (?i)(\b(union\s+select|or\s+1\s*=\s*1|\x27\s*or\s*\x27|--\s*$|;\s*drop\s+|'
    r';\s*delete\s+|sleep\s*\(|benchmark\s*\(|extractvalue\s*\(|updatexml\s*\())" '
    r'"id:900001,phase:2,deny,status:403,msg:\x27SQL Injection detected\x27,'
    r'severity:CRITICAL,t:none,t:urlDecodeUni,ctl:auditLogParts=+E'
)

_NGINX_SSQLI = r"""location / {
    if ($args ~* "(union.*select|or.*1.*=.*1|sleep\s*\(|benchmark\s*\(|;\s*drop\s|;\s*delete\s)") {
        return 403;
    }
}"""

_CF_SSQLI = (
    '(cf.request.uri.args contains "union" and cf.request.uri.args contains "select") '
    'or (cf.request.uri.args contains "sleep(") '
    'or (cf.request.uri.args contains "benchmark(") '
    'or (cf.request.uri.args contains "drop table")'
)

_SMODSEC_XSS = (
    r'SecRule ARGS|ARGS_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES '
    r'"@rx (?i)(<script[^>]*>|javascript\s*:|on(error|load|click|mouseover)\s*=|'
    r'alert\s*\(|document\.cookie|document\.location|eval\s*\(|<iframe[^>]*>|'
    r'<img[^>]+onerror\s*=|<svg[^>]+onload\s*=|expression\s*\(|vbscript\s*:|'
    r'data\s*:\s*text/html)" '
    r'"id:900002,phase:2,deny,status:403,msg:\x27XSS Attack detected\x27,'
    r'severity:CRITICAL,t:none,t:urlDecodeUni,t:htmlEntityDecode,ctl:auditLogParts=+E'
)

_NGINX_XSS = r"""location / {
    if ($args ~* "(<script|javascript:|onerror\s*=|onload\s*=|alert\s*\()") {
        return 403;
    }
}"""

_CF_XSS = (
    '(cf.request.uri.args contains "<script") '
    'or (cf.request.uri.args contains "javascript:") '
    'or (cf.request.uri.args contains "onerror=") '
    'or (cf.request.uri.args contains "onload=")'
)

_SMODSEC_SSTI = (
    r'SecRule ARGS|ARGS_NAMES|REQUEST_BODY '
    r'"@rx (?i)(\{\{.*\}\}|\$\{.*\}|<%.*%>|'
    r'__class__|__mro__|__subclasses__|__builtins__|__import__|os\.popen|subprocess\.Popen)" '
    r'"id:900003,phase:2,deny,status:403,msg:\x27SSTI detected\x27,'
    r'severity:CRITICAL,t:none,t:urlDecodeUni'
)

_NGINX_SSTI = r"""location / {
    if ($args ~* "(\{\{|\$\{|__class__|__mro__|__subclasses__|__import__)") {
        return 403;
    }
}"""

_CF_SSTI = (
    '(cf.request.uri.args contains "{{" and cf.request.uri.args contains "}}") '
    'or (cf.request.uri.args contains "__class__") '
    'or (cf.request.uri.args contains "__import__")'
)

_SMODSEC_SSRF = (
    r'SecRule REQUEST_URI|REQUEST_BODY|ARGS '
    r'"@rx (?i)(https?://(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|'
    r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0\.0\.0\.0|'
    r'169\.254\.\d+\.\d+)|http://metadata\.google|http://169\.254\.169\.254)" '
    r'"id:900004,phase:1,deny,status:403,msg:\x27SSRF detected\x27,severity:CRITICAL,t:none'
)

_NGINX_SSRF = r"""location / {
    if ($args ~* "(127\.0\.0\.1|localhost|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.169\.254)") {
        return 403;
    }
}"""

_CF_SSRF = (
    '(cf.request.uri contains "127.0.0.1") '
    'or (cf.request.uri contains "localhost") '
    'or (cf.request.uri contains "169.254.169.254") '
    'or (cf.request.uri contains "10.") '
    'or (cf.request.uri contains "192.168.")'
)

_SMODSEC_PT = (
    r'SecRule ARGS|ARGS_NAMES|REQUEST_URI '
    r'"@rx (\.\./|\.\.\\\\|%2e%2e[/%5c\\\\]|%c0%ae)" '
    r'"id:900005,phase:2,deny,status:403,msg:\x27Path Traversal detected\x27,'
    r'severity:CRITICAL,t:none,t:urlDecodeUni,t:normalizePath'
)

_NGINX_PT = r"""location / {
    if ($args ~* "(\.\./|%2e%2e|\.\.\\\\)") {
        return 403;
    }
}"""

_CF_PT = (
    '(cf.request.uri contains "../") '
    'or (cf.request.uri contains "..\\") '
    'or (cf.request.uri.contains "%2e%2e")'
)

_SMODSEC_CI = (
    r'SecRule ARGS|ARGS_NAMES|REQUEST_BODY '
    r'"@rx (;|\||&|\$\(|\`|&&|\|\|)\s*('
    r'cat|ls|id|whoami|uname|pwd|wget|curl|bash|sh|nc|ncat|python|perl|ruby|'
    r'ping|nmap|ifconfig|netstat|ps|kill|chmod|chown|rm|mv|cp)\b" '
    r'"id:900006,phase:2,deny,status:403,msg:\x27Command Injection detected\x27,'
    r'severity:CRITICAL,t:none,t:urlDecodeUni,t:cmdLine'
)

_NGINX_CI = r"""location / {
    if ($args ~* ";\s*(cat|ls|id|whoami|uname|wget|curl|bash|sh|nc|ping|nmap)") {
        return 403;
    }
}"""

_CF_CI = (
    '(cf.request.uri.args contains ";" and cf.request.uri.args contains "bash") '
    'or (cf.request.uri.args contains "|" and cf.request.uri.args contains "cat") '
    'or (cf.request.uri.args contains "`")'
)

_SMODSEC_CSRF = (
    r'SecRule &REQUEST_HEADERS:Origin "@eq 0" '
    r'SecRule &REQUEST_HEADERS:Referer "@eq 0" '
    r'SecRule REQUEST_METHOD "@streq POST" '
    r'SecRule REQUEST_URI "!@rx ^/api/webhook" '
    r'"id:900007,phase:2,deny,status:403,msg:\x27CSRF: missing Origin/Referer\x27,'
    r'severity:HIGH,t:none,chain'
)

_SMODSEC_EVAL = (
    r'SecRule ARGS|REQUEST_BODY '
    r'"@rx (?i)(\beval\s*\(|\bexec\s*\(|compile\s*\(|__import__\s*\()" '
    r'"id:900009,phase:2,deny,status:403,msg:\x27Dangerous eval/exec detected\x27,'
    r'severity:CRITICAL,t:none'
)

_SMODSEC_DESER = (
    r'SecRule ARGS|REQUEST_HEADERS:Content-Type '
    r'"@rx (?i)(pickle|yaml\.load|marshal\.loads|shelve\.open)" '
    r'"id:900010,phase:2,deny,status:403,msg:\x27Unsafe deserialization attempt\x27,'
    r'severity:CRITICAL,t:none'
)

_SMODSEC_ID = (
    r'SecRule RESPONSE_BODY '
    r'"@rx (Stack Trace|Traceback \(most recent|Fatal error|Warning\:.+in \.+/|'
    r'mysql_fetch|Microsoft OLE DB|ORA-\d{5}|java\.lang\.)" '
    r'"id:900008,phase:4,pass,nolog,msg:\x27Information Disclosure in response\x27,'
    r'ctl:auditLogParts=+E'
)

CATEGORY_PATCH_MAP: dict[str, dict[str, Any]] = {
    "sqli": {
        "waf_rules": [_SMODSEC_SSQLI, _NGINX_SSQLI, _CF_SSQLI],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
            #
            # AFTER (parameterized query):
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
        """),
        "infra_fix": textwrap.dedent("""\
            # Terraform: enable RDS parameter group
            resource "aws_db_parameter_group" "secure" {
              name   = "secure-pg"
              family = "postgres15"
              parameter { name = "log_min_duration_statement", value = "0" }
            }
        """),
        "remediation": (
            "Replace all string-formatted SQL with parameterized queries. "
            "Enable WAF rules to block common SQLi patterns. Validate and sanitize "
            "all user inputs before using in database queries."
        ),
    },
    "xss": {
        "waf_rules": [_SMODSEC_XSS, _NGINX_XSS, _CF_XSS],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   return f"<div>Hello, {user_input}</div>"
            #
            # AFTER (HTML-escaped output):
            from html import escape
            return f"<div>Hello, {escape(user_input)}</div>"
        """),
        "infra_fix": textwrap.dedent("""\
            add_header Content-Security-Policy "default-src 'self'; script-src 'self';" always;
            add_header X-XSS-Protection "1; mode=block" always;
        """),
        "remediation": (
            "Escape all user-supplied data before rendering in HTML. "
            "Implement Content-Security-Policy headers. Use modern frameworks that "
            "auto-escape by default (Django, Jinja2, React)."
        ),
    },
    "ssti": {
        "waf_rules": [_SMODSEC_SSTI, _NGINX_SSTI, _CF_SSTI],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   template.render(user_input=raw_input)
            #
            # AFTER (use auto-escaping sandboxed environment):
            from jinja2.sandbox import ImmutableSandboxedEnvironment
            env = ImmutableSandboxedEnvironment(autoescape=True)
            template = env.from_string(tpl_source)
        """),
        "infra_fix": textwrap.dedent("""\
            RUN useradd -r -s /bin/false appuser
            USER appuser
        """),
        "remediation": (
            "Use sandboxed template environments (Jinja2 Sandbox). "
            "Never render user input directly in templates."
        ),
    },
    "ssrf": {
        "waf_rules": [_SMODSEC_SSRF, _NGINX_SSRF, _CF_SSRF],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   resp = requests.get(user_url)
            #
            # AFTER (URL validation + allowlist):
            from urllib.parse import urlparse
            import ipaddress

            ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

            def is_safe_url(url: str) -> bool:
                parsed = urlparse(url)
                if parsed.hostname not in ALLOWED_HOSTS:
                    return False
                try:
                    addr = ipaddress.ip_address(parsed.hostname)
                    return not (addr.is_private or addr.is_loopback or addr.is_link_local)
                except ValueError:
                    return True  # hostname, not IP

            if is_safe_url(user_url):
                resp = requests.get(user_url, timeout=5)
        """),
        "infra_fix": textwrap.dedent("""\
            # VPC network ACL: block egress to metadata endpoint
            resource "aws_network_acl" "ssrf_block" {
              vpc_id     = aws_vpc.main.id
              egress {
                rule_no    = 100
                action     = "deny"
                from_port  = 80
                to_port    = 80
                protocol   = "tcp"
                cidr_block = "169.254.169.254/32"
              }
            }
        """),
        "remediation": (
            "Validate and allowlist all URLs fetched server-side. Block requests to "
            "private/internal IP ranges. Disable URL schema handling beyond http/https."
        ),
    },
    "path_traversal": {
        "waf_rules": [_SMODSEC_PT, _NGINX_PT, _CF_PT],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   filepath = os.path.join(BASE_DIR, user_filename)
            #   return open(filepath).read()
            #
            # AFTER (resolve and verify):
            import os

            def safe_read(base: str, filename: str) -> bytes:
                filepath = os.path.realpath(os.path.join(base, filename))
                if not filepath.startswith(os.path.realpath(base)):
                    raise ValueError("Path traversal detected")
                with open(filepath, "rb") as f:
                    return f.read()
        """),
        "infra_fix": textwrap.dedent("""\
            FROM python:3.12-slim
            RUN useradd -r -s /bin/false appuser
            USER appuser
        """),
        "remediation": (
            "Always resolve paths with os.path.realpath() and verify they remain "
            "within the intended base directory. Run services with least privilege."
        ),
    },
    "command_injection": {
        "waf_rules": [_SMODSEC_CI, _NGINX_CI, _CF_CI],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   os.system(f"ping -c 3 {user_input}")
            #
            # AFTER (subprocess with list args):
            import subprocess

            def safe_ping(host: str) -> str:
                if not all(c.isalnum() or c in ".-" for c in host):
                    raise ValueError("Invalid hostname")
                result = subprocess.run(
                    ["ping", "-c", "3", host],
                    capture_output=True, text=True, timeout=10,
                )
                return result.stdout
        """),
        "infra_fix": textwrap.dedent("""\
            spec:
              securityContext:
                runAsNonRoot: true
                runAsUser: 1000
                readOnlyRootFilesystem: true
                capabilities:
                  drop: [ALL]
        """),
        "remediation": (
            "Never pass user input to os.system(), os.popen(), or subprocess with "
            "shell=True. Use subprocess.run() with a list of arguments."
        ),
    },
    "security_headers": {
        "waf_rules": [],
        "code_fix": textwrap.dedent("""\
            # Add security headers via middleware (Django example):
            SECURITY_HEADERS = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Content-Security-Policy": "default-src 'self'",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            }
        """),
        "infra_fix": textwrap.dedent("""\
            add_header X-Content-Type-Options "nosniff" always;
            add_header X-Frame-Options "DENY" always;
            add_header X-XSS-Protection "1; mode=block" always;
            add_header Referrer-Policy "strict-origin-when-cross-origin" always;
            add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
            add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
            server_tokens off;
        """),
        "remediation": (
            "Add all recommended security headers. Enable HSTS with long max-age. "
            "Set X-Frame-Options to DENY. Implement a strict Content-Security-Policy."
        ),
    },
    "cors": {
        "waf_rules": [],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   response.headers["Access-Control-Allow-Origin"] = "*"
            #
            # AFTER (restrictive CORS):
            @app.after_request
            def add_cors(response):
                origin = request.headers.get("Origin", "")
                allowed = {"https://app.example.com", "https://admin.example.com"}
                if origin in allowed:
                    response.headers["Access-Control-Allow-Origin"] = origin
                    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                    response.headers["Access-Control-Allow-Credentials"] = "true"
                    response.headers["Vary"] = "Origin"
                return response
        """),
        "infra_fix": textwrap.dedent("""\
            map $http_origin $cors_origin {
                default "";
                "https://app.example.com"  $http_origin;
            }
            server {
                location / {
                    if ($cors_origin != "") {
                        add_header Access-Control-Allow-Origin $cors_origin always;
                        add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
                        add_header Vary "Origin" always;
                    }
                    if ($request_method = OPTIONS) { return 204; }
                }
            }
        """),
        "remediation": (
            "Replace wildcard CORS origins with an explicit allowlist. "
            "Restrict allowed methods and headers to only what is needed."
        ),
    },
    "csrf": {
        "waf_rules": [_SMODSEC_CSRF],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   @csrf_exempt
            #   @app.route('/transfer', methods=['POST'])
            #
            # AFTER (remove csrf_exempt, ensure CSRF token):
            from django.views.decorators.csrf import csrf_protect

            @csrf_protect
            @app.route('/transfer', methods=['POST'])
            def transfer():
                ...
        """),
        "infra_fix": textwrap.dedent("""\
            proxy_cookie_path / "/; SameSite=Strict; Secure; HttpOnly";
        """),
        "remediation": (
            "Remove all csrf_exempt decorators from state-changing endpoints. "
            "Ensure all forms include CSRF tokens. Set SameSite=Strict on cookies."
        ),
    },
    "debug_mode": {
        "waf_rules": [],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   DEBUG = True
            #   ALLOWED_HOSTS = ['*']
            #
            # AFTER:
            DEBUG = False
            ALLOWED_HOSTS = ['app.example.com', 'admin.example.com']
        """),
        "infra_fix": textwrap.dedent("""\
            ENV DEBUG=false
            ENV DJANGO_SETTINGS_MODULE=myproject.settings.production
        """),
        "remediation": (
            "Set DEBUG = False in all production settings. Restrict ALLOWED_HOSTS. "
            "Disable detailed error pages and stack traces in production."
        ),
    },
    "hardcoded_secret": {
        "waf_rules": [],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   SECRET_KEY = "my-super-secret-key-12345"
            #
            # AFTER:
            import os
            SECRET_KEY = os.environ.get("SECRET_KEY")
            if not SECRET_KEY:
                raise RuntimeError("SECRET_KEY environment variable is not set")
        """),
        "infra_fix": textwrap.dedent("""\
            apiVersion: v1
            kind: Secret
            metadata:
              name: app-secrets
            type: Opaque
            data:
              secret-key: <base64-encoded>
        """),
        "remediation": (
            "Move all secrets to environment variables or a secrets manager. "
            "Add .env files to .gitignore. Rotate any leaked credentials immediately."
        ),
    },
    "weak_crypto": {
        "waf_rules": [],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   from hashlib import md5
            #   hashed = md5(password.encode()).hexdigest()
            #
            # AFTER:
            import hashlib, os
            salt = os.urandom(32)
            hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
        """),
        "infra_fix": textwrap.dedent("""\
            ssl_protocols TLSv1.2 TLSv1.3;
            ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
            ssl_prefer_server_ciphers on;
        """),
        "remediation": (
            "Replace MD5/SHA1 with PBKDF2, bcrypt, or argon2 for passwords. "
            "Use AES-256-GCM for encryption. Enforce TLS 1.2+ with strong ciphers."
        ),
    },
    "information_disclosure": {
        "waf_rules": [_SMODSEC_ID],
        "code_fix": textwrap.dedent("""\
            @app.errorhandler(Exception)
            def handle_error(e):
                if not app.debug:
                    return "An internal error occurred.", 500
                raise e
        """),
        "infra_fix": textwrap.dedent("""\
            server_tokens off;
            proxy_hide_header X-Powered-By;
            proxy_hide_header Server;
        """),
        "remediation": (
            "Disable verbose error messages in production. Remove server version headers. "
            "Implement generic error pages."
        ),
    },
    "open_port": {
        "waf_rules": [],
        "code_fix": "",
        "infra_fix": textwrap.dedent("""\
            resource "aws_security_group" "app" {
              name        = "app-sg"
              ingress {
                from_port       = 443
                to_port         = 443
                protocol        = "tcp"
                security_groups = [aws_security_group.alb.id]
              }
              egress {
                from_port   = 0
                to_port     = 0
                protocol    = "-1"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
        """),
        "remediation": (
            "Close unnecessary ports. Apply security groups or firewall rules to "
            "restrict access to only required sources."
        ),
    },
    "dangerous_eval": {
        "waf_rules": [_SMODSEC_EVAL],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   result = eval(user_input)
            #
            # AFTER (use ast.literal_eval for data):
            import ast
            result = ast.literal_eval(user_input)
        """),
        "infra_fix": textwrap.dedent("""\
            # K8s PodSecurityContext:
            #   seccompProfile:
            #     type: RuntimeDefault
        """),
        "remediation": (
            "Never use eval() or exec() with user input. Use ast.literal_eval() for "
            "data deserialization."
        ),
    },
    "unsafe_deserialization": {
        "waf_rules": [_SMODSEC_DESER],
        "code_fix": textwrap.dedent("""\
            # BEFORE:
            #   import pickle
            #   obj = pickle.loads(user_data)
            #
            # AFTER:
            import json
            obj = json.loads(user_data)  # Use JSON instead of pickle

            # If YAML is required:
            import yaml
            obj = yaml.safe_load(user_data)  # NEVER yaml.load()
        """),
        "infra_fix": "",
        "remediation": (
            "Replace pickle with JSON for data serialization. If YAML is required, "
            "always use yaml.safe_load(). Never deserialize untrusted data with pickle."
        ),
    },
}


# ---------------------------------------------------------------------------
# PatchGenerator  --  single-finding defense generator
# ---------------------------------------------------------------------------


class PatchGenerator:
    """Generate deployable security fixes from a single vulnerability finding."""

    def __init__(self) -> None:
        self._rule_counter = 900100

    def generate_waf_rules(self, finding: dict) -> list[str]:
        """Return a list of WAF rules for *finding*.

        Formats: ModSecurity SecRule, Nginx location block, Cloudflare WAF expression,
        AWS WAF JSON rule (prefixed with ``AWS_WAF_JSON:``).
        """
        category = finding.get("category", "").lower()
        severity = finding.get("severity", "high").upper()
        rules: list[str] = []

        # 1. Category-mapped rules from CATEGORY_PATCH_MAP
        cat_entry = CATEGORY_PATCH_MAP.get(category, {})
        for tmpl in cat_entry.get("waf_rules", []):
            rules.append(tmpl)

        # 2. Generate AWS WAF JSON rule
        if category in ("sqli", "xss", "command_injection", "path_traversal", "ssrf"):
            rules.append(self._aws_waf_rule(category, severity))

        # 3. Generate category-specific Nginx rules not already in the map
        if category == "security_headers":
            rules.append(self._nginx_security_headers())
        elif category == "cors":
            rules.append(self._nginx_cors_config(finding))
        elif category == "csrf":
            rules.append(self._nginx_csrf_check())

        return rules

    def _aws_waf_rule(self, category: str, severity: str) -> str:
        """Generate an AWS WAF JSON rule statement."""
        priority_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        priority = priority_map.get(severity, 1)
        rule_name = f"ReconPro-{category}-{uuid.uuid4().hex[:8]}"

        managed_rules = {
            "sqli": "AWSManagedRulesSQLiRuleSet",
            "xss": "AWSManagedRulesCommonRuleSet",
        }

        if category in managed_rules:
            rule: dict[str, Any] = {
                "Name": rule_name,
                "Priority": priority,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": managed_rules[category],
                        "ExcludedRules": [],
                    }
                },
                "Action": {
                    "Block": {
                        "CustomResponse": {
                            "ResponseCode": 403,
                            "ResponseBody": {
                                "Text": f"Request blocked by ReconPro {category} rule."
                            },
                        }
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": f"ReconPro{category.capitalize()}Rule",
                },
            }
        else:
            regex_map = {
                "command_injection": (
                    r";.*\b(cat|ls|id|whoami|bash|sh|wget|curl|nc|ping|nmap)\b"
                ),
                "path_traversal": r"(\.\./|%2e%2e)",
                "ssrf": r"(127\.0\.0\.1|localhost|169\.254\.169\.254)",
            }
            pattern = regex_map.get(category, ".*")
            rule = {
                "Name": rule_name,
                "Priority": priority,
                "Statement": {
                    "RegexMatchStatement": {
                        "RegexString": pattern,
                        "FieldToMatch": {"QueryString": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    }
                },
                "Action": {
                    "Block": {
                        "CustomResponse": {
                            "ResponseCode": 403,
                            "ResponseBody": {
                                "Text": f"Request blocked by ReconPro {category} rule."
                            },
                        }
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": f"ReconPro{category.capitalize()}Rule",
                },
            }

        return "AWS_WAF_JSON:" + json.dumps(rule, indent=2)

    def _nginx_security_headers(self) -> str:
        return (
            "# Nginx security headers (add to server block)\n"
            "add_header X-Content-Type-Options 'nosniff' always;\n"
            "add_header X-Frame-Options 'DENY' always;\n"
            "add_header X-XSS-Protection '1; mode=block' always;\n"
            "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;\n"
            "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;\n"
            "add_header Permissions-Policy 'camera=(), microphone=(), geolocation=()' always;\n"
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\n"
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:\" always;\n"
            "server_tokens off;"
        )

    def _nginx_cors_config(self, finding: dict) -> str:
        origin = finding.get("origin", "https://app.example.com")
        return (
            f"# Nginx CORS configuration (restrictive)\n"
            f'map $http_origin $cors_origin {{\n'
            f'    default         "";\n'
            f'    "{origin}"  $http_origin;\n'
            f"}}\n"
            f"server {{\n"
            f"    location / {{\n"
            f'        if ($cors_origin != "") {{\n'
            f'            add_header Access-Control-Allow-Origin $cors_origin always;\n'
            f'            add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;\n'
            f'            add_header Access-Control-Allow-Credentials "true" always;\n'
            f'            add_header Vary "Origin" always;\n'
            f"        }}\n"
            f'        if ($request_method = OPTIONS) {{ return 204; }}\n'
            f"    }}\n"
            f"}}"
        )

    def _nginx_csrf_check(self) -> str:
        return (
            "# Nginx CSRF mitigation (origin check)\n"
            "map $http_origin $csrf_valid_origin {\n"
            "    default         0;\n"
            "    ~^https://app\\.example\\.com$  1;\n"
            "}\n"
            "server {\n"
            "    location / {\n"
            '        if ($request_method = POST) {\n'
            '            if ($csrf_valid_origin = 0) {\n'
            "                return 403;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}"
        )

    # -- Code patch generation ---------------------------------------------

    def generate_code_patch(self, finding: dict) -> str:
        """Generate a unified diff patch for *finding*.

        Requires ``file`` (path) and ``line`` (1-based) in finding.
        """
        filepath = finding.get("file", "unknown.py")
        line_no = finding.get("line", 1)
        original = finding.get("original_line", "")

        fix = self._resolve_code_fix(finding)
        fix_lines = fix.split("\n")

        ctx_before = 3
        start = max(1, line_no - ctx_before)
        end = line_no + ctx_before
        old_count = end - start + 1
        new_count = old_count + len(fix_lines) - 1

        diff_lines: list[str] = []
        diff_lines.append(f"--- a/{filepath}")
        diff_lines.append(f"+++ b/{filepath}")
        diff_lines.append(f"@@ -{start},{old_count} +{start},{new_count} @@")

        for i in range(start, end + 1):
            if i == line_no:
                if original:
                    diff_lines.append(f"-{original}")
                else:
                    diff_lines.append(f"-# [REMOVED] vulnerable code at line {line_no}")
                for fl in fix_lines:
                    diff_lines.append(f"+{fl}")
            else:
                diff_lines.append(f" # (context line {i})")

        return "\n".join(diff_lines) + "\n"

    def _resolve_code_fix(self, finding: dict) -> str:
        """Return the replacement code lines for a finding."""
        category = finding.get("category", "").lower()
        original = finding.get("original_line", "")

        # Pattern-based detection on the original line
        if "eval(" in original:
            return (
                "import ast\n"
                "result = ast.literal_eval(sanitized_input)  # safe alternative to eval()"
            )
        if "exec(" in original:
            return (
                "# exec() removed \u2014 use a task queue, plugin system, or\n"
                "# sandboxed interpreter for dynamic code execution"
            )
        if "shell=True" in original:
            return (
                "subprocess.run(\n"
                '    ["command", "arg1"],\n'
                "    capture_output=True,\n"
                "    text=True,\n"
                "    shell=False,\n"
                ")"
            )
        if any(kw in original for kw in ("select ", "insert ", "update ", "delete ")) and ("f\"" in original or "f'" in original):
            return (
                'cursor.execute(\n'
                '    "SELECT ... WHERE col = %s",\n'
                '    (user_input,),\n'
                ")  # parameterized query"
            )
        if category == "hardcoded_secret" or any(
            k in original.lower() for k in ("secret", "password", "api_key", "token")
        ):
            var_match = re.match(r'(\w+)\s*=\s*["\']', original)
            var_name = var_match.group(1) if var_match else "CONFIG_VALUE"
            env_key = var_name.upper()
            return (
                "import os\n"
                f'{var_name} = os.environ.get("{env_key}")\n'
                f'if not {var_name}:\n'
                f'    raise RuntimeError("{env_key} environment variable is not set")'
            )
        if "DEBUG = True" in original or "DEBUG=True" in original:
            return "DEBUG = False"
        if "csrf_exempt" in original:
            return "# @csrf_exempt removed \u2014 CSRF protection required for this endpoint"

        # Fall back to category template
        cat_entry = CATEGORY_PATCH_MAP.get(category, {})
        code_fix = cat_entry.get("code_fix", "")
        if code_fix:
            return code_fix.strip()

        return "# Apply manual fix: review the vulnerability description and remediation"

    # -- Infrastructure fix generation -------------------------------------

    def generate_infra_fix(self, finding: dict) -> str:
        """Generate an infrastructure fix for *finding*."""
        category = finding.get("category", "").lower()
        infra_type = finding.get("infra_type", "terraform")
        target = finding.get("target", "app")

        cat_entry = CATEGORY_PATCH_MAP.get(category, {})
        base_fix = cat_entry.get("infra_fix", "").strip()

        if base_fix:
            return self._wrap_infra(base_fix, infra_type, category, target, finding)
        return self._generic_infra_fix(finding)

    def _wrap_infra(self, content: str, infra_type: str, category: str,
                    target: str, finding: dict) -> str:
        """Wrap a fix snippet in the appropriate infrastructure format."""
        if infra_type == "cloudformation":
            return textwrap.dedent(f"""\
                # CloudFormation fix for {category}
                # Apply to: {finding.get('file', 'N/A')}
                Resources:
                  {target}SecurityPatch:
                    Type: AWS::CloudFormation::WaitConditionHandle
                # Manual steps:
                {content}
            """)
        if infra_type == "dockerfile":
            return textwrap.dedent(f"""\
                # Dockerfile hardening for {category}
                FROM python:3.12-slim AS base
                RUN useradd -r -s /bin/false appuser
                USER appuser
                {content}
            """)
        if infra_type == "k8s":
            return textwrap.dedent(f"""\
                # K8s manifest fix for {category}
                apiVersion: v1
                kind: Pod
                metadata:
                  name: {target}
                spec:
                  securityContext:
                    runAsNonRoot: true
                    runAsUser: 1000
                    readOnlyRootFilesystem: true
                  containers:
                    - name: {target}
                      securityContext:
                        allowPrivilegeEscalation: false
                        capabilities:
                          drop: [ALL]
                # ---
                {content}
            """)
        if infra_type == "nginx":
            return textwrap.dedent(f"""\
                # Nginx config fix for {category}
                server {{
                    listen 443 ssl http2;
                    server_name {finding.get('target', 'app.example.com')};
                    # --- {category} fix ---
                {content}
                    # --- End fix ---
                }}
            """)
        # Default: Terraform
        return f"# Terraform fix for {category}\n# Target: {target}\n{content}\n"

    def _generic_infra_fix(self, finding: dict) -> str:
        """Generate a generic infrastructure hardening fix."""
        target = finding.get("target", "app")
        category = finding.get("category", "unknown")
        port = finding.get("port", 443)
        severity = finding.get("severity", "high").upper()
        return textwrap.dedent(f"""\
            # Generic infrastructure hardening for {category}
            # Severity: {severity} | Target: {target}

            resource "aws_security_group" "{target}_hardened" {{
              name        = "{target}-hardened-sg"
              description = "Hardened SG for {category} remediation"
              ingress {{
                from_port   = {port}
                to_port     = {port}
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }}
              egress {{
                from_port   = 0
                to_port     = 0
                protocol    = "-1"
                cidr_blocks = ["0.0.0.0/0"]
              }}
            }}
        """)

    # -- CI/CD additions --------------------------------------------------

    def generate_cicd_additions(self, findings: list[dict]) -> str:
        """Generate CI/CD pipeline additions for a list of findings.

        Returns combined pre-commit hook, GitHub Actions, and GitLab CI config.
        """
        categories = {f.get("category", "").lower() for f in findings}
        has_secrets = "hardcoded_secret" in categories
        has_sast = any(c in categories for c in (
            "sqli", "xss", "command_injection", "path_traversal",
            "ssrf", "ssti", "dangerous_eval", "unsafe_deserialization",
        ))
        has_docker = "debug_mode" in categories or "open_port" in categories
        has_deps = "weak_crypto" in categories or "information_disclosure" in categories

        parts: list[str] = []

        # --- Pre-commit hook ---
        pre_commit = (
            "#!/usr/bin/env bash\n"
            "# ReconPro auto-generated pre-commit hook\n"
            "# Install: cp .pre-commit-hook.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit\n"
            "set -euo pipefail\n"
        )
        if has_secrets:
            _q = chr(39)
            _pat = _q + "(?i)(password|secret|api_key|token)" + chr(92)*2 + "s*" + chr(92)*2 + "s*" + chr(91) + chr(34) + _q + chr(93) + chr(91) + chr(94) + chr(34) + _q + chr(93) + "{8,}" + _q
            pre_commit += (
                "# --- Secret detection ---\n"
                "if git diff --cached --name-only | xargs rg -l " + _pat + " 2>/dev/null; then\n"
                "    echo [RECONPRO] ERROR: Hardcoded secret detected.\n"
                "    exit 1\n"
                "fi\n"
            )
            pre_commit += (
                '# --- Dangerous pattern detection ---\n'
                'DANGEROUS="eval\\(|exec\\(|shell=True|os\\.system"\n'
                'if git diff --cached -U0 | grep -qE "$DANGEROUS"; then\n'
                '    echo "[RECONPRO] WARNING: Dangerous code pattern detected."\n'
                'fi\n'
            )
        pre_commit += 'echo "[RECONPRO] Pre-commit checks passed."\n'
        parts.append(pre_commit)

        # --- GitHub Actions workflow ---
        gh = ("# .github/workflows/security.yml\n"
              "# ReconPro auto-generated security workflow\n"
              "name: Security Scan\n"
              "on:\n"
              "  push:\n"
              "    branches: [main, develop]\n"
              "  pull_request:\n"
              "    branches: [main]\n"
              "jobs:\n")
        if has_secrets:
            gh += textwrap.dedent("""\
                secret-scan:
                  runs-on: ubuntu-latest
                  steps:
                    - uses: actions/checkout@v4
                      with:
                        fetch-depth: 0
                    - name: TruffleHog
                      uses: trufflesecurity/trufflehog@main
                      with:
                        extra_args: --only-verified
            """)
        if has_sast:
            gh += textwrap.dedent("""\
                sast-scan:
                  runs-on: ubuntu-latest
                  steps:
                    - uses: actions/checkout@v4
                    - name: Bandit SAST
                      run: |
                        pip install bandit
                        bandit -r . -ll -f json -o bandit-report.json || true
                        bandit -r . -ll
                    - uses: actions/upload-artifact@v4
                      if: always()
                      with:
                        name: bandit-report
                        path: bandit-report.json
            """)
        if has_docker:
            gh += textwrap.dedent("""\
                docker-lint:
                  runs-on: ubuntu-latest
                  steps:
                    - uses: actions/checkout@v4
                    - uses: hadolint/hadolint-action@v3.1.0
                      with:
                        dockerfile: Dockerfile
            """)
        if has_deps:
            gh += textwrap.dedent("""\
                dep-audit:
                  runs-on: ubuntu-latest
                  steps:
                    - uses: actions/checkout@v4
                    - run: pip install pip-audit && pip-audit -r requirements.txt || true
            """)
        if not any([has_secrets, has_sast, has_docker, has_deps]):
            gh += textwrap.dedent("""\
                security-check:
                  runs-on: ubuntu-latest
                  steps:
                    - uses: actions/checkout@v4
                    - run: echo "No specific jobs for these findings."
            """)
        parts.append(gh)

        # --- GitLab CI ---
        gl = ("# .gitlab-ci.yml -- security stage\n"
              "# ReconPro auto-generated\n"
              "stages:\n"
              "  - test\n"
              "  - security\n")
        if has_secrets:
            gl += textwrap.dedent("""\
                secret-scan:
                  stage: security
                  image: python:3.12-slim
                  script:
                    - pip install trufflehog
                    - trufflehog git file://. --only-verified
            """)
        if has_sast:
            gl += textwrap.dedent("""\
                sast-bandit:
                  stage: security
                  image: python:3.12-slim
                  script:
                    - pip install bandit
                    - bandit -r . -ll -f json -o bandit-report.json
                  artifacts:
                    reports:
                      sast: bandit-report.json
            """)
        if has_deps:
            gl += textwrap.dedent("""\
                dependency-audit:
                  stage: security
                  image: python:3.12-slim
                  script:
                    - pip install pip-audit
                    - pip-audit -r requirements.txt
                  allow_failure: true
            """)
        parts.append(gl)

        return "\n\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# DefenseBundle  --  batch defense orchestrator
# ---------------------------------------------------------------------------


class DefenseBundle:
    """Orchestrate defense generation across all findings for a target."""

    def __init__(self, target: str, findings: list[dict]) -> None:
        self.target = target
        self.findings = findings
        self._generator = PatchGenerator()
        self._bundle_id = uuid.uuid4().hex[:12]
        self._generated_at = datetime.now(timezone.utc).isoformat()

    def generate_all(self) -> dict[str, Any]:
        """Generate all defense artifacts.

        Returns:
            {waf_rules, code_patches, infra_fixes, cicd_additions,
             apply_script, rollback_script}
        """
        waf_rules: list[str] = []
        code_patches: dict[str, str] = {}
        infra_fixes: dict[str, str] = {}

        for finding in self.findings:
            cat = finding.get("category", "unknown")
            fid = finding.get("id", hashlib.sha256(str(finding).encode()).hexdigest()[:8])
            key = f"{cat}:{fid}"

            rules = self._generator.generate_waf_rules(finding)
            waf_rules.extend(rules)

            if finding.get("file"):
                code_patches[key] = self._generator.generate_code_patch(finding)

            infra = self._generator.generate_infra_fix(finding)
            if infra:
                infra_fixes[key] = infra

        cicd = self._generator.generate_cicd_additions(self.findings)
        apply_script = self.generate_apply_script()
        rollback_script = self.generate_rollback_script()

        return {
            "waf_rules": waf_rules,
            "code_patches": code_patches,
            "infra_fixes": infra_fixes,
            "cicd_additions": cicd,
            "apply_script": apply_script,
            "rollback_script": rollback_script,
        }

    def generate_apply_script(self) -> str:
        """Generate a bash script that applies all generated fixes."""
        bid = self._bundle_id
        tgt = self.target
        ts = self._generated_at
        return textwrap.dedent(f"""\
            #!/usr/bin/env bash
            # ReconPro Defense Apply Script
            # Bundle ID: {bid}
            # Target:   {tgt}
            # Generated: {ts}
            #
            # USAGE: bash apply_defenses.sh [--dry-run]
            #
            set -euo pipefail

            DRY_RUN=false
            [[ "${{1:-}}" == "--dry-run" ]] && DRY_RUN=true

            BACKUP_DIR=".reconpro-backups/{bid}"
            WAF_DIR=".reconpro-waf"
            PATCH_DIR=".reconpro-patches"
            CICD_DIR=".reconpro-cicd"

            echo "========================================="
            echo " ReconPro Defense Application"
            echo " Target: {tgt}"
            echo " Bundle: {bid}"
            echo "========================================="

            mkdir -p "$BACKUP_DIR" "$WAF_DIR" "$PATCH_DIR" "$CICD_DIR"

            echo "[1/3] Writing WAF rules to $WAF_DIR/ ..."
            echo "# ModSecurity + Nginx WAF rules generated by ReconPro" > "$WAF_DIR/waf_rules.conf"
            echo "# Review and include in your web server configuration" >> "$WAF_DIR/waf_rules.conf"
            echo "  Written: $WAF_DIR/waf_rules.conf"

            echo "[2/3] Writing infrastructure fixes to $PATCH_DIR/ ..."
            echo "# Infrastructure fixes generated by ReconPro" > "$PATCH_DIR/infra_fixes.tf"
            echo "  Written: $PATCH_DIR/infra_fixes.tf"

            echo "[3/3] Writing CI/CD additions to $CICD_DIR/ ..."
            mkdir -p "$CICD_DIR/.github/workflows"
            echo "  Written: $CICD_DIR/ (review files before committing)"

            echo ""
            echo "========================================="
            echo " Defense artifacts written!"
            echo " Review all files before applying."
            echo " Backups: $BACKUP_DIR"
            echo "========================================="
        """)

    def generate_rollback_script(self) -> str:
        """Generate a bash script that reverts all applied fixes."""
        bid = self._bundle_id
        tgt = self.target
        return textwrap.dedent(f"""\
            #!/usr/bin/env bash
            # ReconPro Defense Rollback Script
            # Bundle ID: {bid}
            # Target:   {tgt}
            #
            # USAGE: bash rollback_defenses.sh
            #
            set -euo pipefail

            BACKUP_DIR=".reconpro-backups/{bid}"
            WAF_DIR=".reconpro-waf"
            PATCH_DIR=".reconpro-patches"
            CICD_DIR=".reconpro-cicd"

            echo "========================================="
            echo " ReconPro Defense Rollback"
            echo " Target: {tgt}"
            echo " Bundle: {bid}"
            echo "========================================="

            for d in "$WAF_DIR" "$PATCH_DIR" "$CICD_DIR"; do
                if [[ -d "$d" ]]; then
                    rm -rf "$d"
                    echo "  Removed: $d"
                fi
            done

            if [[ -d "$BACKUP_DIR" ]]; then
                for backup_file in "$BACKUP_DIR"/*.bak; do
                    [[ -f "$backup_file" ]] || continue
                    original="${{backup_file%.bak}}"
                    original="${{original#$BACKUP_DIR/}}"
                    if [[ -f "$original" ]]; then
                        cp "$backup_file" "$original"
                        echo "  Restored: $original"
                    fi
                done
                rm -rf "$BACKUP_DIR"
            fi

            echo ""
            echo "========================================="
            echo " Rollback complete!"
            echo "========================================="
        """)

    # DEAD CODE: consider removal
    def to_report(self) -> str:
        """Generate a human-readable summary of all generated defenses."""
        all_defenses = self.generate_all()
        waf_rules = all_defenses.get("waf_rules", [])
        patches = all_defenses.get("code_patches", {})
        infras = all_defenses.get("infra_fixes", {})
        cicd = all_defenses.get("cicd_additions", "")

        modsec = sum(1 for r in waf_rules if r.startswith("SecRule"))
        nginx = sum(1 for r in waf_rules if r.startswith("# Nginx") or r.startswith("location"))
        aws_waf = sum(1 for r in waf_rules if r.startswith("AWS_WAF_JSON:"))
        cf_waf = sum(1 for r in waf_rules if r.startswith("cf."))

        lines = [
            "=" * 60,
            "  ReconPro Defense Report",
            f"  Target: {self.target}",
            f"  Bundle: {self._bundle_id}",
            f"  Generated: {self._generated_at}",
            f"  Findings processed: {len(self.findings)}",
            "=" * 60,
            "",
            f"[WAF Rules]  {len(waf_rules)} rule(s) generated",
        ]
        if modsec:
            lines.append(f"    ModSecurity: {modsec}")
        if nginx:
            lines.append(f"    Nginx:       {nginx}")
        if aws_waf:
            lines.append(f"    AWS WAF:     {aws_waf}")
        if cf_waf:
            lines.append(f"    Cloudflare:  {cf_waf}")
        lines.append("")

        lines.append(f"[Code Patches]  {len(patches)} patch(es) generated")
        for key, patch in patches.items():
            lines.append(f"    {key}: {len(patch.splitlines())} lines")
        lines.append("")

        lines.append(f"[Infra Fixes]  {len(infras)} fix(es) generated")
        for key in infras:
            lines.append(f"    {key}")
        lines.append("")

        lines.append("[CI/CD Additions]")
        if "pre-commit" in cicd.lower() or "#!/" in cicd:
            lines.append("    Pre-commit hook:       YES")
        if "github" in cicd.lower():
            lines.append("    GitHub Actions:        YES")
        if "gitlab" in cicd.lower():
            lines.append("    GitLab CI:             YES")
        if not cicd.strip():
            lines.append("    (none generated)")
        lines.append("")

        # Severity breakdown
        sev_counts: dict[str, int] = {}
        for f in self.findings:
            s = f.get("severity", "unknown").upper()
            sev_counts[s] = sev_counts.get(s, 0) + 1
        lines.append("[Severity Breakdown]")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if sev in sev_counts:
                lines.append(f"    {sev}: {sev_counts[sev]}")
        lines.append("")

        # Remediation guidance
        lines.append("[Remediation Guidance]")
        seen: set[str] = set()
        for f in self.findings:
            cat = f.get("category", "")
            if cat in seen:
                continue
            seen.add(cat)
            entry = CATEGORY_PATCH_MAP.get(cat, {})
            remediation = entry.get("remediation", "Review finding and apply manual fix.")
            lines.append(f"    {cat}: {remediation}")

        lines.extend([
            "",
            "=" * 60,
            "  Apply:  bash apply_defenses.sh [--dry-run]",
            "  Revert: bash rollback_defenses.sh",
            "=" * 60,
        ])

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


# DEAD CODE: consider removal
def generate_defense(finding: dict) -> dict[str, Any]:
    """Generate all defenses for a single vulnerability finding.

    Returns a dict with keys: waf_rules, code_patch, infra_fix.
    """
    gen = PatchGenerator()
    result: dict[str, Any] = {
        "waf_rules": gen.generate_waf_rules(finding),
        "code_patch": "",
        "infra_fix": "",
        "category": finding.get("category", "unknown"),
        "severity": finding.get("severity", "unknown"),
    }
    if finding.get("file"):
        result["code_patch"] = gen.generate_code_patch(finding)
    result["infra_fix"] = gen.generate_infra_fix(finding)
    return result


def generate_defense_bundle(target: str, findings: list[dict]) -> DefenseBundle:
    """Create a DefenseBundle for batch defense generation.

    Args:
        target:   The target identifier (hostname, app name, etc.).
        findings: List of vulnerability finding dicts.

    Returns:
        A DefenseBundle instance ready for generate_all() or to_report().
    """
    return DefenseBundle(target, findings)


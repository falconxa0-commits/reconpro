"""Module: ZERO_DAY_HUNTER — Anomaly-Based Undocumented Vulnerability Detection for ReconPro v9.2.0.

DEFENSIVE / EDUCATIONAL ONLY — This module identifies patterns in HTTP responses
that may indicate undocumented or zero-day vulnerabilities through statistical
anomaly detection, error message analysis, version correlation, behavioral
scoring, fuzzing analysis, header inspection, and access control mapping.

Capabilities:
  1. Response Anomaly Detection — Statistical baseline comparison for abnormal
     status codes, error message patterns, and unexpected response sizes.
  2. Error Message Analysis — Stack traces, internal paths, debug info, database
     errors, framework debug pages revealing unpatched vulnerabilities.
  3. Version-Response Correlation — Cross-reference observed versions with known
     vulnerability databases to find version-specific gaps.
  4. Behavioral Anomaly Scoring — Inconsistent caching, timing anomalies, parameter
     sensitivity across endpoints.
  5. Fuzzing Result Analysis — Crafted inputs detecting anomalous responses
     suggesting injection points or memory corruption.
  6. Header Anomaly Detection — Headers revealing internal architecture, debug
     mode, or development artifacts.
  7. Endpoint Sensitivity Mapping — Paths with/without authentication to find
     broken access control patterns.

References:
  - MITRE ATT&CK: T1595, T1589, T1190, T1195
  - OWASP Testing Guide v4.2
  - CWE-20: Improper Input Validation
  - CWE-209: Generation of Error Message Containing Sensitive Information
"""
from __future__ import annotations

import math
import re
import statistics
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ..http_layer import http_probe, Finding, default_limiter


# ════════════════════════════════════════════════════════════════════════
# ANOMALY_THRESHOLDS — Statistical baselines for response analysis
# ════════════════════════════════════════════════════════════════════════

ANOMALY_THRESHOLDS: Dict[str, Dict[str, Any]] = {
    "response_size": {
        "description": "Response body size deviation from baseline (bytes).",
        "normal_range_min": 200,
        "normal_range_max": 524288,
        "abnormally_large": 1048576,
        "abnormally_small_ok": 5,
        "size_variance_sigma": 2.0,
    },
    "status_codes": {
        "description": "HTTP status code anomaly thresholds.",
        "expected_success": {200, 201, 204, 301, 302, 304},
        "anomaly_codes": {
            206: "Partial content on non-range request suggests chunked leak",
            218: "This is fine (Apache) — may indicate misconfiguration",
            422: "Unprocessable entity — reveals backend validation schema",
            423: "Locked — WebDAV exposed",
            424: "Failed dependency — reveals service coupling",
            425: "Too early — premature HTTP/3 or experimental headers",
            426: "Upgrade required — protocol negotiation leak",
            428: "Precondition required — reveals backend state requirements",
            429: "Rate limit hit — reveals rate-limiting architecture",
            431: "Request header fields too large — reveals header size limits",
            451: "Unavailable for legal reasons — reveals jurisdiction",
            501: "Not implemented — reveals disabled HTTP methods",
            502: "Bad gateway — reveals upstream proxy topology",
            506: "Variant also negotiates — reveals content negotiation config",
            508: "Loop detected — reveals internal redirect chains",
            510: "Not extended — reveals HTTP extension requirements",
            511: "Network authentication required — reveals captive portal",
        },
        "unexpected_5xx_on_static": (
            "Server error on static resource path suggests backend "
            "vulnerability or misconfigured routing"
        ),
    },
    "timing": {
        "description": "Response timing anomaly thresholds (seconds).",
        "baseline_fast_ms": 200,
        "baseline_normal_ms": 1000,
        "suspicious_slow_ms": 5000,
        "time_based_blind_threshold_ms": 3000,
        "timing_variance_sigma": 2.5,
    },
    "headers": {
        "description": "Response header count thresholds.",
        "min_expected": 3,
        "max_expected": 40,
        "missing_security_headers": [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy",
        ],
    },
    "body_entropy": {
        "description": "Shannon entropy thresholds for response body content.",
        "low_entropy_threshold": 0.5,
        "high_entropy_threshold": 7.5,
        "typical_html_range": (2.0, 5.5),
        "typical_json_range": (2.5, 5.0),
    },
    "consistency": {
        "description": "Cross-request consistency thresholds.",
        "max_status_variance": 2,
        "max_size_ratio": 5.0,
        "header_stability_tolerance": 0.3,
    },
}


# ════════════════════════════════════════════════════════════════════════
# ERROR_SIGNATURES — Patterns revealing unpatched vulnerabilities
# ════════════════════════════════════════════════════════════════════════

ERROR_SIGNATURES: Dict[str, List[Dict[str, Any]]] = {
    "stack_traces": [
        {
            "name": "python_traceback",
            "pattern": r"Traceback \(most recent call last\):",
            "severity": "high",
            "framework": "Python",
            "description": "Full Python traceback exposed — reveals code structure and file paths",
        },
        {
            "name": "java_stacktrace",
            "pattern": r"(?:Exception|Error)\s+at\s+[\w$]+\.[\w$]+\(.*?\.java:\d+\)",
            "severity": "high",
            "framework": "Java",
            "description": "Java stack trace with line numbers — reveals class structure",
        },
        {
            "name": "nodejs_stack",
            "pattern": r"at\s+(?:[A-Z][\w$]*\.)?[\w$]+\s+\([^)]*:[\d]+:[\d]+\)",
            "severity": "high",
            "framework": "Node.js",
            "description": "Node.js stack trace — reveals module structure and paths",
        },
        {
            "name": "php_stack_trace",
            "pattern": r"(?:Fatal error|Warning|Notice|Parse error):.*?in\s+.+\.php\s+on line\s+\d+",
            "severity": "high",
            "framework": "PHP",
            "description": "PHP error with file path and line number",
        },
        {
            "name": "csharp_exception",
            "pattern": r"at\s+[\w.]+\([\w.]+\s+\w+,.*?\)\s+in\s+.+:line\s+\d+",
            "severity": "high",
            "framework": ".NET",
            "description": ".NET exception with file and line number",
        },
        {
            "name": "ruby_exception",
            "pattern": r"(?:NoMethodError|NameError|RuntimeError|ArgumentError).*?`\w+'",
            "severity": "high",
            "framework": "Ruby",
            "description": "Ruby exception revealing method names and call chains",
        },
        {
            "name": "go_panic",
            "pattern": r"panic:.*?goroutine\s+\d+",
            "severity": "high",
            "framework": "Go",
            "description": "Go panic with goroutine ID — reveals concurrent architecture",
        },
        {
            "name": "rust_panic",
            "pattern": r"thread '[^']+' panicked at '[^']+',\s*.+\.rs:\d+",
            "severity": "high",
            "framework": "Rust",
            "description": "Rust panic with source file and line number",
        },
    ],
    "database_errors": [
        {
            "name": "mysql_error",
            "pattern": r"(?:MySQL|mysql|MariaDB|mariadb).*?(?:error|syntax|exception)",
            "severity": "critical",
            "description": "MySQL error message — confirms SQL backend and may reveal query structure",
        },
        {
            "name": "postgres_error",
            "pattern": r"(?:PostgreSQL|postgres|PSQL|psql).*?(?:ERROR|error|exception|warning)",
            "severity": "critical",
            "description": "PostgreSQL error — reveals database type and potential query leak",
        },
        {
            "name": "sqlite_error",
            "pattern": r"(?:SQLite|sqlite|sqlite3).*?(?:error|exception|no such table)",
            "severity": "critical",
            "description": "SQLite error — confirms local DB usage and may expose schema",
        },
        {
            "name": "mssql_error",
            "pattern": r"(?:Microsoft SQL Server|SQLServer|ODBC SQL Server Driver).*?(?:error|Exception)",
            "severity": "critical",
            "description": "Microsoft SQL Server error — reveals Windows backend stack",
        },
        {
            "name": "oracle_error",
            "pattern": r"(?:ORA-\d{5}|Oracle.*?error|oracle\.jdbc)",
            "severity": "critical",
            "description": "Oracle error code — reveals database version and operation",
        },
        {
            "name": "mongodb_error",
            "pattern": r"(?:MongoDB|mongo|E11000|BSON|errmsg)",
            "severity": "high",
            "description": "MongoDB error — confirms NoSQL backend and may reveal collection names",
        },
        {
            "name": "redis_error",
            "pattern": r"(?:Redis|redis|ERR\s+)[\w\s]+(?:error|command|wrong)",
            "severity": "high",
            "description": "Redis error — reveals caching architecture and potential command injection",
        },
        {
            "name": "generic_sql_syntax",
            "pattern": r"(?:sql syntax|syntax error|unclosed quotation mark|unterminated string).*(?:SQL|query|statement)",
            "severity": "critical",
            "description": "Generic SQL syntax error — confirms SQL injection surface",
        },
    ],
    "debug_pages": [
        {
            "name": "django_debug_page",
            "pattern": r"(?:Django|django).*?(?:debug|Debug|DEBUG)|<title>Page not found.*?Django",
            "severity": "critical",
            "framework": "Django",
            "description": "Django debug page — full environment, settings, and traceback exposed",
        },
        {
            "name": "rails_debug_page",
            "pattern": r"(?:Rails|rails).*?(?:debug|Routing Error|ActionController::Exception|We're sorry)",
            "severity": "critical",
            "framework": "Rails",
            "description": "Rails debug/error page — reveals framework version and routes",
        },
        {
            "name": "aspnet_debug",
            "pattern": r"(?:ASP\.NET|AspNet\.Core).*?(?:error|Exception|Server Error|Debug)",
            "severity": "critical",
            "framework": "ASP.NET",
            "description": "ASP.NET debug page — reveals .NET version, stack, and request details",
        },
        {
            "name": "spring_boot_error",
            "pattern": r"(?:Whitelabel Error Page|Spring Boot|spring-framework|org\.springframework)",
            "severity": "high",
            "framework": "Spring Boot",
            "description": "Spring Boot error page — reveals Java/Spring version and bean configuration",
        },
        {
            "name": "express_error",
            "pattern": r"(?:Express|express).*?(?:Error|error)|<title>Express</title>",
            "severity": "high",
            "framework": "Express.js",
            "description": "Express.js error page — confirms Node.js/Express stack",
        },
        {
            "name": "flask_debug",
            "pattern": r"(?:Flask|flask|jinja2|Jinja2).*?(?:debug|Debug|traceback|TemplateNotFound)",
            "severity": "critical",
            "framework": "Flask",
            "description": "Flask/Jinja2 debug page — reveals template paths and Python internals",
        },
        {
            "name": "laravel_debug",
            "pattern": r"(?:Laravel|laravel).*?(?:Whoops|debug|Error|Exception|Facade\\\\)",
            "severity": "critical",
            "framework": "Laravel",
            "description": "Laravel Whoops error page — full stack trace and environment variables",
        },
        {
            "name": "phpinfo_page",
            "pattern": r"(?:phpinfo\(\)|PHP Version.*?</h1>|System.*?</td>|php_uname)",
            "severity": "critical",
            "framework": "PHP",
            "description": "phpinfo() output — full PHP configuration, modules, and paths exposed",
        },
        {
            "name": "tomcat_error",
            "pattern": r"(?:Apache Tomcat|tomcat).*?(?:error|Error|HTTP Status|exception)",
            "severity": "high",
            "framework": "Tomcat",
            "description": "Tomcat error page — reveals Java version and servlet container details",
        },
        {
            "name": "webpack_hmr",
            "pattern": r"(?:webpack|webpack-dev-server|Hot Module Replacement|__webpack_hmr)",
            "severity": "medium",
            "framework": "Webpack",
            "description": "Webpack HMR exposed — development build in production reveals source maps",
        },
        {
            "name": "nextjs_debug",
            "pattern": r"(?:Next\.js|nextjs|__next).*?(?:error|Error|500|unhandledrejection)",
            "severity": "high",
            "framework": "Next.js",
            "description": "Next.js debug/error page — reveals React/Next version and component stack",
        },
    ],
    "internal_paths": [
        {
            "name": "unix_path_leak",
            "pattern": r"(?:/home/|/var/www/|/opt/|/srv/|/usr/local/|/etc/)[\w/.-]+",
            "severity": "high",
            "description": "Unix filesystem path exposed — reveals server directory structure",
        },
        {
            "name": "windows_path_leak",
            "pattern": r"(?:[A-Z]:\\(?:Users|Windows|Program Files|inetpub|wwwroot)\\[\w\\.-]+)",
            "severity": "high",
            "description": "Windows filesystem path exposed — reveals server directory structure",
        },
        {
            "name": "docker_path_leak",
            "pattern": r"/(?:app|src|code|workspace|opt/app|var/www)[\w/.-]*(?:\.py|\.js|\.rb|\.java|\.go)",
            "severity": "high",
            "description": "Container source path leaked — reveals Docker image layout",
        },
        {
            "name": "config_file_reference",
            "pattern": r"(?:\.env|config\.yml|config\.json|settings\.py|application\.properties|web\.xml)",
            "severity": "high",
            "description": "Configuration file path referenced — reveals application structure",
        },
        {
            "name": "temp_file_reference",
            "pattern": r"/(?:tmp|temp|var/tmp)[\w/.-]+",
            "severity": "medium",
            "description": "Temporary file path exposed — reveals OS and application temp directory",
        },
    ],
    "sensitive_info": [
        {
            "name": "aws_key_leak",
            "pattern": r"(?:AKIA[A-Z0-9]{16}|aws_secret_access_key)",
            "severity": "critical",
            "description": "AWS access key detected — full cloud account compromise risk",
        },
        {
            "name": "private_key_leak",
            "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "severity": "critical",
            "description": "Private key exposed — cryptographic compromise",
        },
        {
            "name": "jwt_secret_leak",
            "pattern": r"(?:jwt[_-]?secret|JWT[_-]?SECRET)[\s]*[:=][\s]*['\"]?[\w/-]{16,}",
            "severity": "critical",
            "description": "JWT signing secret exposed — token forgery possible",
        },
        {
            "name": "db_connection_string",
            "pattern": r"(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"]+",
            "severity": "critical",
            "description": "Database connection string exposed — direct database access",
        },
        {
            "name": "api_key_leak",
            "pattern": r"(?:api[_-]?key|apikey)[\s]*[:=][\s]*['\"]?[\w-]{20,}",
            "severity": "critical",
            "description": "API key leaked — service impersonation risk",
        },
        {
            "name": "ip_address_leak",
            "pattern": r"(?:internal|private|backend|db-|db_|db\.)[\w-]*(?:\d{1,3}\.){3}\d{1,3}",
            "severity": "medium",
            "description": "Internal IP address exposed in error message",
        },
        {
            "name": "hostname_leak",
            "pattern": r"(?:hostname|server|host)[:\s]+(?:[a-z0-9-]+\.)+(?:internal|local|corp|prod|staging|dev)[\w.-]*",
            "severity": "medium",
            "description": "Internal hostname exposed — reveals infrastructure naming convention",
        },
    ],
}


# ════════════════════════════════════════════════════════════════════════
# VERSION_VULN_DB — Sample version-to-CVE correlation database
# ════════════════════════════════════════════════════════════════════════

VERSION_VULN_DB: Dict[str, List[Dict[str, Any]]] = {
    "nginx": [
        {
            "version_pattern": r"nginx/(\d+\.\d+)\.\d+",
            "vulnerable_ranges": [
                {"max": "0.7", "cve": "CVE-2009-2629", "desc": "URI processing buffer overflow"},
                {"max": "1.0", "cve": "CVE-2013-2070", "desc": "WebSocket DoS"},
                {"max": "1.4", "cve": "CVE-2014-0133", "desc": "SPDY header parsing DoS"},
                {"max": "1.16", "cve": "CVE-2019-9511", "desc": "HTTP/2 multiplexing DoS"},
                {"min": "1.17", "max": "1.21", "cve": "CVE-2021-23017", "desc": "DNS resolver off-by-one heap write"},
                {"min": "1.21", "max": "1.25", "cve": "CVE-2024-7347", "desc": "HTTP/2 rapid reset DoS"},
            ],
        },
    ],
    "apache": [
        {
            "version_pattern": r"Apache/(\d+\.\d+)\.\d+",
            "vulnerable_ranges": [
                {"max": "2.2", "cve": "CVE-2012-0053", "desc": "HTTP header response splitting"},
                {"max": "2.4", "cve": "CVE-2017-7668", "desc": "mod_http2 stream handling DoS"},
                {"min": "2.4", "max": "2.4.49", "cve": "CVE-2021-41773", "desc": "Path traversal / CGI execution"},
                {"min": "2.4.49", "max": "2.4.51", "cve": "CVE-2021-42013", "desc": "Path traversal variant"},
            ],
        },
    ],
    "openSSH": [
        {
            "version_pattern": r"OpenSSH_(\d+\.\d+)",
            "vulnerable_ranges": [
                {"max": "7.6", "cve": "CVE-2018-15473", "desc": "User enumeration via authentication timing"},
                {"min": "8.5", "max": "9.7", "cve": "CVE-2024-6387", "desc": "regreSSHion — signal handler race condition RCE"},
            ],
        },
    ],
    "php": [
        {
            "version_pattern": r"PHP/(\d+\.\d+)\.\d+",
            "vulnerable_ranges": [
                {"max": "5.6", "cve": "CVE-2019-11043", "desc": "PHP-FPM RCE via env variable length"},
                {"min": "7.0", "max": "7.2", "cve": "CVE-2019-11043", "desc": "PHP-FPM RCE"},
                {"min": "7.3", "max": "7.4.32", "cve": "CVE-2022-31631", "desc": "PGSQL double free"},
                {"min": "8.0", "max": "8.0.29", "cve": "CVE-2022-31631", "desc": "PGSQL double free"},
                {"min": "8.1", "max": "8.1.19", "cve": "CVE-2023-3823", "desc": "XML parsing buffer overread"},
                {"min": "8.1", "max": "8.1.29", "cve": "CVE-2023-3824", "desc": "BCMath arbitrary precision integer overflow"},
            ],
        },
    ],
    "tomcat": [
        {
            "version_pattern": r"Apache Tomcat/(\d+\.\d+)\.\d+",
            "vulnerable_ranges": [
                {"max": "9.0", "cve": "CVE-2020-9484", "desc": "Session persistence deserialization RCE"},
                {"min": "10.0", "max": "10.1.13", "cve": "CVE-2024-21733", "desc": "HTTP request smuggling"},
                {"min": "8.5", "max": "8.5.98", "cve": "CVE-2024-23336", "desc": "HTTP request smuggling via transfer-encoding"},
            ],
        },
    ],
    "openssl": [
        {
            "version_pattern": r"OpenSSL\s+(\d+\.\d+)\.\d+",
            "vulnerable_ranges": [
                {"min": "3.0", "max": "3.0.12", "cve": "CVE-2024-5535", "desc": "PKCS7 decryption buffer overread"},
                {"min": "1.1.1", "max": "1.1.1w", "cve": "CVE-2024-4741", "desc": "DTLS bad length DoS"},
            ],
        },
    ],
    "spring": [
        {
            "version_pattern": r"(?:spring|Spring)\s*(?:Framework\s*)?([\d.]+)",
            "vulnerable_ranges": [
                {"min": "5.0", "max": "5.3.17", "cve": "CVE-2022-22965", "desc": "Spring4Shell RCE via data binding"},
                {"min": "5.3", "max": "5.3.17", "cve": "CVE-2022-22950", "desc": "DoS via SpEL expressions"},
            ],
        },
    ],
    "nodejs": [
        {
            "version_pattern": r"(?:Node\.js|node)\s+v?(\d+\.\d+)\.\d+",
            "vulnerable_ranges": [
                {"min": "14.0", "max": "14.21.3", "cve": "CVE-2023-23918", "desc": "Crypto getCurves out-of-bounds read"},
                {"min": "16.0", "max": "16.19.0", "cve": "CVE-2023-23919", "desc": "Ciphersheet WIFS improper key validation"},
                {"min": "18.0", "max": "18.14.0", "cve": "CVE-2023-23920", "desc": "Module permissions bypass via process.mainModule"},
            ],
        },
    ],
}


# ════════════════════════════════════════════════════════════════════════
# FUZZ_PAYLOADS — Crafted inputs for anomaly detection
# ════════════════════════════════════════════════════════════════════════

FUZZ_PAYLOADS: List[Dict[str, Any]] = [
    {"category": "sqli", "value": "' OR '1'='1", "label": "SQLi: boolean-based auth bypass"},
    {"category": "sqli", "value": "' UNION SELECT NULL,NULL,NULL--", "label": "SQLi: UNION column enumeration"},
    {"category": "sqli", "value": "1; WAITFOR DELAY '0:0:5'--", "label": "SQLi: time-based blind (MSSQL)"},
    {"category": "sqli", "value": "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "label": "SQLi: time-based blind (MySQL)"},
    {"category": "xss", "value": "<script>alert(document.domain)</script>", "label": "XSS: reflected script tag"},
    {"category": "xss", "value": "'\"><img src=x onerror=alert(1)>", "label": "XSS: attribute breakout"},
    {"category": "ssti", "value": "{{7*7}}", "label": "SSTI: arithmetic expression probe"},
    {"category": "ssti", "value": "${7*7}", "label": "SSTI: template literal probe (Freemarker/Thymeleaf)"},
    {"category": "ssti", "value": "#{7*7}", "label": "SSTI: OGNL expression probe (Struts)"},
    {"category": "path_traversal", "value": "../../../etc/passwd", "label": "Path traversal: classic"},
    {"category": "path_traversal", "value": "....//....//....//etc/passwd", "label": "Path traversal: double-encoding"},
    {"category": "format_string", "value": "%s%s%s%s%s%s%s%s%s%s", "label": "Format string: printf-style"},
    {"category": "format_string", "value": "{0}{1}{2}{3}{4}", "label": "Format string: Python format"},
    {"category": "buffer_overflow", "value": "A" * 4096, "label": "Buffer overflow: large string (4KB)"},
    {"category": "null_byte", "value": "%00", "label": "Null byte injection"},
    {"category": "crlf", "value": "%0d%0aX-Injected:true", "label": "CRLF: header injection"},
    {"category": "crlf", "value": "\r\nX-Injected: true", "label": "CRLF: raw header injection"},
    {"category": "xml", "value": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>', "label": "XXE: external entity injection"},
    {"category": "json", "value": '{"__proto__":{"admin":true}}', "label": "Prototype pollution: JSON"},
    {"category": "log4j", "value": "${jndi:ldap://127.0.0.1/a}", "label": "Log4Shell: JNDI lookup probe"},
    {"category": "ssrf", "value": "http://169.254.169.254/latest/meta-data/", "label": "SSRF: AWS metadata endpoint"},
]


# ════════════════════════════════════════════════════════════════════════
# SENSITIVITY_PATHS — Endpoints to test for broken access control
# ════════════════════════════════════════════════════════════════════════

SENSITIVITY_PATHS: List[Dict[str, Any]] = [
    {"path": "/admin", "expected_without_auth": 401, "sensitivity": "critical", "label": "Admin dashboard"},
    {"path": "/admin/dashboard", "expected_without_auth": 401, "sensitivity": "critical", "label": "Admin dashboard (sub)"},
    {"path": "/admin/users", "expected_without_auth": 401, "sensitivity": "critical", "label": "User management"},
    {"path": "/api/admin", "expected_without_auth": 401, "sensitivity": "critical", "label": "Admin API root"},
    {"path": "/api/users", "expected_without_auth": 401, "sensitivity": "high", "label": "User API listing"},
    {"path": "/api/config", "expected_without_auth": 401, "sensitivity": "critical", "label": "Configuration API"},
    {"path": "/api/settings", "expected_without_auth": 401, "sensitivity": "high", "label": "Settings API"},
    {"path": "/api/internal", "expected_without_auth": 401, "sensitivity": "critical", "label": "Internal API"},
    {"path": "/api/debug", "expected_without_auth": 401, "sensitivity": "critical", "label": "Debug API"},
    {"path": "/api/health", "expected_without_auth": 200, "sensitivity": "low", "label": "Health check"},
    {"path": "/api/status", "expected_without_auth": 200, "sensitivity": "low", "label": "Status endpoint"},
    {"path": "/user/profile", "expected_without_auth": 401, "sensitivity": "medium", "label": "User profile"},
    {"path": "/account", "expected_without_auth": 401, "sensitivity": "high", "label": "Account page"},
    {"path": "/console", "expected_without_auth": 401, "sensitivity": "high", "label": "Management console"},
    {"path": "/manage", "expected_without_auth": 401, "sensitivity": "high", "label": "Management interface"},
    {"path": "/dashboard", "expected_without_auth": 401, "sensitivity": "high", "label": "Dashboard"},
    {"path": "/backup", "expected_without_auth": 401, "sensitivity": "critical", "label": "Backup endpoint"},
    {"path": "/backups", "expected_without_auth": 401, "sensitivity": "critical", "label": "Backups listing"},
    {"path": "/.git/config", "expected_without_auth": 404, "sensitivity": "critical", "label": "Git config"},
    {"path": "/server-status", "expected_without_auth": 404, "sensitivity": "high", "label": "Apache server-status"},
    {"path": "/actuator/env", "expected_without_auth": 401, "sensitivity": "critical", "label": "Spring Actuator env"},
    {"path": "/actuator/heapdump", "expected_without_auth": 401, "sensitivity": "critical", "label": "Spring Actuator heapdump"},
]


# ════════════════════════════════════════════════════════════════════════
# HEADER_ANOMALY_PATTERNS — Headers revealing internal architecture
# ════════════════════════════════════════════════════════════════════════

HEADER_ANOMALY_PATTERNS: List[Dict[str, Any]] = [
    {"header": "X-Powered-By", "severity": "medium", "description": "Reveals backend technology stack", "indicates": ["development_artifact", "tech_disclosure"]},
    {"header": "X-AspNet-Version", "severity": "medium", "description": "Reveals exact .NET Framework version", "indicates": ["version_disclosure", "tech_disclosure"]},
    {"header": "X-AspNetMvc-Version", "severity": "medium", "description": "Reveals ASP.NET MVC version", "indicates": ["version_disclosure", "tech_disclosure"]},
    {"header": "X-Drupal-Cache", "severity": "low", "description": "Confirms Drupal CMS", "indicates": ["tech_disclosure"]},
    {"header": "X-Generator", "severity": "medium", "description": "Often reveals CMS and version", "indicates": ["version_disclosure", "tech_disclosure"]},
    {"header": "X-Debug-Info", "severity": "high", "description": "Debug mode enabled — reveals internal profiling data", "indicates": ["debug_mode", "development_artifact"]},
    {"header": "X-Rack-Cache", "severity": "low", "description": "Confirms Ruby/Rack stack", "indicates": ["tech_disclosure"]},
    {"header": "X-Runtime", "severity": "low", "description": "Reveals request processing time", "indicates": ["timing_leak", "tech_disclosure"]},
    {"header": "X-Request-Id", "severity": "low", "description": "Reveals request tracing architecture", "indicates": ["architecture_disclosure"]},
    {"header": "X-Cache", "severity": "low", "description": "Reveals caching infrastructure", "indicates": ["architecture_disclosure"]},
    {"header": "X-Served-By", "severity": "medium", "description": "Reveals internal server hostname or CDN node", "indicates": ["hostname_disclosure", "architecture_disclosure"]},
    {"header": "X-Varnish", "severity": "low", "description": "Confirms Varnish cache in use", "indicates": ["tech_disclosure"]},
    {"header": "X-Backend-Server", "severity": "high", "description": "Directly reveals backend server identity", "indicates": ["hostname_disclosure", "architecture_disclosure"]},
    {"header": "Via", "severity": "medium", "description": "Reveals proxy chain and intermediate nodes", "indicates": ["architecture_disclosure", "proxy_disclosure"]},
    {"header": "Server", "severity": "low", "description": "Server header — check for version string", "indicates": ["version_disclosure", "tech_disclosure"]},
]


# ════════════════════════════════════════════════════════════════════════
# HELPER UTILITIES
# ════════════════════════════════════════════════════════════════════════

DREAD_SCALE = {
    "critical": (10, 8, 9, 9, 8),
    "high":     (8, 7, 7, 7, 7),
    "medium":   (5, 5, 5, 5, 5),
    "low":      (3, 3, 3, 3, 4),
    "info":     (1, 1, 1, 1, 2),
}


def _dread_score(severity: str) -> float:
    d, r, e, a, disc = DREAD_SCALE.get(severity, (0, 0, 0, 0, 0))
    return round((d + r + e + a + disc) / 5, 1)


def _host_from_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc.split(":")[0]


def _shannon_entropy(data: str) -> float:
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
    return round(entropy, 2)


def _version_cmp(v1: str, v2: str) -> int:
    def _parts(v: str) -> List[int]:
        parts = []
        for p in re.split(r"\.|-", v):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return parts
    p1, p2 = _parts(v1), _parts(v2)
    max_len = max(len(p1), len(p2))
    p1.extend([0] * (max_len - len(p1)))
    p2.extend([0] * (max_len - len(p2)))
    for a, b in zip(p1, p2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


def _version_in_range(version: str, vuln_range: Dict[str, str]) -> bool:
    min_v = vuln_range.get("min", "0.0.0")
    max_v = vuln_range.get("max", "999.999.999")
    return _version_cmp(version, min_v) >= 0 and _version_cmp(version, max_v) <= 0


def _safe_probe(url: str, method: str = "GET", body: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None, timeout: int = 8,
                verify_tls: bool = True) -> Dict[str, Any]:
    try:
        return http_probe(
            url, method=method, body=body, headers=headers,
            timeout=timeout, verify_tls=verify_tls,
            limiter=default_limiter,
        )
    except Exception:
        return {"ok": False, "status": 0, "reason": "probe failed", "headers": {}, "body": ""}


def _severity_points(severity: str) -> int:
    return {"critical": 15, "high": 10, "medium": 5, "low": 3, "info": 1}.get(severity, 0)


# ════════════════════════════════════════════════════════════════════════
# CAPABILITY 1: RESPONSE ANOMALY DETECTION
# ════════════════════════════════════════════════════════════════════════

def _detect_response_anomalies(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> Tuple[List[Finding], List[Dict[str, Any]]]:
    """Compare response characteristics against statistical baselines."""
    findings: List[Finding] = []
    host = _host_from_url(base_url)

    probe_paths = [
        "/", "/index.html", "/robots.txt", "/favicon.ico",
        "/sitemap.xml", "/manifest.json", "/.well-known/security.txt",
        "/api", "/api/v1", "/api/health", "/health",
        "/login", "/register", "/api/docs", "/swagger.json",
    ]

    responses: List[Dict[str, Any]] = []
    for path in probe_paths:
        url = base_url.rstrip("/") + path
        t0 = time.monotonic()
        resp = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)
        elapsed_ms = (time.monotonic() - t0) * 1000
        resp["url"] = url
        resp["path"] = path
        resp["elapsed_ms"] = round(elapsed_ms, 1)
        resp["body_length"] = len(resp.get("body", ""))
        responses.append(resp)

    if not responses:
        return findings, responses

    statuses = [r["status"] for r in responses if r["status"] > 0]
    sizes = [r["body_length"] for r in responses]
    timings = [r["elapsed_ms"] for r in responses]

    # ── Anomalous status codes ──
    if statuses:
        status_set = set(statuses)
        anom_codes = ANOMALY_THRESHOLDS["status_codes"]["anomaly_codes"]
        for r in responses:
            code = r["status"]
            if code in anom_codes:
                desc = anom_codes[code]
                findings.append(Finding(
                    title=f"Anomalous status code {code} at {r['path']}",
                    severity="medium", category="response_anomaly",
                    module="zero_day_hunter",
                    description=f"HTTP {code} ({r.get('reason', '')}) on {r['path']}: {desc}",
                    evidence=f"GET {r['path']} -> {code} ({r['body_length']} bytes, {r['elapsed_ms']}ms)",
                    asset=host, points_deducted=5,
                    remediation="Review endpoint configuration; unusual status codes may indicate unhandled edge cases.",
                    dread_score=_dread_score("medium"),
                ))

        # Unexpected 5xx on static paths
        static_exts = {".css", ".js", ".png", ".jpg", ".ico", ".svg", ".woff", ".ttf"}
        for r in responses:
            if r["status"] >= 500 and any(r["path"].lower().endswith(e) for e in static_exts):
                findings.append(Finding(
                    title=f"Server error on static resource: {r['path']}",
                    severity="high", category="response_anomaly",
                    module="zero_day_hunter",
                    description=ANOMALY_THRESHOLDS["status_codes"]["unexpected_5xx_on_static"],
                    evidence=f"GET {r['path']} -> {r['status']} ({r.get('reason', '')})",
                    asset=host, points_deducted=10,
                    remediation="Ensure static assets are served correctly; 5xx on static files suggests misconfigured routing.",
                    dread_score=_dread_score("high"),
                ))

        if len(status_set) > ANOMALY_THRESHOLDS["consistency"]["max_status_variance"]:
            findings.append(Finding(
                title=f"High status code variance: {len(status_set)} distinct codes",
                severity="low", category="response_anomaly",
                module="zero_day_hunter",
                description=f"Probing returned {len(status_set)} distinct status codes: {sorted(status_set)}. May indicate inconsistent routing or partial WAF.",
                evidence=f"Statuses: {sorted(status_set)} across {len(responses)} paths",
                asset=host, points_deducted=3,
                remediation="Audit routing rules and middleware for consistency.",
                dread_score=_dread_score("low"),
            ))

    # ── Size anomaly detection ──
    if len(sizes) >= 3:
        mean_size = statistics.mean(sizes)
        try:
            stdev_size = statistics.stdev(sizes)
        except statistics.StatisticsError:
            stdev_size = 0.0

        sigma = ANOMALY_THRESHOLDS["response_size"]["size_variance_sigma"]
        for r in responses:
            bl = r["body_length"]
            if stdev_size > 0 and bl > 0:
                z_score = abs(bl - mean_size) / stdev_size
                if z_score > sigma:
                    findings.append(Finding(
                        title=f"Response size outlier at {r['path']} (z={z_score:.1f})",
                        severity="low", category="response_anomaly",
                        module="zero_day_hunter",
                        description=f"Body size ({bl} bytes) is {z_score:.1f}σ from mean ({mean_size:.0f}). May indicate unexpected data type or error content.",
                        evidence=f"GET {r['path']} -> {r['status']} ({bl} bytes, μ={mean_size:.0f}, σ={stdev_size:.0f})",
                        asset=host, points_deducted=3,
                        remediation="Investigate endpoints returning significantly different sizes than the baseline.",
                        dread_score=_dread_score("low"),
                    ))

        for r in responses:
            if r["status"] == 200 and r["body_length"] < ANOMALY_THRESHOLDS["response_size"]["abnormally_small_ok"]:
                findings.append(Finding(
                    title=f"Suspiciously small 200 response at {r['path']}",
                    severity="medium", category="response_anomaly",
                    module="zero_day_hunter",
                    description=f"HTTP 200 with only {r['body_length']} bytes. May indicate empty default page or stub response.",
                    evidence=f"GET {r['path']} -> 200 ({r['body_length']} bytes)",
                    asset=host, points_deducted=5,
                    remediation="Ensure endpoints return meaningful content or proper error codes.",
                    dread_score=_dread_score("medium"),
                ))

    # ── Timing anomaly detection ──
    if len(timings) >= 3:
        mean_time = statistics.mean(timings)
        try:
            stdev_time = statistics.stdev(timings)
        except statistics.StatisticsError:
            stdev_time = 0.0

        time_sigma = ANOMALY_THRESHOLDS["timing"]["timing_variance_sigma"]
        for r in responses:
            t = r["elapsed_ms"]
            if stdev_time > 0 and t > 0:
                z_time = abs(t - mean_time) / stdev_time
                if z_time > time_sigma:
                    sev = "high" if t > ANOMALY_THRESHOLDS["timing"]["suspicious_slow_ms"] else "medium"
                    findings.append(Finding(
                        title=f"Timing anomaly at {r['path']} ({t:.0f}ms)",
                        severity=sev, category="response_anomaly",
                        module="zero_day_hunter",
                        description=f"Response time ({t:.0f}ms) is {z_time:.1f}σ from baseline ({mean_time:.0f}ms). May indicate time-based blind injection vector or uncached computation.",
                        evidence=f"GET {r['path']} -> {r['status']} ({t:.0f}ms, μ={mean_time:.0f}ms, σ={stdev_time:.0f}ms)",
                        asset=host, points_deducted=_severity_points(sev),
                        remediation="Investigate slow endpoints for missing caching, N+1 queries, or time-based side channels.",
                        dread_score=_dread_score(sev),
                    ))

    # ── Body entropy analysis ──
    for r in responses:
        body = r.get("body", "")
        if len(body) > 50:
            entropy = _shannon_entropy(body)
            if entropy < ANOMALY_THRESHOLDS["body_entropy"]["low_entropy_threshold"]:
                findings.append(Finding(
                    title=f"Low-entropy response body at {r['path']} (H={entropy})",
                    severity="low", category="response_anomaly",
                    module="zero_day_hunter",
                    description=f"Shannon entropy {entropy} bits — suggests template/placeholder content, possibly a default installation.",
                    evidence=f"GET {r['path']} -> {r['status']} ({r['body_length']} bytes, entropy={entropy})",
                    asset=host, points_deducted=3,
                    remediation="Low entropy may indicate default configurations requiring hardening.",
                    dread_score=_dread_score("low"),
                ))
            elif entropy > ANOMALY_THRESHOLDS["body_entropy"]["high_entropy_threshold"]:
                if r["status"] == 200 and not any(r["path"].lower().endswith(e) for e in [".png", ".jpg", ".ico", ".woff", ".ttf"]):
                    findings.append(Finding(
                        title=f"High-entropy response at {r['path']} (H={entropy})",
                        severity="medium", category="response_anomaly",
                        module="zero_day_hunter",
                        description=f"Shannon entropy {entropy} bits — suggests encrypted/compressed content or binary data leak on a non-static endpoint.",
                        evidence=f"GET {r['path']} -> {r['status']} ({r['body_length']} bytes, entropy={entropy})",
                        asset=host, points_deducted=5,
                        remediation="High-entropy text responses on API endpoints may indicate source map leakage or serialized binary data exposure.",
                        dread_score=_dread_score("medium"),
                    ))

    return findings, responses


# ════════════════════════════════════════════════════════════════════════
# CAPABILITY 2: ERROR MESSAGE ANALYSIS
# ════════════════════════════════════════════════════════════════════════

def _analyze_error_messages(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    """Parse error responses for stack traces, internal paths, debug info."""
    findings: List[Finding] = []
    host = _host_from_url(base_url)

    error_probes: List[Tuple[str, str, Optional[bytes]]] = [
        ("/nonexistent_endpoint_404_test", "GET", None),
        ("/api/nonexistent", "GET", None),
        ("/api/v1/invalid_route_xyz", "GET", None),
        ("/", "POST", b'{"invalid_key": "trigger_error"}'),
        ("/api", "POST", b'{"malformed_json"'),
        ("/api/search", "GET", None),
        ("/api/search?q=%27%20OR%201%3D1--", "GET", None),
        ("/login", "POST", b"username=admin&password='"),
        ("/api/user/999999999", "GET", None),
        ("/api/test?debug=1", "GET", None),
        ("/api/test?trace=1", "GET", None),
    ]

    seen_signatures: set = set()

    for path, method, body in error_probes:
        url = base_url.rstrip("/") + path
        resp = _safe_probe(url, method=method, body=body, timeout=timeout, verify_tls=verify_tls)
        resp_body = resp.get("body", "")
        resp_headers_str = " ".join(f"{k}: {v}" for k, v in resp.get("headers", {}).items())
        combined = resp_body + " " + resp_headers_str

        for sig_category, signatures in ERROR_SIGNATURES.items():
            for sig in signatures:
                sig_name = sig["name"]
                if sig_name in seen_signatures:
                    continue
                pattern = sig["pattern"]
                match = re.search(pattern, combined, re.IGNORECASE | re.DOTALL)
                if match:
                    seen_signatures.add(sig_name)
                    sev = sig["severity"]
                    desc = sig["description"]
                    framework = sig.get("framework", "Unknown")
                    matched_text = match.group(0)[:200]
                    resp_status = resp['status']
                    findings.append(Finding(
                        title=f"{sig_category}: {sig_name} detected ({framework})",
                        severity=sev, category="error_disclosure",
                        module="zero_day_hunter",
                        description=f"{desc} Found via {method} {path}.",
                        evidence=f"Match: [{matched_text}] in response to {method} {path} -> {resp_status}",
                        asset=host, points_deducted=_severity_points(sev),
                        remediation=(
                            f"Disable debug/error detail exposure in {framework} production environment. "
                            "Implement custom error pages that do not reveal internal implementation details."
                        ),
                        dread_score=_dread_score(sev),
                    ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# CAPABILITY 3: VERSION-RESPONSE CORRELATION
# ════════════════════════════════════════════════════════════════════════

def _correlate_versions(
    target: str, base_url: str, timeout: int, verify_tls: bool,
    probe_responses: List[Dict[str, Any]],
) -> List[Finding]:
    """Cross-reference observed versions with known vulnerability databases."""
    findings: List[Finding] = []
    host = _host_from_url(base_url)

    # Gather version strings from headers and body
    version_sources: List[Tuple[str, str]] = []

    for r in probe_responses:
        # Check Server header
        server = r.get("headers", {}).get("Server", "")
        if server:
            version_sources.append(("Server", server))

        # Check X-Powered-By
        powered = r.get("headers", {}).get("X-Powered-By", "")
        if powered:
            version_sources.append(("X-Powered-By", powered))

        # Scan body for version patterns
        body = r.get("body", "")
        body_version_patterns = [
            ("body", m.group(0))
            for p in [r"nginx/[\d.]+", r"Apache/[\d.]+", r"OpenSSH_[\d.]+",
                      r"PHP/[\d.]+", r"Tomcat/[\d.]+", r"OpenSSL\s*[\d.]+",
                      r"Spring\s*Framework\s*[\d.]+", r"Node\.?js\s*v?[\d.]+",
                      r"Express\s*[\d.]+", r"Django\s*[\d.]+", r"Rails\s*[\d.]+",
                      r"Laravel\s*v?[\d.]+", r"Next\.?js\s*[\d.]+"]
            for m in [re.search(p, body, re.IGNORECASE)] if m
        ]
        version_sources.extend(body_version_patterns)

    # Deduplicate version sources
    seen: set = set()
    for source, value in version_sources:
        key = f"{source}:{value}"
        if key in seen:
            continue
        seen.add(key)

        # Try each product in VERSION_VULN_DB
        for product, entries in VERSION_VULN_DB.items():
            for entry in entries:
                pattern = entry["version_pattern"]
                m = re.search(pattern, value, re.IGNORECASE)
                if not m:
                    continue
                version = m.group(1)
                for vuln_range in entry["vulnerable_ranges"]:
                    if _version_in_range(version, vuln_range):
                        cve = vuln_range["cve"]
                        desc = vuln_range["desc"]
                        findings.append(Finding(
                            title=f"Version vulnerability: {product} {version} -> {cve}",
                            severity="critical", category="version_vulnerability",
                            module="zero_day_hunter",
                            description=f"{product} version {version} detected in {source} header/body. This version is vulnerable to {cve}: {desc}.",
                            evidence=f"{source}: {value} | Pattern: {pattern} | Version: {version} | CVE: {cve}",
                            asset=host, points_deducted=15,
                            remediation=f"Upgrade {product} to a patched version beyond the affected range. See {cve} for specific fix details.",
                            dread_score=_dread_score("critical"),
                        ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# CAPABILITY 4: BEHAVIORAL ANOMALY SCORING
# ════════════════════════════════════════════════════════════════════════

def _score_behavioral_anomalies(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    """Score endpoints on inconsistent caching, timing, parameter sensitivity."""
    findings: List[Finding] = []
    host = _host_from_url(base_url)

    # Test caching consistency: send same request twice, compare headers
    cache_test_paths = ["/", "/api/health", "/api/v1"]
    for path in cache_test_paths:
        url = base_url.rstrip("/") + path
        r1 = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)
        r2 = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)

        h1 = r1.get("headers", {})
        h2 = r2.get("headers", {})

        # Check Cache-Control consistency
        cc1 = h1.get("Cache-Control", "")
        cc2 = h2.get("Cache-Control", "")
        if cc1 != cc2:
            findings.append(Finding(
                title=f"Inconsistent Cache-Control header on {path}",
                severity="low", category="behavioral_anomaly",
                module="zero_day_hunter",
                description=f"Cache-Control header changed between identical requests: '{cc1}' -> '{cc2}'. May indicate load-balanced backends with inconsistent configurations.",
                evidence=f"Request 1: Cache-Control={cc1} | Request 2: Cache-Control={cc2}",
                asset=host, points_deducted=3,
                remediation="Ensure all backend servers share identical cache configuration. Inconsistent caching can lead to cache poisoning.",
                dread_score=_dread_score("low"),
            ))

        # Check ETag consistency
        etag1 = h1.get("ETag", "")
        etag2 = h2.get("ETag", "")
        if etag1 and etag2 and etag1 != etag2 and r1["status"] == 200 and r2["status"] == 200:
            findings.append(Finding(
                title=f"ETag instability on {path}",
                severity="medium", category="behavioral_anomaly",
                module="zero_day_hunter",
                description=f"ETag changed between identical requests: '{etag1}' -> '{etag2}'. May reveal weak ETag generation or load balancer inconsistency.",
                evidence=f"Request 1: ETag={etag1} | Request 2: ETag={etag2}",
                asset=host, points_deducted=5,
                remediation="Use strong, deterministic ETags. ETag instability can facilitate cache-based attacks.",
                dread_score=_dread_score("medium"),
            ))

    # Parameter sensitivity: test how different params affect response
    param_test_url = base_url.rstrip("/") + "/api/search"
    param_variants = [
        {},
        {"q": "test"},
        {"q": "' OR 1=1"},
        {"q": "<script>alert(1)</script>"},
        {"q": "../../../etc/passwd"},
        {"page": "1"},
        {"page": "-1"},
        {"page": "999999"},
        {"sort": "id"},
        {"sort": "id; DROP TABLE users"},
        {"_debug": "1"},
        {"admin": "true"},
    ]

    baseline_sizes: List[int] = []
    baseline_statuses: List[int] = []
    param_responses: List[Dict[str, Any]] = []

    for params in param_variants:
        qs = urllib.parse.urlencode(params) if params else ""
        url = f"{param_test_url}?{qs}" if qs else param_test_url
        t0 = time.monotonic()
        resp = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)
        elapsed = (time.monotonic() - t0) * 1000
        resp["params"] = params
        resp["elapsed_ms"] = round(elapsed, 1)
        resp["body_length"] = len(resp.get("body", ""))
        param_responses.append(resp)

        if not params:
            baseline_sizes.append(resp["body_length"])
            baseline_statuses.append(resp["status"])

    if baseline_sizes:
        baseline_mean = statistics.mean(baseline_sizes)
        for r in param_responses:
            params = r["params"]
            if not params:
                continue
            bl = r["body_length"]
            status = r["status"]
            # Check for significant size deviation from baseline
            if baseline_mean > 0 and bl > 0:
                ratio = max(bl, baseline_mean) / max(min(bl, baseline_mean), 1)
                if ratio > ANOMALY_THRESHOLDS["consistency"]["max_size_ratio"]:
                    findings.append(Finding(
                        title=f"Parameter sensitivity anomaly: {params}",
                        severity="high", category="behavioral_anomaly",
                        module="zero_day_hunter",
                        description=f"Parameter set {params} caused a {ratio:.1f}x response size change ({baseline_mean:.0f} -> {bl} bytes). This magnitude of change may indicate injection vulnerability or unintended data exposure.",
                        evidence=f"Params: {params} | Baseline: {baseline_mean:.0f} bytes -> Response: {bl} bytes | Status: {status} | Time: {r['elapsed_ms']}ms",
                        asset=host, points_deducted=10,
                        remediation="Audit parameter handling for this endpoint. Large size changes from crafted inputs may indicate SQL injection, path traversal, or information disclosure.",
                        dread_score=_dread_score("high"),
                    ))

            # Check for status code change from 200 baseline to error
            if baseline_statuses and baseline_statuses[0] == 200 and status >= 400:
                param_str = str(params)
                findings.append(Finding(
                    title=f"Parameter-induced error: {params}",
                    severity="medium", category="behavioral_anomaly",
                    module="zero_day_hunter",
                    description=f"Parameters {params} changed response from 200 to {status}. Error may reveal backend validation logic or input handling defects.",
                    evidence=f"Params: {params} | Status: {status} | Body: {r.get('body', '')[:200]}",
                    asset=host, points_deducted=5,
                    remediation="Implement robust input validation that returns consistent error responses without leaking implementation details.",
                    dread_score=_dread_score("medium"),
                ))

    # Timing sensitivity: compare response times across parameter variants
    timings = [r["elapsed_ms"] for r in param_responses if r["elapsed_ms"] > 0]
    if len(timings) >= 3:
        mean_t = statistics.mean(timings)
        for r in param_responses:
            t = r["elapsed_ms"]
            if t > ANOMALY_THRESHOLDS["timing"]["time_based_blind_threshold_ms"]:
                findings.append(Finding(
                    title=f"Timing sensitivity: {r['params']} took {t:.0f}ms",
                    severity="high", category="behavioral_anomaly",
                    module="zero_day_hunter",
                    description=f"Parameter set {r['params']} caused {t:.0f}ms response (baseline ~{mean_t:.0f}ms). Timing delta of {t - mean_t:.0f}ms may indicate time-based blind injection vulnerability.",
                    evidence=f"Params: {r['params']} | Time: {t:.0f}ms | Baseline: ~{mean_t:.0f}ms | Status: {r['status']}",
                    asset=host, points_deducted=10,
                    remediation="Investigate timing differences for potential time-based blind SQL injection or command injection vulnerabilities.",
                    dread_score=_dread_score("high"),
                ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# CAPABILITY 5: FUZZING RESULT ANALYSIS
# ════════════════════════════════════════════════════════════════════════

def _analyze_fuzzing_results(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    """Send crafted inputs and detect anomalous responses."""
    findings: List[Finding] = []
    host = _host_from_url(base_url)

    # Establish baseline from clean request
    baseline_url = base_url.rstrip("/") + "/api/search"
    baseline_resp = _safe_probe(baseline_url, timeout=timeout, verify_tls=verify_tls)
    baseline_status = baseline_resp["status"]
    baseline_size = len(baseline_resp.get("body", ""))
    baseline_headers = set(baseline_resp.get("headers", {}).keys())

    # Also establish baseline for the root endpoint
    root_resp = _safe_probe(base_url.rstrip("/") + "/", timeout=timeout, verify_tls=verify_tls)
    root_status = root_resp["status"]
    root_size = len(root_resp.get("body", ""))

    fuzz_targets = [
        ("/api/search", "GET", None),
        ("/", "POST", None),
        ("/api/login", "POST", None),
        ("/api/user", "GET", None),
    ]

    for target_path, method, _ in fuzz_targets:
        base_target = base_url.rstrip("/") + target_path

        for payload in FUZZ_PAYLOADS:
            category = payload["category"]
            value = payload["value"]
            label = payload["label"]

            if method == "GET":
                url = f"{base_target}?q={urllib.parse.quote(value)}"
                resp = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)
            else:
                if category == "xml":
                    body = value.encode("utf-8", errors="replace")
                else:
                    body = urllib.parse.urlencode({"input": value}).encode()
                if category in ("json", "ssti"):
                    extra_headers = {"Content-Type": "application/json"}
                elif category == "xml":
                    extra_headers = {"Content-Type": "application/xml"}
                else:
                    extra_headers = None
                resp = _safe_probe(base_target, method=method, body=body, headers=extra_headers, timeout=timeout, verify_tls=verify_tls)

            resp_body = resp.get("body", "")
            resp_status = resp["status"]
            resp_size = len(resp_body)

            # Check for reflected payload (XSS/injection indication)
            if value in resp_body and len(value) > 5 and resp_status == 200:
                findings.append(Finding(
                    title=f"Payload reflected: {label}",
                    severity="high", category="fuzzing_anomaly",
                    module="zero_day_hunter",
                    description=f"Payload for {category} was reflected in the response body without sanitization. This strongly suggests the endpoint is vulnerable to {category}.",
                    evidence=f"{method} {target_path} with payload -> {resp_status} ({resp_size} bytes) | Payload found in response body",
                    asset=host, points_deducted=10,
                    remediation=f"Implement proper input validation and output encoding for {category} payloads. Use parameterized queries for SQL, template auto-escaping for XSS/SSTI.",
                    dread_score=_dread_score("high"),
                ))
                continue

            # Check for SSTI arithmetic evaluation (e.g., {{7*7}} -> 49)
            if category == "ssti":
                if re.search(r"49", resp_body) and "{{7*7}}" not in resp_body:
                    findings.append(Finding(
                        title=f"SSTI confirmed: {label}",
                        severity="critical", category="fuzzing_anomaly",
                        module="zero_day_hunter",
                        description=f"Server-Side Template Injection confirmed — arithmetic expression {{7*7}} was evaluated to 49. This enables remote code execution.",
                        evidence=f"{method} {target_path} with SSTI payload -> {resp_status} | '49' found in response, original '{{7*7}}' not present",
                        asset=host, points_deducted=15,
                        remediation="Upgrade template engine, disable template rendering of user input, and use sandboxed template environments.",
                        dread_score=_dread_score("critical"),
                    ))
                elif re.search(r"49", resp_body) and "${7*7}" not in resp_body and "$" in value:
                    findings.append(Finding(
                        title=f"SSTI confirmed: {label}",
                        severity="critical", category="fuzzing_anomaly",
                        module="zero_day_hunter",
                        description=f"Server-Side Template Injection confirmed — ${7*7} was evaluated to 49. This enables remote code execution.",
                        evidence=f"{method} {target_path} -> {resp_status} | Arithmetic evaluation detected in response",
                        asset=host, points_deducted=15,
                        remediation="Disable template expression evaluation on user input. Use sandboxed rendering.",
                        dread_score=_dread_score("critical"),
                    ))

            # Check for database error triggered by fuzzing
            db_error_found = False
            for sig in ERROR_SIGNATURES.get("database_errors", []):
                if re.search(sig["pattern"], resp_body, re.IGNORECASE):
                    db_error_found = True
                    findings.append(Finding(
                        title=f"Fuzz-triggered DB error: {label}",
                        severity="critical", category="fuzzing_anomaly",
                        module="zero_day_hunter",
                        description=f"{label} triggered a database error ({sig['name']}): {sig['description']}. This confirms SQL injection surface.",
                        evidence=f"{method} {target_path} -> {resp_status} | DB error: {sig['name']} in response",
                        asset=host, points_deducted=15,
                        remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
                        dread_score=_dread_score("critical"),
                    ))
                    break
            if db_error_found:
                continue

            # Check for crash-like behavior (0 status, very slow, or 500)
            if resp_status == 0 or resp_status >= 500:
                if resp_status == 500 and baseline_status != 500:
                    findings.append(Finding(
                        title=f"Fuzz-triggered 500 error: {label}",
                        severity="high", category="fuzzing_anomaly",
                        module="zero_day_hunter",
                        description=f"{label} caused an internal server error (500) where baseline returned {baseline_status}. May indicate unhandled exception, memory corruption, or incomplete input validation.",
                        evidence=f"{method} {target_path} with {category} payload -> 500 | Baseline: {baseline_status}",
                        asset=host, points_deducted=10,
                        remediation="Implement robust error handling and input validation. 500 errors from crafted inputs suggest the application does not properly sanitize or validate input.",
                        dread_score=_dread_score("high"),
                    ))

            # Check for path traversal success indicators
            if category == "path_traversal":
                traversal_indicators = ["root:", "/bin/bash", "/bin/sh", "nobody:", "www-data:"]
                if any(ind in resp_body for ind in traversal_indicators):
                    findings.append(Finding(
                        title=f"Path traversal confirmed: {label}",
                        severity="critical", category="fuzzing_anomaly",
                        module="zero_day_hunter",
                        description=f"Path traversal payload successfully read file contents — file content markers detected in response. Arbitrary file read confirmed.",
                        evidence=f"{method} {target_path} -> {resp_status} | File content markers found in {resp_size} byte response",
                        asset=host, points_deducted=15,
                        remediation="Implement path canonicalization and whitelist allowed directories. Never pass user input directly to file system operations.",
                        dread_score=_dread_score("critical"),
                    ))

            # Check for CRLF injection success (injected header in response)
            if category == "crlf" and "X-Injected" in str(resp.get("headers", {})):
                findings.append(Finding(
                    title="CRLF injection confirmed: header injection",
                    severity="high", category="fuzzing_anomaly",
                    module="zero_day_hunter",
                    description="CRLF payload successfully injected a custom HTTP response header. This can lead to response splitting, XSS, and cache poisoning.",
                    evidence=f"{method} {target_path} -> {resp_status} | X-Injected header found in response",
                    asset=host, points_deducted=10,
                    remediation="Sanitize newlines and carriage returns from user input before including in HTTP responses.",
                    dread_score=_dread_score("high"),
                ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# CAPABILITY 6: HEADER ANOMALY DETECTION
# ════════════════════════════════════════════════════════════════════════

def _detect_header_anomalies(
    target: str, base_url: str, timeout: int, verify_tls: bool,
    probe_responses: List[Dict[str, Any]],
) -> List[Finding]:
    """Find headers revealing internal architecture, debug mode, or dev artifacts."""
    findings: List[Finding] = []
    host = _host_from_url(base_url)

    # Collect all unique headers across responses
    all_headers: Dict[str, List[str]] = {}
    for r in probe_responses:
        for key, value in r.get("headers", {}).items():
            if key not in all_headers:
                all_headers[key] = []
            all_headers[key].append(value)

    # Check for anomalous headers from HEADER_ANOMALY_PATTERNS
    for pattern_entry in HEADER_ANOMALY_PATTERNS:
        header_name = pattern_entry["header"]
        if header_name in all_headers:
            values = list(set(all_headers[header_name]))
            sev = pattern_entry["severity"]
            desc = pattern_entry["description"]
            indicates = ", ".join(pattern_entry["indicates"])
            findings.append(Finding(
                title=f"Anomalous header: {header_name}",
                severity=sev, category="header_anomaly",
                module="zero_day_hunter",
                description=f"Header '{header_name}' detected with value(s): {values}. {desc} Indicates: {indicates}.",
                evidence=f"Header: {header_name} | Values: {values} | Indicates: {indicates}",
                asset=host, points_deducted=_severity_points(sev),
                remediation=f"Remove or obfuscate the {header_name} header in production. Configure the server/framework to suppress technology-revealing headers.",
                dread_score=_dread_score(sev),
            ))

    # Check for missing security headers
    for sec_header in ANOMALY_THRESHOLDS["headers"]["missing_security_headers"]:
        if sec_header not in all_headers:
            findings.append(Finding(
                title=f"Missing security header: {sec_header}",
                severity="medium", category="header_anomaly",
                module="zero_day_hunter",
                description=f"Security header '{sec_header}' is missing from all responses. This increases risk of clickjacking, MIME sniffing, and other client-side attacks.",
                evidence=f"Header '{sec_header}' not found in any of {len(probe_responses)} responses",
                asset=host, points_deducted=5,
                remediation=f"Add the {sec_header} header to all responses. Configure the web server or application framework to include it by default.",
                dread_score=_dread_score("medium"),
            ))

    # Check for headers that reveal debug/dev mode
    debug_header_patterns = [
        (r"X-Debug", "Debug mode header detected"),
        (r"Debug", "Debug-related header present"),
        (r"X-Profiler", "Application profiler header exposed"),
        (r"X-Cake", "CakePHP debug header exposed"),
        (r"X-Laravel", "Laravel debug header exposed"),
        (r"X-RateLimit-Reset", "Rate limit header reveals API throttling config"),
        (r"X-Request-Id", "Request tracing ID reveals distributed architecture"),
    ]
    for pattern, desc in debug_header_patterns:
        for h in all_headers:
            if re.search(pattern, h, re.IGNORECASE):
                values = list(set(all_headers[h]))
                sev = "high" if "debug" in h.lower() or "profiler" in h.lower() else "low"
                findings.append(Finding(
                    title=f"Development artifact header: {h}",
                    severity=sev, category="header_anomaly",
                    module="zero_day_hunter",
                    description=f"{desc}. Value(s): {values}. Development headers in production reveal internal architecture and attack surface.",
                    evidence=f"Header: {h} | Values: {values}",
                    asset=host, points_deducted=_severity_points(sev),
                    remediation=f"Remove development/debug headers before deploying to production.",
                    dread_score=_dread_score(sev),
                ))

    # Check for inconsistent headers across identical requests
    root_responses = [r for r in probe_responses if r.get("path") == "/"]
    if len(root_responses) >= 2:
        h1_keys = set(root_responses[0].get("headers", {}).keys())
        h2_keys = set(root_responses[1].get("headers", {}).keys())
        if h1_keys != h2_keys:
            only_in_first = h1_keys - h2_keys
            only_in_second = h2_keys - h1_keys
            findings.append(Finding(
                title="Inconsistent headers across identical requests",
                severity="medium", category="header_anomaly",
                module="zero_day_hunter",
                description=f"Headers differ between identical requests to /. Only in request 1: {only_in_first}. Only in request 2: {only_in_second}. May indicate load-balanced heterogeneous backends.",
                evidence=f"Headers only in R1: {only_in_first} | Only in R2: {only_in_second}",
                asset=host, points_deducted=5,
                remediation="Ensure all backend servers are configured identically. Header inconsistency can reveal infrastructure topology.",
                dread_score=_dread_score("medium"),
            ))

    # Check for overly verbose Server header
    for h_name, h_values in all_headers.items():
        if h_name.lower() == "server":
            for v in h_values:
                if re.search(r"[\d]+\.[\d]+", v):
                    findings.append(Finding(
                        title=f"Version disclosure in Server header",
                        severity="medium", category="header_anomaly",
                        module="zero_day_hunter",
                        description=f"Server header reveals version information: '{v}'. Version disclosure enables targeted exploit selection from vulnerability databases.",
                        evidence=f"Server: {v}",
                        asset=host, points_deducted=5,
                        remediation="Configure the server to suppress version information in the Server header.",
                        dread_score=_dread_score("medium"),
                    ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# CAPABILITY 7: ENDPOINT SENSITIVITY MAPPING
# ════════════════════════════════════════════════════════════════════════

def _map_endpoint_sensitivity(
    target: str, base_url: str, timeout: int, verify_tls: bool,
) -> List[Finding]:
    """Test paths with/without authentication to find broken access control."""
    findings: List[Finding] = []
    host = _host_from_url(base_url)

    # Test each sensitivity path without authentication
    for entry in SENSITIVITY_PATHS:
        path = entry["path"]
        expected = entry["expected_without_auth"]
        sensitivity = entry["sensitivity"]
        label = entry["label"]

        url = base_url.rstrip("/") + path
        resp = _safe_probe(url, timeout=timeout, verify_tls=verify_tls)
        status = resp["status"]
        body = resp.get("body", "")
        body_len = len(body)

        if status == 0:
            continue

        # Check for broken access control: sensitive path accessible without auth
        if expected in (401, 403) and status == 200:
            findings.append(Finding(
                title=f"Broken access control: {label} ({path})",
                severity=sensitivity, category="access_control",
                module="zero_day_hunter",
                description=f"{label} at {path} returned HTTP 200 without authentication. Expected {expected}. This is a broken access control vulnerability — sensitive functionality is exposed to unauthenticated users.",
                evidence=f"GET {path} -> 200 ({body_len} bytes) | Expected: {expected} | Sensitivity: {sensitivity}",
                asset=host, points_deducted=_severity_points(sensitivity),
                remediation="Implement proper authentication and authorization checks on this endpoint. Deny access by default and require explicit authorization.",
                dread_score=_dread_score(sensitivity),
            ))
        elif expected in (401, 403) and status not in (401, 403, 0) and status < 500:
            # Unexpected non-auth status on protected path (e.g., 302 redirect without auth)
            if status in (301, 302, 303, 307, 308):
                location = resp.get("headers", {}).get("Location", "")
                findings.append(Finding(
                    title=f"Access control redirect: {label} ({path})",
                    severity="medium", category="access_control",
                    module="zero_day_hunter",
                    description=f"{label} at {path} returned {status} redirect to '{location}' instead of {expected}. Redirect-based access control may be bypassable by following redirects without authentication.",
                    evidence=f"GET {path} -> {status} Location: {location} | Expected: {expected}",
                    asset=host, points_deducted=5,
                    remediation="Use proper 401/403 status codes for unauthorized access instead of redirects. Validate authentication before redirecting.",
                    dread_score=_dread_score("medium"),
                ))
            else:
                findings.append(Finding(
                    title=f"Unexpected status on protected path: {label} ({path})",
                    severity="medium", category="access_control",
                    module="zero_day_hunter",
                    description=f"{label} at {path} returned {status} instead of expected {expected}. Protected endpoint returned unexpected status code.",
                    evidence=f"GET {path} -> {status} ({body_len} bytes) | Expected: {expected}",
                    asset=host, points_deducted=5,
                    remediation="Review access control configuration for this endpoint. Ensure consistent authorization behavior.",
                    dread_score=_dread_score("medium"),
                ))

        # Check for information disclosure on error pages from protected paths
        if status >= 400 and body_len > 500:
            for sig_category, signatures in ERROR_SIGNATURES.items():
                for sig in signatures:
                    if re.search(sig["pattern"], body, re.IGNORECASE | re.DOTALL):
                        findings.append(Finding(
                            title=f"Info disclosure on protected path: {label}",
                            severity=sig["severity"], category="access_control",
                            module="zero_day_hunter",
                            description=f"{label} at {path} returned error ({status}) with {sig['name']} disclosure. Error pages on protected endpoints should not reveal internal details.",
                            evidence=f"GET {path} -> {status} | {sig['name']}: {sig['description']}",
                            asset=host, points_deducted=_severity_points(sig["severity"]),
                            remediation="Implement generic error pages for protected endpoints that do not reveal internal implementation details.",
                            dread_score=_dread_score(sig["severity"]),
                        ))

    # Test HTTP method variations on sensitive paths
    method_test_paths = ["/admin", "/api/config", "/api/internal", "/api/users"]
    for path in method_test_paths:
        url = base_url.rstrip("/") + path
        for method in ["PUT", "DELETE", "PATCH", "OPTIONS"]:
            resp = _safe_probe(url, method=method, timeout=timeout, verify_tls=verify_tls)
            status = resp["status"]
            # If non-standard methods return 200 on protected paths, access control may be broken
            if status == 200 and method in ("PUT", "DELETE", "PATCH"):
                findings.append(Finding(
                    title=f"Method-based access control bypass: {method} {path}",
                    severity="critical", category="access_control",
                    module="zero_day_hunter",
                    description=f"{method} request to {path} returned HTTP 200 without authentication. Access control may only be applied to GET requests, allowing state-changing operations without authorization.",
                    evidence=f"{method} {path} -> 200 ({len(resp.get('body', ''))} bytes)",
                    asset=host, points_deducted=15,
                    remediation="Apply authentication and authorization to ALL HTTP methods, not just GET. Use framework-level middleware for consistent access control.",
                    dread_score=_dread_score("critical"),
                ))
            elif status == 200 and method == "OPTIONS":
                allow = resp.get("headers", {}).get("Allow", "")
                if allow:
                    findings.append(Finding(
                        title=f"OPTIONS method reveals allowed methods: {path}",
                        severity="low", category="access_control",
                        module="zero_day_hunter",
                        description=f"OPTIONS request to {path} reveals allowed methods: '{allow}'. This information helps an attacker target specific HTTP methods.",
                        evidence=f"OPTIONS {path} -> 200 | Allow: {allow}",
                        asset=host, points_deducted=3,
                        remediation="Restrict OPTIONS responses or remove the Allow header from unauthorized requests.",
                        dread_score=_dread_score("low"),
                    ))

    return findings


# ════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ════════════════════════════════════════════════════════════════════════

def run_zero_day_hunter(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Run all zero-day hunter analysis capabilities against a target.

    Performs seven-pass analysis:
      1. Response Anomaly Detection
      2. Error Message Analysis
      3. Version-Response Correlation
      4. Behavioral Anomaly Scoring
      5. Fuzzing Result Analysis
      6. Header Anomaly Detection
      7. Endpoint Sensitivity Mapping

    Args:
        target: Target hostname or IP address.
        base_url: Base URL for the target (e.g., https://example.com).
        timeout: HTTP request timeout in seconds (default: 8).
        verify_tls: Whether to verify TLS certificates (default: True).

    Returns:
        List of Finding objects documenting detected anomalies.
    """
    all_findings: List[Finding] = []

    # ── Pass 1: Response Anomaly Detection ──
    anomaly_findings, probe_responses = _detect_response_anomalies(
        target, base_url, timeout, verify_tls,
    )
    all_findings.extend(anomaly_findings)

    # ── Pass 2: Error Message Analysis ──
    error_findings = _analyze_error_messages(
        target, base_url, timeout, verify_tls,
    )
    all_findings.extend(error_findings)

    # ── Pass 3: Version-Response Correlation ──
    version_findings = _correlate_versions(
        target, base_url, timeout, verify_tls, probe_responses,
    )
    all_findings.extend(version_findings)

    # ── Pass 4: Behavioral Anomaly Scoring ──
    behavioral_findings = _score_behavioral_anomalies(
        target, base_url, timeout, verify_tls,
    )
    all_findings.extend(behavioral_findings)

    # ── Pass 5: Fuzzing Result Analysis ──
    fuzzing_findings = _analyze_fuzzing_results(
        target, base_url, timeout, verify_tls,
    )
    all_findings.extend(fuzzing_findings)

    # ── Pass 6: Header Anomaly Detection ──
    header_findings = _detect_header_anomalies(
        target, base_url, timeout, verify_tls, probe_responses,
    )
    all_findings.extend(header_findings)

    # ── Pass 7: Endpoint Sensitivity Mapping ──
    sensitivity_findings = _map_endpoint_sensitivity(
        target, base_url, timeout, verify_tls,
    )
    all_findings.extend(sensitivity_findings)

    return all_findings

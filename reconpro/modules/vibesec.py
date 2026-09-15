"""Module: VIBESEC — AI/Vibe-Coding Vulnerability Benchmark.

7 vulnerability categories checked:
  1. Exposed environment/config files
  2. Unauthenticated API/webhook routes
  3. CORS policy analysis
  4. Exposed anon/public backend keys (Supabase, Firebase, S3, etc.)
  5. Missing security headers
  6. Exposed database admin interfaces
  7. S3/R2/Cloud storage directory listings

Produces a 100-point score with A+–F grades and a GitHub badge.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List
from ..http_layer import http_probe, Finding


SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.development",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/docker-compose.yml", "/docker-compose.yaml",
    "/config.json", "/config.yaml", "/config.yml",
    "/package.json", "/.npmrc",
    "/vercel.json", "/netlify.toml",
    "/firebase.json", "/firestore.rules",
    "/.vscode/settings.json", "/.idea/workspace.xml",
    "/.aws/credentials", "/.aws/config",
    "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.ssh/authorized_keys",
    "/.github/workflows/secret", "/.gitlab-ci.yml",
    "/travis.yml", "/.circleci/config.yml",
]

API_PATHS = [
    "/api/webhooks", "/api/trpc", "/api/v1/admin", "/api/v1/users",
    "/api/v1/config", "/api/internal", "/api/debug",
    "/api/graphql", "/api/stripe/webhook", "/api/upload",
    "/admin", "/admin/login", "/dashboard",
]

ANON_KEY_PATTERNS: List[tuple[str, re.Pattern]] = [
    ("supabase", re.compile(r'[\w-]*\.supabase\.co', re.I)),
    ("firebase", re.compile(r'[\w-]*\.firebaseapp\.com', re.I)),
    ("aws-s3", re.compile(r's3\.amazonaws\.com|s3-\w+-\d+\.amazonaws\.com', re.I)),
    ("cloudflare-r2", re.compile(r'[\w-]+\.r2\.cloudflarestorage\.com', re.I)),
    ("vercel-blob", re.compile(r'blob\.vercel-storage\.com', re.I)),
    ("gcp-storage", re.compile(r'storage\.googleapis\.com', re.I)),
    ("azure-blob", re.compile(r'[\w]+\.blob\.core\.windows\.net', re.I)),
]

DB_ADMIN_PATHS = [
    "/phpmyadmin", "/phpmyadmin/", "/adminer", "/adminer.php",
    "/mongo-express", "/mongo-express/", "/_utils",
    "/pgadmin4", "/pgadmin/",
    "/redis-commander", "/redis-insight",
    "/prisma-studio", "/studio.apollo",
    "/graphql-playground", "/altair",
]

S3_LISTING_INDICATORS = [
    "ListBucketResult", "<Key>", "<Contents>", "Name</",
    "Prefix</", "<IsTruncated>",
]

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "high", 8),
    ("content-security-policy", "CSP", "medium", 6),
    ("x-content-type-options", "X-Content-Type-Options", "medium", 4),
    ("referrer-policy", "Referrer-Policy", "low", 3),
    ("permissions-policy", "Permissions-Policy", "low", 2),
]

STORAGE_PATHS = ["/uploads/", "/static/uploads/", "/media/", "/files/",
                "/public/", "/assets/", "/images/"]

AUTH_PATTERN = re.compile(
    r'(?i)(unauthorized|forbidden|401|403|login required|authentication required|"error":.*auth)'
)


def run_vibesec(target: str, base_url: str, timeout: int = 8,
                verify_tls: bool = True) -> tuple[List[Finding], int, str, str]:
    """Run VibeSec benchmark. Returns (findings, score, grade, badge_md)."""
    findings: List[Finding] = []
    deductions = 0
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    def add(title, severity, category, desc, evidence, pts):
        nonlocal deductions
        deductions += pts
        findings.append(Finding(
            title=title, severity=severity, category=category,
            module="vibesec", description=desc, evidence=evidence,
            asset=host, points_deducted=pts,
            remediation=f"Fix: Secure or remove {title.split('—')[0].strip()}",
        ))

    # Cat 1: Exposed config files
    for path in SENSITIVE_PATHS:
        resp = http_probe(base_url.rstrip("/") + path, timeout=timeout, verify_tls=verify_tls)
        status, body = resp.get("status", 0), resp.get("body", "")[:2048]
        if status == 200 and len(body) > 10:
            has_secrets = any(kw in body.lower() for kw in [
                "api_key", "secret", "password", "token", "database_url",
                "private_key", "supabase", "firebase", "aws_access",
            ])
            if has_secrets:
                add(f"Exposed config — {path}", "critical", "exposed_config",
                    f"Sensitive configuration with secrets: {path}",
                    f"GET {path} -> 200 (secrets detected)", 15)
            else:
                add(f"Exposed config — {path}", "high", "exposed_config",
                    f"Configuration endpoint accessible: {path}",
                    f"GET {path} -> 200", 10)

    # Cat 2: Unauthenticated API routes
    for path in API_PATHS:
        resp = http_probe(base_url.rstrip("/") + path, timeout=timeout, verify_tls=verify_tls)
        status, body = resp.get("status", 0), resp.get("body", "")[:2048]
        if status == 200:
            is_protected = any(kw in body.lower() for kw in [
                "unauthorized", "401", "forbidden", "authentication required",
            ])
            if not is_protected and len(body) > 20:
                add(f"Unauthenticated API — {path}", "high", "unauth_api",
                    f"API route accessible without auth: {path}",
                    f"GET {path} -> 200 (no auth)", 10)

    # Cat 3: CORS
    cors_resp = http_probe(base_url, timeout=timeout, verify_tls=verify_tls)
    acao = cors_resp.get("headers", {}).get("Access-Control-Allow-Origin", "")
    if acao == "*":
        add("Permissive CORS — wildcard origin", "high", "cors",
            "Access-Control-Allow-Origin: *", f"CORS: {acao}", 12)
    elif acao:
        reflect = http_probe(base_url, headers={"Origin": "https://evil-attacker.com"},
                              timeout=timeout, verify_tls=verify_tls)
        reflected = reflect.get("headers", {}).get("Access-Control-Allow-Origin", "")
        if "evil-attacker" in reflected:
            add("CORS origin reflection", "critical", "cors",
                "Server reflects any Origin header", f"Reflected: {reflected}", 15)

    # Cat 4: Exposed backend keys
    main_body = http_probe(base_url, timeout=timeout, verify_tls=verify_tls).get("body", "")[:16384]
    for name, pattern in ANON_KEY_PATTERNS:
        matches = pattern.findall(main_body)
        if matches:
            unique = list(set(matches))[:5]
            verified = []
            for m in unique:
                test_url = f"https://{m}" if not m.startswith("http") else m
                probe = http_probe(test_url, timeout=3, verify_tls=verify_tls)
                if probe.get("status", 0) > 0:
                    verified.append(m)
            if verified:
                add(f"Exposed {name} backend — {len(verified)} hit(s)", "critical",
                    "anon_keys", f"Public {name} URLs confirmed reachable",
                    f"{name}: {', '.join(verified[:3])}", 15)
            else:
                add(f"Detected {name} references", "medium", "anon_keys",
                    f"{name} URLs in source (unverified)",
                    f"{name}: {', '.join(unique[:3])}", 5)

    # Cat 5: Missing security headers
    root_h = cors_resp.get("headers", {})
    for hdr, display, sev, pts in SECURITY_HEADERS:
        if hdr.lower() not in {k.lower() for k in root_h}:
            add(f"Missing {display}", sev, "security_headers",
                f"{display} ({hdr}) not set", f"Header {hdr} absent", pts)

    # Cat 6: Exposed DB admin
    for path in DB_ADMIN_PATHS:
        resp = http_probe(base_url.rstrip("/") + path, timeout=timeout, verify_tls=verify_tls)
        status, body = resp.get("status", 0), resp.get("body", "")[:2048]
        if status == 200 and len(body) > 20:
            db_sigs = ["phpmyadmin", "adminer", "mongo", "redis", "pgadmin",
                       "prisma", "graphql", "apollo", "database", "mysql", "postgres"]
            is_db = any(s in body.lower() for s in db_sigs)
            is_protected = bool(AUTH_PATTERN.search(body))
            if is_db and not is_protected:
                add(f"Exposed DB admin — {path}", "critical", "exposed_db",
                    f"Database admin accessible without auth: {path}",
                    f"GET {path} -> 200 (no auth)", 15)

    # Cat 7: Storage directory listings
    for path in STORAGE_PATHS:
        resp = http_probe(base_url.rstrip("/") + path, timeout=timeout, verify_tls=verify_tls)
        status, body = resp.get("status", 0), resp.get("body", "")[:4096]
        if status == 200 and len(body) > 50:
            is_listing = any(ind in body for ind in S3_LISTING_INDICATORS)
            is_html = "Index of" in body or "Directory listing" in body
            if is_listing or is_html:
                add(f"Storage listing — {path}", "critical", "storage_exposure",
                    f"Directory listing enabled: {path}",
                    f"GET {path} -> 200 (listing)", 15)

    # Score
    score = max(0, min(100, 100 - deductions))
    if not findings:
        score = 100
    from ..http_layer import compute_grade, badge_markdown
    grade = compute_grade(score)
    badge_md = badge_markdown(host, grade)
    return findings, score, grade, badge_md

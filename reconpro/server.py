"""REST API server for ReconPro.

Run as a background service:
  reconpro serve [--port 7890]

Endpoints:
  GET  /                          Status
  POST /scan                     Start a remote scan (auth required when tokens active)
  POST /audit                    Start a local audit (auth required when tokens active)
  POST /blitz                    Multi-target parallel scan (auth required when tokens active)
  GET  /history                   List scan history
  GET  /history/<filename>        Get specific scan
  GET  /modules                   List modules
  POST /agent                    Run agent mode (auth required when tokens active)
  POST /report                   Generate HTML report from scan data
  GET  /report/<filename>        Serve generated reports
  GET  /subdomains/<domain>       Discover subdomains
  GET  /auth/status               Auth status (public)
  POST /auth/token                Generate API token (public)
  POST /auth/revoke               Revoke API token (auth required)
  GET  /auth/tokens               List tokens (auth required)
  GET  /passive/<domain>          Passive intel on domain
  GET  /cve/<cve_id>              CVE lookup
  POST /scan/vibesec              Run vibesec module (auth required)
  POST /export/csv                Export findings to CSV (auth required)
  POST /export/sarif              Export findings to SARIF (auth required)
  GET  /events                    SSE stream for scan progress
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sys
import threading
import time as _time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

from . import __version__
from .scanner import scan, audit_scan, MODULE_REGISTRY, LOCAL_MODULES, ALL_MODULES
from .parallel import blitz_scan
from .history import list_scans, get_scan
from .subdomains import discover_subdomains
from .reports import generate_html_report
from .agent import run_agent

REPORTS_DIR = os.path.join(os.path.expanduser("~/.reconpro"), "reports")

# ── Token-based authentication (HMAC-SHA256, stdlib only) ──────────────

_API_TOKENS: Dict[str, Dict[str, Any]] = {}  # {token: {created, expires, label}}
_API_TOKEN_SECRET = secrets.token_hex(32)


def generate_api_token(label: str = "default", hours: int = 24) -> str:
    """Generate a time-limited API token."""
    token = secrets.token_urlsafe(32)
    _API_TOKENS[token] = {
        "created": _time.time(),
        "expires": _time.time() + hours * 3600,
        "label": label,
    }
    return token


def validate_api_token(token: str) -> bool:
    """Validate an API token."""
    if not token or token not in _API_TOKENS:
        return False
    info = _API_TOKENS[token]
    if _time.time() > info["expires"]:
        del _API_TOKENS[token]
        return False
    return True


def revoke_api_token(token: str) -> bool:
    """Revoke an API token."""
    if token in _API_TOKENS:
        del _API_TOKENS[token]
        return True
    return False


def list_api_tokens() -> List[Dict[str, Any]]:
    """List active tokens (masked)."""
    result = []
    for t, info in _API_TOKENS.items():
        result.append({
            "token_preview": t[:8] + "...",
            "label": info["label"],
            "created": info["created"],
            "expires": info["expires"],
            "active": _time.time() < info["expires"],
        })
    return result

# Optional imports for new endpoints
try:
    from .passive_intel import PassiveDNS, WaybackMachine
    _HAS_PASSIVE_INTEL = True
except ImportError:
    _HAS_PASSIVE_INTEL = False

try:
    from .cve_radar import lookup_cve
    _HAS_CVE_RADAR = True
except ImportError:
    _HAS_CVE_RADAR = False


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logging

    def _json_response(self, code: int, data: Any) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    _MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB

    def _read_body(self) -> Dict:
        length = int(self.headers.get("Content-Length", 0))
        if length > self._MAX_BODY_SIZE:
            self._json_response(413, {"error": "request body too large"})
            return None  # type: ignore[return-value]
        if length:
            return json.loads(self.rfile.read(length))
        return {}

    def _check_auth(self) -> bool:
        """Check for Bearer token in Authorization header.
        C-03 FIX: Require authentication when tokens exist or env is set."""
        if not _API_TOKENS and not os.environ.get("RECONPRO_REQUIRE_AUTH"):
            return True  # Open mode only if no tokens AND no env flag
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
            return validate_api_token(token)
        return False

    def _unauthorized(self) -> None:
        self._json_response(401, {"error": "Unauthorized — valid Bearer token required"})

    def _forbidden(self) -> None:
        self._json_response(403, {"error": "Forbidden"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query)

        # Status
        if path == "" or path == "/":
            self._json_response(200, {
                "name": "ReconPro API",
                "version": __version__,
                "modules": len(ALL_MODULES),
                "auth_enabled": bool(_API_TOKENS),
                "endpoints": [
                    "POST /scan", "POST /audit", "POST /blitz",
                    "GET /history", "GET /modules",
                    "POST /agent", "GET /subdomains/<domain>",
                    "GET /auth/status", "POST /auth/token",
                    "POST /auth/revoke", "GET /auth/tokens",
                    "GET /passive/<domain>", "GET /cve/<cve_id>",
                    "POST /scan/vibesec",
                    "POST /export/csv", "POST /export/sarif",
                    "POST /intelligence",
                    "GET /events",
                ],
            })
            return

        # Modules
        if path == "/modules":
            mods = {}
            for k, v in MODULE_REGISTRY.items():
                mods[k] = v["name"]
            for k, v in LOCAL_MODULES.items():
                mods[k] = v["name"]
            self._json_response(200, {"modules": mods})
            return

        # History
        if path == "/history":
            target = qs.get("target", [None])[0]
            limit = int(qs.get("limit", ["20"])[0])
            scans = list_scans(target=target, limit=limit)
            self._json_response(200, {"scans": scans})
            return

        # History detail
        if path.startswith("/history/"):
            filename = path.split("/history/")[1]
            # C-02 FIX: Sanitize filename and prevent path traversal
            from .security import sanitize_filename
            safe_name = sanitize_filename(filename)
            data = get_scan(safe_name)
            if data:
                self._json_response(200, data)
            else:
                self._json_response(404, {"error": "Scan not found"})
            return

        # Subdomains
        if path.startswith("/subdomains/"):
            domain = path.split("/subdomains/")[1]
            subs = discover_subdomains(domain)
            self._json_response(200, {"domain": domain, "subdomains": subs, "count": len(subs)})
            return

        # Auth status (public)
        if path == "/auth/status":
            self._json_response(200, {
                "auth_enabled": bool(_API_TOKENS),
                "active_tokens": len(_API_TOKENS),
            })
            return

        # Auth tokens list (auth required)
        if path == "/auth/tokens":
            if not self._check_auth():
                return self._unauthorized()
            self._json_response(200, {"tokens": list_api_tokens()})
            return

        # Passive intel
        if path.startswith("/passive/"):
            domain = path.split("/passive/")[1]
            if not _HAS_PASSIVE_INTEL:
                return self._json_response(501, {"error": "passive_intel module not available"})
            try:
                dns_results = PassiveDNS.query(domain)
                wb_results = WaybackMachine.query(domain)
                self._json_response(200, {
                    "domain": domain,
                    "dns": dns_results,
                    "wayback": wb_results,
                })
            except Exception as e:
                self._json_response(500, {"error": str(e)})
            return

        # CVE lookup
        if path.startswith("/cve/"):
            cve_id = path.split("/cve/")[1].upper()
            if not cve_id.startswith("CVE-"):
                return self._json_response(400, {"error": "Invalid CVE ID format (expected CVE-YYYY-NNNN)"})
            if not _HAS_CVE_RADAR:
                return self._json_response(501, {"error": "cve_radar module not available"})
            try:
                result = lookup_cve(cve_id)
                self._json_response(200, result)
            except Exception as e:
                self._json_response(500, {"error": str(e)})
            return

        # SSE events stream
        if path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                counter = 0
                while True:
                    counter += 1
                    event = json.dumps({"type": "heartbeat", "counter": counter, "ts": _time.time()})
                    self.wfile.write(f"data: {event}\n\n".encode())
                    self.wfile.flush()
                    _time.sleep(15)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            return

        # Serve reports
        if path.startswith("/report/"):
            filename = path.split("/report/")[1]
            # C-01 FIX: Sanitize filename and prevent path traversal
            from .security import sanitize_filename
            safe_name = sanitize_filename(filename)
            fpath = os.path.realpath(os.path.join(REPORTS_DIR, safe_name))
            if not fpath.startswith(os.path.realpath(REPORTS_DIR)):
                return self._json_response(403, {"error": "Forbidden"})
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
            else:
                self._json_response(404, {"error": "Report not found"})
            return

        self._json_response(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        body = self._read_body()
        if body is None:
            return  # Response already sent by _read_body (413)

        try:
            if path == "/auth/token":
                # C-03 FIX: Require bootstrap secret for token generation
                bootstrap_secret = os.environ.get("RECONPRO_BOOTSTRAP_SECRET", "")
                if bootstrap_secret:
                    provided = body.get("bootstrap_secret", "")
                    if not secrets.compare_digest(provided, bootstrap_secret):
                        return self._json_response(403, {"error": "Invalid bootstrap secret"})
                label = body.get("label", "default")
                hours = int(body.get("hours", 24))
                if hours < 1 or hours > 8760:
                    return self._json_response(400, {"error": "hours must be between 1 and 8760"})
                token = generate_api_token(label=label, hours=hours)
                return self._json_response(201, {
                    "token": token,
                    "label": label,
                    "expires_in_hours": hours,
                    "message": "Use this token in the Authorization header as: Bearer <token>",
                })

            if path == "/auth/revoke":
                if not self._check_auth():
                    return self._unauthorized()
                token = body.get("token", "")
                if not token:
                    return self._json_response(400, {"error": "token required"})
                revoked = revoke_api_token(token)
                if revoked:
                    return self._json_response(200, {"revoked": True})
                return self._json_response(404, {"error": "Token not found"})

            if path == "/scan":
                if not self._check_auth():
                    return self._unauthorized()
                target = body.get("target")
                if not target:
                    return self._json_response(400, {"error": "target required"})
                result = scan(
                    target,
                    modules=body.get("modules"),
                    all_modules=body.get("all_modules", False),
                    timeout=body.get("timeout", 8),
                    verify_tls=body.get("verify_tls", True),
                    rate_limit=body.get("rate_limit", 10.0),
                )
                from .history import save_scan
                save_scan(result.to_dict())
                return self._json_response(200, result.to_dict())

            if path == "/audit":
                if not self._check_auth():
                    return self._unauthorized()
                result = audit_scan(
                    target=body.get("target", "."),
                    modules=body.get("modules"),
                )
                from .history import save_scan
                save_scan(result.to_dict())
                return self._json_response(200, result.to_dict())

            if path == "/blitz":
                if not self._check_auth():
                    return self._unauthorized()
                targets = body.get("targets", [])
                if not targets:
                    return self._json_response(400, {"error": "targets required"})
                result = blitz_scan(
                    targets,
                    max_workers=body.get("max_workers", 4),
                    modules=body.get("modules"),
                )
                return self._json_response(200, result)

            if path == "/agent":
                if not self._check_auth():
                    return self._unauthorized()
                goal = body.get("goal", "")
                if not goal:
                    return self._json_response(400, {"error": "goal required"})
                result = run_agent(goal, save=False)
                return self._json_response(200, result)

            if path == "/report":
                scan_data = body.get("scan_data")
                if not scan_data:
                    return self._json_response(400, {"error": "scan_data required"})
                os.makedirs(REPORTS_DIR, exist_ok=True)
                fpath = generate_html_report(scan_data, output_path=os.path.join(REPORTS_DIR, f"report_{int(os.times()[4]*1000)}.html"))
                return self._json_response(200, {"report_path": fpath, "url": f"/report/{os.path.basename(fpath)}"})

            if path == "/scan/vibesec":
                if not self._check_auth():
                    return self._unauthorized()
                target = body.get("target")
                if not target:
                    return self._json_response(400, {"error": "target required"})
                result = scan(
                    target,
                    modules=["vibesec"],
                    timeout=body.get("timeout", 10),
                    verify_tls=body.get("verify_tls", True),
                )
                from .history import save_scan as _save_scan
                _save_scan(result.to_dict())
                return self._json_response(200, result.to_dict())

            if path == "/export/csv":
                if not self._check_auth():
                    return self._unauthorized()
                scan_data = body.get("scan_data")
                if not scan_data:
                    return self._json_response(400, {"error": "scan_data required"})
                output = io.StringIO()
                writer = csv.writer(output)
                # Flatten findings
                findings = scan_data.get("findings", scan_data.get("results", []))
                if findings:
                    headers = list(findings[0].keys()) if isinstance(findings[0], dict) else ["finding"]
                    writer.writerow(headers)
                    for f in findings:
                        if isinstance(f, dict):
                            writer.writerow([str(f.get(h, "")) for h in headers])
                        else:
                            writer.writerow([str(f)])
                csv_body = output.getvalue()
                raw = csv_body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv")
                self.send_header("Content-Disposition", "attachment; filename=findings.csv")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(raw)
                return

            if path == "/intelligence":
                if not self._check_auth():
                    return self._unauthorized()
                findings = body.get("findings")
                if not isinstance(findings, list) or not findings:
                    return self._json_response(400, {"error": "findings (non-empty list) required"})
                scan_data = body.get("scan_data")
                if scan_data is not None and not isinstance(scan_data, dict):
                    return self._json_response(400, {"error": "scan_data must be an object or null"})
                try:
                    from .intelligence_pipeline import run_intelligence_pipeline
                    intel_result = run_intelligence_pipeline(findings, scan_data=scan_data)
                    return self._json_response(200, intel_result.to_dict())
                except Exception:
                    return self._json_response(500, {"error": "internal intelligence pipeline error"})

            if path == "/export/sarif":
                if not self._check_auth():
                    return self._unauthorized()
                scan_data = body.get("scan_data")
                if not scan_data:
                    return self._json_response(400, {"error": "scan_data required"})
                findings = scan_data.get("findings", scan_data.get("results", []))
                rules = []
                results = []
                seen_rules = set()
                for i, f in enumerate(findings):
                    if isinstance(f, dict):
                        rule_id = f.get("module", f.get("type", f.get("rule", f"rule-{i}")))
                        severity = f.get("severity", "warning")
                        msg = f.get("message", f.get("description", f.get("finding", str(f))))
                    else:
                        rule_id = f"rule-{i}"
                        severity = "warning"
                        msg = str(f)
                    if rule_id not in seen_rules:
                        seen_rules.add(rule_id)
                        rules.append({
                            "id": rule_id,
                            "shortDescription": {"text": rule_id},
                            "defaultConfiguration": {"level": severity},
                        })
                    results.append({
                        "ruleId": rule_id,
                        "level": severity,
                        "message": {"text": msg},
                    })
                sarif = {
                    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [{
                        "tool": {"driver": {"name": "ReconPro", "version": __version__, "rules": rules}},
                        "results": results,
                    }],
                }
                return self._json_response(200, sarif)

            self._json_response(404, {"error": "Not found"})
        except Exception as e:
            # H-06 FIX: Don't leak internal exception details
            self._json_response(500, {"error": "Internal server error", "request_id": secrets.token_hex(8)})

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()


def run_server(port: int = 7890) -> None:
    """Start the ReconPro API server."""
    server = HTTPServer(("0.0.0.0", port), _Handler)
    print(f"  [bright_green]ReconPro API v{__version__}[/] running on [cyan]http://localhost:{port}[/]")
    print(f"  [dim]Endpoints: POST /scan, /audit, /blitz, /agent | GET /history, /modules, /subdomains/<domain>[/]")
    print(f"  [dim]Auth: POST /auth/token, GET /auth/status | SSE: GET /events[/]")
    print(f"  [dim]Press Ctrl+C to stop[/]")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [yellow]Server stopped.[/]")
        server.server_close()

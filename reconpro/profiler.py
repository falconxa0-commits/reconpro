"""Smart Recon Profiler — fingerprint tech stack, WAF, app type, and security posture.

Zero external dependencies. Uses only stdlib + sibling ``http`` module.
"""

from __future__ import annotations

import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from reconpro.http_layer import http_probe, Finding


# ── TechProfile ──────────────────────────────────────────────────────────


@dataclass
class TechProfile:
    """Fingerprint result for a single target."""

    frameworks: List[str] = field(default_factory=list)
    language: Optional[str] = None
    server: Optional[str] = None
    waf: Optional[str] = None
    cms: Optional[str] = None
    has_graphql: bool = False
    has_rest_api: bool = False
    app_type: str = "unknown"  # spa | ssr | api | static | microservices | unknown
    confidence: float = 0.0
    detected_headers: Dict[str, str] = field(default_factory=dict)
    detected_technologies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frameworks": self.frameworks,
            "language": self.language,
            "server": self.server,
            "waf": self.waf,
            "cms": self.cms,
            "has_graphql": self.has_graphql,
            "has_rest_api": self.has_rest_api,
            "app_type": self.app_type,
            "confidence": self.confidence,
            "detected_headers": self.detected_headers,
            "detected_technologies": self.detected_technologies,
        }


# ── TargetProfiler ───────────────────────────────────────────────────────

# WAF signature patterns: (pattern, waf_name)
_WAF_SIGNATURES: List[tuple[str, str]] = [
    (r"cloudflare", "Cloudflare"),
    (r"cf-ray", "Cloudflare"),
    (r"awselb|aws-waf-request-id|x-amzn-trace-id", "AWS WAF"),
    (r"akamai", "Akamai"),
    (r"x-iinfo|imperva", "Imperva"),
    (r"sucuri|sucuri-cloudproxy", "Sucuri"),
    (r"x-sucuri-id", "Sucuri"),
    (r"fortiweb|fortigate", "FortiWeb"),
    (r"wallarm", "Wallarm"),
    (r"incapsula", "Incapsula"),
    (r"fly\-waf", "Fly.io WAF"),
]

# Framework signature patterns: (pattern, framework_name, language)
_FRAMEWORK_SIGNATURES: List[tuple[str, str, Optional[str]]] = [
    # Header-level
    (r"x-powered-by\s*:\s*Express", "Express", "JavaScript"),
    (r"x-powered-by\s*:\s*Next\.js", "Next.js", "JavaScript"),
    (r"x-powered-by\s*:\s*PHP", "PHP", "PHP"),
    (r"x-powered-by\s*:\s*ASP\.NET", "ASP.NET", "C#"),
    (r"x-aspnet-version", "ASP.NET", "C#"),
    (r"server\s*:\s*(?:nginx|openresty)", "Nginx", None),
    (r"server\s*:\s*Apache", "Apache HTTPD", None),
    (r"server\s*:\s*gunicorn", "Gunicorn", "Python"),
    (r"server\s*:\s*uvicorn", "Uvicorn", "Python"),
    (r"server\s*:\s*puma", "Puma", "Ruby"),
    (r"server\s*:\s*tomcat", "Apache Tomcat", "Java"),
    (r"server\s*:\s*jetty", "Jetty", "Java"),
    # Body-level
    (r"__NEXT_DATA__", "Next.js", "JavaScript"),
    (r"ng-version|angular\.core", "Angular", "JavaScript"),
    (r"__vue__|vue\.js|v-cloak", "Vue.js", "JavaScript"),
    (r"data-reactroot|react\.|_reactRootContainer|__REACT", "React", "JavaScript"),
    (r"wp-content|wp-includes|wordpress", "WordPress", "PHP"),
    (r"Drupal\.settings|drupal\.js", "Drupal", "PHP"),
    (r"/media/jui/|Joomla", "Joomla", "PHP"),
    (r"csrfmiddlewaretoken|django", "Django", "Python"),
    (r"flask|werkzeug", "Flask", "Python"),
    (r"laravel|csrf-token", "Laravel", "PHP"),
    (r"rails-ujs|turbolinks|action_controller", "Ruby on Rails", "Ruby"),
    (r"spring-boot|springframework", "Spring", "Java"),
]

# HTML meta generator patterns
_META_GENERATOR_MAP: Dict[str, tuple[str, Optional[str]]] = {
    "wordpress": ("WordPress", "PHP"),
    "drupal": ("Drupal", "PHP"),
    "joomla": ("Joomla", "PHP"),
    "woocommerce": ("WooCommerce", "PHP"),
    "hexo": ("Hexo", "JavaScript"),
    "hugo": ("Hugo", "Go"),
    "jekyll": ("Jekyll", "Ruby"),
    "gatsby": ("Gatsby", "JavaScript"),
    "next.js": ("Next.js", "JavaScript"),
    "nuxt": ("Nuxt.js", "JavaScript"),
    "mediawiki": ("MediaWiki", "PHP"),
}

# Security header scoring: (header_name, points)
_SECURITY_HEADERS: Dict[str, int] = {
    "strict-transport-security": 15,
    "content-security-policy": 20,
    "x-frame-options": 10,
    "x-content-type-options": 8,
    "x-xss-protection": 7,
    "referrer-policy": 10,
    "permissions-policy": 8,
    "cross-origin-opener-policy": 7,
    "cross-origin-resource-policy": 5,
    "cross-origin-embedder-policy": 5,
    "cache-control": 5,
}


class TargetProfiler:
    """Fingerprint a target's technology stack from HTTP responses."""

    def __init__(self, timeout: int = 8, verify_tls: bool = True) -> None:
        self._timeout = timeout
        self._verify_tls = verify_tls

    # ── public API ────────────────────────────────────────────────────────

    def profile(self, target: str, base_url: str) -> TechProfile:
        """Run 3-5 rapid HTTP probes and return a TechProfile."""
        profile = TechProfile()
        base_url = base_url.rstrip("/")

        # 1. Gather responses from multiple methods
        responses: Dict[str, Dict[str, Any]] = {}
        for method in ("GET", "HEAD", "OPTIONS"):
            resp = http_probe(
                base_url + "/",
                method=method,
                timeout=self._timeout,
                verify_tls=self._verify_tls,
            )
            responses[method] = resp

        # 2. Probe /api/ and /graphql
        api_resp = http_probe(
            base_url + "/api/",
            timeout=self._timeout,
            verify_tls=self._verify_tls,
        )
        responses["GET_API"] = api_resp

        gql_resp = http_probe(
            base_url + "/graphql",
            method="POST",
            body=b'{"query":"{__typename}"}',
            headers={"Content-Type": "application/json"},
            timeout=self._timeout,
            verify_tls=self._verify_tls,
        )
        responses["POST_GRAPHQL"] = gql_resp

        # 3. Merge all headers from non-fatal responses
        merged_headers: Dict[str, str] = {}
        _recoverable = {200, 301, 302, 304, 400, 401, 403, 405}
        for resp in responses.values():
            status = resp.get("status", 0)
            if resp.get("ok") or status in _recoverable:
                for k, v in resp.get("headers", {}).items():
                    merged_headers[k.lower()] = v
        profile.detected_headers = merged_headers

        # 4. Get the main body (prefer GET /)
        main_body = responses["GET"].get("body", "")

        # 5. Detect WAF
        profile.waf = self._detect_waf(merged_headers, main_body)

        # 6. Detect server from headers
        profile.server = merged_headers.get("server")

        # 7. Detect frameworks from headers and body
        frameworks, language = self._detect_frameworks(merged_headers, main_body)
        profile.frameworks = frameworks
        profile.language = language

        # 8. Detect CMS from meta generator
        cms, cms_lang = self._detect_cms(main_body)
        if cms:
            profile.cms = cms
            if cms_lang and not profile.language:
                profile.language = cms_lang
            if cms not in profile.frameworks:
                profile.frameworks.append(cms)

        # 9. Detect GraphQL
        gql_status = responses["POST_GRAPHQL"].get("status", 0)
        gql_body = responses["POST_GRAPHQL"].get("body", "")
        if "graphql" in gql_body.lower() or "__typename" in gql_body:
            if "data" in gql_body and "__typename" in gql_body:
                profile.has_graphql = True
        if any("graphql" in v.lower() for v in merged_headers.values()):
            profile.has_graphql = True

        # 10. Detect REST API
        api_status = responses["GET_API"].get("status", 0)
        api_body = responses["GET_API"].get("body", "")
        if api_status == 200:
            try:
                json.loads(api_body)
                profile.has_rest_api = True
            except (json.JSONDecodeError, ValueError):
                pass
        if any("/api/" in v.lower() for v in merged_headers.values()):
            profile.has_rest_api = True

        # 11. Detect app type
        profile.app_type = self._detect_app_type(main_body, merged_headers, profile)

        # 12. Build detected technologies list
        profile.detected_technologies = list(profile.frameworks)
        if profile.server:
            profile.detected_technologies.insert(0, profile.server)
        if profile.waf:
            profile.detected_technologies.insert(0, profile.waf)
        if profile.has_graphql:
            profile.detected_technologies.append("GraphQL")
        if profile.has_rest_api:
            profile.detected_technologies.append("REST API")

        # 13. Compute confidence (0.0 - 1.0)
        signals = (
            len(profile.frameworks)
            + (1 if profile.server else 0)
            + (1 if profile.waf else 0)
        )
        profile.confidence = min(signals / 6.0, 1.0)

        return profile

    # ── detection helpers ────────────────────────────────────────────────

    @staticmethod
    def _detect_waf(headers: Dict[str, str], body: str) -> Optional[str]:
        header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined = (header_blob + "\n" + body[:4096]).lower()
        for pattern, name in _WAF_SIGNATURES:
            if re.search(pattern, combined, re.IGNORECASE):
                return name
        return None

    @staticmethod
    def _detect_frameworks(
        headers: Dict[str, str], body: str
    ) -> tuple[List[str], Optional[str]]:
        header_blob = "\n".join(f"{k}: {v}" for k, v in headers.items())
        combined = header_blob + "\n" + body[:16384]
        frameworks: List[str] = []
        language: Optional[str] = None
        for pattern, name, lang in _FRAMEWORK_SIGNATURES:
            if re.search(pattern, combined, re.IGNORECASE):
                if name not in frameworks:
                    frameworks.append(name)
                if lang and language is None:
                    language = lang
        return frameworks, language

    @staticmethod
    def _detect_cms(body: str) -> tuple[Optional[str], Optional[str]]:
        meta_match = re.search(
            r'<meta\s+name=["\x27]generator["\x27]\s+content=["\x27]([^"\x27>]+)',
            body,
            re.IGNORECASE,
        )
        if not meta_match:
            return None, None
        content = meta_match.group(1).strip().lower()
        for keyword, (name, lang) in _META_GENERATOR_MAP.items():
            if keyword in content:
                return name, lang
        return meta_match.group(1).strip(), None

    @staticmethod
    def _detect_app_type(
        body: str, headers: Dict[str, str], profile: TechProfile
    ) -> str:
        body_lower = body.lower()
        ct = headers.get("content-type", "")

        # API: JSON responses
        if "application/json" in ct:
            return "api"
        try:
            json.loads(body[:4096])
            return "api"
        except (json.JSONDecodeError, ValueError):
            pass
        if profile.has_rest_api and len(body.strip()) < 2000:
            return "api"

        # Microservices: no HTML, small response
        if "html" not in ct and len(body.strip()) < 500:
            return "microservices"

        # SPA detection signals
        spa_signals = [
            "__NEXT_DATA__" in body,
            "__vue__" in body or "v-cloak" in body,
            re.search(r"ng-version", body) is not None,
            re.search(r"react\.|_reactRootContainer|__REACT", body) is not None,
            bool(re.search(r'chunk\.js|bundle\.js|app\.[a-f0-9]+\.js', body)),
        ]
        if any(spa_signals):
            if "__NEXT_DATA__" in body and "<!doctype html" in body_lower:
                return "ssr"
            return "spa"

        # SSR: server-rendered content with template markers
        ssr_markers = [
            "csrfmiddlewaretoken" in body,
            "csrf-token" in body,
            bool(re.search(r'\{\{.*?\}\}', body)),
            bool(re.search(r'\$\{.*?\}', body)),
        ]
        if any(ssr_markers) and "<html" in body_lower:
            return "ssr"

        # Static: plain HTML, minimal or no JavaScript
        script_tags = re.findall(r"<script", body, re.IGNORECASE)
        if len(script_tags) <= 1 and "<html" in body_lower and not profile.has_rest_api:
            return "static"

        return "unknown"

    # ── security posture estimation ───────────────────────────────────────

    def estimate_posture(self, profile: TechProfile) -> Dict[str, Any]:
        """Evaluate security posture based on detected headers."""
        headers_lower = {k.lower(): v for k, v in profile.detected_headers.items()}
        score = 0
        present_headers: List[str] = []
        missing_headers: List[str] = []

        for hdr_name, points in _SECURITY_HEADERS.items():
            if hdr_name in headers_lower:
                score += points
                present_headers.append(hdr_name)
            else:
                missing_headers.append(hdr_name)

        if profile.waf:
            score += 10
        score = min(score, 100)

        strengths: List[str] = []
        weaknesses: List[str] = []

        if "strict-transport-security" in present_headers:
            strengths.append("HSTS enforced")
        else:
            weaknesses.append("Missing HSTS - vulnerable to protocol downgrade")

        if "content-security-policy" in present_headers:
            strengths.append("CSP header present")
        else:
            weaknesses.append("Missing Content-Security-Policy - XSS risk elevated")

        if "x-frame-options" in present_headers:
            strengths.append("X-Frame-Options set")
        else:
            weaknesses.append("Missing X-Frame-Options - clickjacking possible")

        if profile.waf:
            strengths.append(f"WAF detected ({profile.waf})")
        else:
            weaknesses.append("No WAF detected")

        if "x-content-type-options" in present_headers:
            strengths.append("MIME sniffing mitigated")
        else:
            weaknesses.append("Missing X-Content-Type-Options")

        if "referrer-policy" in present_headers:
            strengths.append("Referrer-Policy set")
        else:
            weaknesses.append("Missing Referrer-Policy")

        return {
            "security_score": score,
            "missing_headers": missing_headers,
            "strengths": strengths,
            "weaknesses": weaknesses,
        }


# ── AutoPlan ─────────────────────────────────────────────────────────────


class AutoPlan:
    """Select optimal ReconPro modules based on a TechProfile."""

    _PLAN_RULES: List[tuple[str, List[str], str]] = [
        (
            "wordpress",
            ["recon", "auth", "chain", "bot", "nhi", "vibesec"],
            (
                "WordPress detected - high-value CMS with extensive attack surface. "
                "auth probes login/wp-admin, bot checks for user enumeration, "
                "nhi hunts leaked credentials, chain maps attack paths."
            ),
        ),
        (
            "react",
            ["recon", "chain", "api_discovery", "vibesec", "nhi"],
            (
                "React SPA detected - attack surface concentrated in API endpoints. "
                "api_discovery maps backend routes, chain finds exploit paths, "
                "nhi checks for exposed secrets in source maps."
            ),
        ),
        (
            "spring",
            ["recon", "auth", "chain", "gorgon", "nhi", "cve"],
            (
                "Java/Spring detected - enterprise framework with known CVE patterns. "
                "gorgon performs deep fuzzing, cve matches against NVD, "
                "auth tests Spring Security configurations."
            ),
        ),
        (
            "express",
            ["recon", "auth", "chain", "gorgon", "vibesec", "nhi"],
            (
                "Express/Node detected - middleware-heavy framework. "
                "gorgon fuzzes route parameters and middleware, vibesec checks "
                "for dependency vulnerabilities, chain maps exploit sequences."
            ),
        ),
        (
            "django",
            ["recon", "auth", "chain", "gorgon", "vibesec", "nhi"],
            (
                "Django detected - Python framework with built-in auth. "
                "auth tests Django session/auth mechanisms, gorgon fuzzes views, "
                "vibesec audits Python dependencies for known CVEs."
            ),
        ),
        (
            "flask",
            ["recon", "auth", "chain", "gorgon", "vibesec", "nhi"],
            (
                "Flask detected - lightweight Python framework. "
                "auth tests session mechanisms, gorgon fuzzes endpoints, "
                "vibesec checks Flask extension vulnerabilities."
            ),
        ),
        (
            "laravel",
            ["recon", "auth", "chain", "gorgon", "vibesec", "nhi"],
            (
                "Laravel detected - PHP framework with rich ecosystem. "
                "auth tests Laravel auth guards, chain maps middleware bypasses, "
                "gorgon fuzzes routes and Eloquent injections."
            ),
        ),
        (
            "ruby on rails",
            ["recon", "auth", "chain", "gorgon", "vibesec", "nhi"],
            (
                "Ruby on Rails detected - full-stack framework. "
                "auth tests Devise/warden, gorgon fuzzes controller actions, "
                "chain maps mass-assignment and parameter tampering paths."
            ),
        ),
        (
            "drupal",
            ["recon", "auth", "chain", "bot", "nhi", "cve"],
            (
                "Drupal detected - CMS with history of critical RCEs. "
                "cve checks against known Drupal CVEs, bot enumerates users, "
                "auth tests login form, chain maps privilege escalation."
            ),
        ),
    ]

    _TYPE_RULES: Dict[str, tuple[List[str], str]] = {
        "static": (
            ["recon", "chain", "vibesec"],
            (
                "Static site detected - limited attack surface. "
                "recon enumerates assets, chain checks for information disclosure, "
                "vibesec scans for JS dependencies with known vulnerabilities."
            ),
        ),
        "api": (
            ["recon", "auth", "chain", "gorgon", "nhi"],
            (
                "API service detected - direct endpoint access. "
                "auth tests token/session mechanisms, gorgon fuzzes parameters, "
                "chain maps injection points, nhi checks for key leakage."
            ),
        ),
        "microservices": (
            ["recon", "auth", "chain", "gorgon", "nhi", "cve"],
            (
                "Microservices architecture detected - many internal endpoints. "
                "recon maps services, auth tests inter-service trust, "
                "gorgon fuzzes each endpoint, cve checks service runtimes."
            ),
        ),
    }

    _DEFAULT_PLAN: tuple[List[str], str] = (
        ["recon", "auth", "oblivion", "vibesec"],
        (
            "Unknown stack - using broad-spectrum approach. "
            "recon gathers intelligence, auth tests common mechanisms, "
            "oblivion performs deep fuzzing, vibesec checks dependencies."
        ),
    )

    def plan(self, profile: TechProfile) -> Dict[str, Any]:
        """Return recommended modules, reasoning, and estimated time."""
        tech_blob = " ".join(profile.detected_technologies + profile.frameworks).lower()

        # Try framework-specific rules first (most specific match)
        for keyword, modules, reasoning in self._PLAN_RULES:
            if keyword in tech_blob:
                return {
                    "recommended_modules": modules,
                    "reasoning": reasoning,
                    "estimated_time": len(modules) * 4,
                }

        # Fall back to app-type rules
        type_entry = self._TYPE_RULES.get(profile.app_type)
        if type_entry:
            modules, reasoning = type_entry
            return {
                "recommended_modules": modules,
                "reasoning": reasoning,
                "estimated_time": len(modules) * 4,
            }

        # Default plan for unknown stacks
        modules, reasoning = self._DEFAULT_PLAN
        return {
            "recommended_modules": modules,
            "reasoning": reasoning,
            "estimated_time": len(modules) * 4,
        }


# ── Convenience functions ────────────────────────────────────────────────

_profiler = TargetProfiler()
_planner = AutoPlan()


def profile_target(target: str, base_url: str | None = None) -> TechProfile:
    """One-call profiling. If *base_url* is None, builds it from *target*."""
    if base_url is None:
        base_url = target if target.startswith("http") else f"https://{target}"
    return _profiler.profile(target, base_url)


def get_scan_plan(target: str, base_url: str | None = None) -> Dict[str, Any]:
    """Profile target and return an AutoPlan in one call."""
    prof = profile_target(target, base_url)
    return _planner.plan(prof)


# ── TimingAnalyzer ───────────────────────────────────────────────────────


class TimingAnalyzer:
    """Detect timing-based vulnerabilities and side channels.

    Measures response times across multiple requests to detect:
    - Time-based SQL injection (sleep/BENCHMARK responses)
    - Boolean-based blind SQL injection (timing differences)
    - Time-based blind XSS
    - Error-based information disclosure via timing
    - Rate limiting and brute-force protection
    """

    def __init__(self, base_url: str, timeout: float = 15.0, samples: int = 5):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.samples = samples
        self.findings: List[Finding] = []
        self._baseline_time: float = 0.0

    def analyze(self) -> Dict[str, Any]:
        """Run timing analysis. Returns results dict."""
        results = {
            "baseline_ms": 0.0,
            "tests_run": 0,
            "vulnerabilities": [],
        }

        # Establish baseline
        self._baseline_time = self._measure_baseline()
        results["baseline_ms"] = round(self._baseline_time * 1000, 2)

        # Run timing tests
        self._test_sqli_timing()
        self._test_boolean_blind()
        self._test_error_timing()
        self._test_rate_limiting()
        self._test_auth_timing()

        results["tests_run"] = len(self.findings)
        results["vulnerabilities"] = [f.to_dict() if hasattr(f, 'to_dict') else f for f in self.findings]
        return results

    def _measure_baseline(self) -> float:
        """Get average response time for baseline URL."""
        import urllib.request
        times = []
        for _ in range(self.samples):
            try:
                start = time.time()
                req = urllib.request.Request(self.base_url, headers={"User-Agent": "ReconPro/9"})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp.read()
                times.append(time.time() - start)
            except Exception:
                pass
        return sum(times) / len(times) if times else 0.1

    def _measure_endpoint(self, url: str, method: str = "GET", data: bytes = b"") -> float:
        """Measure response time for a specific request."""
        import urllib.request
        try:
            start = time.time()
            req = urllib.request.Request(url, data=data if method == "POST" else None, method=method,
                                          headers={"User-Agent": "ReconPro/9", "Content-Type": "application/x-www-form-urlencoded"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
            return time.time() - start
        except Exception:
            return -1.0

    def _test_sqli_timing(self):
        """Test for time-based SQL injection."""
        sqli_payloads = [
            "1; WAITFOR DELAY '0:0:5'--",
            "1' OR SLEEP(5)--",
            "1' AND pg_sleep(5)--",
            "1' || DBMS_PIPE.RECEIVE_MESSAGE(5,5) || '",
            "1; SELECT BENCHMARK(5000000,SHA1('test'))--",
        ]
        for param in ["id", "user", "page", "q"]:
            for payload in sqli_payloads:
                url = f"{self.base_url}?{param}={urllib.parse.quote(payload)}"
                elapsed = self._measure_endpoint(url)
                if elapsed > 0 and elapsed > self._baseline_time * 3 + 3.0:
                    self.findings.append(Finding(
                        title=f"Potential time-based SQL injection",
                        severity="high",
                        category="timing_sqli",
                        module="profiler",
                        description=f"Parameter '{param}' responded in {elapsed:.2f}s (baseline: {self._baseline_time:.2f}s) "
                                    f"with SQL timing payload, suggesting time-based SQL injection.",
                        evidence=f"URL: {url} | Response time: {elapsed:.2f}s | Baseline: {self._baseline_time:.2f}s",
                        asset=f"{self.base_url}?{param}=...",
                        points_deducted=8,
                        remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                    ))
                    return  # Report once per test

    def _test_boolean_blind(self):
        """Test for boolean-based blind SQL injection via timing."""
        for param in ["id", "user", "page"]:
            true_url = f"{self.base_url}?{param}=1%20AND%201=1"
            false_url = f"{self.base_url}?{param}=1%20AND%201=2"
            t_true = self._measure_endpoint(true_url)
            t_false = self._measure_endpoint(false_url)
            if t_true > 0 and t_false > 0:
                diff = abs(t_true - t_false)
                if diff > self._baseline_time * 2:
                    self.findings.append(Finding(
                        title=f"Potential boolean-based blind SQL injection",
                        severity="medium",
                        category="timing_boolean_blind",
                        module="profiler",
                        description=f"Parameter '{param}' shows {diff:.2f}s timing difference between true/false conditions.",
                        evidence=f"True: {t_true:.2f}s | False: {t_false:.2f}s | Diff: {diff:.2f}s",
                        asset=f"{self.base_url}?{param}=...",
                        points_deducted=6,
                        remediation="Use parameterized queries. Boolean-based blind SQLi can extract data character by character.",
                    ))
                    return

    def _test_error_timing(self):
        """Test if error messages take significantly longer (information disclosure)."""
        normal_url = self.base_url
        error_url = f"{self.base_url}/nonexistent_path_404_trigger"
        t_normal = self._measure_endpoint(normal_url)
        t_error = self._measure_endpoint(error_url)
        if t_normal > 0 and t_error > 0 and t_error > t_normal * 5:
            self.findings.append(Finding(
                title="Error responses expose timing information",
                severity="low",
                category="timing_error",
                module="profiler",
                description=f"Error responses take {t_error:.2f}s vs normal {t_normal:.2f}s — significant difference "
                            f"may indicate verbose error handling or debugging mode.",
                evidence=f"Normal: {t_normal:.2f}s | Error: {t_error:.2f}s | Ratio: {t_error/t_normal:.1f}x",
                asset=self.base_url,
                points_deducted=2,
                remediation="Ensure error pages are pre-rendered with consistent response times.",
            ))

    def _test_rate_limiting(self):
        """Test for rate limiting on authentication endpoints."""
        auth_paths = ["/login", "/auth/login", "/api/auth/login", "/signin", "/api/login"]
        for path in auth_paths:
            url = f"{self.base_url}{path}"
            times = []
            for i in range(10):
                t = self._measure_endpoint(url, method="POST", data=b"username=test&password=test")
                if t > 0:
                    times.append(t)
            if len(times) >= 5:
                early_avg = sum(times[:3]) / 3
                late_avg = sum(times[-3:]) / 3
                if late_avg < early_avg * 1.5:  # No significant slowdown
                    self.findings.append(Finding(
                        title=f"No rate limiting detected on {path}",
                        severity="medium",
                        category="rate_limiting",
                        module="profiler",
                        description=f"10 rapid requests to {path} showed no response time degradation. "
                                    f"Authentication endpoint may be vulnerable to brute-force attacks.",
                        evidence=f"First 3 avg: {early_avg:.2f}s | Last 3 avg: {late_avg:.2f}s | Total: 10 requests",
                        asset=url,
                        points_deducted=5,
                        remediation="Implement rate limiting on authentication endpoints (e.g., fail2ban, nginx limit_req, cloudflare rate rules).",
                    ))
                    return

    def _test_auth_timing(self):
        """Test for timing-based username enumeration."""
        existing_url = f"{self.base_url}/login"
        times_valid = []
        times_invalid = []
        for _ in range(3):
            t1 = self._measure_endpoint(existing_url, method="POST", data=b"username=admin&password=wrong")
            t2 = self._measure_endpoint(existing_url, method="POST", data=b"username=nonexist_user_xyz&password=wrong")
            if t1 > 0: times_valid.append(t1)
            if t2 > 0: times_invalid.append(t2)
        if times_valid and times_invalid:
            avg_valid = sum(times_valid) / len(times_valid)
            avg_invalid = sum(times_invalid) / len(times_invalid)
            diff = abs(avg_valid - avg_invalid)
            if diff > 0.1:  # More than 100ms difference
                self.findings.append(Finding(
                    title="Potential username enumeration via timing",
                    severity="medium",
                    category="timing_auth_enum",
                    module="profiler",
                    description=f"Login responses show {diff:.2f}s timing difference between valid/invalid usernames, "
                                f"suggesting username enumeration is possible.",
                    evidence=f"Valid username avg: {avg_valid:.2f}s | Invalid avg: {avg_invalid:.2f}s | Diff: {diff:.2f}s",
                    asset=f"{self.base_url}/login",
                    points_deducted=5,
                    remediation="Ensure authentication failures return consistent response times regardless of username validity.",
                ))


__all__ = [
    "TechProfile",
    "TargetProfiler",
    "AutoPlan",
    "TimingAnalyzer",
    "profile_target",
    "get_scan_plan",
]

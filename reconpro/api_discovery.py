"""Module: API Discovery — Dynamic API Blueprint Reconstruction for ReconPro v8.0.

Discovers hidden/undocumented APIs by analyzing JavaScript bundles,
GraphQL introspection, OpenAPI specs, link crawling, and auth matrix testing.

Classes:
    JsEndpointExtractor  — regex-based API extraction from JS sources
    GraphQLIntrospector  — probe & introspect GraphQL endpoints
    OpenAPISpecParser   — fetch and parse Swagger/OpenAPI specs
    LinkCrawler         — BFS link discovery with form action extraction
    AuthMatrix          — multi-state auth testing on discovered endpoints
    GrpcIntrospector    — detect and probe gRPC / Twirp / gRPC-Web endpoints

Functions:
    discover_api(target, base_url) -> tuple[list[Finding], int, str, str]
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlunparse

from .http_layer import Finding, http_probe, default_limiter
from .utils import compute_grade, badge_markdown


# ── JS Endpoint Extractor ────────────────────────────────────────────────


class JsEndpointExtractor:
    """Extract API endpoint URLs from JavaScript source code using regex.

    Supports REST paths, fetch/axios calls, jQuery AJAX, XMLHttpRequest,
    ES module imports, and template-literal interpolations.
    """

    # Ordered list of (name, pattern, default_method, confidence, group_idx)
    # group_idx points to the capturing group that contains the URL string.
    _PATTERNS: List[Tuple[str, re.Pattern, str, float, int]] = []

    def __init__(self) -> None:
        if not JsEndpointExtractor._PATTERNS:
            JsEndpointExtractor._PATTERNS = [
                # REST-style versioned paths: /api/v1/users
                ("rest_versioned", re.compile(
                    r'(?i)(?:\"|\'|`)(/(?:api|rest)/v\d+/[\w/\-\.\{\}]+?)(?:\"|\'|`)',
                ), "GET", 0.95, 1),

                # /v1/ or /v2/ versioned paths
                ("versioned_path", re.compile(
                    r'(?i)(?:\"|\'|`)(/v\d+/[\w/\-\.\{\}]+?)(?:\"|\'|`)',
                ), "GET", 0.80, 1),

                # fetch("https://...") or fetch('https://...')
                ("fetch_call", re.compile(
                    r'(?i)fetch\s*\(\s*(?:\"|\'|`)(https?://[^"\'`\s]+?)(?:\"|\'|`)',
                ), "GET", 0.95, 1),

                # fetch() with method option: fetch(url, { method: 'POST' })
                ("fetch_with_method", re.compile(
                    r'(?i)fetch\s*\(\s*(?:\"|\'|`)(https?://[^"\'`\s]+?)(?:\"|\'|`)'
                    r'[^}]*?method\s*:\s*(?:\"|\'|`)(GET|POST|PUT|DELETE|PATCH)',
                    re.S,
                ), "GET", 0.95, 1),

                # axios.get/post/put/delete/patch("url")
                ("axios_method", re.compile(
                    r'(?i)axios\.(get|post|put|delete|patch)\s*\('
                    r'\s*(?:\"|\'|`)(https?://[^"\'`]+?)(?:\"|\'|`)',
                ), "GET", 0.95, 2),

                # axios({ method, url })
                ("axios_config", re.compile(
                    r'(?i)axios\s*\(\s*\{[^}]*?url\s*:\s*(?:\"|\'|`)(https?://[^"\'`]+?)(?:\"|\'|`)'
                    r'[^}]*?method\s*:\s*(?:\"|\'|`)(GET|POST|PUT|DELETE|PATCH)',
                    re.S,
                ), "GET", 0.90, 1),

                # $.ajax({ url: ... })
                ("jquery_ajax", re.compile(
                    r'(?i)\$\.ajax\s*\(\s*\{[^}]*?url\s*:\s*(?:\"|\'|`)(https?://[^"\'`]+?)(?:\"|\'|`)'
                    r'[^}]*?(?:type|method)\s*:\s*(?:\"|\'|`)(GET|POST|PUT|DELETE|PATCH)',
                    re.S,
                ), "GET", 0.90, 1),

                # $.get("url"), $.post("url")
                ("jquery_short", re.compile(
                    r'(?i)\$\.(get|post)\s*\(\s*(?:\"|\'|`)(https?://[^"\'`]+?)(?:\"|\'|`)',
                ), "GET", 0.95, 2),

                # xhttp.open("METHOD", "url")
                ("xmlhttp_open", re.compile(
                    r'(?i)xhttp\.open\s*\(\s*(?:\"|\'|`)(GET|POST|PUT|DELETE|PATCH)(?:\"|\'|`)'
                    r'\s*,\s*(?:\"|\'|`)(https?://[^"\'`]+?)(?:\"|\'|`)',
                ), "GET", 0.95, 2),

                # new XMLHttpRequest() followed by .open
                ("xmlhttp_new", re.compile(
                    r'(?i)new\s+XMLHttpRequest[^;]*?\.open\s*\(\s*(?:\"|\'|`)'
                    r'(GET|POST|PUT|DELETE|PATCH)(?:\"|\'|`)'
                    r'\s*,\s*(?:\"|\'|`)(https?://[^"\'`]+?)(?:\"|\'|`)',
                    re.S,
                ), "GET", 0.90, 2),

                # import ... from '.../api/...'
                ("es_import", re.compile(
                    r'(?i)import\s+.*?from\s+(?:\"|\'|`)'
                    r'(https?://[^"\'`]*?/api/[^"\'`]*?)(?:\"|\'|`)',
                ), "GET", 0.75, 1),

                                # Template literal: `/api/${...}` or `https://host/api/${...}`
                ("template_literal", re.compile(
                    r'(?i)(?:\"|\'|`)(/api/[\w/\-\.{}]*\${[\w.]+}[\w/\-\.{}]*)(?:\"|\'|`)?',
                ), "GET", 0.70, 1),

                # Relative REST paths in string literals (no scheme)
                ("relative_rest", re.compile(
                    r'(?i)(?:\"|\'|`)(/api/[\w/\-\.\{\}]+?)(?:\"|\'|`)'
                    r'(?=[^\w/\-]|$)',
                ), "GET", 0.65, 1),
            ]

    def extract_from_url(self, url: str) -> List[Dict[str, Any]]:
        """Fetch a JS file and extract API URLs from it.

        Parameters
        ----------
        url : str
            Full URL to a JavaScript file.

        Returns
        -------
        list[dict]
            Each dict has keys: url, method, source_pattern, confidence.
        """
        resp = http_probe(url)
        if not resp.get("ok") or resp.get("status", 0) != 200:
            return []
        body = resp.get("body", "")
        if len(body) < 20:
            return []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return self.extract_from_content(body, base_url=base)

    def extract_from_content(
        self, js_content: str, base_url: str = ""
    ) -> List[Dict[str, Any]]:
        """Extract API URLs from raw JavaScript content.

        Parameters
        ----------
        js_content : str
            Raw JavaScript source text.
        base_url : str
            Origin (scheme + host) used to resolve relative paths.

        Returns
        -------
        list[dict]
            Each dict: {url, method, source_pattern, confidence}.
        """
        results: List[Dict[str, Any]] = []
        seen: set = set()

        for name, pattern, default_method, confidence, url_group in self._PATTERNS:
            for m in pattern.finditer(js_content):
                raw_url = m.group(url_group).strip()
                # Determine actual method
                method = default_method
                if url_group == 2:
                    # Pattern has method in group 1, url in group 2
                    method = m.group(1).upper()
                elif "fetch_with_method" in name and len(m.groups()) >= 2:
                    method = m.group(2).upper()
                elif "axios_config" in name and len(m.groups()) >= 2:
                    method = m.group(2).upper()
                elif "jquery_ajax" in name and len(m.groups()) >= 2:
                    method = m.group(2).upper()

                # Resolve relative URLs against base_url
                if raw_url.startswith("/") and base_url:
                    full_url = urljoin(base_url, raw_url)
                else:
                    full_url = raw_url

                # Skip non-HTTP, data URIs, and obvious non-endpoints
                if not full_url.startswith(("http://", "https://")):
                    continue
                if ".css" in full_url.rsplit("?", 1)[0] or ".png" in full_url.rsplit("?", 1)[0]:
                    continue

                # Deduplicate by (url, method)
                key = (full_url, method)
                if key in seen:
                    continue
                seen.add(key)

                results.append({
                    "url": full_url,
                    "method": method,
                    "source_pattern": name,
                    "confidence": confidence,
                })

        # Sort by confidence descending
        results.sort(key=lambda r: r["confidence"], reverse=True)
        return results


# ── GraphQL Introspector ─────────────────────────────────────────────────


class GraphQLIntrospector:
    """Probe and introspect GraphQL endpoints to enumerate schema.

    Tries common GraphQL paths, runs the introspection query, and
    extracts query/mutation/type definitions.
    """

    _INTROSPECTION_QUERY = json.dumps({
        "query": """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    name
                    kind
                    fields {
                        name
                        args { name type { name kind ofType { name } } }
                    }
                    inputFields { name type { name kind ofType { name } } }
                }
            }
        }
        """
    }).encode("utf-8")

    # Candidate paths to check for GraphQL
    _PROBE_PATHS = [
        "/graphql",
        "/api/graphql",
        "/graphql/v1",
        "/gql",
        "/api/gql",
        "/query",
    ]

    def probe(self, base_url: str) -> Optional[Dict[str, Any]]:
        """Check if a GraphQL endpoint exists at common paths.

        Parameters
        ----------
        base_url : str
            Target base URL (e.g. ``https://example.com``).

        Returns
        -------
        dict | None
            ``{"endpoint": url}`` if a GraphQL endpoint was found, else ``None``.
        """
        origin = base_url.rstrip("/")

        for path in self._PROBE_PATHS:
            url = origin + path
            # Try POST first (most GraphQL servers accept POST)
            resp = http_probe(
                url,
                method="POST",
                body=self._INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"},
            )
            if resp.get("status") == 200:
                body = resp.get("body", "")
                if "__schema" in body or "__type" in body:
                    return {"endpoint": url}
            # Try GET with query param
            get_url = url + "?query=%7B__schema%7BqueryType%7Bname%7D%7D%7D"
            resp2 = http_probe(get_url)
            if resp2.get("status") == 200:
                body2 = resp2.get("body", "")
                if "__schema" in body2 or "__type" in body2:
                    return {"endpoint": url}

            # Also check if the path responds at all (even without introspection)
            resp3 = http_probe(url, method="POST", body=b'{"query":"{__typename}"}',
                                headers={"Content-Type": "application/json"})
            if resp3.get("status") == 200:
                body3 = resp3.get("body", "")
                if "__typename" in body3:
                    return {"endpoint": url}

        return None

    def introspect(self, url: str) -> Dict[str, Any]:
        """Run the full introspection query against a GraphQL endpoint.

        Parameters
        ----------
        url : str
            Full URL of the GraphQL endpoint.

        Returns
        -------
        dict
            ``{endpoint, queries, mutations, types}``.
        """
        result: Dict[str, Any] = {
            "endpoint": url,
            "queries": [],
            "mutations": [],
            "types": [],
        }

        # Try POST introspection
        resp = http_probe(
            url,
            method="POST",
            body=self._INTROSPECTION_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if not resp.get("ok") and resp.get("status", 0) != 200:
            # Try GET
            encoded = ("{__schema{queryType{name}mutationType{name}types{name kind "
                        "fields{name args{name type{name kind ofType{name}}}}}}}")
            get_url = url + "?query=" + encoded.replace(" ", "")
            resp = http_probe(get_url)

        body = resp.get("body", "")
        if not body:
            return result

        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return result

        # Navigate the response envelope
        schema_data = data.get("data", {}).get("__schema")
        if not schema_data:
            # Maybe errors
            if data.get("errors"):
                result["error"] = str(data["errors"])[:500]
            return result

        # Extract query type name
        query_type_name = None
        qt = schema_data.get("queryType")
        if qt:
            query_type_name = qt.get("name")

        # Extract mutation type name
        mutation_type_name = None
        mt = schema_data.get("mutationType")
        if mt:
            mutation_type_name = mt.get("name")

        # Walk all types and collect fields
        for t in schema_data.get("types", []):
            type_name = t.get("name", "")
            type_kind = t.get("kind", "")

            type_entry: Dict[str, Any] = {
                "name": type_name,
                "kind": type_kind,
                "fields": [],
                "input_fields": [],
            }

            for f in t.get("fields", []) or []:
                field_info: Dict[str, Any] = {"name": f.get("name", "")}
                args = []
                for a in f.get("args", []) or []:
                    arg_type = a.get("type", {})
                    args.append({
                        "name": a.get("name", ""),
                        "type": self._resolve_type_name(arg_type),
                    })
                field_info["args"] = args
                type_entry["fields"].append(field_info)

            for f in t.get("inputFields", []) or []:
                arg_type = f.get("type", {})
                type_entry["input_fields"].append({
                    "name": f.get("name", ""),
                    "type": self._resolve_type_name(arg_type),
                })

            result["types"].append(type_entry)

            # If this is the root Query type, extract query names
            if type_name == query_type_name:
                result["queries"] = [
                    f["name"] for f in type_entry["fields"] if f["name"]
                ]

            # If this is the root Mutation type, extract mutation names
            if type_name == mutation_type_name:
                result["mutations"] = [
                    f["name"] for f in type_entry["fields"] if f["name"]
                ]

        return result

    @staticmethod
    def _resolve_type_name(type_obj: Any) -> str:
        """Resolve a GraphQL type reference to its name string."""
        if not isinstance(type_obj, dict):
            return str(type_obj)
        if type_obj.get("name"):
            return type_obj["name"]
        of_type = type_obj.get("ofType")
        if of_type and isinstance(of_type, dict):
            inner = GraphQLIntrospector._resolve_type_name(of_type)
            kind = type_obj.get("kind", "")
            if kind == "NON_NULL":
                return f"{inner}!"
            if kind == "LIST":
                return f"[{inner}]"
            return inner
        return type_obj.get("kind", "UNKNOWN")


# ── OpenAPI Spec Parser ──────────────────────────────────────────────────


class OpenAPISpecParser:
    """Fetch and parse OpenAPI / Swagger specification files.

    Probes common spec locations and extracts endpoint definitions.
    """

    _SPEC_PATHS = [
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/api-docs/json",
        "/docs",
        "/v3/api-docs",
        "/v2/api-docs",
        "/swagger/v1/swagger.json",
        "/api/swagger.json",
        "/api/openapi.json",
        "/static/swagger.json",
    ]

    def probe(self, base_url: str) -> Optional[Dict[str, Any]]:
        """Try common OpenAPI/Swagger spec paths.

        Parameters
        ----------
        base_url : str
            Target base URL.

        Returns
        -------
        dict | None
            ``{"url": url, "spec": parsed_dict}`` if found, else ``None``.
        """
        origin = base_url.rstrip("/")

        for path in self._SPEC_PATHS:
            url = origin + path
            resp = http_probe(
                url,
                headers={"Accept": "application/json"},
            )
            if resp.get("status") != 200:
                # Some endpoints redirect to an HTML doc page
                if resp.get("status") in (301, 302, 307, 308):
                    loc = resp.get("headers", {}).get("location", "")
                    if loc:
                        url = urljoin(url, loc)
                        resp = http_probe(url, headers={"Accept": "application/json"})
                        if resp.get("status") != 200:
                            continue
                    else:
                        continue
                else:
                    continue

            body = resp.get("body", "")
            # Try to parse as JSON
            try:
                spec = json.loads(body)
                if isinstance(spec, dict) and (
                    "openapi" in spec or "swagger" in spec or "paths" in spec
                ):
                    return {"url": url, "spec": spec}
            except (json.JSONDecodeError, ValueError):
                # Maybe it's YAML — skip (no yaml in stdlib)
                pass

        return None

    def parse_spec(self, spec: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract endpoints from an OpenAPI/Swagger specification.

        Parameters
        ----------
        spec : dict
            Parsed OpenAPI JSON spec.

        Returns
        -------
        list[dict]
            Each dict: {path, method, parameters, summary, tags}.
        """
        results: List[Dict[str, Any]] = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get", "post", "put", "delete", "patch", "options", "head"):
                op = path_item.get(method)
                if not isinstance(op, dict):
                    continue

                parameters: List[Dict[str, str]] = []
                for p in op.get("parameters", []):
                    if isinstance(p, dict):
                        parameters.append({
                            "name": p.get("name", ""),
                            "in": p.get("in", ""),
                            "type": p.get("schema", {}).get("type", ""),
                            "required": str(p.get("required", False)),
                        })

                # Also pull path-level parameters
                for p in path_item.get("parameters", []):
                    if isinstance(p, dict):
                        p_name = p.get("name", "")
                        if not any(param["name"] == p_name for param in parameters):
                            parameters.append({
                                "name": p_name,
                                "in": p.get("in", ""),
                                "type": p.get("schema", {}).get("type", ""),
                                "required": str(p.get("required", False)),
                            })

                results.append({
                    "path": path,
                    "method": method.upper(),
                    "parameters": parameters,
                    "summary": op.get("summary", ""),
                    "tags": op.get("tags", []),
                })

        # Also check webhooks (OpenAPI 3.1)
        for hook_path, hook_item in spec.get("webhooks", {}).items():
            if isinstance(hook_item, dict):
                for method in ("post", "get", "put"):
                    op = hook_item.get(method)
                    if isinstance(op, dict):
                        results.append({
                            "path": hook_path,
                            "method": method.upper(),
                            "parameters": [],
                            "summary": op.get("summary", ""),
                            "tags": op.get("tags", []) + ["webhook"],
                        })

        return results


# ── Link Crawler ──────────────────────────────────────────────────────────


class LinkCrawler:
    """BFS link crawler that discovers API-like URLs from HTML pages.

    Extracts links from href, src, and form action attributes,
    filters by domain and API patterns, and follows links
    up to a configurable depth.
    """

    # Regex for extracting URLs from HTML attributes
    _HREF_RE = re.compile(r'href\s*=\s*(?:"([^"\s]+)"|\'([^\'\s]+)\')', re.I)
    _SRC_RE = re.compile(r'src\s*=\s*(?:"([^"\s]+)"|\'([^\'\s]+)\')', re.I)
    _ACTION_RE = re.compile(
        r'<form[^>]*action\s*=\s*(?:"([^"\s]+)"|\'([^\'\s]+)\')' 
        r'[^>]*(?:method\s*=\s*(?:"(GET|POST|PUT|DELETE|PATCH)"|\'(GET|POST|PUT|DELETE|PATCH)\'))?',
        re.I,
    )
    _API_PATTERN = re.compile(
        r'(?i)(?:/api/|/rest/|/v\d+/|/graphql|/gql|/trpc|/rpc|/_next/data|'
        r'/__api|/api-docs|/swagger|/openapi)',
    )

    def crawl(
        self,
        start_url: str,
        max_pages: int = 50,
        same_domain: bool = True,
        max_depth: int = 3,
    ) -> List[Dict[str, Any]]:
        """Crawl a website and discover API-like URLs.

        Parameters
        ----------
        start_url : str
            Starting URL for the crawl.
        max_pages : int
            Maximum number of pages to fetch.
        same_domain : bool
            If True, only follow links within the same domain.
        max_depth : int
            Maximum BFS depth.

        Returns
        -------
        list[dict]
            Each dict: {url, source_page, method, type}.
        """
        results: List[Dict[str, Any]] = []
        seen_urls: set = set()
        seen_results: set = set()

        parsed_start = urlparse(start_url)
        start_domain = parsed_start.netloc

        # BFS queue: (url, depth, source_page)
        queue: List[Tuple[str, int, str]] = [(start_url, 0, start_url)]
        seen_urls.add(start_url.rstrip("/") or start_url)

        pages_fetched = 0

        while queue and pages_fetched < max_pages:
            url, depth, source = queue.pop(0)

            if depth > max_depth:
                continue

            resp = http_probe(url)
            pages_fetched += 1

            if resp.get("status", 0) not in (200, 301, 302, 307, 308):
                continue

            body = resp.get("body", "")
            content_type = resp.get("headers", {}).get("content-type", "").lower()

            # Only parse HTML pages for links
            if "text/html" not in content_type and depth == 0:
                # At depth 0 we always try; beyond that, skip non-HTML
                if "text/html" not in content_type:
                    continue

            # Extract all href links
            hrefs = set()
            for m in self._HREF_RE.finditer(body):
                href = m.group(1) or m.group(2) or ""
                if href and not href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                    hrefs.add(href)

            # Extract src links (scripts, iframes)
            srcs = set()
            for m in self._SRC_RE.finditer(body):
                src = m.group(1) or m.group(2) or ""
                if src and not src.startswith(("data:", "blob:")):
                    srcs.add(src)

            # Extract form actions
            form_methods: Dict[str, str] = {}
            for m in self._ACTION_RE.finditer(body):
                action = m.group(1) or m.group(2) or ""
                method = m.group(3) or m.group(4) or "POST"
                if action:
                    form_methods[action] = method

            # Resolve and classify all discovered URLs
            all_raw = hrefs | srcs | set(form_methods.keys())

            for raw in all_raw:
                resolved = urljoin(url, raw)
                parsed = urlparse(resolved)

                # Domain filter
                if same_domain and parsed.netloc != start_domain:
                    continue

                # Skip common non-useful extensions
                skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                           ".css", ".woff", ".woff2", ".ttf", ".eot",
                           ".mp4", ".mp3", ".webp", ".webm")
                path_lower = parsed.path.lower()
                if any(path_lower.endswith(ext) for ext in skip_ext):
                    continue

                # Classify the link
                is_api = bool(self._API_PATTERN.search(resolved))
                is_form = raw in form_methods
                is_js = path_lower.endswith(".js")

                link_type = "link"
                method = "GET"

                if is_form:
                    link_type = "form"
                    method = form_methods[raw]
                elif is_api:
                    link_type = "api"
                elif is_js:
                    link_type = "js"

                result_key = (resolved, method)
                if result_key not in seen_results:
                    seen_results.add(result_key)
                    results.append({
                        "url": resolved,
                        "source_page": url,
                        "method": method,
                        "type": link_type,
                    })

                # Queue HTML links for further crawling
                if link_type in ("link", "api") and depth < max_depth:
                    normalized = resolved.rstrip("/") or resolved
                    if normalized not in seen_urls:
                        seen_urls.add(normalized)
                        queue.append((resolved, depth + 1, url))

        return results


# ── Auth Matrix ───────────────────────────────────────────────────────────


class AuthMatrix:
    """Test endpoints with multiple authentication states to find
    access control issues.

    Checks: no auth, invalid auth, case-sensitivity bypass.
    """

    def test_endpoint(self, url: str) -> Dict[str, Any]:
        """Test a single endpoint with multiple auth states.

        Parameters
        ----------
        url : str
            The endpoint URL to test.

        Returns
        -------
        dict
            {url, no_auth_status, no_auth_body_len, broken_auth, auth_required}
        """
        result: Dict[str, Any] = {
            "url": url,
            "no_auth_status": 0,
            "no_auth_body_len": 0,
            "broken_auth": False,
            "auth_required": False,
        }

        # Test 1: No authentication
        resp_none = http_probe(url)
        status_none = resp_none.get("status", 0)
        body_none = resp_none.get("body", "")
        result["no_auth_status"] = status_none
        result["no_auth_body_len"] = len(body_none)

        # Test 2: Invalid/broken auth (Bearer token with garbage)
        resp_bad = http_probe(
            url,
            headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.INVALID.TOKEN"},
        )
        status_bad = resp_bad.get("status", 0)
        body_bad = resp_bad.get("body", "")

        # Auth is required if the server returns 401/403 for either request
        is_auth_required = status_none in (401, 403) or status_bad in (401, 403)
        result["auth_required"] = is_auth_required

        # Broken auth = invalid token accepted (same status as no-auth or 200
        # when no-auth returns 401/403)
        if is_auth_required and status_bad == 200:
            result["broken_auth"] = True
        elif status_none in (401, 403) and status_bad not in (401, 403):
            # Server treats invalid token differently from no token — possible bypass
            result["broken_auth"] = True

        # Test 3: Case sensitivity bypass (bearer vs Bearer, etc.)
        case_variants = [
            {"authorization": "bearer invalid_token"},     # lowercase
            {"Authorization": "Bearer  invalid_token"},   # double space
            {"authorization": "Bearer invalid_token"},     # lower header name
        ]
        case_bypass = False
        for headers in case_variants:
            resp_case = http_probe(url, headers=headers)
            sc = resp_case.get("status", 0)
            if status_none in (401, 403) and sc == 200:
                case_bypass = True
                break
            if status_bad in (401, 403) and sc == 200:
                case_bypass = True
                break
        result["case_bypass"] = case_bypass

        # No auth returns data when it should be protected
        if status_none == 200 and is_auth_required:
            result["broken_auth"] = True

        return result


# ── gRPC Introspector ──────────────────────────────────────────────────────


class GrpcIntrospector:
    """Detect and probe gRPC endpoints.

    gRPC uses HTTP/2 with specific content-types and paths:
    - POST /grpcservice.MethodName with content-type: application/grpc
    - POST /twirp/ServiceName/Method with standard content-type
    - gRPC-Web uses application/grpc-web+proto or application/grpc-web+json

    Detection methods:
    1. Probe common gRPC paths with gRPC content-type header
    2. Check for gRPC reflection (server reflection service)
    3. Look for gRPC-Web endpoints
    """

    GRPC_PATHS = [
        "/grpc/", "/api/grpc/", "/twirp/",
        "/grpc.Service/", "/grpc.Reflection/",
        "/helloworld.Greeter/", "/echo.Echo/",
    ]

    GRPC_REFLECTION_METHODS = [
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    ]

    CONTENT_TYPES = [
        "application/grpc",
        "application/grpc+proto",
        "application/grpc-web+proto",
        "application/grpc-web+json",
        "application/proto",
    ]

    def __init__(self, base_url: str, timeout: float = 8.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.findings: List[Finding] = []

    def detect(self) -> List[Finding]:
        """Run gRPC detection. Returns list of findings."""
        self._probe_grpc_paths()
        self._probe_reflection()
        self._probe_twirp()
        return self.findings

    def _probe_grpc_paths(self):
        """Probe common gRPC paths."""
        for path in self.GRPC_PATHS:
            url = f"{self.base_url}{path}"
            for ct in self.CONTENT_TYPES[:2]:  # Try top 2 content types
                try:
                    # Send a 5-byte gRPC frame (compressed=0, length=0)
                    payload = b"\x00\x00\x00\x00\x00"
                    req = urllib.request.Request(
                        url, data=payload, method="POST",
                        headers={
                            "Content-Type": ct,
                            "TE": "trailers",
                            "User-Agent": "ReconPro-grpc/9",
                            "grpc-encoding": "identity",
                        },
                    )
                    with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                        body = resp.read()
                        resp_ct = resp.headers.get("Content-Type", "")
                        if "grpc" in resp_ct.lower():
                            self.findings.append(Finding(
                                title=f"gRPC endpoint detected: {path}",
                                severity="medium",
                                category="grpc_exposure",
                                module="api_discovery",
                                description=f"gRPC service found at {url} with response content-type: {resp_ct}",
                                evidence=f"Response: {resp.status} | Content-Type: {resp_ct} | Body length: {len(body)}",
                                asset=url,
                                points_deducted=3,
                                remediation="Ensure gRPC endpoints require authentication and are not publicly accessible.",
                            ))
                            break  # Don't double-report for same path
                except Exception:
                    pass

    def _probe_reflection(self):
        """Probe gRPC server reflection."""
        for method in self.GRPC_REFLECTION_METHODS:
            url = f"{self.base_url}{method}"
            try:
                # gRPC reflection request (empty message, compressed=0, length=0)
                payload = b"\x00\x00\x00\x00\x00"
                req = urllib.request.Request(
                    url, data=payload, method="POST",
                    headers={
                        "Content-Type": "application/grpc",
                        "TE": "trailers",
                        "User-Agent": "ReconPro-grpc/9",
                    },
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read()
                    if len(body) > 5:
                        self.findings.append(Finding(
                            title="gRPC Server Reflection enabled",
                            severity="high",
                            category="grpc_exposure",
                            module="api_discovery",
                            description=f"gRPC server reflection is enabled at {url}, allowing service enumeration.",
                            evidence=f"Reflection endpoint responded with {len(body)} bytes",
                            asset=url,
                            points_deducted=8,
                            remediation="Disable gRPC server reflection in production: use grpc.Server reflection=None.",
                        ))
                        return  # Only report once
            except Exception:
                pass

    # DEAD CODE: consider removal
    def _probe_twirp(self):
        """Probe Twirp (gRPC-compatible) endpoints."""
        twirp_paths = [
            "/twirp/", "/twirp/auth.Auth/",
            "/twirp/user.UserService/",
            "/twirp/admin.AdminService/",
        ]
        for path in twirp_paths:
            url = f"{self.base_url}{path}"
            try:
                req = urllib.request.Request(
                    url, data=b"{}", method="POST",
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "ReconPro-twirp/9",
                    },
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read()
                    resp_ct = resp.headers.get("Content-Type", "")
                    if resp.status in (200, 400) and "twirp" in resp_ct.lower():
                        self.findings.append(Finding(
                            title=f"Twirp endpoint detected: {path}",
                            severity="medium",
                            category="grpc_exposure",
                            module="api_discovery",
                            description=f"Twirp (gRPC-compatible) endpoint found at {url}",
                            evidence=f"Status: {resp.status} | Content-Type: {resp_ct}",
                            asset=url,
                            points_deducted=3,
                            remediation="Ensure Twirp endpoints are protected behind authentication.",
                        ))
            except Exception:
                pass


# ── Orchestrator ──────────────────────────────────────────────────────────


# DEAD CODE: consider removal
def discover_api(
    target: str,
    base_url: str,
    timeout: int = 10,
    verify_tls: bool = True,
) -> Tuple[List[Finding], int, str, str]:
    """Orchestrate all API discovery techniques against a target.

    Runs JS endpoint extraction (on JS files found via link crawl),
    GraphQL introspection, OpenAPI spec parsing, link crawling, and
    auth matrix testing.  Converts discovered endpoints into Findings.

    Parameters
    ----------
    target : str
        Domain or host string.
    base_url : str
        Full base URL (e.g. ``https://example.com``).
    timeout : int
        Per-request HTTP timeout in seconds.
    verify_tls : bool
        Whether to verify TLS certificates.

    Returns
    -------
    tuple[list[Finding], int, str, str]
        (findings, score, grade, badge_markdown)
    """
    findings: List[Finding] = []
    deductions = 0
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    origin = base_url.rstrip("/")

    def add(
        title: str, severity: str, category: str,
        desc: str, evidence: str, pts: int = 0,
    ) -> None:
        nonlocal deductions
        findings.append(Finding(
            title=title, severity=severity, category=category,
            module="api_discovery", description=desc, evidence=evidence,
            asset=host, points_deducted=pts,
        ))
        deductions += pts

    # ── Phase 1: Link crawl to discover JS files and pages ──────────
    crawler = LinkCrawler()
    crawled = crawler.crawl(origin, max_pages=30, same_domain=True, max_depth=2)
    js_urls = [item["url"] for item in crawled if item["type"] == "js"]
    api_links = [item for item in crawled if item["type"] in ("api", "form")]

    # ── Phase 2: JS endpoint extraction ─────────────────────────────
    js_extractor = JsEndpointExtractor()
    all_js_endpoints: List[Dict[str, Any]] = []

    for js_url in js_urls[:15]:  # Limit JS files to process
        endpoints = js_extractor.extract_from_url(js_url)
        all_js_endpoints.extend(endpoints)

    # Also try extracting from the main page itself
    main_resp = http_probe(origin)
    if main_resp.get("status") == 200:
        main_body = main_resp.get("body", "")
        inline_endpoints = js_extractor.extract_from_content(main_body, base_url=origin)
        all_js_endpoints.extend(inline_endpoints)

    # Deduplicate
    seen_eps: set = set()
    unique_js: List[Dict[str, Any]] = []
    for ep in all_js_endpoints:
        key = (ep["url"], ep["method"])
        if key not in seen_eps:
            seen_eps.add(key)
            unique_js.append(ep)

    if unique_js:
        add(
            f"JS API surface: {len(unique_js)} endpoints discovered",
            "medium", "js_api_discovery",
            f"Found {len(unique_js)} API endpoints by analyzing JavaScript sources",
            ", ".join(f"{e['method']} {e['url'][:80]}" for e in unique_js[:5]),
            3,
        )

    # ── Phase 3: GraphQL introspection ───────────────────────────────
    gql = GraphQLIntrospector()
    gql_probe = gql.probe(origin)
    if gql_probe:
        gql_url = gql_probe["endpoint"]
        schema = gql.introspect(gql_url)
        n_queries = len(schema.get("queries", []))
        n_mutations = len(schema.get("mutations", []))
        n_types = len(schema.get("types", []))

        add(
            f"GraphQL endpoint exposed: {gql_url}",
            "high", "graphql_exposed",
            f"GraphQL introspection enabled — {n_queries} queries, "
            f"{n_mutations} mutations, {n_types} types enumerable",
            f"POST {gql_url} -> introspection success, "
            f"queries=[{', '.join(schema['queries'][:10])}]" if n_queries else f"POST {gql_url}",
            10,
        )

        # Check for dangerous mutations
        dangerous_keywords = ("delete", "remove", "admin", "reset", "config",
                             "password", "user", "role", "permission")
        for mutation in schema.get("mutations", []):
            if any(kw in mutation.lower() for kw in dangerous_keywords):
                add(
                    f"Dangerous GraphQL mutation: {mutation}",
                    "high", "graphql_dangerous_mutation",
                    f"Mutation '{mutation}' may allow privileged operations via introspection",
                    f"Mutation: {mutation} at {gql_url}",
                    8,
                )
    
    # ── Phase 4: OpenAPI / Swagger spec ──────────────────────────────
    oas = OpenAPISpecParser()
    spec_result = oas.probe(origin)
    if spec_result:
        spec = spec_result["spec"]
        endpoints = oas.parse_spec(spec)
        add(
            f"OpenAPI/Swagger spec exposed: {spec_result['url']}",
            "medium", "openapi_exposed",
            f"API specification publicly accessible — {len(endpoints)} endpoints documented",
            f"GET {spec_result['url']} -> 200 ({len(endpoints)} paths)",
            4,
        )

        # Flag sensitive endpoints found in the spec
        sensitive_words = ("admin", "internal", "debug", "config", "secret",
                          "credential", "key", "token", "webhook")
        for ep in endpoints:
            path = ep["path"].lower()
            if any(sw in path for sw in sensitive_words):
                add(
                    f"Sensitive endpoint in spec: {ep['method']} {ep['path']}",
                    "medium", "openapi_sensitive_endpoint",
                    f"API spec documents potentially sensitive endpoint",
                    f"{ep['method']} {ep['path']}",
                    3,
                )

    # ── Phase 5: Auth matrix testing on discovered endpoints ─────────
    auth_tester = AuthMatrix()
    # Gather candidate endpoints to test
    test_candidates: List[str] = []
    
    # From JS extraction
    for ep in unique_js[:10]:
        if ep["url"].startswith(origin):
            test_candidates.append(ep["url"])
    
    # From link crawl API/form results
    for item in api_links[:10]:
        if item["url"].startswith(origin):
            test_candidates.append(item["url"])
    
    # Deduplicate candidates
    test_candidates = list(dict.fromkeys(test_candidates))

    for endpoint_url in test_candidates[:8]:  # Limit auth tests
        auth_result = auth_tester.test_endpoint(endpoint_url)

        if auth_result.get("broken_auth"):
            add(
                f"Auth bypass: {endpoint_url[:80]}",
                "high", "auth_bypass",
                "Endpoint accessible with broken or missing authentication",
                f"no_auth={auth_result['no_auth_status']}, "
                f"broken_auth=True"
                + (", case_bypass=True" if auth_result.get("case_bypass") else ""),
                12,
            )
        elif auth_result.get("case_bypass"):
            add(
                f"Case-sensitivity auth bypass: {endpoint_url[:80]}",
                "high", "auth_case_bypass",
                "Authorization header case variation bypasses auth check",
                f"case_bypass=True on {endpoint_url}",
                10,
            )
        elif not auth_result.get("auth_required") and auth_result["no_auth_status"] == 200:
            # Endpoint accessible without auth — flag if it looks sensitive
            sensitive = any(
                kw in endpoint_url.lower()
                for kw in ("admin", "user", "config", "internal", "delete", "key")
            )
            if sensitive:
                add(
                    f"Unprotected sensitive endpoint: {endpoint_url[:80]}",
                    "high", "unprotected_endpoint",
                    "Sensitive API endpoint accessible without authentication",
                    f"GET {endpoint_url} -> 200 (no auth)",
                    8,
                )

    # ── Phase 6: gRPC endpoint detection ────────────────────────────
    grpc_scanner = GrpcIntrospector(origin)
    grpc_findings = grpc_scanner.detect()
    for gf in grpc_findings:
        findings.append(gf)
        deductions += gf.points_deducted

    # ── Score calculation ────────────────────────────────────────────
    score = max(0, min(100, 100 - deductions))
    if not findings:
        score = 100
    grade = compute_grade(score)
    badge_md = badge_markdown(host, grade)

    return findings, score, grade, badge_md

"""ReconPro v9.0.1 — Supply Chain / Web Content Extraction.

Provides:
  - WebExtractor: stdlib HTMLParser-based web page content extraction
  - GitHubScraper: unauthenticated GitHub API scraper (60 req/hr)
  - SupplyChainAnalyzer: secrets, deps, infra, CI/CD, cloud config analysis
  - run_supply_chain(): module entry point returning List[Finding]

All using stdlib only — no BeautifulSoup, requests, or external dependencies.
"""

from __future__ import annotations

import base64
import html
import html.parser
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .http_layer import Finding


# ── Encoding Detection ─────────────────────────────────────────────────

_ENCODING_MARKERS: List[Tuple[bytes, str]] = [
    (b'charset=utf-8', 'utf-8'),
    (b'charset=UTF-8', 'utf-8'),
    (b'charset=iso-8859-1', 'iso-8859-1'),
    (b'charset=ISO-8859-1', 'iso-8859-1'),
    (b'charset=windows-1252', 'windows-1252'),
    (b'charset=gb2312', 'gb2312'),
    (b'charset=shift_jis', 'shift_jis'),
    (b'charset=euc-kr', 'euc-kr'),
]


def _detect_encoding(raw: bytes, headers: Dict[str, str]) -> str:
    """Detect encoding from Content-Type header or meta tags in raw bytes."""
    content_type = headers.get('content-type', '')
    for marker, enc in _ENCODING_MARKERS:
        if marker.decode('ascii', errors='ignore') in content_type:
            return enc
    # Check first 1024 bytes for <meta charset=...>
    head = raw[:1024].lower()
    for marker, enc in _ENCODING_MARKERS:
        if marker in head:
            return enc
    return 'utf-8'


# ── HTML Parser for WebExtractor ──────────────────────────────────────

class _PageParser(html.parser.HTMLParser):
    """Lightweight HTML parser that extracts structured content from pages."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=False)
        self.base_url = base_url
        self.title: str = ''
        self.description: str = ''
        self.text_parts: List[str] = []
        self.links: List[Dict[str, str]] = []
        self.forms: List[Dict[str, Any]] = []
        self.scripts: List[Dict[str, str]] = []
        self.meta_tags: List[Dict[str, str]] = []
        self.headings: Dict[str, List[str]] = {
            'h1': [], 'h2': [], 'h3': [], 'h4': [], 'h5': [], 'h6': [],
        }
        self._in_title = False
        self._in_script = False
        self._script_attrs: Dict[str, str] = {}
        self._in_form = False
        self._form_attrs: Dict[str, str] = {}
        self._form_inputs: List[Dict[str, str]] = []
        self._skip_tags: set = {'script', 'style', 'noscript', 'svg'}
        self._current_tag: str = ''
        self._heading_depth: int = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        attr_dict = {k: v or '' for k, v in attrs}

        if tag == 'title':
            self._in_title = True
        elif tag == 'script':
            self._in_script = True
            self._script_attrs = attr_dict
        elif tag == 'form':
            self._in_form = True
            self._form_attrs = attr_dict
            self._form_inputs = []
        elif tag == 'input' and self._in_form:
            self._form_inputs.append(attr_dict)
        elif tag == 'meta':
            name = attr_dict.get('name', attr_dict.get('property', ''))
            content = attr_dict.get('content', '')
            if name or content:
                self.meta_tags.append({'name': name, 'content': content})
                if name.lower() == 'description':
                    self.description = html.unescape(content)
        elif tag == 'a':
            href = attr_dict.get('href', '')
            if href and not href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                resolved = urllib.parse.urljoin(self.base_url, href)
                self.links.append({
                    'href': href,
                    'resolved': resolved,
                    'text': '',
                })
        elif tag in self.headings:
            self._heading_depth = int(tag[1])
            self._current_tag = tag

        if tag not in self._skip_tags and tag != 'br':
            self.text_parts.append(' ')

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == 'title':
            self._in_title = False
        elif tag == 'script':
            self._in_script = False
            src = self._script_attrs.get('src', '')
            if src:
                self.scripts.append({
                    'src': urllib.parse.urljoin(self.base_url, src),
                    'type': self._script_attrs.get('type', ''),
                })
            self._script_attrs = {}
        elif tag == 'form':
            self.forms.append({
                'action': self._form_attrs.get('action', ''),
                'method': self._form_attrs.get('method', 'GET').upper(),
                'inputs': list(self._form_inputs),
            })
            self._in_form = False
            self._form_attrs = {}
            self._form_inputs = []
        elif tag in self.headings:
            self._heading_depth = 0
            self._current_tag = ''

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif self._in_script:
            pass  # skip script body
        elif self._heading_depth > 0:
            key = f'h{self._heading_depth}'
            self.headings[key].append(data.strip())
        else:
            self.text_parts.append(data)

    def handle_entityref(self, name: str) -> None:
        char = html.unescape(f'&{name};')
        self.text_parts.append(char)
        if self._in_title:
            self.title += char

    def handle_charref(self, name: str) -> None:
        char = html.unescape(f'&#{name};')
        self.text_parts.append(char)
        if self._in_title:
            self.title += char

    def get_text_content(self) -> str:
        raw = ''.join(self.text_parts)
        cleaned = re.sub(r'\s+', ' ', raw).strip()
        return cleaned[:10000]

    def get_result(self) -> Dict[str, Any]:
        return {
            'title': html.unescape(self.title).strip(),
            'description': self.description,
            'text_content': self.get_text_content(),
            'links': self.links,
            'forms': self.forms,
            'scripts': self.scripts,
            'meta_tags': self.meta_tags,
            'headings': {k: v for k, v in self.headings.items() if v},
        }


# ── Web Content Extractor ─────────────────────────────────────────────

class WebExtractor:
    """Extracts structured content from web pages using stdlib HTMLParser.

    Handles encoding detection, relative URL resolution, and structured
    extraction of titles, links, forms, scripts, meta tags, and headings.
    """

    def __init__(self, timeout: int = 15) -> None:
        self._timeout = timeout

    def extract(self, url: str) -> Dict[str, Any]:
        """Fetch a URL and extract structured content.

        Returns dict with: title, description, text_content, links,
        forms, scripts, meta_tags, headings.
        """
        result: Dict[str, Any] = {
            'url': url,
            'status': 0,
            'title': '',
            'description': '',
            'text_content': '',
            'links': [],
            'forms': [],
            'scripts': [],
            'meta_tags': [],
            'headings': {},
            'error': None,
        }
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'ReconPro/9.0.1 (Supply Chain Auditor)',
                    'Accept': 'text/html,application/xhtml+xml,application/json',
                    'Accept-Language': 'en-US,en;q=0.9',
                },
            )
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                result['status'] = resp.status
                raw = resp.read(512_000)  # 512 KB cap
                headers = dict(resp.headers.items())
                encoding = _detect_encoding(raw, headers)
                body = raw.decode(encoding, errors='replace')
                result['body_size'] = len(body)
                parser = _PageParser(url)
                parser.feed(body)
                extracted = parser.get_result()
                for key in extracted:
                    result[key] = extracted[key]
        except urllib.error.HTTPError as e:
            result['status'] = e.code
            result['error'] = f'HTTP {e.code} {e.reason}'
        except Exception as e:
            result['error'] = str(e)[:120]
        return result

    def extract_multiple(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Batch-extract content from multiple URLs.

        Returns a list of result dicts, one per URL.
        """
        return [self.extract(url) for url in urls]


# ── GitHub Scraper ────────────────────────────────────────────────────

class GitHubScraper:
    """Scrapes GitHub repos using the unauthenticated GitHub API.

    Rate limit: 60 requests/hour for unauthenticated access.
    Tracks remaining requests via the X-RateLimit-Remaining header.
    """

    GITHUB_API = 'https://api.github.com'
    GITHUB_RAW = 'https://raw.githubusercontent.com'

    def __init__(self, timeout: int = 15) -> None:
        self._timeout = timeout
        self._request_count: int = 0
        self._remaining: Optional[int] = None
        self._reset_time: Optional[int] = None

    def _github_request(self, path: str) -> Optional[Any]:
        """Make a GitHub API request with rate limit tracking."""
        url = f'{self.GITHUB_API}{path}'
        self._request_count += 1
        try:
            req = urllib.request.Request(
                url,
                headers={
                    'User-Agent': 'ReconPro/9.0.1',
                    'Accept': 'application/vnd.github.v3+json',
                },
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                # Track rate limit headers
                remaining = resp.headers.get('X-RateLimit-Remaining')
                reset = resp.headers.get('X-RateLimit-Reset')
                if remaining is not None:
                    self._remaining = int(remaining)
                if reset is not None:
                    self._reset_time = int(reset)
                raw = resp.read().decode('utf-8')
                return json.loads(raw)
        except urllib.error.HTTPError as e:
            if e.code == 403 and 'rate limit' in str(e).lower():
                self._remaining = 0
            return {'_error': f'HTTP {e.code}', '_status': e.code}
        except Exception as e:
            return {'_error': str(e)[:120], '_status': 0}

    @property
    def remaining_requests(self) -> Optional[int]:
        """Return remaining API requests, or None if unknown."""
        return self._remaining

    @property
    def request_count(self) -> int:
        """Return total API requests made this session."""
        return self._request_count

    def get_repo_info(self, owner: str, repo: str) -> Dict[str, Any]:
        """Get repository metadata (description, stars, language, etc.)."""
        data = self._github_request(f'/repos/{owner}/{repo}')
        if not data or not isinstance(data, dict):
            return {}
        return {
            'name': data.get('full_name', f'{owner}/{repo}'),
            'description': data.get('description', ''),
            'stars': data.get('stargazers_count', 0),
            'forks': data.get('forks_count', 0),
            'language': data.get('language', ''),
            'license': (data.get('license') or {}).get('spdx_id', ''),
            'default_branch': data.get('default_branch', 'main'),
            'is_fork': data.get('fork', False),
            'is_private': data.get('private', False),
            'created_at': data.get('created_at', ''),
            'updated_at': data.get('updated_at', ''),
            'topics': data.get('topics', []),
            'size_kb': data.get('size', 0),
        }

    def get_file_tree(self, owner: str, repo: str, path: str = '') -> List[Dict[str, Any]]:
        """Get directory listing at the given path."""
        api_path = f'/repos/{owner}/{repo}/contents/{path}'.rstrip('/')
        data = self._github_request(api_path)
        if not data or isinstance(data, dict):
            return []
        return [
            {
                'name': item.get('name', ''),
                'path': item.get('path', ''),
                'type': item.get('type', 'file'),
                'size': item.get('size', 0),
            }
            for item in data
        ]

    def get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        """Get decoded file content from a GitHub repo."""
        api_path = f'/repos/{owner}/{repo}/contents/{path}'
        data = self._github_request(api_path)
        if not data or not isinstance(data, dict):
            return None
        content_b64 = data.get('content', '')
        encoding = data.get('encoding', '')
        if encoding == 'base64' and content_b64:
            try:
                return base64.b64decode(content_b64).decode('utf-8', errors='replace')
            except Exception:
                return None
        if data.get('download_url'):
            try:
                req = urllib.request.Request(
                    data['download_url'],
                    headers={'User-Agent': 'ReconPro/9.0.1'},
                )
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    return resp.read().decode('utf-8', errors='replace')
            except Exception:
                return None
        return None

    def get_workflow_files(self, owner: str, repo: str) -> List[Dict[str, Any]]:
        """Get all .yml/.yaml files from .github/workflows/."""
        files = self.get_file_tree(owner, repo, '.github/workflows')
        workflows: List[Dict[str, Any]] = []
        for f in files:
            if f['type'] == 'file' and f['name'].endswith(('.yml', '.yaml')):
                content = self.get_file_content(owner, repo, f['path'])
                workflows.append({
                    'name': f['name'],
                    'path': f['path'],
                    'content': content,
                    'size': f['size'],
                })
        return workflows

    def get_readme(self, owner: str, repo: str) -> Optional[str]:
        """Get README content (tries common names in order)."""
        for name in ('README.md', 'README.rst', 'README.txt', 'README', 'readme.md'):
            content = self.get_file_content(owner, repo, name)
            if content:
                return content
        return None

    def _parse_github_url(self, full_url: str) -> Optional[Tuple[str, str]]:
        """Extract (owner, repo) from a GitHub URL."""
        parsed = urllib.parse.urlparse(full_url)
        parts = parsed.path.strip('/').split('/')
        # Handle github.com/owner/repo or github.com/owner/repo/
        if len(parts) >= 2 and parts[0] and parts[1]:
            return parts[0], parts[1]
        # Handle bare owner/repo string
        if '/' in full_url and not full_url.startswith('http'):
            segments = full_url.strip('/').split('/')
            if len(segments) >= 2:
                return segments[0], segments[1]
        return None

    def scrape_repo(self, full_url: str, max_files: int = 30) -> Dict[str, Any]:
        """Auto-parse owner/repo from URL and extract everything.

        Returns repo info, file tree, README, workflows, and source files.
        """
        parsed = self._parse_github_url(full_url)
        if not parsed:
            return {'error': f'Cannot parse GitHub URL: {full_url}'}
        owner, repo = parsed

        repo_info = self.get_repo_info(owner, repo)
        file_tree = self.get_file_tree(owner, repo)
        readme = self.get_readme(owner, repo)
        workflows = self.get_workflow_files(owner, repo)

        # Recursively collect source files
        source_extensions = (
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rs',
            '.rb', '.php', '.yml', '.yaml', '.json', '.toml', '.cfg',
            '.ini', '.env', '.dockerfile', '.tf', '.hcl',
        )
        source_files: List[Dict[str, Any]] = []
        dirs_to_scan: List[Tuple[str, int]] = [('', 0)]

        while dirs_to_scan and len(source_files) < max_files:
            current_path, depth = dirs_to_scan.pop(0)
            if depth > 3:
                continue
            tree = self.get_file_tree(owner, repo, current_path)
            for item in tree:
                if item['type'] == 'dir' and depth < 3:
                    dirs_to_scan.append((item['path'], depth + 1))
                elif item['type'] == 'file':
                    if any(item['name'].lower().endswith(ext) for ext in source_extensions):
                        content = self.get_file_content(owner, repo, item['path'])
                        source_files.append({
                            'name': item['name'],
                            'path': item['path'],
                            'content': content,
                            'size': item['size'],
                        })
                        if len(source_files) >= max_files:
                            break

        return {
            'repo': f'{owner}/{repo}',
            'info': repo_info,
            'file_tree': file_tree,
            'readme': readme,
            'workflows': workflows,
            'source_files': source_files,
            'api_requests': self._request_count,
            'remaining_requests': self._remaining,
        }


# ── Supply Chain Analyzer ─────────────────────────────────────────────

class SupplyChainAnalyzer:
    """Analyzes extracted web/repo content for supply chain risks.

    Detects:
      - Hardcoded secrets (API keys, tokens, passwords)
      - Dependency declarations (package.json, requirements.txt, etc.)
      - Infrastructure configs (Terraform, Docker, K8s)
      - CI/CD pipelines (GitHub Actions, GitLab CI, Jenkinsfile)
      - Cloud configs (AWS, Azure, GCP, Supabase, Vercel)
      - Security files (security.txt, .env, .env.example)
    """

    SECRET_PATTERNS: List[Tuple[str, str, str]] = [
        (r'(?:api[_-]?key|apikey)\s*[=:\"]+\s*[\"\']?([a-zA-Z0-9_\-]{20,})',
         'API Key', 'critical'),
        (r'(?:secret|token|auth_token|access_token)\s*[=:\"]+\s*[\"\']?([a-zA-Z0-9_\-/.]{20,})',
         'Secret Token', 'critical'),
        (r'(?:password|passwd|pwd)\s*[=:\"]+\s*[\"\']([^\"\'{]{8,})',
         'Hardcoded Password', 'critical'),
        (r'(sk-[a-zA-Z0-9]{20,})', 'OpenAI API Key', 'critical'),
        (r'(AKIA[0-9A-Z]{16})', 'AWS Access Key ID', 'critical'),
        (r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}', 'GitHub Token', 'critical'),
        (r'(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)', 'Private Key', 'critical'),
        (r'(xox[bposa]-[a-zA-Z0-9-]{10,})', 'Slack Token', 'critical'),
        (r'((?:mongodb|postgres|mysql|redis|amqp)://[^\s\'\"\]>]+)',
         'Database Connection String', 'high'),
        (r'(AIza[0-9A-Za-z_\-]{35})', 'Google API Key', 'critical'),
        (r'(eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)', 'JWT Token', 'high'),
    ]

    DEP_FILE_NAMES: Dict[str, str] = {
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'yarn.lock': 'yarn',
        'pnpm-lock.yaml': 'pnpm',
        'requirements.txt': 'pip',
        'Pipfile': 'pipenv',
        'Pipfile.lock': 'pipenv',
        'pyproject.toml': 'python',
        'setup.py': 'python',
        'setup.cfg': 'python',
        'go.mod': 'go',
        'go.sum': 'go',
        'Cargo.toml': 'rust',
        'Cargo.lock': 'rust',
        'Gemfile': 'ruby',
        'Gemfile.lock': 'ruby',
        'composer.json': 'php',
        'composer.lock': 'php',
        'pom.xml': 'java/maven',
        'build.gradle': 'java/gradle',
        'build.gradle.kts': 'java/gradle',
        'pubspec.yaml': 'dart/flutter',
        'pubspec.lock': 'dart/flutter',
        'mix.exs': 'elixir',
    }

    INFRA_PATTERNS: Dict[str, str] = {
        'Dockerfile': 'Docker',
        'docker-compose.yml': 'Docker Compose',
        'docker-compose.yaml': 'Docker Compose',
        '.dockerignore': 'Docker',
        'Jenkinsfile': 'Jenkins',
        '.gitlab-ci.yml': 'GitLab CI',
        '.circleci/config.yml': 'CircleCI',
    }

    CLOUD_CONFIG_PATTERNS: List[Tuple[str, str]] = [
        (r'aws_access_key_id|aws_secret_access_key|AWS_REGION|S3_BUCKET', 'AWS'),
        (r'AZURE_CLIENT_ID|AZURE_TENANT_ID|AZURE_SUBSCRIPTION', 'Azure'),
        (r'GOOGLE_CLOUD_PROJECT|GCP_PROJECT|firebase', 'GCP'),
        (r'SUPABASE_URL|SUPABASE_ANON_KEY|SUPABASE_SERVICE_KEY', 'Supabase'),
        (r'VERCEL_TOKEN|VERCEL_URL|NEXT_PUBLIC_VERCEL', 'Vercel'),
        (r'DIGITALOCEAN_TOKEN|DO_API_TOKEN', 'DigitalOcean'),
        (r'STRIPE_SECRET|STRIPE_PUBLISHABLE', 'Stripe'),
        (r'SENDGRID_API_KEY|TWILIO_ACCOUNT_SID', 'Third-party SaaS'),
    ]

    SECURITY_FILE_NAMES: List[str] = [
        'security.txt', '.env', '.env.example', '.env.local',
        '.env.production', '.env.staging', '.env.development',
        '.npmrc', '.pypirc', '.netrc', '.pgpass',
    ]

    def analyze(self, extracted_content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze extracted content and return a list of findings.

        Each finding is a dict with: type, severity, description, evidence, file.
        """
        findings: List[Dict[str, Any]] = []
        files = extracted_content.get('source_files', [])

        # Also include workflows as files for analysis
        workflows = extracted_content.get('workflows', [])
        for w in workflows:
            files.append({
                'name': w.get('name', ''),
                'path': w.get('path', ''),
                'content': w.get('content', ''),
                'size': w.get('size', 0),
            })

        # Include README
        readme = extracted_content.get('readme', '')
        if readme:
            files.append({'name': 'README.md', 'path': 'README.md',
                          'content': readme, 'size': len(readme)})

        # Also analyze web-extracted text content if present
        text_content = extracted_content.get('text_content', '')
        if text_content:
            files.append({'name': '_web_page', 'path': extracted_content.get('url', ''),
                          'content': text_content, 'size': len(text_content)})

        for f in files:
            content = f.get('content', '')
            if not content:
                continue
            fname = f.get('name', '')
            fpath = f.get('path', '')

            # ── Secret scanning ──
            for pattern, secret_type, severity in self.SECRET_PATTERNS:
                try:
                    for match in re.finditer(pattern, content):
                        value = match.group(1) if match.lastindex else match.group(0)
                        display = str(value)[:80] + ('...' if len(str(value)) > 80 else '')
                        findings.append({
                            'type': f'Hardcoded Secret: {secret_type}',
                            'severity': severity,
                            'description': f'{secret_type} found in {fpath}',
                            'evidence': f'File: {fpath} | Match: {display}',
                            'file': fpath,
                            'file_name': fname,
                        })
                except re.error:
                    pass

            # ── Dependency declarations ──
            for dep_file, pkg_manager in self.DEP_FILE_NAMES.items():
                if fname == dep_file or fname.lower() == dep_file.lower():
                    findings.append({
                        'type': 'Dependency Declaration',
                        'severity': 'info',
                        'description': f'{pkg_manager} dependency file: {fpath}',
                        'evidence': f'File: {fpath} | Manager: {pkg_manager}',
                        'file': fpath,
                        'file_name': fname,
                    })

            # ── Infrastructure configs ──
            for infra_file, infra_type in self.INFRA_PATTERNS.items():
                if fname == infra_file or fname.lower() == infra_file.lower():
                    findings.append({
                        'type': 'Infrastructure Config',
                        'severity': 'info',
                        'description': f'{infra_type} config file: {fpath}',
                        'evidence': f'File: {fpath} | Type: {infra_type}',
                        'file': fpath,
                        'file_name': fname,
                    })

            # ── CI/CD pipeline detection ──
            if '.github/workflows/' in fpath and fpath.endswith(('.yml', '.yaml')):
                findings.append({
                    'type': 'CI/CD Pipeline',
                    'severity': 'info',
                    'description': f'GitHub Actions workflow: {fpath}',
                    'evidence': f'File: {fpath}',
                    'file': fpath,
                    'file_name': fname,
                })
            if fname == 'Jenkinsfile':
                findings.append({
                    'type': 'CI/CD Pipeline',
                    'severity': 'info',
                    'description': 'Jenkins pipeline detected',
                    'evidence': f'File: {fpath}',
                    'file': fpath,
                    'file_name': fname,
                })
            if fname == '.gitlab-ci.yml':
                findings.append({
                    'type': 'CI/CD Pipeline',
                    'severity': 'info',
                    'description': 'GitLab CI pipeline detected',
                    'evidence': f'File: {fpath}',
                    'file': fpath,
                    'file_name': fname,
                })

            # ── Cloud configs ──
            for pattern, cloud_provider in self.CLOUD_CONFIG_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        'type': f'Cloud Config: {cloud_provider}',
                        'severity': 'medium',
                        'description': f'{cloud_provider} configuration reference in {fpath}',
                        'evidence': f'File: {fpath} | Provider: {cloud_provider}',
                        'file': fpath,
                        'file_name': fname,
                    })
                    break  # one cloud provider hit per file is enough

            # ── Security files ──
            if fname in self.SECURITY_FILE_NAMES:
                sev = 'high' if fname in ('.env', '.env.local', '.env.production') else 'medium'
                findings.append({
                    'type': 'Security-Sensitive File',
                    'severity': sev,
                    'description': f'Security-sensitive file committed: {fpath}',
                    'evidence': f'File: {fpath}',
                    'file': fpath,
                    'file_name': fname,
                })

            # ── Terraform / K8s ──
            if fname.endswith('.tf') or fname.endswith('.tfvars'):
                findings.append({
                    'type': 'Infrastructure Config',
                    'severity': 'info',
                    'description': f'Terraform file: {fpath}',
                    'evidence': f'File: {fpath}',
                    'file': fpath,
                    'file_name': fname,
                })
            if fname.endswith(('.yaml', '.yml')) and any(
                kw in content.lower() for kw in ('kind:', 'apiVersion:', 'metadata:', 'spec:')
            ):
                findings.append({
                    'type': 'Infrastructure Config',
                    'severity': 'info',
                    'description': f'Possible Kubernetes manifest: {fpath}',
                    'evidence': f'File: {fpath}',
                    'file': fpath,
                    'file_name': fname,
                })

            # ── Suspicious code patterns ──
            self._check_suspicious(content, fname, fpath, findings)

        return findings

    # DEAD CODE: consider removal
    def _check_suspicious(
        self, content: str, fname: str, fpath: str,
        findings: List[Dict[str, Any]],
    ) -> None:
        """Check for suspicious code patterns."""
        checks: List[Tuple[str, str, str]] = [
            (r'\beval\s*\(', 'eval() usage detected', 'high'),
            (r'verify\s*=\s*False|CERT_NONE|ssl\._create_unverified_context',
             'TLS verification disabled', 'high'),
            (r'DEBUG\s*=\s*True|debug.*=.*true', 'Debug mode enabled', 'medium'),
            (r'pickle\.load|yaml\.load\s*\(|unserialize',
             'Potential insecure deserialization', 'high'),
            (r'os\.system\s*\(|subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True',
             'Potential command injection via shell=True', 'critical'),
            (r'exec\s*\([^)]*input\s*\)|exec\s*\(.*\+.*\)',
             'Dynamic code execution', 'high'),
            (r'__import__\s*\([^)]*input\s*\)',
             'Dynamic import from user input', 'high'),
            (r'cors.*\*|Access-Control-Allow-Origin.*\*',
             'CORS wildcard detected', 'medium'),
            (r'xml\.etree\.ElementParse|lxml\.etree\.parse\s*\(',
             'XML parsing without defusedxml', 'medium'),
        ]
        for pattern, desc, severity in checks:
            try:
                if re.search(pattern, content):
                    findings.append({
                        'type': f'Suspicious Pattern: {desc}',
                        'severity': severity,
                        'description': f'{desc} in {fpath}',
                        'evidence': f'File: {fpath} | Pattern: {desc}',
                        'file': fpath,
                        'file_name': fname,
                    })
            except re.error:
                pass


# ── Module Entry Point ────────────────────────────────────────────────

# DEAD CODE: consider removal
def run_supply_chain(
    target: str,
    base_url: str = '',
    timeout: int = 30,
    verify_tls: bool = True,
) -> List[Finding]:
    """Module entry point compatible with other ReconPro modules.

    If *target* looks like a GitHub URL or owner/repo, performs a full
    supply chain audit on the repository.  Otherwise extracts content
    from *base_url* and analyzes it.

    Returns a list of Finding dicts.
    """
    findings: List[Finding] = []
    asset = target.replace('https://', '').replace('http://', '').split('/')[0]

    scraper = GitHubScraper(timeout=timeout)
    analyzer = SupplyChainAnalyzer()

    # Detect GitHub targets
    parsed = scraper._parse_github_url(target)
    if parsed:
        owner, repo = parsed
        repo_slug = f'{owner}/{repo}'

        result = scraper.scrape_repo(target)

        if 'error' in result:
            findings.append(Finding(
                title=f'Supply chain scan failed for {repo_slug}',
                severity='low', category='supply_chain',
                module='supply_chain',
                description=result['error'],
                evidence=result['error'],
                asset=asset, points_deducted=0,
                remediation='Verify the repository URL and try again.',
            ))
            return findings

        analysis = analyzer.analyze(result)

        # Convert analyzer findings to Finding objects
        for af in analysis:
            sev = af.get('severity', 'info')
            if sev not in ('critical', 'high', 'medium', 'low', 'info'):
                sev = 'info'
            pts = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2, 'info': 0}
            findings.append(Finding(
                title=af.get('type', 'Supply Chain Finding'),
                severity=sev, category='supply_chain',
                module='supply_chain',
                description=af.get('description', ''),
                evidence=af.get('evidence', ''),
                asset=repo_slug,
                points_deducted=pts.get(sev, 0),
                remediation=_remediation_for(af.get('type', '')),
            ))

        # Summary findings
        info = result.get('info', {}
        )
        n_files = len(result.get('source_files', []))
        n_workflows = len(result.get('workflows', []))
        findings.append(Finding(
            title=f'Supply chain audit complete: {repo_slug}',
            severity='info', category='supply_chain',
            module='supply_chain',
            description=(
                f'Scanned {n_files} source files, '
                f'{n_workflows} workflows. '
                f'{len(analysis)} findings. '
                f'Language: {info.get("language", "unknown")}. '
                f'Stars: {info.get("stars", 0)}. '
                f'API requests used: {result.get("api_requests", 0)}. '
                f'Remaining: {result.get("remaining_requests", "?")}.'
            ),
            evidence=f'Repo: {repo_slug} | Files: {n_files} | Findings: {len(analysis)}',
            asset=repo_slug,
            points_deducted=0,
            remediation='',
        ))

        return findings

    # ── Web page extraction path ──
    url = base_url or target
    extractor = WebExtractor(timeout=timeout)
    page = extractor.extract(url)

    if page.get('error'):
        findings.append(Finding(
            title=f'Web extraction failed: {url}',
            severity='low', category='supply_chain',
            module='supply_chain',
            description=page['error'],
            evidence=page['error'],
            asset=asset, points_deducted=0,
            remediation='Verify the URL and network connectivity.',
        ))
        return findings

    # Analyze the extracted page
    analysis = analyzer.analyze({
        'url': url,
        'text_content': page.get('text_content', ''),
        'source_files': [],
        'workflows': [],
        'readme': '',
    })

    for af in analysis:
        sev = af.get('severity', 'info')
        pts = {'critical': 15, 'high': 10, 'medium': 5, 'low': 2, 'info': 0}
        findings.append(Finding(
            title=af.get('type', 'Web Content Finding'),
            severity=sev, category='supply_chain',
            module='supply_chain',
            description=af.get('description', ''),
            evidence=af.get('evidence', ''),
            asset=asset, points_deducted=pts.get(sev, 0),
            remediation=_remediation_for(af.get('type', '')),
        ))

    n_links = len(page.get('links', []))
    n_scripts = len(page.get('scripts', []))
    n_forms = len(page.get('forms', []))
    findings.append(Finding(
        title=f'Web content extracted: {url}',
        severity='info', category='supply_chain',
        module='supply_chain',
        description=(
            f'Extracted from {url}: {n_links} links, '
            f'{n_scripts} scripts, {n_forms} forms. '
            f'Title: "{page.get("title", "")}". '
            f'{len(analysis)} analysis findings.'
        ),
        evidence=f'URL: {url} | Links: {n_links} | Scripts: {n_scripts}',
        asset=asset, points_deducted=0,
        remediation='',
    ))

    return findings


def _remediation_for(finding_type: str) -> str:
    """Return a remediation suggestion for a finding type."""
    t = finding_type.lower()
    if 'secret' in t or 'key' in t or 'token' in t or 'password' in t:
        return (
            'Rotate the exposed credential immediately. Use environment variables '
            'or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager). '
            'Never commit secrets to version control.'
        )
    if 'tls' in t or 'ssl' in t:
        return 'Enable TLS certificate verification in production environments.'
    if 'eval' in t or 'exec' in t or 'deserialization' in t:
        return 'Avoid dynamic code execution. Use safe alternatives and validate all inputs.'
    if 'command injection' in t:
        return 'Avoid shell=True. Use argument lists and validate/sanitize all inputs.'
    if 'env' in t or 'security' in t:
        return 'Remove sensitive files from version control. Use .gitignore and pre-commit hooks.'
    if 'cors' in t:
        return 'Restrict CORS to specific trusted origins instead of using wildcards.'
    if 'debug' in t:
        return 'Disable debug mode in production deployments.'
    return ''


# ────────────────────────────────────────────────────────────────────────
# SCCAudit — High-level audit facade used by the CLI ``supply-chain`` command
# ────────────────────────────────────────────────────────────────────────

class SCCAudit:
    """Supply-chain audit controller for the CLI.

    Wraps :class:`WebExtractor`, :class:`GitHubScraper`, and
    :class:`SupplyChainAnalyzer` into two convenience entry-points:
    ``audit_github(owner/repo)`` and ``audit_url(url)``.
    """

    def __init__(self) -> None:
        self._scraper = GitHubScraper()
        self._analyzer = SupplyChainAnalyzer()
        self._extractor = WebExtractor()

    # ── GitHub audit ──────────────────────────────────────────────────

    def audit_github(self, repo_path: str, max_files: int = 50) -> Dict[str, Any]:
        """Audit a GitHub *repo_path* (``owner/repo``).

        Returns a dict with scraped files, analysis results, and metadata.
        """
        scrape_result = self._scraper.scrape_repo(repo_path, max_files=max_files)
        files = scrape_result.get("files", {})

        analysis = self._analyzer.analyze(files)
        workflows = scrape_result.get("workflows_found", 0)
        api_requests = scrape_result.get("api_requests", 0)

        return {
            "repo": repo_path,
            "files_scraped": len(files),
            "api_requests": api_requests,
            "workflows_found": workflows,
            "analysis": analysis,
        }

    # ── URL audit ──────────────────────────────────────────────────────

    def audit_url(self, url: str) -> Dict[str, Any]:
        """Audit a web page for supply-chain signals.

        Returns a dict with extracted page data (links, scripts, forms, etc.).
        """
        page = self._extractor.extract(url)
        return {
            "url": url,
            "page": page,
        }

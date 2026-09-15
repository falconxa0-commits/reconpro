"""Browser automation module.

Uses Playwright for headless browser operations:
- Screenshots
- Page crawling (spider)
- JS-rendered content extraction
- Form detection
- DOM-based secret scanning
"""
from __future__ import annotations

import os
import base64
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .http_layer import Finding

HAS_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    pass


def _require_playwright() -> None:
    if not HAS_PLAYWRIGHT:
        raise ImportError(
            "Playwright is required for browser features. "
            "Install with: pip install reconpro[browser] && playwright install"
        )


# DEAD CODE: consider removal
def take_screenshot(url: str, output_path: str = "", full_page: bool = True,
                     timeout: int = 30000) -> str:
    """Take a screenshot of a URL. Returns the file path."""
    _require_playwright()

    if not output_path:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        host = url.replace("https://", "").replace("http://", "").split("/")[0][:30]
        output_path = f"reconpro_screenshot_{host}_{ts}.png"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(url, timeout=timeout, wait_until="networkidle")
        page.screenshot(path=output_path, full_page=full_page)
        browser.close()

    return os.path.abspath(output_path)


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def spider(url: str, max_pages: int = 50, timeout: int = 15000) -> List[Dict[str, Any]]:
    """Crawl a website and return discovered pages.

    Returns list of {url, title, status, content_length} dicts.
    """
    _require_playwright()

    visited = set()
    to_visit = {url}
    pages = []
    base_domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        while to_visit and len(visited) < max_pages:
            current = to_visit.pop()
            if current in visited:
                continue
            visited.add(current)

            # Stay on same domain
            current_domain = current.replace("https://", "").replace("http://", "").split("/")[0]
            if current_domain != base_domain:
                continue

            try:
                resp = page.goto(current, timeout=timeout, wait_until="domcontentloaded")
                if not resp:
                    continue

                title = page.title()
                content = page.content()
                links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")

                pages.append({
                    "url": current,
                    "title": title,
                    "status": resp.status,
                    "content_length": len(content),
                })

                for link in links:
                    if link and link.startswith("http") and link not in visited:
                        to_visit.add(link.split("#")[0].split("?")[0])

            except Exception:
                continue

        browser.close()

    return pages


def scan_browser_secrets(url: str, timeout: int = 15000) -> List[Finding]:
    """Scan a page's JS bundle for secrets using a real browser."""
    _require_playwright()
    findings: List[Finding] = []
    host = url.replace("https://", "").replace("http://", "").split("/")[0]

    patterns = [
        (r'api[_-]?key["\':\s]*=["\']([\w\-]{20,})', "API key in page JS"),
        (r'firebase[_-]?config\s*=\s*\{[^}]*apiKey["\']:\s*["\']([^"\']+)', "Firebase API key"),
        (r'mapbox["\'].*?["\']\s*:\s*["\']([\w\-.]{20,})', "Mapbox token"),
        (r'stripe["\'].*?pk_[\w]+', "Stripe public key"),
        (r'google["\'].*?AIza[\w\-]{30,}', "Google API key"),
    ]

    import re

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(url, timeout=timeout, wait_until="networkidle")
            content = page.content()
        except Exception:
            content = ""
        browser.close()

    for pattern, title in patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            match = matches[0]
            masked = match[:8] + "..." + match[-4:] if len(match) > 12 else "***"
            findings.append(Finding(
                title=f"{title}: {masked}",
                severity="high", category="browser_secrets",
                module="browser",
                description=f"Secret found in rendered page content",
                evidence=f"URL: {url}",
                asset=host, points_deducted=8,
                remediation="Move secrets to server-side environment variables.",
            ))

    return findings


def open_browser(url: str) -> None:
    """Open a URL in the system's default browser."""
    import webbrowser
    webbrowser.open(url)

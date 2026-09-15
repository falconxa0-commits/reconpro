"""Module: WEAPONIZED REPORT DETECTOR — Tracking Element Analysis in Served Documents.

Detects if documents/reports served by a target contain tracking elements
that could be used for defensive analysis or intelligence gathering against
the consumer of the document.

7 detection categories:
  1. Tracking Pixel Detection — 1x1 tracking pixels, web bugs, beacon images
  2. Beaconing Detection in Documents — URLs in document metadata that phone home
  3. Steganographic Watermark Detection — invisible watermarks in served content
  4. Malicious Link Analysis — URLs leading to malicious/tracking destinations
  5. Document Metadata Analysis — hidden tracking metadata in served documents
  6. JavaScript Tracker Detection — analytics, fingerprinting, tracking scripts
  7. CSS-based Tracking Detection — visited link detection, font fingerprinting
"""
from __future__ import annotations

import base64
import hashlib
import re
import struct
import urllib.parse
from typing import Any, Dict, List, Optional

from ..http_layer import http_probe, Finding, default_limiter


# ═══════════════════════════════════════════════════════════════════════════
# Database 1: TRACKER_SIGNATURES
# Known analytics, tracking, and fingerprinting script signatures.
# ═══════════════════════════════════════════════════════════════════════════

TRACKER_SIGNATURES: List[Dict[str, Any]] = [
    # ── Major analytics platforms ──
    {
        "id": "TRK-001",
        "name": "Google Analytics",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"google-analytics\.com/(ga|analytics)\.js",
            r"googletagmanager\.com/gtag/js",
            r"google-analytics\.com/collect",
            r"_gaq\.push",
            r'''ga\(["']create["']''',
            r'''gtag\(["']config["']''',
            r"google-analytics\.com/mp/collect",
        ],
        "description": "Google Analytics tracking beacon for visitor analytics.",
    },
    {
        "id": "TRK-002",
        "name": "Facebook Pixel",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"connect\.facebook\.net/en_US/fbevents\.js",
            r"fbq\(['\"]init['\"]",
            r"facebook\.com/tr\?id=",
            r"fbq\(['\"]track['\"]",
        ],
        "description": "Facebook/Meta Pixel for conversion tracking and retargeting.",
    },
    {
        "id": "TRK-003",
        "name": "Hotjar",
        "category": "heatmaps",
        "severity": "medium",
        "patterns": [
            r"static\.hotjar\.com/c/hotjar-",
            r"hotjar\.com/h",
            r"hj\(['\"]trigger['\"]",
            r"_hjSettings",
        ],
        "description": "Hotjar for heatmaps, session recording, and funnel analytics.",
    },
    {
        "id": "TRK-004",
        "name": "Mixpanel",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"cdn\.mixpanel\.com",
            r"mixpanel\.com/track",
            r"mixpanel\.track\(",
            r"api\.mixpanel\.com/track",
        ],
        "description": "Mixpanel user analytics and event tracking.",
    },
    {
        "id": "TRK-005",
        "name": "Amplitude",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"cdn\.amplitude\.com",
            r"amplitude\.com/logger",
            r"amplitude\.getInstance\(\)\.logEvent",
            r"api2\.amplitude\.com/2/httpapi",
        ],
        "description": "Amplitude product analytics and user behavior tracking.",
    },
    {
        "id": "TRK-006",
        "name": "Segment",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"cdn\.segment\.com/analytics\.js",
            r"segment\.io/v1/(track|identify|page)",
            r"analytics\.load\(",
        ],
        "description": "Segment analytics hub routing events to multiple destinations.",
    },
    {
        "id": "TRK-007",
        "name": "Matomo / Piwik",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"matomo\.\w+/matomo\.js",
            r"piwik\.\w+/piwik\.js",
            r"matomo\.php\?action_name=",
            r"_paq\.push",
        ],
        "description": "Matomo/Piwik self-hosted web analytics platform.",
    },
    # ── Fingerprinting libraries ──
    {
        "id": "TRK-008",
        "name": "FingerprintJS",
        "category": "fingerprinting",
        "severity": "high",
        "patterns": [
            r"openfpcdn\.io/fingerprintjs",
            r"fingerprintjs[/_]v",
            r"Fingerprint2\(",
            r"FingerprintJS\.load",
            r"fpjs\.io",
        ],
        "description": "Browser fingerprinting library for device identification.",
    },
    {
        "id": "TRK-009",
        "name": "Canvas Fingerprinting",
        "category": "fingerprinting",
        "severity": "high",
        "patterns": [
            r"\.toDataURL\(['\"]image/",
            r"canvas\.getContext\(['\"]2d['\"]\)",
            r"getImageData\(0\s*,\s*0",
            r"isPointInPath",
            r"measureText\(",
        ],
        "description": "Canvas-based browser fingerprinting technique.",
    },
    {
        "id": "TRK-010",
        "name": "WebGL Fingerprinting",
        "category": "fingerprinting",
        "severity": "high",
        "patterns": [
            r"getParameter\([A-Z_]+RENDERER",
            r"getExtension\(['\"](WEBGL_debug_renderer|ANGLE_instanced)",
            r"WEBGL_debug_renderer_info",
            r"getSupportedExtensions\(\)",
            r"drawingBufferWidth",
        ],
        "description": "WebGL-based hardware fingerprinting via GPU parameters.",
    },
    {
        "id": "TRK-011",
        "name": "AudioContext Fingerprinting",
        "category": "fingerprinting",
        "severity": "high",
        "patterns": [
            r"AudioContext\(",
            r"webkitAudioContext\(",
            r"createOscillator\(",
            r"createDynamicsCompressor\(",
            r"createScriptProcessor\(",
            r"onAudioProcess",
        ],
        "description": "AudioContext-based browser fingerprinting via audio stack.",
    },
    {
        "id": "TRK-012",
        "name": "Font Enumeration Fingerprinting",
        "category": "fingerprinting",
        "severity": "high",
        "patterns": [
            r"document\.fonts",
            r"check\(['\"]\\d+px",
            r"fontmetrics",
            r"measure\(\s*['\"]\w+['\"]",
            r"getComputedStyle.*fontFamily",
        ],
        "description": "System font enumeration for fingerprinting.",
    },
    # ── Tracking pixels / web bugs ──
    {
        "id": "TRK-013",
        "name": "Email Tracking Pixel",
        "category": "tracking-pixel",
        "severity": "medium",
        "patterns": [
            r"[?&](utm_|open|email|mail|cid|uid|recipient)=",
            r"(opens|clicks|reads?)\.track",
            r"pixel\.(track|log|beacon|ping)",
            r"(email|mail)\.open",
        ],
        "description": "Email open/read tracking via invisible pixel.",
    },
    {
        "id": "TRK-014",
        "name": "Customer.io",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"track\.customer\.io",
            r"cdp\.customer\.io",
            r"_cio\s*=\s*",
        ],
        "description": "Customer.io email and behavioral analytics tracking.",
    },
    {
        "id": "TRK-015",
        "name": "HubSpot",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"js\.hs-(analytics|forms|scripts)\.net",
            r"track\.hsforms\.net",
            r"_hsq\.push",
        ],
        "description": "HubSpot marketing and lead tracking.",
    },
    {
        "id": "TRK-016",
        "name": "Plausible Analytics",
        "category": "analytics",
        "severity": "low",
        "patterns": [
            r"plausible\.io/js/script\.js",
            r"plausible\.io/api/event",
        ],
        "description": "Plausible privacy-focused analytics (still a tracker).",
    },
    {
        "id": "TRK-017",
        "name": "PostHog",
        "category": "analytics",
        "severity": "medium",
        "patterns": [
            r"assets\.posthog\.com",
            r"posthog\.com/capture",
            r"posthog\(['\"]capture['\"]",
        ],
        "description": "PostHog product analytics with session recording.",
    },
    {
        "id": "TRK-018",
        "name": "Clarity (Microsoft)",
        "category": "heatmaps",
        "severity": "medium",
        "patterns": [
            r"clarity\.ms/tag",
            r"clarity\.ms/s/",
            r"""clarity\(["']""",
        ],
        "description": "Microsoft Clarity for heatmaps and session recording.",
    },
    {
        "id": "TRK-019",
        "name": "FullStory",
        "category": "session-recording",
        "severity": "high",
        "patterns": [
            r"fullstory\.com/s/fs\.js",
            r"fullstory\.io/api",
            r"_fs_namespace",
            r"FS\.identify",
        ],
        "description": "FullStory session recording and replay platform.",
    },
    {
        "id": "TRK-020",
        "name": "Crazy Egg",
        "category": "heatmaps",
        "severity": "medium",
        "patterns": [
            r"cetrk\.com",
            r"script\.crazyegg\.com",
            r"CE\.Snippet",
        ],
        "description": "Crazy Egg heatmap, scrollmap, and confetti tracking.",
    },
    # ── Ad networks & retargeting ──
    {
        "id": "TRK-021",
        "name": "Google Ads / DoubleClick",
        "category": "advertising",
        "severity": "medium",
        "patterns": [
            r"doubleclick\.net",
            r"googleadservices\.com/pagead",
            r"googleads\.g\.doubleclick\.net",
            r"googlesyndication\.com",
        ],
        "description": "Google Ads/DoubleClick retargeting and conversion tracking.",
    },
    {
        "id": "TRK-022",
        "name": "LinkedIn Insight Tag",
        "category": "advertising",
        "severity": "medium",
        "patterns": [
            r"snap\.licdn\.com/li\.lms-analytics/insight\.min\.js",
            r"px\.ads\.linkedin\.com/collect",
            r"_linkedin_partner_id",
        ],
        "description": "LinkedIn advertising conversion tracking pixel.",
    },
    # ── Privacy-invasive / surveillance-grade ──
    {
        "id": "TRK-023",
        "name": "Mouse/Keyboard Fingerprinting",
        "category": "fingerprinting",
        "severity": "critical",
        "patterns": [
            r"on(mouse(move|down|up|wheel|click))",
            r"addEventListener\(['\"]mouse",
            r"event\.(clientX|clientY|pageX|pageY|screenX|screenY|movementX|movementY)",
            r"\.mousemove|\.mousedown|\.mouseup",
        ],
        "description": "Behavioral biometrics: mouse movement fingerprinting.",
    },
    {
        "id": "TRK-024",
        "name": "Keystroke Dynamics Fingerprinting",
        "category": "fingerprinting",
        "severity": "critical",
        "patterns": [
            r"on(key(down|up|press))",
            r"addEventListener\(['\"]key",
            r"event\.(keyCode|key|which|code)",
            r"typing.*pattern",
            r"keystroke.*dynamics",
        ],
        "description": "Keystroke dynamics analysis for user identification.",
    },
    {
        "id": "TRK-025",
        "name": "Screen/Window Fingerprinting",
        "category": "fingerprinting",
        "severity": "high",
        "patterns": [
            r"screen\.(width|height|colorDepth|pixelDepth|availWidth|availHeight)",
            r"window\.(innerWidth|innerHeight|outerWidth|outerHeight)",
            r"devicePixelRatio",
            r"(screen|window)\.orientation",
        ],
        "description": "Screen and window property enumeration for fingerprinting.",
    },
    {
        "id": "TRK-026",
        "name": "Battery Fingerprinting",
        "category": "fingerprinting",
        "severity": "medium",
        "patterns": [
            r"navigator\.getBattery",
            r"battery\.(charging|level|chargingTime|dischargingTime)",
        ],
        "description": "Battery API fingerprinting (deprecated but still used).",
    },
    {
        "id": "TRK-027",
        "name": "Bluetooth/USB Fingerprinting",
        "category": "fingerprinting",
        "severity": "high",
        "patterns": [
            r"navigator\.bluetooth",
            r"navigator\.usb",
            r"requestDevice",
            r"getDevices",
        ],
        "description": "Web Bluetooth/USB device enumeration for hardware fingerprinting.",
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# Database 2: BEACON_PATTERNS
# URL patterns and response behaviors that indicate beaconing / phone-home.
# ═══════════════════════════════════════════════════════════════════════════

BEACON_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "BCN-001",
        "name": "Classic Web Bug (1x1 GIF)",
        "category": "tracking-pixel",
        "severity": "high",
        "patterns": [
            r"""(?:width|height)\s*[=:]+\s*["\']?1["\']?""",
            r"""(?:width|height)\s*[=:]+\s*["\']?1\s["\']?(?:width|height)\s*[=:]+\s*["\']?1""",
            r"""<img[^>]+(?:width|height)\s*=\s*["\']?1["\']?[^>]+(?:width|height)\s*=\s*["\']?1""",
        ],
        "url_patterns": [
            r"\.(gif|png|jpg|jpeg|svg|webp)[?&]",
            r"/pixel",
            r"/beacon",
            r"/track",
            r"/log",
            r"/ping",
            r"/collect",
            r"/hit",
            r"/record",
            r"/impression",
            r"/view",
        ],
        "description": "Invisible 1x1 pixel image used to track document access.",
    },
    {
        "id": "BCN-002",
        "name": "JavaScript Beacon (fetch/XHR)",
        "category": "js-beacon",
        "severity": "high",
        "patterns": [
            r"(fetch|XMLHttpRequest)\s*\(",
            r"new\s+Image\(\)\.src\s*=",
            r"\.send\(\s*(?:null|undefined|'')?\s*\)",
            r"navigator\.sendBeacon\(",
            r"\.(postMessage|send)\s*\(",
        ],
        "url_patterns": [
            r"/event",
            r"/log",
            r"/track",
            r"/report",
            r"/beacon",
            r"/collect",
            r"/batch",
            r"/ingest",
            r"/api/v\d/(event|track|log)",
        ],
        "description": "JavaScript-based beacon using fetch, XHR, sendBeacon, or Image.src.",
    },
    {
        "id": "BCN-003",
        "name": "CSS-based Beacon",
        "category": "css-beacon",
        "severity": "medium",
        "patterns": [
            r"background(-image)?\s*:\s*url\([^)]*\)",
            r"@import\s+url\([^)]*\)",
            r"content\s*:\s*url\([^)]*\)",
            r"src\s*:\s*url\([^)]*\)",
            r"list-style-image\s*:\s*url\([^)]*\)",
        ],
        "url_patterns": [
            r"/pixel",
            r"/track",
            r"/css-beacon",
            r"/log",
            r"\.css[?&]",
        ],
        "description": "CSS properties used to trigger HTTP requests as beacons.",
    },
    {
        "id": "BCN-004",
        "name": "Document Metadata Phone-Home",
        "category": "document-beacon",
        "severity": "critical",
        "patterns": [
            r"""<meta[^>]+http-equiv=["']refresh["'][^>]+url""",
            r'''<meta[^>]+content=["']\d+;\s*url=''',
            r'''<link[^>]+rel=["']ping["']''',
            r'''<a[^>]+ping=["']''',
            r'''ping=\s*["']https?://''',
            r"<object[^>]+data=",
            r"<embed[^>]+src=",
            r"<iframe[^>]+src=",
        ],
        "url_patterns": [
            r"/phone-home",
            r"/callback",
            r"/notify",
            r"/webhook",
            r"/exfil",
            r"/c2",
            r"/command",
            r"/register-open",
            r"/doc-viewed",
            r"/report-accessed",
        ],
        "description": "HTML metadata or elements that trigger automatic outbound requests.",
    },
    {
        "id": "BCN-005",
        "name": "DNS-based Beacon",
        "category": "dns-beacon",
        "severity": "critical",
        "patterns": [
            r"new\s+Image\(\)\.src\s*=\s*['\"]https?://[a-f0-9]+\.",
            r"(fetch|XMLHttpRequest)\s*\(['\"]https?://[a-f0-9]{8,}\.",
            r"\.src\s*=\s*['\"]https?://[a-f0-9]{8,}\.",
        ],
        "url_patterns": [
            r"^https?://[a-f0-9]{8,}\.",
            r"^https?://[a-z0-9]{16,}\.",
            r"^https?://[a-f0-9-]{32,}\.",
        ],
        "description": "Encoded data embedded in DNS/HTTP hostnames for C2 exfiltration.",
    },
    {
        "id": "BCN-006",
        "name": "WebSocket Beacon",
        "category": "ws-beacon",
        "severity": "high",
        "patterns": [
            r"""new\s+WebSocket\(\s*["']wss?://""",
            r"\.on(message|open|close)\s*=",
            r"socket\.io",
            r"SockJS",
            r"ws://|wss://",
        ],
        "url_patterns": [
            r"/ws",
            r"/socket",
            r"/realtime",
            r"/live",
            r"/stream",
            r"/events",
        ],
        "description": "WebSocket connection used for real-time tracking/telemetry.",
    },
    {
        "id": "BCN-007",
        "name": "Ping Attribute Beacon",
        "category": "html-beacon",
        "severity": "high",
        "patterns": [
            r"""<a[^>]+ping\s*=\s*["\']https?://[^"\']+>""",
            r"""ping\s*=\s*["\']https?://[^"\']+""",
        ],
        "url_patterns": [],
        "description": "HTML anchor ping attribute triggers notification on click.",
    },
    {
        "id": "BCN-008",
        "name": "Prefetch/Prerender Beacon",
        "category": "resource-beacon",
        "severity": "medium",
        "patterns": [
            r"""<link[^>]+rel\s*=\s*["\'](?:prefetch|prerender|preload)["\']""",
            r"""rel\s*=\s*["\'](?:prefetch|prerender)["\']""",
        ],
        "url_patterns": [
            r"/track",
            r"/log",
            r"/beacon",
            r"/pixel",
        ],
        "description": "Resource hints used as covert beacons via prefetch/prerender.",
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# Database 3: FINGERPRINT_TECHNIQUES
# Known browser/system fingerprinting techniques.
# ═══════════════════════════════════════════════════════════════════════════

FINGERPRINT_TECHNIQUES: List[Dict[str, Any]] = [
    {
        "id": "FP-001",
        "name": "Canvas Fingerprinting",
        "category": "canvas",
        "severity": "high",
        "indicators": [
            r"canvas\.getContext\(['\"]2d['\"]\)",
            r"\.fillText\(",
            r"\.toDataURL\(",
            r"\.toBlob\(",
            r"getImageData\(",
            r"isPointInPath\(",
            r"createLinearGradient|createRadialGradient",
        ],
        "description": "Renders hidden text/shapes to a canvas and hashes the pixel output to identify the browser/GPU combo.",
    },
    {
        "id": "FP-002",
        "name": "WebGL Fingerprinting",
        "category": "webgl",
        "severity": "high",
        "indicators": [
            r"getParameter\([A-Z_]+RENDERER",
            r"getParameter\([A-Z_]+VENDOR",
            r"WEBGL_debug_renderer_info",
            r"getSupportedExtensions\(",
            r"getExtension\(['\"](WEBGL|ANGLE)",
            r"SHADING_LANGUAGE_VERSION",
            r"drawingBuffer(Width|Height)",
            r"createBuffer|bindBuffer|bufferData",
            r"vertexAttribPointer",
            r"drawArrays|drawElements",
        ],
        "description": "Enumerates WebGL parameters (renderer, vendor, extensions) for GPU hardware fingerprint.",
    },
    {
        "id": "FP-003",
        "name": "AudioContext Fingerprinting",
        "category": "audio",
        "severity": "high",
        "indicators": [
            r"AudioContext\(",
            r"webkitAudioContext\(",
            r"createOscillator\(",
            r"createDynamicsCompressor\(",
            r"createScriptProcessor\(",
            r"createAnalyser\(",
            r"onAudioProcess",
            r"start\(\s*0\s*\)",
            r"oscillator\.frequency",
            r"destination\.channelCount",
        ],
        "description": "Uses the Audio API's processing pipeline to generate a unique audio fingerprint.",
    },
    {
        "id": "FP-004",
        "name": "Font Enumeration",
        "category": "fonts",
        "severity": "high",
        "indicators": [
            r"document\.fonts",
            r"\.check\(['\"]",
            r"@font-face",
            r"FontFace\(",
            r"fonts\.ready",
            r"fonts\.load\(",
            r"measureText\(",
            r"offsetWidth|offsetHeight",
            r"getComputedStyle.*font",
        ],
        "description": "Enumerates installed system fonts by measuring rendered text dimensions.",
    },
    {
        "id": "FP-005",
        "name": "Navigator/UA Fingerprinting",
        "category": "navigator",
        "severity": "medium",
        "indicators": [
            r"navigator\.(userAgent|platform|vendor|language|languages)",
            r"navigator\.(hardwareConcurrency|maxTouchPoints|deviceMemory)",
            r"navigator\.(cookieEnabled|doNotTrack|webdriver)",
            r"navigator\.(plugins|mimeTypes)",
            r"navigator\.(connection|network|onLine)",
            r"navigator\.(pdfViewerEnabled|pdfViewer)",
            r"navigator\.(storage|permissions)",
        ],
        "description": "Collects navigator properties to build a device/browser profile.",
    },
    {
        "id": "FP-006",
        "name": "Screen Fingerprinting",
        "category": "screen",
        "severity": "medium",
        "indicators": [
            r"screen\.(width|height|colorDepth|pixelDepth)",
            r"screen\.avail(Width|Height)",
            r"window\.(innerWidth|innerHeight|outerWidth|outerHeight)",
            r"devicePixelRatio",
            r"matchMedia\(",
            r"(screen|window)\.orientation",
            r"visualViewport",
        ],
        "description": "Collects screen dimensions, color depth, and pixel ratio for fingerprinting.",
    },
    {
        "id": "FP-007",
        "name": "Timezone/Locale Fingerprinting",
        "category": "timezone",
        "severity": "medium",
        "indicators": [
            r"Intl\.(DateTimeFormat|NumberFormat|Collator)",
            r"getTimezoneOffset\(",
            r"resolvedOptions\(\)",
            r"navigator\.(language|languages)",
            r"new\s+Date\(\)\.getTimezoneOffset",
        ],
        "description": "Uses timezone, locale, and formatting preferences to narrow user identity.",
    },
    {
        "id": "FP-008",
        "name": "Storage Fingerprinting",
        "category": "storage",
        "severity": "medium",
        "indicators": [
            r"localStorage\.(getItem|setItem|length)",
            r"sessionStorage\.(getItem|setItem|length)",
            r"indexedDB",
            r"openDatabase",
            r"caches\.(open|keys|match)",
            r"navigator\.(storage|persisted|estimate)",
            r"FileSystem",
            r"requestPersistentStorage",
        ],
        "description": "Probes storage APIs and quotas to identify the user/browser.",
    },
    {
        "id": "FP-009",
        "name": "Media Device Fingerprinting",
        "category": "media",
        "severity": "high",
        "indicators": [
            r"navigator\.mediaDevices",
            r"enumerateDevices\(",
            r"getUserMedia\(",
            r"device\.kind",
            r"device\.deviceId",
            r"device\.groupId",
        ],
        "description": "Enumerates connected media devices (cameras, mics, speakers) for hardware fingerprint.",
    },
    {
        "id": "FP-010",
        "name": "Battery/Connection Fingerprinting",
        "category": "hardware",
        "severity": "medium",
        "indicators": [
            r"navigator\.getBattery",
            r"navigator\.connection",
            r"navigator\.network",
            r"battery\.(charging|level|chargingTime|dischargingTime)",
            r"connection\.(effectiveType|downlink|rtt|saveData)",
        ],
        "description": "Uses Battery and Network Information APIs for device profiling.",
    },
    {
        "id": "FP-011",
        "name": "CSS Visited-Link Detection",
        "category": "css-tracking",
        "severity": "high",
        "indicators": [
            r":visited\s*",
            r"getComputedStyle.*:visited",
            r"a\s*:\s*visited\s*\{",
            r"querySelectorAll.*:visited",
            r"\[href\]\\s*:\\s*visited",
        ],
        "description": "Detects which links a user has visited by measuring computed styles (history sniffing).",
    },
    {
        "id": "FP-012",
        "name": "CSS Font-Loading Fingerprinting",
        "category": "css-tracking",
        "severity": "high",
        "indicators": [
            r"@font-face",
            r"FontFace\(",
            r"document\.fonts\.(load|check|ready)",
            r"unicode-range\s*:",
            r"font-display\s*:",
            r"font-family\s*:\s*['\"]?[A-Z][a-z]+",
        ],
        "description": "Probes which fonts are available on the system by loading and measuring fallback behavior.",
    },
    {
        "id": "FP-013",
        "name": "ClientRect/Position Fingerprinting",
        "category": "dom",
        "severity": "medium",
        "indicators": [
            r"getBoundingClientRect\(",
            r"getClientRects\(",
            r"elementFromPoint\(",
            r"scrollPosition",
            r"pageXOffset|pageYOffset",
            r"scrollX|scrollY",
        ],
        "description": "Measures element positions and scroll offsets which vary by browser/OS/font rendering.",
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# Compiled regexes (built once at module load)
# ═══════════════════════════════════════════════════════════════════════════

# Pre-compile all pattern lists
_compiled_trackers: List[Dict[str, Any]] = []
for _t in TRACKER_SIGNATURES:
    _compiled_trackers.append({
        **_t,
        "compiled": [re.compile(p, re.IGNORECASE) for p in _t["patterns"]],
    })

_compiled_beacons: List[Dict[str, Any]] = []
for _b in BEACON_PATTERNS:
    _entry = {
        **_b,
        "compiled_patterns": [re.compile(p, re.IGNORECASE) for p in _b["patterns"]],
        "compiled_urls": [re.compile(p, re.IGNORECASE) for p in _b.get("url_patterns", [])],
    }
    _compiled_beacons.append(_entry)

_compiled_fingerprints: List[Dict[str, Any]] = []
for _f in FINGERPRINT_TECHNIQUES:
    _compiled_fingerprints.append({
        **_f,
        "compiled": [re.compile(p, re.IGNORECASE) for p in _f["indicators"]],
    })

# General-purpose compiled patterns
_RE_TAG: re.Pattern = re.compile(r"<[^>]+>", re.IGNORECASE | re.DOTALL)
_RE_SCRIPT: re.Pattern = re.compile(
    r"<script[^>]*>(.*?)</script>", re.IGNORECASE | re.DOTALL
)
_RE_STYLE: re.Pattern = re.compile(
    r"<style[^>]*>(.*?)</style>", re.IGNORECASE | re.DOTALL
)
_RE_LINK_HREF: re.Pattern = re.compile(
    r"""(?:href|src|action|data|ping)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_RE_META_URL: re.Pattern = re.compile(
    r"""<meta[^>]+(?:http-equiv|content|name)[^>]+url\s*=\s*([^"'\s>]+)""",
    re.IGNORECASE,
)
_RE_IMG_TAG: re.Pattern = re.compile(
    r"<img\s+([^>]+?)/?>", re.IGNORECASE
)
_RE_DIM_ATTR: re.Pattern = re.compile(
    r"""(?:width|height)\s*=\s*["\']?(\d+)["\']?""", re.IGNORECASE
)
_RE_CSS_URL: re.Pattern = re.compile(
    r"""url\(\s*["']?([^"'\)]+)["']?\s*\)""", re.IGNORECASE
)
_RE_PING_ATTR: re.Pattern = re.compile(
    r"""ping\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_RE_REFRESH_META: re.Pattern = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+content\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_RE_IFRAME_SRC: re.Pattern = re.compile(
    r"""<iframe\s+[^>]*src\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_RE_OBJECT_DATA: re.Pattern = re.compile(
    r"""<object\s+[^>]*data\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_RE_EMBED_SRC: re.Pattern = re.compile(
    r"""<embed\s+[^>]*src\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_RE_BASE64_IMG: re.Pattern = re.compile(
    r"""<img[^>]+src\s*=\s*["']data:image/[^"']+["']""", re.IGNORECASE
)
_RE_BASE64_DATA_URL: re.Pattern = re.compile(
    r"data:[a-zA-Z0-9/+.-]+;base64,([A-Za-z0-9+/=]+)", re.IGNORECASE
)
_RE_HEX_STRING: re.Pattern = re.compile(r"[0-9a-fA-F]{32,}")
_RE_SUSPICIOUS_PARAMS: re.Pattern = re.compile(
    r"[?&](?:utm_|cid|uid|sid|session|token|key|id|ref|source|campaign|medium|content)="
    r"[a-zA-Z0-9_\-]{8,}", re.IGNORECASE,
)
_RE_EXTERNAL_URL: re.Pattern = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_RE_JS_FETCH_XHR: re.Pattern = re.compile(
    r"(?:fetch|new\s+XMLHttpRequest|\.send\(|navigator\.sendBeacon)\s*\(",
    re.IGNORECASE,
)
_RE_WS_CONN: re.Pattern = re.compile(
    r"""new\s+WebSocket\(\s*["']([^"']+)["']""", re.IGNORECASE
)
_RE_VISITED: re.Pattern = re.compile(
    r":visited", re.IGNORECASE
)
_RE_FONT_FACE: re.Pattern = re.compile(
    r"@font-face", re.IGNORECASE
)
_RE_INVISIBLE_STYLE: re.Pattern = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|"
    r"position\s*:\s*absolute[^;]*left\s*:\s*-[\d]+|"
    r"width\s*:\s*(?:0|1)px|height\s*:\s*(?:0|1)px|"
    r"overflow\s*:\s*hidden|clip\s*:\s*rect\(0|"
    r"font-size\s*:\s*0|color\s*:\s*transparent|"
    r"z-index\s*:\s*-[\d]+)",
    re.IGNORECASE,
)
_RE_DOC_METADATA_FIELDS: re.Pattern = re.compile(
    r"(?:author|creator|producer|title|subject|keywords|description|"
    r"company|manager|category|comments|last-author|"
    r"revision-number|version|created|modified|last-modified|"
    r"content-type|generator|x-generator|template|"
    r"tracking-id|correlation-id|x-request-id|x-correlation-id)"
    r"""\s*[=:]+\s*["']?([^"'\n]+)["']?""",
    re.IGNORECASE,
)
_RE_UTM_PARAMS: re.Pattern = re.compile(
    r"[?&]utm_(source|medium|campaign|term|content|id)=[^&\s'\"<>]+",
    re.IGNORECASE,
)
_RE_CLICK_ID: re.Pattern = re.compile(
    r"[?&](?:fbclid|gclid|msclkid|dclid|mc_eid|"
    r"_ga|_gl|_gid|igshid|twclid|ttclid|li_fat_id|"
    r"yclid|vero_id|_hsenc|_hsmi|__hstc|__hsfp|"
    r"otc|oly_anon_id|oly_enc_id|"
    r"wickedid|_openstat|ymclid|ad_id|"
    r"adgroup|creative|placement|"
    r"subid1|subid2|subid3|subid4|subid5)=[^&\s'\"<>]+",
    re.IGNORECASE,
)
_RE_SUSPICIOUS_HOST: re.Pattern = re.compile(
    r"(?:track|pixel|beacon|log|collect|hit|ping|analytics|"
    r"stats?|metric|telemetry|report|event|ingest|batch|"
    r"spy|monitor|watch|trace|signal|callback|notify|webhook|"
    r"exfil|c2|command|phone-home|register|impression|view)"
    r"(?:\.|/|\\-)",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════════

MODULE_NAME = "weaponized_report"


def _is_same_domain(url: str, base_url: str) -> bool:
    """Check if a URL belongs to the same domain as the target."""
    try:
        parsed_url = urllib.parse.urlparse(url)
        parsed_base = urllib.parse.urlparse(base_url)
        return parsed_url.hostname == parsed_base.hostname
    except Exception:
        return False


def _is_external_url(url: str) -> bool:
    """Check if a URL is an absolute external URL."""
    return bool(re.match(r"^https?://", url, re.IGNORECASE))


def _extract_domain(url: str) -> str:
    """Extract hostname from a URL."""
    try:
        return urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return ""


def _normalize_url(base: str, url: str) -> str:
    """Resolve a potentially relative URL against a base."""
    try:
        return urllib.parse.urljoin(base, url)
    except Exception:
        return url


def _truncate_evidence(text: str, max_len: int = 500) -> str:
    """Truncate evidence text to a reasonable length."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "... [truncated]"


def _severity_points(severity: str) -> int:
    """Map severity to point deductions."""
    return {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 0,
    }.get(severity, 5)


def _severity_dread(severity: str) -> float:
    """Map severity to DREAD score."""
    return {
        "critical": 0.9,
        "high": 0.7,
        "medium": 0.5,
        "low": 0.3,
        "info": 0.1,
    }.get(severity, 0.4)


def _extract_urls_from_text(text: str) -> List[str]:
    """Extract all URLs from a text body."""
    return list(dict.fromkeys(_RE_EXTERNAL_URL.findall(text)))


def _count_matching_patterns(
    text: str, patterns: List[re.Pattern]
) -> List[str]:
    """Return matched strings for all matching patterns."""
    matches: List[str] = []
    seen: set = set()
    for pat in patterns:
        for m in pat.finditer(text):
            matched_text = m.group(0)
            # Truncate long matches for evidence
            if len(matched_text) > 200:
                matched_text = matched_text[:200] + "..."
            if matched_text not in seen:
                seen.add(matched_text)
                matches.append(matched_text)
    return matches


def _analyze_document_binary_header(
    body: str, content_type: str
) -> List[Finding]:
    """Detect steganographic watermarks in binary document formats.

    Looks for zero-width characters, unusual byte sequences, and
    encoding artifacts in document content.
    """
    findings: List[Finding] = []
    if not body:
        return findings

    # ── Zero-width character detection ──
    zwc_map = {
        "\u200b": "ZERO WIDTH SPACE (U+200B)",
        "\u200c": "ZERO WIDTH NON-JOINER (U+200C)",
        "\u200d": "ZERO WIDTH JOINER (U+200D)",
        "\ufeff": "BOM / ZERO WIDTH NO-BREAK SPACE (U+FEFF)",
        "\u2060": "WORD JOINER (U+2060)",
        "\u2061": "FUNCTION APPLICATION (U+2061)",
        "\u2062": "INVISIBLE TIMES (U+2062)",
        "\u2063": "INVISIBLE SEPARATOR (U+2063)",
        "\u2064": "INVISIBLE PLUS (U+2064)",
        "\u180e": "MONGOLIAN VOWEL SEPARATOR (U+180E)",
        "\u202a": "LEFT-TO-RIGHT EMBEDDING (U+202A)",
        "\u202b": "RIGHT-TO-LEFT EMBEDDING (U+202B)",
        "\u202c": "POP DIRECTIONAL FORMATTING (U+202C)",
        "\u202d": "LEFT-TO-RIGHT OVERRIDE (U+202D)",
        "\u202e": "RIGHT-TO-LEFT OVERRIDE (U+202E)",
        "\u206a": "INHIBIT SYMMETRIC SWAPPING (U+206A)",
        "\u206b": "ACTIVATE SYMMETRIC SWAPPING (U+206B)",
        "\u206c": "INHIBIT ARABIC FORM SHAPING (U+206C)",
        "\u206d": "ACTIVATE ARABIC FORM SHAPING (U+206D)",
        "\u206e": "NATIONAL DIGIT SHAPES (U+206E)",
        "\u206f": "NOMINAL DIGIT SHAPES (U+206F)",
    }

    found_zwc: List[str] = []
    zwc_count = 0
    for char, name in zwc_map.items():
        count = body.count(char)
        if count > 0:
            found_zwc.append(f"{name} x{count}")
            zwc_count += count

    if found_zwc:
        # Determine if this is just BOM at the start or actual steganography
        is_bom_only = (
            zwc_count == 1
            and body.startswith("\ufeff")
            and "\u200b" not in body
            and "\u200c" not in body
            and "\u200d" not in body
        )
        severity = "info" if is_bom_only else "high"
        if not is_bom_only:
            findings.append(Finding(
                title="Steganographic Watermark — Invisible Characters Detected",
                severity=severity,
                category="stego-watermark",
                module=MODULE_NAME,
                description=(
                    f"Document contains {zwc_count} invisible/zero-width characters that can "
                    f"encode hidden data (steganographic watermarking). Found: "
                    f"{', '.join(found_zwc[:5])}. "
                    f"{'This may be a legitimate BOM.' if is_bom_only else 'This strongly suggests intentional data hiding.'}"
                ),
                evidence=f"ZWC types: {'; '.join(found_zwc[:5])}; total count: {zwc_count}",
                asset="",
                points_deducted=12 if not is_bom_only else 0,
                remediation=(
                    "Sanitize documents to remove zero-width characters before distribution. "
                    "Use unicode-normalization (NFKC) to strip invisible chars."
                ),
                dread_score=0.7 if not is_bom_only else 0.1,
            ))

    # ── Base64-encoded image data (possible hidden payload) ──
    b64_matches = _RE_BASE64_DATA_URL.findall(body)
    suspicious_b64: List[str] = []
    for b64data in b64_matches:
        if len(b64data) < 64:
            continue
        try:
            decoded = base64.b64decode(b64data)
            # Check if decoded content has unusual structure
            # Very large base64 images with little visible content is suspicious
            if len(decoded) > 50000:
                suspicious_b64.append(
                    f"base64 image: {len(decoded)} bytes decoded from {len(b64data)} chars"
                )
        except Exception:
            # Invalid base64 — could be intentional obfuscation
            if len(b64data) > 100:
                suspicious_b64.append(f"invalid base64 data: {len(b64data)} chars")

    if suspicious_b64:
        findings.append(Finding(
            title="Steganographic Watermark — Suspicious Base64-Embedded Content",
            severity="medium",
            category="stego-watermark",
            module=MODULE_NAME,
            description=(
                f"Document contains {len(suspicious_b64)} suspicious base64-embedded data blocks. "
                f"Large or malformed base64 in images can hide tracking payloads."
            ),
            evidence=_truncate_evidence("; ".join(suspicious_b64[:3])),
            asset="",
            points_deducted=8,
            remediation="Inspect base64-embedded images for hidden payloads. Compare against known-good versions.",
            dread_score=0.5,
        ))

    # ── Trailing whitespace steganography ──
    lines = body.split("\n")
    trailing_space_lines = 0
    trailing_tab_lines = 0
    for line in lines:
        stripped = line.rstrip("\r")
        if stripped != stripped.rstrip():
            trailing_space_lines += 1
        if stripped != stripped.rstrip("\t"):
            trailing_tab_lines += 1

    total_lines = len(lines)
    if total_lines > 10:
        trailing_ratio = (trailing_space_lines + trailing_tab_lines) / total_lines
        if trailing_ratio > 0.3 and (trailing_space_lines + trailing_tab_lines) > 20:
            findings.append(Finding(
                title="Steganographic Watermark — Trailing Whitespace Encoding",
                severity="medium",
                category="stego-watermark",
                module=MODULE_NAME,
                description=(
                    f"{trailing_ratio:.1%} of lines ({trailing_space_lines} spaces, "
                    f"{trailing_tab_lines} tabs out of {total_lines}) have trailing whitespace. "
                    f"Trailing whitespace can encode binary data (space=0, tab=1 or vice versa)."
                ),
                evidence=(
                    f"Trailing spaces: {trailing_space_lines}, trailing tabs: {trailing_tab_lines}, "
                    f"total lines: {total_lines}, ratio: {trailing_ratio:.2%}"
                ),
                asset="",
                points_deducted=6,
                remediation="Strip trailing whitespace from documents. Use automated linters to prevent whitespace steganography.",
                dread_score=0.4,
            ))

    # ── Line-ending inconsistency (CRLF vs LF steganography) ──
    crlf_count = body.count("\r\n")
    lf_only = body.replace("\r\n", "").count("\n")
    if crlf_count > 0 and lf_only > 0 and total_lines > 20:
        mixed_ratio = crlf_count / (crlf_count + lf_only)
        if 0.1 < mixed_ratio < 0.9:
            findings.append(Finding(
                title="Steganographic Watermark — Mixed Line Ending Encoding",
                severity="low",
                category="stego-watermark",
                module=MODULE_NAME,
                description=(
                    f"Document has mixed line endings: {crlf_count} CRLF, {lf_only} LF-only. "
                    f"Mixed ratio: {mixed_ratio:.2%}. This can encode binary data "
                    f"(CRLF=1, LF=0)."
                ),
                evidence=f"CRLF: {crlf_count}, LF: {lf_only}, mixed ratio: {mixed_ratio:.2%}",
                asset="",
                points_deducted=4,
                remediation="Normalize all line endings to a consistent format (LF or CRLF).",
                dread_score=0.3,
            ))

    return findings


def _check_tracking_pixels(
    body: str, base_url: str, target: str
) -> List[Finding]:
    """Cat 1: Detect 1x1 tracking pixels, web bugs, and beacon images."""
    findings: List[Finding] = []
    if not body:
        return findings

    img_tags = _RE_IMG_TAG.findall(body)
    for img_attrs in img_tags:
        # Check dimensions
        dims = _RE_DIM_ATTR.findall(img_attrs)
        width = int(dims[0]) if len(dims) > 0 else 0
        height = int(dims[1]) if len(dims) > 1 else 0

        is_tiny = (width == 1 and height == 1) or (width == 0 and height == 0)
        is_hidden = _RE_INVISIBLE_STYLE.search(img_attrs)

        if not (is_tiny or is_hidden):
            continue

        # Extract src
        src_match = re.search(r"""src\s*=\s*["']([^"']+)["']""", img_attrs, re.IGNORECASE)
        if not src_match:
            continue

        src = src_match.group(1)
        full_url = _normalize_url(base_url, src)
        domain = _extract_domain(full_url)

        # Determine evidence
        dim_str = f"{width}x{height}" if (width or height) else "hidden"
        evidence_parts = [f"<{dim_str}>"]
        if is_hidden:
            evidence_parts.append("invisible style")
        if is_tiny:
            evidence_parts.append("tiny dimensions")

        # Check if external tracking domain
        is_external = _is_external_url(src) and not _is_same_domain(full_url, base_url)
        has_tracking_params = bool(_RE_UTM_PARAMS.search(src) or _RE_CLICK_ID.search(src))
        has_tracking_path = bool(_RE_SUSPICIOUS_HOST.search(full_url))

        if is_tiny and (is_external or has_tracking_path or has_tracking_params):
            severity = "high"
            desc = (
                f"Classic web bug / tracking pixel detected: {dim_str} image pointing to "
                f"{'external domain ' + domain if is_external else ''}"
                f"{'tracking URL path' if has_tracking_path else ''}"
                f"{' with tracking parameters (UTM/click IDs)' if has_tracking_params else ''}. "
                f"This image loads when the document is opened, signaling access to a third party."
            )
            evidence_parts.append(f"src: {src}")
        elif is_hidden and is_external:
            severity = "medium"
            desc = (
                f"Hidden image ({dim_str}) with invisible styling loads from external domain "
                f"'{domain}'. May be a tracking pixel using CSS to hide rather than tiny dimensions."
            )
            evidence_parts.append(f"src: {src}")
        elif is_tiny:
            severity = "low"
            desc = (
                f"Tiny image ({dim_str}) found. While it may be legitimate spacer, "
                f"1x1 images are commonly used as tracking pixels."
            )
            evidence_parts.append(f"src: {src}")
        else:
            continue

        findings.append(Finding(
            title="Tracking Pixel — Web Bug / Beacon Image Detected",
            severity=severity,
            category="tracking-pixel",
            module=MODULE_NAME,
            description=desc,
            evidence="; ".join(evidence_parts),
            asset=domain or target,
            points_deducted=_severity_points(severity),
            remediation=(
                "Remove tracking pixels from documents. If analytics are needed, use "
                "server-side logging that doesn't leak reader identity to third parties."
            ),
            dread_score=_severity_dread(severity),
        ))

    # Check for empty/hidden div-based pixels
    hidden_div_pattern = re.compile(
        r"""<div[^>]+style\s*=\s*["'][^"']*(?:width\s*:\s*[01]px|height\s*:\s*[01]px|"""
        r"""display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^"']*""'>"""
        r"[^<]*(?:<img[^>]+>)?[^<]*</div>",
        re.IGNORECASE | re.DOTALL,
    )
    hidden_divs = hidden_div_pattern.findall(body)
    if len(hidden_divs) > 3:
        findings.append(Finding(
            title="Tracking Pixel — Multiple Hidden Container Elements",
            severity="medium",
            category="tracking-pixel",
            module=MODULE_NAME,
            description=(
                f"Found {len(hidden_divs)} hidden container elements (divs) with zero/tiny dimensions "
                f"or invisible styling. This pattern is commonly used to wrap tracking pixels."
            ),
            evidence=f"Hidden div count: {len(hidden_divs)}",
            asset=target,
            points_deducted=8,
            remediation="Audit hidden container elements. Remove any that serve no functional purpose.",
            dread_score=0.5,
        ))

    return findings


def _check_beaconing(
    body: str, base_url: str, target: str, headers: Dict[str, str]
) -> List[Finding]:
    """Cat 2: Detect beaconing URLs in document metadata and content."""
    findings: List[Finding] = []
    if not body:
        return findings

    # ── Meta refresh redirects (phone-home on open) ──
    refresh_matches = _RE_REFRESH_META.findall(body)
    for refresh_url in refresh_matches:
        clean_url = refresh_url.strip().split("url=", 1)[-1].strip("'\" ")
        if _is_external_url(clean_url):
            domain = _extract_domain(clean_url)
            findings.append(Finding(
                title="Beaconing — Meta Refresh Redirect to External Domain",
                severity="critical",
                category="document-beacon",
                module=MODULE_NAME,
                description=(
                    f"Document contains a <meta http-equiv=refresh> that redirects to external domain "
                    f"'{domain}'. This triggers an automatic request when the document is opened, "
                    f"potentially leaking access information."
                ),
                evidence=f"Refresh URL: {clean_url}",
                asset=domain or target,
                points_deducted=25,
                remediation=(
                    "Remove meta refresh redirects. If timed navigation is needed, use "
                    "JavaScript with user consent."
                ),
                dread_score=0.9,
            ))

    # ── Ping attributes ──
    ping_matches = _RE_PING_ATTR.findall(body)
    for ping_url in ping_matches:
        full_url = _normalize_url(base_url, ping_url)
        domain = _extract_domain(full_url)
        is_external = not _is_same_domain(full_url, base_url)
        severity = "high" if is_external else "medium"
        findings.append(Finding(
            title="Beaconing — HTML Ping Attribute Detected",
            severity=severity,
            category="html-beacon",
            module=MODULE_NAME,
            description=(
                f"HTML element with ping attribute sends notification to '{domain}' on interaction. "
                f"{'External domain — recipient can track link engagement.' if is_external else ''}"
            ),
            evidence=f"ping URL: {ping_url}",
            asset=domain or target,
            points_deducted=_severity_points(severity),
            remediation="Remove ping attributes. Use server-side redirect logging if click tracking is required.",
            dread_score=_severity_dread(severity),
        ))

    # ── Hidden iframes ──
    iframe_srcs = _RE_IFRAME_SRC.findall(body)
    for src in iframe_srcs:
        full_url = _normalize_url(base_url, src)
        # Check if the iframe is hidden (look for surrounding context)
        is_hidden = bool(re.search(
            r'<iframe[^>]*' + re.escape(src[:80]) + r'[^>]*' +
            r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|'
            r'width\s*:\s*[01]px|height\s*:\s*[01]px|'
            r'position\s*:\s*absolute[^;]*left\s*:\s*-)',
            body[:body.index(src) + len(src) + 200],
            re.IGNORECASE,
        )) if src in body else False

        domain = _extract_domain(full_url)
        is_external = not _is_same_domain(full_url, base_url)

        if is_hidden and is_external:
            findings.append(Finding(
                title="Beaconing — Hidden IFRAME Loading External Resource",
                severity="critical",
                category="document-beacon",
                module=MODULE_NAME,
                description=(
                    f"Hidden iframe loads content from external domain '{domain}'. "
                    f"Hidden iframes can execute tracking scripts, load exploits, or exfiltrate data "
                    f"without the user's knowledge."
                ),
                evidence=f"iframe src: {src}",
                asset=domain or target,
                points_deducted=25,
                remediation=(
                    "Remove hidden iframes. All iframes should be visible and serve a clear purpose. "
                    "Audit all cross-origin iframe inclusions."
                ),
                dread_score=0.9,
            ))
        elif is_external:
            findings.append(Finding(
                title="Beaconing — IFRAME Loading External Resource",
                severity="medium",
                category="document-beacon",
                module=MODULE_NAME,
                description=(
                    f"Iframe loads content from external domain '{domain}'. "
                    f"Cross-origin iframes can leak referrer information and enable tracking."
                ),
                evidence=f"iframe src: {src}",
                asset=domain or target,
                points_deducted=8,
                remediation="Review cross-origin iframe usage. Consider sandbox attribute or CSP restrictions.",
                dread_score=0.5,
            ))

    # ── Object/embed tags loading external resources ──
    for tag_name, pattern, label in [
        ("object", _RE_OBJECT_DATA, "data"),
        ("embed", _RE_EMBED_SRC, "src"),
    ]:
        for src in pattern.findall(body):
            full_url = _normalize_url(base_url, src)
            domain = _extract_domain(full_url)
            is_external = not _is_same_domain(full_url, base_url)
            if is_external:
                findings.append(Finding(
                    title=f"Beaconing — External {tag_name.upper()} Tag",
                    severity="high",
                    category="document-beacon",
                    module=MODULE_NAME,
                    description=(
                        f"<{tag_name}> tag with {label}='{src}' loads from external domain '{domain}'. "
                        f"Object/embed tags can execute plugins and scripts from remote sources."
                    ),
                    evidence=f"<{tag_name} {label}={src}",
                    asset=domain or target,
                    points_deducted=15,
                    remediation=f"Remove external <{tag_name}> tags or host the resource locally.",
                    dread_score=0.7,
                ))

    # ── WebSocket connections ──
    ws_matches = _RE_WS_CONN.findall(body)
    for ws_url in ws_matches:
        domain = _extract_domain(ws_url.replace("wss://", "https://").replace("ws://", "http://"))
        is_external = not _is_same_domain(
            ws_url.replace("wss://", "https://").replace("ws://", "http://"),
            base_url,
        )
        severity = "critical" if is_external else "high"
        findings.append(Finding(
            title="Beaconing — WebSocket Connection Detected",
            severity=severity,
            category="ws-beacon",
            module=MODULE_NAME,
            description=(
                f"JavaScript opens a WebSocket connection to '{ws_url}'. "
                f"{'External WebSocket — enables real-time data exfiltration.' if is_external else ''} "
                f"WebSockets bypass standard HTTP logging and can maintain persistent tracking channels."
            ),
            evidence=f"WebSocket URL: {ws_url}",
            asset=domain or target,
            points_deducted=_severity_points(severity),
            remediation=(
                "Remove or justify all WebSocket connections. Ensure WebSocket traffic is encrypted (WSS) "
                "and serves a documented functional purpose."
            ),
            dread_score=_severity_dread(severity),
        ))

    # ── Link rel=prefetch/prerender beacons ──
    prefetch_pattern = re.compile(
        r"""<link[^>]+rel\s*=\s*["\'](?:prefetch|prerender)["\'][^>]+href\s*=\s*["\']([^"']+)["']""",
        re.IGNORECASE,
    )
    prefetch_urls = prefetch_pattern.findall(body)
    for pf_url in prefetch_urls:
        full_url = _normalize_url(base_url, pf_url)
        domain = _extract_domain(full_url)
        has_tracking_path = bool(_RE_SUSPICIOUS_HOST.search(full_url))
        if has_tracking_path:
            findings.append(Finding(
                title="Beaconing — Prefetch/Prerender Used as Tracking Beacon",
                severity="medium",
                category="resource-beacon",
                module=MODULE_NAME,
                description=(
                    f"Link with rel=prefetch/prerender points to tracking URL '{pf_url}' on domain '{domain}'. "
                    f"Browsers automatically fetch these URLs, creating a tracking beacon without JavaScript."
                ),
                evidence=f"Prefetch URL: {pf_url}",
                asset=domain or target,
                points_deducted=8,
                remediation="Remove prefetch links to tracking endpoints. Use standard analytics if needed.",
                dread_score=0.5,
            ))

    # ── DNS-based beaconing (encoded data in subdomains) ──
    all_urls = _extract_urls_from_text(body)
    for url in all_urls:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        # Check for hex-encoded subdomains (common in DNS tunneling)
        parts = hostname.split(".")
        for part in parts:
            if len(part) >= 16 and re.match(r"^[a-f0-9]+$", part, re.IGNORECASE):
                findings.append(Finding(
                    title="Beaconing — Potential DNS Tunneling / Encoded Subdomain",
                    severity="critical",
                    category="dns-beacon",
                    module=MODULE_NAME,
                    description=(
                        f"URL '{url}' contains a hex-encoded subdomain '{part}' ({len(part)} chars). "
                        f"DNS queries for encoded subdomains are a classic C2 beaconing technique used to "
                        f"exfiltrate data through DNS, bypassing most firewalls and proxies."
                    ),
                    evidence=f"URL: {url}; encoded subdomain: {part}",
                    asset=hostname or target,
                    points_deducted=25,
                    remediation=(
                        "Investigate the source of this URL. DNS tunneling indicates a compromised or "
                        "maliciously crafted document. Block the domain and analyze network DNS logs."
                    ),
                    dread_score=0.9,
                ))
                break

    return findings


def _check_malicious_links(
    body: str, base_url: str, target: str
) -> List[Finding]:
    """Cat 4: Analyze URLs in served content for malicious/tracking destinations."""
    findings: List[Finding] = []
    if not body:
        return findings

    all_urls = _extract_urls_from_text(body)
    if not all_urls:
        return findings

    malicious_categories: List[Dict[str, Any]] = []
    tracking_domains_found: List[str] = []
    utm_tracked: List[str] = []
    click_id_tracked: List[str] = []
    suspicious_param_urls: List[str] = []

    for url in all_urls:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        # ── Check for known tracking/analytics parameters ──
        utm_matches = _RE_UTM_PARAMS.findall(query)
        if utm_matches:
            utm_tracked.append(f"{hostname}{path} (UTM: {', '.join(utm_matches[:3])})")

        click_id_matches = _RE_CLICK_ID.findall(query)
        if click_id_matches:
            click_id_tracked.append(f"{hostname}{path} (IDs: {', '.join([m.split('=')[0] for m in click_id_matches[:3]])})")

        # ── Check for suspicious URL parameters (long encoded IDs) ──
        if _RE_SUSPICIOUS_PARAMS.search(query):
            suspicious_param_urls.append(url)

        # ── Check for tracking-related domain patterns ──
        is_tracking_domain = bool(_RE_SUSPICIOUS_HOST.search(hostname + "/" + path))
        if is_tracking_domain and not _is_same_domain(url, base_url):
            tracking_domains_found.append(hostname)

        # ── Check for known malicious TLD patterns ──
        suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs commonly abused
        ]
        tld = "." + hostname.split(".")[-1] if "." in hostname else ""
        if tld in suspicious_tlds and not _is_same_domain(url, base_url):
            malicious_categories.append({
                "url": url,
                "reason": f"Free/abusable TLD ({tld})",
                "severity": "high",
            })

        # ── Check for IP address URLs (no DNS) ──
        if re.match(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
            malicious_categories.append({
                "url": url,
                "reason": "Direct IP address URL (bypasses DNS-based filtering)",
                "severity": "high",
            })

        # ── Check for encoded/obfuscated URLs ──
        if "%" in url and len(re.findall(r"%[0-9a-fA-F]{2}", url)) > 5:
            malicious_categories.append({
                "url": url,
                "reason": "Heavily URL-encoded (possible obfuscation)",
                "severity": "medium",
            })

        # ── Check for data exfiltration patterns in query ──
        exfil_param_patterns = [
            (r"(?:data|payload|exfil|content|info)=[A-Za-z0-9+/=%]{50,}", "large data in query parameter"),
            (r"""(?:cmd|exec|run|eval)=[^">&]+", "command execution parameter"""),
            (r"(?:callback|cb)=[a-zA-Z_$][\w$]*$", "JSONP callback parameter"),
        ]
        for pat, reason in exfil_param_patterns:
            if re.search(pat, query, re.IGNORECASE):
                malicious_categories.append({
                    "url": url,
                    "reason": reason,
                    "severity": "high",
                })

    # ── Generate findings for tracking parameters ──
    if utm_tracked:
        findings.append(Finding(
            title="Malicious Link — UTM Tracking Parameters on External URLs",
            severity="medium",
            category="tracking-params",
            module=MODULE_NAME,
            description=(
                f"Found {len(utm_tracked)} URLs with UTM tracking parameters. "
                f"UTM parameters allow the link creator to track who clicked the link, from where, "
                f"and in what context. In a weaponized report, this reveals reader identity to the sender."
            ),
            evidence=_truncate_evidence("; ".join(utm_tracked[:5])),
            asset=target,
            points_deducted=8,
            remediation="Strip all UTM parameters from URLs before including them in reports.",
            dread_score=0.5,
        ))

    if click_id_tracked:
        findings.append(Finding(
            title="Malicious Link — Click ID Tracking Parameters Detected",
            severity="high",
            category="tracking-params",
            module=MODULE_NAME,
            description=(
                f"Found {len(click_id_tracked)} URLs with platform click IDs (fbclid, gclid, etc.). "
                f"Click IDs uniquely identify the user-session that generated the click, allowing "
                f"the ad platform to correlate the report reader with their profile."
            ),
            evidence=_truncate_evidence("; ".join(click_id_tracked[:5])),
            asset=target,
            points_deducted=15,
            remediation="Strip all click ID parameters from URLs. Use URL cleaners before distribution.",
            dread_score=0.7,
        ))

    if tracking_domains_found:
        unique_domains = list(dict.fromkeys(tracking_domains_found))
        findings.append(Finding(
            title="Malicious Link — URLs Pointing to Tracking/Analytics Domains",
            severity="high",
            category="tracking-domain",
            module=MODULE_NAME,
            description=(
                f"Found {len(unique_domains)} unique tracking/analytics domains referenced in document URLs: "
                f"{', '.join(unique_domains[:5])}. Links to these domains reveal reader activity."
            ),
            evidence="Domains: " + ", ".join(unique_domains[:10]),
            asset=target,
            points_deducted=15,
            remediation="Replace tracking URLs with direct destinations or use link sanitization.",
            dread_score=0.7,
        ))

    if suspicious_param_urls:
        findings.append(Finding(
            title="Malicious Link — URLs with Suspicious Tracking Parameters",
            severity="medium",
            category="suspicious-params",
            module=MODULE_NAME,
            description=(
                f"Found {len(suspicious_param_urls)} URLs with long encoded tracking parameters. "
                f"These parameters can uniquely identify the recipient or session."
            ),
            evidence=_truncate_evidence("; ".join(suspicious_param_urls[:5])),
            asset=target,
            points_deducted=8,
            remediation="Audit URL parameters. Remove non-essential query strings before distribution.",
            dread_score=0.5,
        ))

    for mc in malicious_categories:
        findings.append(Finding(
            title=f"Malicious Link — {mc['reason']}",
            severity=mc["severity"],
            category="malicious-url",
            module=MODULE_NAME,
            description=(
                f"URL '{mc['url']}' flagged: {mc['reason']}. "
                f"This could indicate a malicious link embedded in the document."
            ),
            evidence=f"URL: {mc['url']}",
            asset=_extract_domain(mc["url"]) or target,
            points_deducted=_severity_points(mc["severity"]),
            remediation="Verify all external links. Remove or replace suspicious URLs.",
            dread_score=_severity_dread(mc["severity"]),
        ))

    return findings


def _check_document_metadata(
    body: str, headers: Dict[str, str], target: str
) -> List[Finding]:
    """Cat 5: Analyze served documents for hidden tracking metadata."""
    findings: List[Finding] = []
    if not body:
        return findings

    # ── HTML meta tag tracking fields ──
    meta_pattern = re.compile(
        r"<meta\s+([^>]+?)/?>", re.IGNORECASE
    )
    tracking_meta_fields: List[str] = []
    for meta_match in meta_pattern.finditer(body):
        meta_attrs = meta_match.group(1)
        # Check for tracking-related meta names
        tracking_names = [
            "tracking-id", "correlation-id", "x-request-id",
            "x-correlation-id", "visitor-id", "session-id",
            "user-id", "recipient-id", "doc-id", "report-id",
        ]
        for tname in tracking_names:
            if re.search(rf"""(?:name|http-equiv)\s*=\s*["']?{re.escape(tname)}["']?""",
                        meta_attrs, re.IGNORECASE):
                content_match = re.search(
                    r"""content\s*=\s*["']([^"']+)["']""",
                    meta_attrs, re.IGNORECASE,
                )
                if content_match:
                    tracking_meta_fields.append(f"{tname}={content_match.group(1)}")

    if tracking_meta_fields:
        findings.append(Finding(
            title="Document Metadata — Tracking IDs in HTML Meta Tags",
            severity="high",
            category="metadata-tracking",
            module=MODULE_NAME,
            description=(
                f"Document contains {len(tracking_meta_fields)} tracking-related meta fields. "
                f"These unique identifiers can link document access to specific recipients."
            ),
            evidence=_truncate_evidence("; ".join(tracking_meta_fields[:5])),
            asset=target,
            points_deducted=15,
            remediation="Remove tracking identifiers from meta tags before distribution.",
            dread_score=0.7,
        ))

    # ── HTTP response header tracking ──
    tracking_headers: List[str] = []
    suspicious_header_names = [
        "x-request-id", "x-correlation-id", "x-trace-id",
        "x-session-id", "x-visitor-id", "x-tracking-id",
        "x-b3-traceid", "x-b3-spanid", "x-datadog-trace-id",
        "x-amz-request-id", "x-aws-request-id",
    ]
    for hname, hval in headers.items():
        if hname.lower() in suspicious_header_names:
            tracking_headers.append(f"{hname}: {hval}")

    if tracking_headers:
        findings.append(Finding(
            title="Document Metadata — Tracking IDs in HTTP Response Headers",
            severity="medium",
            category="metadata-tracking",
            module=MODULE_NAME,
            description=(
                f"HTTP response contains {len(tracking_headers)} tracking/correlation headers. "
                f"While often used for internal debugging, these can correlate requests to specific users."
            ),
            evidence="; ".join(tracking_headers[:5]),
            asset=target,
            points_deducted=8,
            remediation="Configure server to strip internal tracing headers from external responses.",
            dread_score=0.5,
        ))

    # ── Generator/creator metadata ──
    gen_meta = re.search(
        r"""<meta\s+[^>]*name\s*=\s*["\']generator[""][^>]*content\s*=\s*["\']([^"']+)["\']""",
        body, re.IGNORECASE,
    )
    if gen_meta:
        gen_val = gen_meta.group(1)
        # Check for tracking-capable generators
        tracking_generators = [
            "mailchimp", "campaign monitor", "sendgrid", "hubspot",
            "marketo", "pardot", "activecampaign", "convertkit",
            "mailerlite", "brevo", "constant contact",
        ]
        for tg in tracking_generators:
            if tg in gen_val.lower():
                findings.append(Finding(
                    title="Document Metadata — Email Marketing Platform Generator Detected",
                    severity="medium",
                    category="metadata-tracking",
                    module=MODULE_NAME,
                    description=(
                        f"Document generator is '{gen_val}' ({tg}). Email marketing platforms "
                        f"automatically embed tracking pixels and click tracking in all generated content."
                    ),
                    evidence=f"Generator: {gen_val}",
                    asset=target,
                    points_deducted=8,
                    remediation=(
                        f"Content from {tg} likely contains tracking. Export to clean HTML and "
                        f"strip all tracking elements before redistribution."
                    ),
                    dread_score=0.5,
                ))
                break

    # ── Comment-embedded tracking data ──
    html_comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
    tracking_comments: List[str] = []
    for comment in html_comments:
        comment_stripped = comment.strip()
        if len(comment_stripped) < 5:
            continue
        # Look for IDs, tokens, or tracking data in comments
        if re.search(r"""(?:id|token|key|uid|session|tracking|correlation|request)["']?\s*[=:]""",
                     comment_stripped, re.IGNORECASE):
            tracking_comments.append(comment_stripped[:100])
        # Look for base64-encoded data in comments
        b64_in_comment = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", comment_stripped)
        if b64_in_comment:
            tracking_comments.append(f"base64 data ({len(b64_in_comment[0])} chars)")

    if tracking_comments:
        findings.append(Finding(
            title="Document Metadata — Tracking Data in HTML Comments",
            severity="medium",
            category="metadata-tracking",
            module=MODULE_NAME,
            description=(
                f"Found {len(tracking_comments)} HTML comments containing tracking identifiers or "
                f"encoded data. HTML comments are invisible to readers but can be parsed by the sender "
                f"to verify document access."
            ),
            evidence=_truncate_evidence("; ".join(tracking_comments[:3])),
            asset=target,
            points_deducted=8,
            remediation="Remove all HTML comments before distributing documents, especially those containing IDs or encoded data.",
            dread_score=0.5,
        ))

    # ── Custom/proprietary tracking headers in the response ──
    custom_tracking_headers: List[str] = []
    for hname, hval in headers.items():
        hlower = hname.lower()
        if hlower.startswith("x-") and hlower not in {
            "x-powered-by", "x-frame-options", "x-content-type-options",
            "x-xss-protection", "x-robots-tag", "x-requested-with",
        }:
            # Check if the value looks like a tracking ID (UUID, hex, long base64)
            if (re.match(r"^[a-f0-9]{8}-[a-f0-9]{4}-", hval, re.IGNORECASE) or  # UUID
                re.match(r"^[a-f0-9]{32,}$", hval, re.IGNORECASE) or  # Hex ID
                len(hval) > 50):  # Long opaque value
                custom_tracking_headers.append(f"{hname}: {hval[:60]}")

    if len(custom_tracking_headers) >= 2:
        findings.append(Finding(
            title="Document Metadata — Multiple Suspicious Custom Headers",
            severity="low",
            category="metadata-tracking",
            module=MODULE_NAME,
            description=(
                f"Found {len(custom_tracking_headers)} custom X- headers with ID-like values. "
                f"May be used for request correlation and user tracking."
            ),
            evidence="; ".join(custom_tracking_headers[:5]),
            asset=target,
            points_deducted=3,
            remediation="Audit custom headers and remove any that serve only tracking purposes.",
            dread_score=0.3,
        ))

    return findings


def _check_js_trackers(
    body: str, base_url: str, target: str
) -> List[Finding]:
    """Cat 6: Detect analytics, fingerprinting, and tracking scripts."""
    findings: List[Finding] = []
    if not body:
        return findings

    # Extract all script content
    script_blocks = _RE_SCRIPT.findall(body)
    inline_js = "\n".join(script_blocks)
    all_js = body  # Also scan the full HTML for script src references

    # ── Check against TRACKER_SIGNATURES database ──
    detected_trackers: List[Dict[str, Any]] = []
    for tracker in _compiled_trackers:
        matches = _count_matching_patterns(all_js, tracker["compiled"])
        if matches:
            detected_trackers.append({
                **tracker,
                "matched_evidence": matches[:3],
            })

    # Deduplicate by category
    seen_categories: set = set()
    for dt in detected_trackers:
        cat = dt["category"]
        # Group analytics together, fingerprinting together, etc.
        if cat in seen_categories:
            continue
        # For analytics, allow up to 3 unique trackers before grouping
        if cat == "analytics" and len([d for d in detected_trackers if d["category"] == "analytics"]) > 3:
            if dt != [d for d in detected_trackers if d["category"] == "analytics"][0]:
                continue

        seen_categories.add(cat)

        # Count total trackers in this category
        category_count = len([d for d in detected_trackers if d["category"] == cat])
        other_names = [d["name"] for d in detected_trackers if d["category"] == cat and d["name"] != dt["name"]]

        desc = dt["description"]
        if category_count > 1:
            desc += f" Also detected in same category: {', '.join(other_names[:3])}."

        evidence_str = "; ".join(dt["matched_evidence"])
        if category_count > 1:
            evidence_str += f" (plus {category_count - 1} more in {cat} category)"

        findings.append(Finding(
            title=f"JavaScript Tracker — {dt['name']} Detected",
            severity=dt["severity"],
            category=f"js-{cat}",
            module=MODULE_NAME,
            description=desc,
            evidence=_truncate_evidence(evidence_str),
            asset=target,
            points_deducted=_severity_points(dt["severity"]),
            remediation=(
                f"Remove or disable {dt['name']} ({dt['id']}). If analytics are required, "
                f"implement privacy-preserving alternatives (server-side aggregation, "
                f"anonymized collection)."
            ),
            dread_score=_severity_dread(dt["severity"]),
        ))

    # ── Check for beacon-like outbound requests in JS ──
    if inline_js:
        beacon_requests = _RE_JS_FETCH_XHR.findall(inline_js)
        # Check URLs in fetch/XHR calls
        fetch_urls = re.findall(
            r"""(?:fetch|open|send)\s*\(\s*["']([^"']+)["']""",
            inline_js, re.IGNORECASE,
        )
        tracking_fetch_urls: List[str] = []
        for furl in fetch_urls:
            full_url = _normalize_url(base_url, furl)
            if _RE_SUSPICIOUS_HOST.search(full_url) and not _is_same_domain(full_url, base_url):
                tracking_fetch_urls.append(furl)

        if tracking_fetch_urls and not any(f["category"] == "js-beacon" for f in findings):
            findings.append(Finding(
                title="JavaScript Tracker — Outbound Requests to Tracking Endpoints",
                severity="high",
                category="js-beacon",
                module=MODULE_NAME,
                description=(
                    f"JavaScript makes {len(tracking_fetch_urls)} fetch/XHR/sendBeacon requests to "
                    f"external tracking endpoints. These fire when the document is opened."
                ),
                evidence=_truncate_evidence("; ".join(tracking_fetch_urls[:5])),
                asset=target,
                points_deducted=15,
                remediation="Remove outbound tracking requests from document JavaScript.",
                dread_score=0.7,
            ))

        # ── Check for sendBeacon specifically (harder to block) ──
        if "sendBeacon" in inline_js:
            beacon_urls = re.findall(
                r"""sendBeacon\s*\(\s*["']([^"']+)["']""",
                inline_js, re.IGNORECASE,
            )
            if beacon_urls:
                findings.append(Finding(
                    title="JavaScript Tracker — navigator.sendBeacon Detected",
                    severity="high",
                    category="js-beacon",
                    module=MODULE_NAME,
                    description=(
                        f"JavaScript uses navigator.sendBeacon() to {len(beacon_urls)} endpoint(s). "
                        f"sendBeacon is designed to be reliable even during page unload, making it "
                        f"difficult to block. It's commonly used for analytics tracking that persists "
                        f"even if the user navigates away quickly."
                    ),
                    evidence="; ".join(beacon_urls[:5]),
                    asset=target,
                    points_deducted=15,
                    remediation=(
                        "Remove sendBeacon calls. This API is specifically designed to guarantee delivery "
                        "of tracking data and is very difficult for users to block."
                    ),
                    dread_score=0.7,
                ))

        # ── Check for Image.src beacons (no-JS fallback tracking) ──
        img_src_beacons = re.findall(
            r"(?:new\s+Image|document\.createElement\(['\"]img['\"])"  # noqa: handle string concat in regex
            r"""[^;]{0,100}\.src\s*=\s*["']([^"']+)["']""",
            inline_js, re.IGNORECASE,
        )
        if img_src_beacons:
            findings.append(Finding(
                title="JavaScript Tracker — Image.src Beacon Pattern",
                severity="medium",
                category="js-beacon",
                module=MODULE_NAME,
                description=(
                    f"JavaScript creates Image objects and sets .src to trigger HTTP requests. "
                    f"This is a classic tracking technique that works even without XHR/fetch. "
                    f"Found {len(img_src_beacons)} beacon URL(s)."
                ),
                evidence="; ".join(img_src_beacons[:5]),
                asset=target,
                points_deducted=8,
            remediation="Remove Image.src beacon patterns from JavaScript.",
            dread_score=0.5,
            ))

    # ── Count total distinct trackers found ──
    if len(detected_trackers) > 5:
        findings.append(Finding(
            title="JavaScript Tracker — Excessive Tracking Script Density",
            severity="high",
            category="js-tracker-density",
            module=MODULE_NAME,
            description=(
                f"Document contains {len(detected_trackers)} distinct tracking/analytics/fingerprinting "
                f"scripts. This level of tracking is excessive and likely intended for surveillance rather "
                f"than legitimate analytics. Tracker names: "
                f"{', '.join(d['name'] for d in detected_trackers[:10])}."
            ),
            evidence=f"Total trackers: {len(detected_trackers)}; " + ", ".join(
                d["id"] for d in detected_trackers[:10]
            ),
            asset=target,
            points_deducted=15,
            remediation=(
                "Reduce tracking to the minimum required. Each tracker is a potential data leak and "
                "increases the attack surface of the document."
            ),
            dread_score=0.7,
        ))

    return findings


def _check_css_tracking(
    body: str, base_url: str, target: str
) -> List[Finding]:
    """Cat 7: Detect CSS-based tracking techniques."""
    findings: List[Finding] = []
    if not body:
        return findings

    # Extract CSS from <style> blocks and inline styles
    style_blocks = _RE_STYLE.findall(body)
    all_css = "\n".join(style_blocks)

    # Also extract inline style attributes
    inline_styles = re.findall(r"""style\s*=\s*["']([^"']+)["']""", body, re.IGNORECASE)
    all_css += "\n".join(inline_styles)

    if not all_css.strip():
        return findings

    # ── CSS visited-link detection (:visited history sniffing) ──
    visited_matches = _RE_VISITED.findall(all_css)
    if visited_matches:
        # Verify it's actually being used for detection, not just styling
        is_sniffing = bool(re.search(
            r":visited\s*[{;]", all_css, re.IGNORECASE
        )) or bool(re.search(
            r"getComputedStyle.*:visited",
            body, re.IGNORECASE,
        ))

        if is_sniffing:
            severity = "high"
            desc = (
                f"CSS contains :visited pseudo-class rules ({len(visited_matches)} occurrences). "
                f"When combined with JavaScript getComputedStyle() checks, this can detect which "
                f"websites the user has visited — a privacy-invasive history sniffing technique."
            )
        else:
            severity = "low"
            desc = (
                f"CSS contains :visited pseudo-class styling ({len(visited_matches)} occurrences). "
                f"While often legitimate, :visited styles can be abused for history sniffing."
            )

        findings.append(Finding(
            title="CSS Tracking — :visited Link Detection (History Sniffing)",
            severity=severity,
            category="css-visited-tracking",
            module=MODULE_NAME,
            description=desc,
            evidence=f":visited occurrences: {len(visited_matches)}",
            asset=target,
            points_deducted=_severity_points(severity),
            remediation=(
                "Remove :visited styling rules from documents. Modern browsers restrict :visited "
                "style access, but older browsers remain vulnerable."
            ),
            dread_score=_severity_dread(severity),
        ))

    # ── CSS font-loading fingerprinting ──
    font_face_matches = _RE_FONT_FACE.findall(all_css)
    if font_face_matches:
        # Check for font enumeration patterns
        font_enum_patterns = [
            r"document\.fonts\.(load|check|ready)",
            r"FontFace\(",
            r"font-family\s*:\s*['\"]?[A-Z][a-zA-Z]+",
        ]
        has_font_enum = any(
            re.search(p, body, re.IGNORECASE) for p in font_enum_patterns
        )

        # Count unique custom font declarations
        unique_fonts = set(re.findall(
            r"""font-family\s*:\s*['\"]?([^'";}{]+)""", all_css, re.IGNORECASE
        ))
        # Filter out generic font families
        generic_families = {
            "serif", "sans-serif", "monospace", "cursive", "fantasy",
            "system-ui", "ui-serif", "ui-sans-serif", "ui-monospace",
            "ui-rounded", "emoji", "math", "fangsong",
        }
        custom_fonts = {f.strip() for f in unique_fonts if f.strip().lower() not in generic_families}

        if has_font_enum and len(custom_fonts) > 3:
            findings.append(Finding(
                title="CSS Tracking — Font-Loading Fingerprinting Detected",
                severity="high",
                category="css-font-fingerprinting",
                module=MODULE_NAME,
                description=(
                    f"Document declares {len(custom_fonts)} custom @font-face rules and uses JavaScript "
                    f"font enumeration APIs. By measuring which fonts are available on the user's system "
                    f"(via fallback rendering), a unique fingerprint can be created. Custom fonts: "
                    f"{', '.join(list(custom_fonts)[:5])}."
                ),
                evidence=f"@font-face count: {len(font_face_matches)}; custom fonts: {', '.join(list(custom_fonts)[:5])}",
                asset=target,
                points_deducted=15,
                remediation=(
                    "Remove unnecessary @font-face declarations. Avoid JavaScript font enumeration. "
                    "Use a minimal set of web-safe or self-hosted fonts."
                ),
                dread_score=0.7,
            ))
        elif len(custom_fonts) > 5:
            findings.append(Finding(
                title="CSS Tracking — Excessive Custom Font Declarations",
                severity="medium",
                category="css-font-fingerprinting",
                module=MODULE_NAME,
                description=(
                    f"Document declares {len(custom_fonts)} custom @font-face rules. Large font sets "
                    f"can be used for system fingerprinting by measuring rendering differences."
                ),
                evidence=f"Custom fonts ({len(custom_fonts)}): {', '.join(list(custom_fonts)[:5])}",
                asset=target,
                points_deducted=8,
                remediation="Reduce custom font usage to the minimum required for display.",
                dread_score=0.5,
            ))

    # ── CSS url() beacons ──
    css_urls = _RE_CSS_URL.findall(all_css)
    tracking_css_urls: List[str] = []
    for css_url in css_urls:
        if css_url.startswith("data:"):
            continue
        full_url = _normalize_url(base_url, css_url)
        is_external = not _is_same_domain(full_url, base_url)
        has_tracking_path = bool(_RE_SUSPICIOUS_HOST.search(full_url))
        if is_external or has_tracking_path:
            tracking_css_urls.append(css_url)

    if tracking_css_urls:
        findings.append(Finding(
            title="CSS Tracking — External URL() Requests in Stylesheets",
            severity="medium",
            category="css-beacon",
            module=MODULE_NAME,
            description=(
                f"CSS contains {len(tracking_css_urls)} url() references to external/tracking domains. "
                f"CSS url() requests fire automatically when the stylesheet is parsed, even without JavaScript. "
                f"URLs: {', '.join(tracking_css_urls[:5])}."
            ),
            evidence="; ".join(tracking_css_urls[:5]),
            asset=target,
            points_deducted=8,
            remediation="Host all CSS resources locally. Remove external url() references from stylesheets.",
            dread_score=0.5,
        ))

    # ── CSS attribute selector fingerprinting ──
    # Detect patterns like [data-value="x"] { background: url(/track/x); }
    attr_selector_pattern = re.compile(
        r"""\[\w+-?[\w]*\s*[~|^$*]?=\s*["']([^"']+)["']\]""",
        re.IGNORECASE,
    )
    attr_selectors = attr_selector_pattern.findall(all_css)
    # Look for CSS rules that combine attribute selectors with url() loads
    attr_beacon_pattern = re.compile(
        r"""\[\w[^\]]*\][^{]*\{[^}]*url\(["']?https?://""",
        re.IGNORECASE,
    )
    attr_beacons = attr_beacon_pattern.findall(all_css)
    if attr_beacons and len(attr_selectors) > 5:
        findings.append(Finding(
            title="CSS Tracking — Attribute Selector-Based Beaconing",
            severity="high",
            category="css-attribute-tracking",
            module=MODULE_NAME,
            description=(
                f"CSS uses {len(attr_selectors)} attribute selectors, some combined with url() loads. "
                f"This pattern can detect specific attribute values (e.g., user ID, configuration) and "
                f"trigger different tracking URLs based on the matched value."
            ),
            evidence=f"Attribute selectors: {len(attr_selectors)}; beacon rules: {len(attr_beacons)}",
            asset=target,
            points_deducted=15,
            remediation="Audit attribute selectors combined with url() loads. Remove any that serve tracking purposes.",
            dread_score=0.7,
        ))

    # ── CSS counter/variable exfiltration patterns ──
    if re.search(r"counter\s*\(", all_css, re.IGNORECASE) and re.search(
        r"content\s*:\s*counter\(", all_css, re.IGNORECASE
    ):
        findings.append(Finding(
            title="CSS Tracking — CSS Counter Content Generation",
            severity="low",
            category="css-exfiltration",
            module=MODULE_NAME,
            description=(
                "CSS uses counter() in content properties. While often legitimate, CSS counters "
                "can be used in advanced exfiltration techniques to encode data in generated content."
            ),
            evidence="CSS counter() and content: counter() patterns detected",
            asset=target,
            points_deducted=3,
            remediation="Review CSS counter usage for necessity.",
            dread_score=0.3,
        ))

    return findings


def _check_fingerprinting(
    body: str, target: str
) -> List[Finding]:
    """Cross-cutting check: Detect browser fingerprinting techniques in JS/CSS."""
    findings: List[Finding] = []
    if not body:
        return findings

    # ── Check against FINGERPRINT_TECHNIQUES database ──
    detected_fps: List[Dict[str, Any]] = []
    for fp in _compiled_fingerprints:
        matches = _count_matching_patterns(body, fp["compiled"])
        if matches:
            detected_fps.append({
                **fp,
                "matched_evidence": matches[:3],
            })

    if not detected_fps:
        return findings

    # Group findings by category
    fp_categories: Dict[str, List[Dict[str, Any]]] = {}
    for fp in detected_fps:
        cat = fp["category"]
        fp_categories.setdefault(cat, []).append(fp)

    for cat, fps in fp_categories.items():
        if cat in ("css-tracking",):
            # CSS tracking is handled by _check_css_tracking
            continue

        # Take the most severe finding per category
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        fps.sort(key=lambda x: severity_order.get(x["severity"], 5))
        primary = fps[0]

        other_names = [f["name"] for f in fps[1:]]
        desc = primary["description"]
        if other_names:
            desc += f" Related techniques: {', '.join(other_names[:3])}."

        evidence_str = "; ".join(primary["matched_evidence"])
        if len(fps) > 1:
            evidence_str += f" (plus {len(fps) - 1} related indicators)"

        findings.append(Finding(
            title=f"Fingerprinting — {primary['name']} Detected",
            severity=primary["severity"],
            category=f"fingerprint-{cat}",
            module=MODULE_NAME,
            description=desc,
            evidence=_truncate_evidence(evidence_str),
            asset=target,
            points_deducted=_severity_points(primary["severity"]),
            remediation=(
                f"Remove {primary['name']} code ({primary['id']}). Browser fingerprinting "
                f"uniquely identifies the document reader without their consent."
            ),
            dread_score=_severity_dread(primary["severity"]),
        ))

    # ── Summary finding for high fingerprint density ──
    if len(detected_fps) > 4:
        findings.append(Finding(
            title="Fingerprinting — Multi-Vector Fingerprinting Campaign Detected",
            severity="critical",
            category="fingerprint-campaign",
            module=MODULE_NAME,
            description=(
                f"Document employs {len(detected_fps)} distinct fingerprinting techniques across "
                f"{len(fp_categories)} categories: {', '.join(fp_categories.keys())}. "
                f"This multi-vector approach maximizes identification accuracy and resilience against "
                f"individual technique blocking. This strongly indicates an intentional fingerprinting campaign."
            ),
            evidence=(
                f"Techniques: {', '.join(f['name'] for f in detected_fps[:10])}; "
                f"Categories: {', '.join(fp_categories.keys())}"
            ),
            asset=target,
            points_deducted=25,
            remediation=(
                "This document is aggressively fingerprinting its readers. Do not open in a standard browser. "
                "Use a hardened reader that blocks JavaScript, CSS, and all external resource loading."
            ),
            dread_score=0.9,
        ))

    return findings


def _generate_summary(
    findings: List[Finding], target: str
) -> Optional[Finding]:
    """Generate a summary finding if enough issues were found."""
    if len(findings) < 3:
        return None

    severity_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    total_points = 0

    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1
        total_points += f.points_deducted

    # Determine overall severity
    if severity_counts.get("critical", 0) > 0:
        overall_severity = "critical"
    elif severity_counts.get("high", 0) >= 2:
        overall_severity = "high"
    elif severity_counts.get("high", 0) > 0 or severity_counts.get("medium", 0) >= 3:
        overall_severity = "high"
    else:
        overall_severity = "medium"

    # Top categories
    top_cats = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_cats_str = ", ".join(f"{cat} ({count})" for cat, count in top_cats)

    return Finding(
        title="Weaponized Report — Comprehensive Tracking Analysis Summary",
        severity=overall_severity,
        category="summary",
        module=MODULE_NAME,
        description=(
            f"Target '{target}' serves documents containing {len(findings)} tracking elements across "
            f"{len(category_counts)} categories. Severity breakdown: "
            f"{', '.join(f'{s}: {c}' for s, c in sorted(severity_counts.items(), key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(x[0], 5)) if c > 0)}. "
            f"Top categories: {top_cats_str}. Total risk score: {total_points}. "
            f"This document/report should be considered weaponized — it tracks readers through "
            f"multiple independent channels."
        ),
        evidence=(
            f"Total findings: {len(findings)}; Categories: {len(category_counts)}; "
            f"Points deducted: {total_points}; "
            f"Categories: {top_cats_str}"
        ),
        asset=target,
        points_deducted=min(total_points, 50),
        remediation=(
            "This document contains multiple tracking vectors. Recommendations: (1) Open in a sandboxed "
            "reader with all network access blocked. (2) Convert to plain text. (3) Remove all JavaScript, "
            "CSS, images, and external references. (4) Use a privacy-focused document viewer."
        ),
        dread_score=0.8 if overall_severity in ("critical", "high") else 0.5,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Main entry point
# ═══════════════════════════════════════════════════════════════════════════

def run_weaponized_report(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
) -> List[Finding]:
    """Detect tracking elements in documents/reports served by the target.

    Analyzes the target URL for weaponized report indicators — tracking pixels,
    beaconing URLs, steganographic watermarks, malicious links, hidden metadata,
    JavaScript trackers, and CSS-based tracking techniques.

    Args:
        target: The target identifier (hostname or IP).
        base_url: The base URL to probe for document content.
        timeout: HTTP request timeout in seconds.
        verify_tls: Whether to verify TLS certificates.

    Returns:
        List of Finding objects describing detected tracking elements.
    """
    findings: List[Finding] = []

    # Fetch the target document
    resp = http_probe(
        base_url,
        method="GET",
        timeout=timeout,
        verify_tls=verify_tls,
        limiter=default_limiter,
    )

    if not resp.get("ok") and resp.get("status", 0) == 0:
        # Connection failure
        findings.append(Finding(
            title="Weaponized Report — Unable to Fetch Target Document",
            severity="info",
            category="fetch-error",
            module=MODULE_NAME,
            description=(
                f"Failed to fetch document from '{base_url}': {resp.get('reason', 'unknown error')}. "
                f"Cannot analyze for tracking elements."
            ),
            evidence=f"URL: {base_url}; Error: {resp.get('reason', 'unknown')}",
            asset=target,
            points_deducted=0,
            remediation="Verify the target URL is accessible and retry the scan.",
            dread_score=0.0,
        ))
        return findings

    body: str = resp.get("body", "")
    headers: Dict[str, str] = resp.get("headers", {})
    content_type: str = headers.get("content-type", "")

    if not body or len(body) < 10:
        return findings

    # ── Run all 7 detection categories ──

    # Cat 1: Tracking Pixel Detection
    findings.extend(_check_tracking_pixels(body, base_url, target))

    # Cat 2: Beaconing Detection in Documents
    findings.extend(_check_beaconing(body, base_url, target, headers))

    # Cat 3: Steganographic Watermark Detection
    findings.extend(_analyze_document_binary_header(body, content_type))

    # Cat 4: Malicious Link Analysis
    findings.extend(_check_malicious_links(body, base_url, target))

    # Cat 5: Document Metadata Analysis
    findings.extend(_check_document_metadata(body, headers, target))

    # Cat 6: JavaScript Tracker Detection
    findings.extend(_check_js_trackers(body, base_url, target))

    # Cat 7: CSS-based Tracking Detection
    findings.extend(_check_css_tracking(body, base_url, target))

    # Cross-cutting: Fingerprinting (uses FINGERPRINT_TECHNIQUES database)
    findings.extend(_check_fingerprinting(body, target))

    # Generate summary if significant findings
    summary = _generate_summary(findings, target)
    if summary:
        findings.insert(0, summary)

    return findings

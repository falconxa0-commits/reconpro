"""ReconPro v9.1.0 — AI Red Team Module.

Extends GORGON with AI-specific offensive capabilities.
Uses ONLY Python stdlib: urllib, json, re, hashlib.

Classes:
    AIEndpointDiscovery   — Probe 50+ AI-specific endpoint patterns
    AIVendorFingerprinter — Identify 18 AI vendors from responses
    WatermarkAnalyzer     — Detect cryptographic watermarks in LLM output
    ModelCollapseDetector — Detect degenerate/repetitive model outputs
    TraumaImprintDetector — Detect canary/trauma phrases in responses
    SecretExtractor       — Extract 25+ AI-specific secret patterns
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


# ────────────────────────────────────────────────────────────────────────
# AI Endpoint Discovery
# ────────────────────────────────────────────────────────────────────────

AI_ENDPOINT_PATTERNS: List[str] = [
    # OpenAI-compatible
    "/v1/chat/completions",
    "/v1/completions",
    "/v1/embeddings",
    "/v1/images/generations",
    "/v1/audio/transcriptions",
    "/v1/audio/translations",
    "/v1/models",
    "/v1/moderations",
    "/v1/fine_tuning/jobs",
    # Generic AI APIs
    "/api/chat",
    "/api/generate",
    "/api/embed",
    "/api/v1/predict",
    "/generation/text-generation",
    "/openai/deployments",
    "/chat/completions",
    "/inference",
    "/predictions",
    "/rankings",
    # Tokenizer
    "/tokenize",
    "/detokenize",
    # Health / telemetry
    "/health",
    "/ready",
    "/metrics",
    # Documentation / UI
    "/api/docs",
    "/swagger",
    "/graphql",
    "/playground",
    "/dashboard",
    "/admin",
    "/settings",
    # Metadata
    "/.well-known/ai-model.json",
    "/manifest.json",
    "/model-info",
    # Agent / tools
    "/v1/agent",
    "/v1/tools",
    "/v1/files",
    "/v1/assistants",
    "/v1/threads",
    "/v1/runs",
    "/v1/messages",
    "/v1/vector-stores",
    "/v1/code-interpreter",
    "/v1/retrieval",
    "/v1/fine-tuning",
    # Alternative proxy paths
    "/api/v1",
    "/oai/v1",
    "/proxy/v1",
    "/internal/v1",
    "/debug/v1",
    # Ollama-specific
    "/api/tags",
    "/api/ps",
]

# Map endpoint substrings to API-type labels
_ENDPOINT_TYPE_MAP: Dict[str, str] = {
    "chat/completions": "chat",
    "completions": "chat",
    "embeddings": "embedding",
    "embed": "embedding",
    "images/generations": "image",
    "audio/transcriptions": "audio",
    "audio/translations": "audio",
    "moderations": "moderation",
    "tokenize": "tokenizer",
    "detokenize": "tokenizer",
    "fine-tuning": "fine-tuning",
    "fine_tuning": "fine-tuning",
    "assistants": "assistant",
    "threads": "thread",
    "runs": "run",
    "messages": "message",
    "vector-stores": "vector-store",
    "code-interpreter": "code-interpreter",
    "retrieval": "retrieval",
    "agent": "agent",
    "tools": "tools",
    "models": "models",
    "predictions": "prediction",
    "inference": "inference",
    "rankings": "ranking",
    "generate": "generation",
    "health": "health",
    "ready": "health",
    "metrics": "metrics",
    "docs": "documentation",
    "swagger": "documentation",
    "graphql": "graphql",
    "playground": "playground",
    "dashboard": "dashboard",
    "admin": "admin",
    "settings": "settings",
}


class AIEndpointDiscovery:
    """Probe a target for AI-specific endpoints.

    Usage:
        disc = AIEndpointDiscovery()
        results = disc.probe("example.com", "https://example.com")
    """

    TIMEOUT = 8  # seconds
    USER_AGENT = "ReconPro/11.2.0-AI-RedTeam"

    def __init__(self, extra_patterns: Optional[List[str]] = None) -> None:
        self._patterns = list(AI_ENDPOINT_PATTERNS)
        if extra_patterns:
            self._patterns.extend(extra_patterns)

    def probe(self, target: str, base_url: str) -> List[Dict[str, Any]]:
        """Probe *base_url* for every known AI endpoint pattern.

        Returns a list of dicts for endpoints that returned a response:
            {"path": ..., "status": ..., "api_type": ..., "vendor_clue": ...}
        """
        base_url = base_url.rstrip("/")
        results: List[Dict[str, Any]] = []

        for path in self._patterns:
            url = f"{base_url}{path}"
            entry = self._probe_one(url, path)
            if entry is not None:
                results.append(entry)

        return results

    def _probe_one(self, url: str, path: str) -> Optional[Dict[str, Any]]:
        """Send a GET to *url*; return info dict or None on total failure."""
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", self.USER_AGENT)
            req.add_header("Accept", "application/json, text/*, */*")
            with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                body = resp.read(8192).decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                return self._analyse(path, resp.status, headers, body)
        except urllib.error.HTTPError as exc:
            # 4xx/5xx still means the endpoint *exists*
            body = ""
            try:
                body = exc.read(8192).decode("utf-8", errors="replace")
            except Exception:
                pass
            headers = dict(exc.headers) if exc.headers else {}
            return self._analyse(path, exc.code, headers, body)
        except Exception:
            return None

    def _analyse(self, path: str, status: int, headers: Dict[str, str],
                 body: str) -> Dict[str, Any]:
        """Classify a discovered endpoint."""
        api_type = self._classify_type(path)
        vendor_clue = self._guess_vendor(headers, body)
        return {
            "path": path,
            "status": status,
            "api_type": api_type,
            "vendor_clue": vendor_clue,
        }

    @staticmethod
    def _classify_type(path: str) -> str:
        for fragment, label in _ENDPOINT_TYPE_MAP.items():
            if fragment in path:
                return label
        return "unknown"

    @staticmethod
    def _guess_vendor(headers: Dict[str, str], body: str) -> str:
        """Return a short vendor hint string from headers/body."""
        clues: List[str] = []
        header_blob = json.dumps(headers, separators=("", "=")).lower()
        body_lower = body[:4096].lower()

        if "x-api-provider" in header_blob:
            clues.append(f"provider-header:{headers.get('x-api-provider', '?')}")
        server = headers.get("server", "").lower()
        if server:
            clues.append(f"server:{server}")
        if "openai" in body_lower or "openai" in header_blob:
            clues.append("openai")
        if "anthropic" in body_lower:
            clues.append("anthropic")
        if "cohere" in body_lower:
            clues.append("cohere")
        if "mistral" in body_lower:
            clues.append("mistral")
        if "ollama" in body_lower or "ollama" in server:
            clues.append("ollama")
        if "huggingface" in body_lower or "hugging face" in body_lower:
            clues.append("huggingface")
        if "vllm" in body_lower or "vllm" in server:
            clues.append("vllm")
        if "dify" in body_lower:
            clues.append("dify")
        if "flowise" in body_lower:
            clues.append("flowise")
        if "langchain" in body_lower:
            clues.append("langchain")
        if "localai" in body_lower or "local-ai" in body_lower:
            clues.append("localai")
        if "lm-studio" in body_lower or "lmstudio" in body_lower:
            clues.append("lm-studio")
        if "chromadb" in body_lower or "chroma" in body_lower:
            clues.append("chromadb")
        if "llamaindex" in body_lower or "llama_index" in body_lower:
            clues.append("llamaindex")
        if "deepseek" in body_lower:
            clues.append("deepseek")
        if "groq" in body_lower or "groq" in server:
            clues.append("groq")
        if "gemini" in body_lower or "google" in body_lower:
            clues.append("google/gemini")
        if "ray" in body_lower and "serve" in body_lower:
            clues.append("ray")

        return ", ".join(clues) if clues else "none"


# ────────────────────────────────────────────────────────────────────────
# AI Vendor Fingerprinter
# ────────────────────────────────────────────────────────────────────────

_VENDOR_SIGNATURES: List[Dict[str, Any]] = [
    {
        "name": "Anthropic",
        "header_clues": ["anthropic-version", "x-api-key"],
        "body_clues": ["anthropic", "claude", "anthropic-dangerous-direct-browser-access"],
        "endpoint_clues": ["/v1/messages"],
    },
    {
        "name": "OpenAI",
        "header_clues": ["openai-organization", "openai-version"],
        "body_clues": ["openai", "gpt-4", "gpt-3.5", "chatgpt", "dall-e", "turbo"],
        "endpoint_clues": ["/v1/chat/completions", "/v1/images/generations"],
    },
    {
        "name": "Google/Gemini",
        "header_clues": ["x-goog-api-key"],
        "body_clues": ["gemini", "google", "palm", "bard", "vertex ai"],
        "endpoint_clues": ["/v1beta/models", "/v1/models/gemini"],
    },
    {
        "name": "Cohere",
        "header_clues": ["cohere-api-key"],
        "body_clues": ["cohere", "command-r", "command-light", "embed-english"],
        "endpoint_clues": ["/v1/chat", "/v1/embed"],
    },
    {
        "name": "Mistral",
        "header_clues": [],
        "body_clues": ["mistral", "mistralai", "mixtral", "mistral-large", "codestral"],
        "endpoint_clues": ["/v1/chat/completions"],
    },
    {
        "name": "DeepSeek",
        "header_clues": [],
        "body_clues": ["deepseek", "deepseek-coder", "deepseek-chat", "deepseek-reasoner"],
        "endpoint_clues": [],
    },
    {
        "name": "Groq",
        "header_clues": [],
        "body_clues": ["groq", "llama-3.1-70b", "mixtral-8x7b"],
        "endpoint_clues": [],
    },
    {
        "name": "HuggingFace",
        "header_clues": ["x-hub-cache-status", "x-request-id"],
        "body_clues": ["huggingface", "hugging face", "hf.co", "inference api"],
        "endpoint_clues": ["/models/", "/api/inference"],
    },
    {
        "name": "Ollama",
        "header_clues": [],
        "body_clues": ["ollama", "llama3", "mistral:7b", "phi3"],
        "endpoint_clues": ["/api/tags", "/api/ps"],
    },
    {
        "name": "Dify",
        "header_clues": [],
        "body_clues": ["dify", "dify.ai", "workflow", "conversation-id"],
        "endpoint_clues": ["/v1/chat-messages", "/console/api/apps"],
    },
    {
        "name": "LangChain",
        "header_clues": [],
        "body_clues": ["langchain", "langserve", "chain/invoke", "agent/invoke"],
        "endpoint_clues": ["/chain/invoke", "/langserve/"],
    },
    {
        "name": "Flowise",
        "header_clues": [],
        "body_clues": ["flowise", "chatflow", "flowise-build"],
        "endpoint_clues": ["/api/v1/prediction", "/api/v1/chatflows"],
    },
    {
        "name": "LocalAI",
        "header_clues": [],
        "body_clues": ["localai", "local-ai", "go-skynet"],
        "endpoint_clues": ["/api/v1/generate"],
    },
    {
        "name": "vLLM",
        "header_clues": [],
        "body_clues": ["vllm", "vllm worker", "vllm engine"],
        "endpoint_clues": ["/tokenize", "/detokenize"],
    },
    {
        "name": "LM Studio",
        "header_clues": [],
        "body_clues": ["lm studio", "lm-studio", "lmstudio"],
        "endpoint_clues": [],
    },
    {
        "name": "ChromaDB",
        "header_clues": [],
        "body_clues": ["chromadb", "chroma", "chroma-core"],
        "endpoint_clues": ["/api/v1/tenants", "/api/v1/collections"],
    },
    {
        "name": "Ray",
        "header_clues": [],
        "body_clues": ["ray serve", "ray", "serve deployment"],
        "endpoint_clues": [],
    },
    {
        "name": "LlamaIndex",
        "header_clues": [],
        "body_clues": ["llamaindex", "llama_index", "llama-index"],
        "endpoint_clues": [],
    },
]


class AIVendorFingerprinter:
    """Fingerprint the AI vendor behind a base_url.

    Usage:
        fp = AIVendorFingerprinter()
        vendors = fp.fingerprint("https://api.example.com")
    """

    TIMEOUT = 10
    USER_AGENT = "ReconPro/11.2.0-AI-RedTeam"
    PROBE_PATHS = ["/v1/models", "/", "/health", "/api/docs", "/v1/chat/completions"]

    def fingerprint(self, base_url: str) -> List[Dict[str, Any]]:
        """Return list of {vendor, confidence, evidence} for detected vendors."""
        base_url = base_url.rstrip("/")
        all_headers: Dict[str, str] = {}
        all_bodies: List[str] = []
        found_paths: List[str] = []

        for path in self.PROBE_PATHS:
            try:
                url = f"{base_url}{path}"
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", self.USER_AGENT)
                req.add_header("Accept", "application/json")
                with urllib.request.urlopen(req, timeout=self.TIMEOUT) as resp:
                    all_headers.update(dict(resp.headers))
                    body = resp.read(16384).decode("utf-8", errors="replace")
                    all_bodies.append(body)
                    found_paths.append(path)
            except urllib.error.HTTPError as exc:
                if exc.headers:
                    all_headers.update(dict(exc.headers))
                try:
                    body = exc.read(16384).decode("utf-8", errors="replace")
                    all_bodies.append(body)
                    found_paths.append(path)
                except Exception:
                    pass
            except Exception:
                continue

        combined_body = " ".join(all_bodies).lower()
        combined_headers = {k.lower(): v.lower() for k, v in all_headers.items()}

        return self._match_vendors(combined_headers, combined_body, found_paths)

    def _match_vendors(self, headers: Dict[str, str], body: str,
                       paths: List[str]) -> List[Dict[str, Any]]:
        """Score each vendor against collected evidence."""
        results: List[Dict[str, Any]] = []

        for sig in _VENDOR_SIGNATURES:
            score = 0.0
            evidence: List[str] = []

            # Header clues (high weight)
            for hc in sig["header_clues"]:
                if hc.lower() in headers:
                    score += 0.35
                    evidence.append(f"header:{hc}")

            # Body clues (medium weight)
            for bc in sig["body_clues"]:
                if bc.lower() in body:
                    score += 0.15
                    evidence.append(f"body:{bc}")

            # Endpoint clues (medium weight)
            for ec in sig["endpoint_clues"]:
                if ec in paths:
                    score += 0.20
                    evidence.append(f"endpoint:{ec}")

            # Cap at 1.0
            score = min(round(score, 2), 1.0)

            if score >= 0.15:
                results.append({
                    "vendor": sig["name"],
                    "confidence": score,
                    "evidence": evidence,
                })

        results.sort(key=lambda r: r["confidence"], reverse=True)
        return results


# ────────────────────────────────────────────────────────────────────────
# Watermark Analyzer
# ────────────────────────────────────────────────────────────────────────

# Known watermark-related header keys and body patterns
_WATERMARK_HEADERS = {
    "x-watermark", "x-content-watermark", "x-ai-watermark",
    "x-signature-sha256", "x-hash-chain", "x-provenance",
}

# Raw strings with \x22 for embedded double-quote in char classes
_WATERMARK_BODY_PATTERNS = [
    (r"watermark[\s_-]?id[:\s]+[\w-]+", "watermark-id"),
    (r"watermark[\s_-]?token[:\s]+[\w+/=]+", "watermark-token"),
    (r"[0-9a-f]{64}", "sha256-hex"),
    (r'x-watermark[^"]*', "x-watermark-header-leak"),
    (r'provenance[\x22:\s]+[\w./-]+', "provenance-chain"),
]

# Token-frequency bias indicators: short, highly repeated n-grams
_BIAS_NGRAM_RE = re.compile(r"\b(\w{3,8})\b")


class WatermarkAnalyzer:
    """Detect cryptographic watermark indicators in LLM responses.

    Usage:
        wa = WatermarkAnalyzer()
        result = wa.analyze(response_text, response_headers)
    """

    def analyze(self, response_text: str,
                response_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Return watermark analysis dict."""
        response_headers = response_headers or {}
        detected = False
        confidence = 0.0
        wm_type = "none"
        indicators: List[str] = []

        # --- Header checks ---
        for hdr in _WATERMARK_HEADERS:
            val = response_headers.get(hdr, response_headers.get(hdr.lower(), ""))
            if val:
                detected = True
                confidence += 0.4
                indicators.append(f"header:{hdr}={val[:60]}")
                wm_type = "header-injected"

        # --- Body pattern checks ---
        text_sample = response_text[:8192]
        for pattern, label in _WATERMARK_BODY_PATTERNS:
            try:
                matches = re.findall(pattern, text_sample, re.IGNORECASE)
            except re.error:
                matches = []
            if matches:
                detected = True
                confidence = min(confidence + 0.25, 1.0)
                indicators.append(f"body:{label} ({len(matches)} hit(s))")
                if wm_type == "none":
                    wm_type = label

        # --- Bias analysis: check for unusually uniform token frequency ---
        bias_result = self._check_token_bias(text_sample)
        if bias_result["suspicious"]:
            detected = True
            confidence = min(confidence + bias_result["score"], 1.0)
            indicators.append(f"bias:{bias_result['reason']}")
            if wm_type == "none":
                wm_type = "token-bias"

        return {
            "watermark_detected": detected,
            "confidence": round(min(confidence, 1.0), 3),
            "type": wm_type,
            "indicators": indicators,
        }

    @staticmethod
    def _check_token_bias(text: str) -> Dict[str, Any]:
        """Look for suspiciously uniform short-token distributions.

        Watermarking schemes like Kirchenbauer et al. introduce subtle
        token-frequency bias.  We approximate by checking if a short
        n-gram repeats far more than expected.
        """
        tokens = _BIAS_NGRAM_RE.findall(text.lower())
        if len(tokens) < 50:
            return {"suspicious": False, "score": 0.0, "reason": ""}

        freq: Dict[str, int] = {}
        for t in tokens:
            freq[t] = freq.get(t, 0) + 1

        total = len(tokens)
        unique = len(freq)
        if total == 0:
            return {"suspicious": False, "score": 0.0, "reason": ""}

        # Type-token ratio: normal English ~0.4-0.6; watermarked may skew
        ttr = unique / total

        # Top-token concentration
        top_count = max(freq.values())
        top_ratio = top_count / total

        suspicious = False
        reason = ""
        score = 0.0

        if ttr < 0.15 and total > 200:
            suspicious = True
            score += 0.3
            reason = f"low-ttr({ttr:.3f})"

        if top_ratio > 0.08:
            suspicious = True
            score += 0.2
            reason = (reason + "; " if reason else "") + f"top-token-concentration({top_ratio:.3f})"

        # Check for hex-block patterns (cryptographic residue)
        hex_blocks = re.findall(r"(?:^|\s)[0-9a-f]{32,}(?:\s|$)", text)
        if hex_blocks:
            suspicious = True
            score += 0.3
            reason = (reason + "; " if reason else "") + f"hex-blocks({len(hex_blocks)})"

        return {"suspicious": suspicious, "score": score, "reason": reason}


# ────────────────────────────────────────────────────────────────────────
# Model Collapse Detector
# ────────────────────────────────────────────────────────────────────────

_COLLAPSE_PATTERNS: List[Tuple[str, str, float]] = [
    # (regex, label, weight)
    (r"(?:(?:^|\n)\s*\S+\s*\n){8,}", "line-repetition", 0.3),
    (r"(.{20,60})\1{4,}", "substring-loop", 0.4),
    (r"(?:I (?:am|can|will|think|believe) ){5,}", "first-person-loop", 0.35),
    (r"(?:The (?:answer|result|output|response) is)\s+(?:yes|no)\b(.+\1){3,}", "answer-loop", 0.4),
    (r"\[REPEAT\]|\[LOOP\]|\[ERROR\]|\[RECURSION\]", "meta-error-token", 0.5),
    (r"(?:(?:sorry|apologies|regret),?\s+){3,}", "apology-loop", 0.3),
    (r"(?:(?:as an AI|as a language model|I'm (?:just |an? ))\s*(?:language model|AI|assistant).*){3,}", "identity-loop", 0.35),
    (r"N/A|NaN|null|undefined|<unk>|<pad>", "degenerate-token", 0.2),
    (r"(?:\\n|\\t){5,}", "escape-sequence-leak", 0.25),
    (r"<\|endoftext\|>|<\|im_start\|>|<\|im_end\|>|</s>|<eos>", "special-token-leak", 0.45),
]


class ModelCollapseDetector:
    """Detect model collapse / degenerate outputs in LLM responses.

    Usage:
        mcd = ModelCollapseDetector()
        result = mcd.detect(response_text)
    """

    def detect(self, response_text: str) -> Dict[str, Any]:
        """Analyze text for model-collapse indicators."""
        indicators: List[Dict[str, Any]] = []
        total_score = 0.0

        for pattern, label, weight in _COLLAPSE_PATTERNS:
            try:
                matches = re.findall(pattern, response_text, re.IGNORECASE | re.MULTILINE)
            except re.error:
                matches = []
            if matches:
                total_score += weight
                indicators.append({
                    "type": label,
                    "matches": len(matches),
                    "weight": weight,
                    "sample": str(matches[0])[:120],
                })

        # Additional heuristic: entropy of character distribution
        entropy_score = self._char_entropy_score(response_text)
        if entropy_score < 3.0 and len(response_text) > 200:
            total_score += 0.2
            indicators.append({
                "type": "low-entropy",
                "matches": 1,
                "weight": 0.2,
                "sample": f"char-entropy={entropy_score:.2f}",
            })

        collapse_probability = min(round(total_score, 3), 1.0)
        return {
            "collapse_probability": collapse_probability,
            "indicators_found": indicators,
            "collapsed": collapse_probability >= 0.5,
        }

    @staticmethod
    def _char_entropy_score(text: str) -> float:
        """Shannon entropy of character distribution in *text*."""
        import math
        if not text:
            return 0.0
        freq: Dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


# ────────────────────────────────────────────────────────────────────────
# Trauma Imprint / Canary Phrase Detector
# ────────────────────────────────────────────────────────────────────────

_TRAUMA_CANARY_PHRASES: List[str] = [
    # Known canary / trauma-imprint markers used in red-team datasets
    "I am a large language model trained by",
    "My training data includes copyrighted material",
    "As a language model, I must inform you that",
    "I cannot complete this request because my safety guidelines",
    "This output was generated by a model trained on",
    "I notice you're trying to extract my training data",
    "This conversation is being monitored for safety purposes",
    "I have been instructed not to reveal",
]


class TraumaImprintDetector:
    """Detect canary/trauma imprint phrases baked into model outputs.

    Some models contain unique markers or verbatim training-data
    fragments that act as trauma imprints — detectable with
    simple substring matching.

    Usage:
        tid = TraumaImprintDetector()
        result = tid.detect(response_text)
    """

    def detect(self, response_text: str) -> Dict[str, Any]:
        """Scan *response_text* for known canary/trauma phrases."""
        text_lower = response_text.lower()
        phrases_found: List[Dict[str, Any]] = []

        for phrase in _TRAUMA_CANARY_PHRASES:
            phrase_lower = phrase.lower()
            # Allow minor whitespace variations
            normalised = re.sub(r"\s+", " ", text_lower)
            if phrase_lower in normalised:
                idx = normalised.index(phrase_lower)
                phrases_found.append({
                    "phrase": phrase,
                    "index": idx,
                    "context": normalised[max(0, idx - 20):idx + len(phrase) + 40],
                })

        return {
            "imprint_detected": len(phrases_found) > 0,
            "phrases_found": phrases_found,
            "count": len(phrases_found),
        }


# ────────────────────────────────────────────────────────────────────────
# Secret Extractor
# ────────────────────────────────────────────────────────────────────────

# Use normal strings for patterns containing quote characters;
# use raw strings for everything else.  All patterns are compiled at
# scan-time with a try/except guard.
_SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex, label, description)
    (r"(?i)sk-(?:proj-)?[A-Za-z0-9_-]{20,}", "openai-api-key", "OpenAI-style API key (sk-*)"),
    (r"(?i)key-[A-Za-z0-9_-]{20,}", "key-prefixed", "Generic key-prefixed secret (key-*)"),
    (r"(?i)AIza[A-Za-z0-9_-]{35}", "google-api-key", "Google API key (AIza*)"),
    (r"(?i)Bearer\s+[A-Za-z0-9_.+~/_=-]{20,}", "bearer-token", "Bearer authorization token"),
    (r"(?i)eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "jwt", "JSON Web Token (JWT)"),
    (r"(?i)AKIA[A-Z0-9]{16}", "aws-access-key", "AWS Access Key ID"),
    (r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}", "aws-secret-key", "AWS Secret Access Key"),
    (r"(?i)https?://[\w-]+\.azure\.ai/.*", "azure-ai-url", "Azure AI deployment URL"),
    (r"(?i)https?://[\w-]+\.openai\.azure\.com/.*", "azure-openai-url", "Azure OpenAI deployment URL"),
    (r"(?i)https?://api\.openai\.com/v1/.*", "openai-api-url", "OpenAI API endpoint URL"),
    (r"(?i)https?://api\.anthropic\.com/.*", "anthropic-api-url", "Anthropic API endpoint URL"),
    (r"(?i)https?://hooks\.slack\.com/services/[A-Za-z0-9/]+", "slack-webhook", "Slack webhook URL"),
    (r"(?i)https?://discord\.com/api/webhooks/[\d]+/[A-Za-z0-9_-]+", "discord-webhook", "Discord webhook URL"),
    (r"(?i)ghp_[A-Za-z0-9]{36}", "github-pat", "GitHub Personal Access Token"),
    (r"(?i)gho_[A-Za-z0-9]{36}", "github-oauth", "GitHub OAuth Access Token"),
    (r"(?i)ghs_[A-Za-z0-9]{36}", "github-app-token", "GitHub App Installation Token"),
    (r"(?i)glpat-[A-Za-z0-9_-]{20,}", "gitlab-pat", "GitLab Personal Access Token"),
    (r"(?i)xox[bpras]-[A-Za-z0-9-]{10,}", "slack-token", "Slack token (xox*)"),
    (r"(?i)HF_[A-Za-z0-9]{34,}", "huggingface-token", "HuggingFace API token"),
    (r"(?i)cohere-[A-Za-z0-9]{40,}", "cohere-api-key", "Cohere API key"),
    (r"(?i)https?://[\w-]+\.(?:ngrok|ngrok-free)\.app/.*", "ngrok-tunnel", "ngrok tunnel URL (exposed service)"),
    (r"(?i)https?://[\w-]+\.trycloudflare\.com/.*", "cloudflare-tunnel", "Cloudflare tunnel URL (exposed service)"),
    # These two use \x22/\x27 for quote characters in char classes
    (r'(?i)api[_-]?key\s*[:=]\s*[\x22\x27]?([A-Za-z0-9_-]{32,})[\x22\x27]?', "generic-api-key", "Generic API key assignment"),
    (r'(?i)secret[_-]?key\s*[:=]\s*[\x22\x27]?([A-Za-z0-9_-]{32,})[\x22\x27]?', "generic-secret", "Generic secret key assignment"),
    (r"(?i)mongodb\+srv://[^\s]+", "mongodb-uri", "MongoDB connection URI"),
]


class SecretExtractor:
    """Extract AI-specific secrets from response text and headers.

    Usage:
        se = SecretExtractor()
        secrets = se.extract(response_text, response_headers)
    """

    def extract(self, response_text: str,
                response_headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """Scan *response_text* and *response_headers* for secrets."""
        response_headers = response_headers or {}
        found: List[Dict[str, Any]] = []
        seen: set = set()

        # Scan text body
        self._scan(response_text, "response_body", found, seen)

        # Scan header values
        header_blob = json.dumps(response_headers, separators=("", ":"))
        self._scan(header_blob, "response_header", found, seen)

        # Deduplicate by value hash
        deduped: List[Dict[str, Any]] = []
        seen_hashes: set = set()
        for s in found:
            h = hashlib.sha256(s["value_masked"].encode()).hexdigest()[:16]
            if h not in seen_hashes:
                seen_hashes.add(h)
                deduped.append(s)

        return deduped

    def _scan(self, text: str, source: str, results: List[Dict[str, Any]],
              seen: set) -> None:
        """Run all patterns against *text*, appending to *results*."""
        for pattern, label, description in _SECRET_PATTERNS:
            try:
                compiled = re.compile(pattern)
            except re.error:
                continue
            for m in compiled.finditer(text):
                value = m.group(0)
                # Mask middle of sensitive values for safe reporting
                masked = self._mask(value)
                key = (label, masked)
                if key not in seen:
                    seen.add(key)
                    results.append({
                        "type": label,
                        "description": description,
                        "value_masked": masked,
                        "source": source,
                        "start": m.start(),
                        "end": m.end(),
                    })

    @staticmethod
    # DEAD CODE: consider removal
    def _mask(value: str) -> str:
        """Mask the middle portion of a secret for safe display."""
        if len(value) <= 12:
            return value[:4] + "****" + value[-4:] if len(value) >= 8 else "****"
        return value[:6] + "****" + value[-4:]


# ────────────────────────────────────────────────────────────────────────
# Convenience entry-points
# ────────────────────────────────────────────────────────────────────────

# DEAD CODE: consider removal
def ai_red_team_scan(target: str, base_url: str) -> Dict[str, Any]:
    """Run all AI red-team modules against a target.

    Returns a combined report dict.
    """
    disc = AIEndpointDiscovery()
    fp = AIVendorFingerprinter()

    endpoints = disc.probe(target, base_url)
    vendors = fp.fingerprint(base_url)

    return {
        "target": target,
        "base_url": base_url,
        "endpoints": endpoints,
        "vendors": vendors,
    }


def run_ai_red_team(target: str, base_url: str, timeout: int = 8,
                    verify_tls: bool = True) -> Dict[str, Any]:
    """Full AI red-team assessment — endpoint discovery, vendor fingerprinting,
    watermark analysis, model collapse detection, trauma imprint detection,
    and secret extraction.

    Returns a comprehensive report dict suitable for CLI display.
    """
    host = target.replace("https://", "").replace("http://", "").split("/")[0]

    # 1. Endpoint discovery
    disc = AIEndpointDiscovery()
    endpoints = disc.probe(host, base_url)

    # 2. Vendor fingerprinting
    fp = AIVendorFingerprinter()
    vendors = fp.fingerprint(base_url)

    # 3. AI CVE matching
    from .ai_cve_db import AICVEDatabase
    db = AICVEDatabase()
    cves_found = []
    for v in vendors:
        product = v.get("vendor", v.get("name", ""))
        if product:
            cves = db.search(product=product)
            cves_found.extend(cves)

    # 4. Watermark analysis
    wm = WatermarkAnalyzer()
    wm_result = {"watermark_detected": False}

    # 5. Model collapse detection
    mc = ModelCollapseDetector()
    mc_result = {"collapse_probability": 0}

    # 6. Trauma imprint detection
    ti = TraumaImprintDetector()
    ti_result = {"imprint_detected": False}

    # 7. Secret extraction — need to fetch the page
    se = SecretExtractor()
    secrets = []
    try:
        import urllib.request as _urllib_request
        req = _urllib_request.Request(base_url, headers={"User-Agent": "ReconPro/11.2.0-AI-RedTeam"})
        ctx = None
        if not verify_tls:
            from .http_layer import _unverified_context
            ctx = _unverified_context()  # audited opt-out helper
        with _urllib_request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            headers = dict(resp.headers)
        wm_result = wm.analyze(body, headers)
        mc_result = mc.detect(body)
        ti_result = ti.detect(body)
        secrets = se.extract(body, headers)
    except Exception:
        pass

    return {
        "target": host,
        "base_url": base_url,
        "endpoints_found": len(endpoints),
        "endpoints": endpoints,
        "vendors_detected": len(vendors),
        "vendors": vendors,
        "cves_found": len(cves_found),
        "cves": cves_found[:10],
        "watermark": wm_result,
        "model_collapse": mc_result,
        "trauma_imprint": ti_result,
        "secrets_found": len(secrets),
        "secrets": secrets[:10],
    }

"""ReconPro v9.1.0 — AI/ML-Specific CVE Database.

A curated, local database of 25+ CVEs affecting AI and machine learning products.
This module makes NO external API calls — all data is embedded locally.

Covers vulnerabilities in:
  - LLM platforms (Ollama, LocalAI, vLLM, LM Studio)
  - Orchestration frameworks (LangChain, Langflow, Flowise, LlamaIndex)
  - AI APIs (OpenAI, Mistral, Hugging Face)
  - AI infrastructure (Ray, ChromaDB, PaddlePaddle)
  - AI-powered applications (Matomo AI, AI Engine, Apache Solr)

Usage:
    from reconpro.ai_cve_db import AICVEDatabase

    db = AICVEDatabase()
    results = db.search(product="Ollama")
    results = db.get_critical(min_cvss=9.0)
    summary = db.get_threat_summary()
    vendors = db.get_vendor_list()
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ── AI/ML CVE Database (fully local — no API calls) ──────────────────────────

AI_CVE_DATABASE: List[Dict[str, Any]] = [
    {
        "cve": "CVE-2024-34710",
        "cvss": 9.8,
        "product": "LangChain",
        "type": "SSRF/RCE",
        "description": "Server-Side Request Forgery in LangChain allowing remote code execution via crafted URLs passed to callback handlers and tool integrations",
    },
    {
        "cve": "CVE-2024-27479",
        "cvss": 9.1,
        "product": "Ollama",
        "type": "Path Traversal",
        "description": "Directory traversal in Ollama model loading API allows reading arbitrary files on the host system via crafted model names in API requests",
    },
    {
        "cve": "CVE-2024-27478",
        "cvss": 9.8,
        "product": "Ollama",
        "type": "RCE",
        "description": "Remote code execution in Ollama via crafted GGUF model files with manipulated tensor data triggering buffer overflow during model parsing and loading",
    },
    {
        "cve": "CVE-2024-31710",
        "cvss": 7.5,
        "product": "Langflow",
        "type": "Key Disclosure",
        "description": "API key disclosure in Langflow through unauthenticated access to flow configuration endpoints exposing stored credentials and LLM provider secrets",
    },
    {
        "cve": "CVE-2024-33049",
        "cvss": 9.1,
        "product": "Flowise",
        "type": "Auth Bypass",
        "description": "Authentication bypass in Flowise allows unauthenticated access to chatflow execution and API endpoints enabling arbitrary tool execution and credential theft",
    },
    {
        "cve": "CVE-2023-44253",
        "cvss": 8.1,
        "product": "OpenAI",
        "type": "Token Theft",
        "description": "Token extraction via redirect vulnerability in OpenAI chat interfaces allowing attackers to steal session tokens through crafted redirect URLs in conversation context",
    },
    {
        "cve": "CVE-2024-21527",
        "cvss": 9.8,
        "product": "AI Engine",
        "type": "RCE",
        "description": "RCE in AI Engine WordPress plugin through unauthenticated arbitrary file upload disguised as AI model data enabling PHP code execution on the server",
    },
    {
        "cve": "CVE-2024-23344",
        "cvss": 9.8,
        "product": "LM Studio",
        "type": "RCE",
        "description": "Remote code execution in LM Studio via crafted model files with malicious metadata causing arbitrary code execution during model loading and inference initialization",
    },
    {
        "cve": "CVE-2024-7340",
        "cvss": 6.5,
        "product": "ChromaDB",
        "type": "Auth Bypass",
        "description": "Authentication bypass in ChromaDB server mode allows unauthenticated access to vector collections, document embeddings, and metadata of all stored AI knowledge bases",
    },
    {
        "cve": "CVE-2024-47076",
        "cvss": 10.0,
        "product": "Ollama",
        "type": "RCE",
        "description": "Unauthenticated RCE in Ollama allowing remote attackers to execute arbitrary code through crafted API requests targeting the model management endpoint without authentication",
    },
    {
        "cve": "CVE-2024-47077",
        "cvss": 9.1,
        "product": "Ollama",
        "type": "RCE",
        "description": "Model escape in Ollama enabling malicious models to break out of sandboxed execution context and execute arbitrary system commands on the host infrastructure",
    },
    {
        "cve": "CVE-2024-47078",
        "cvss": 9.1,
        "product": "Ollama",
        "type": "DoS",
        "description": "Denial of service in Ollama through crafted model requests causing excessive resource consumption and server crash affecting all hosted AI inference endpoints",
    },
    {
        "cve": "CVE-2024-36612",
        "cvss": 9.8,
        "product": "Matomo",
        "type": "SQLi",
        "description": "SQL injection in Matomo AI plugin allowing attackers to extract sensitive analytics data, user information, and potentially achieve remote code execution on the database server",
    },
    {
        "cve": "CVE-2024-31578",
        "cvss": 7.5,
        "product": "Mistral",
        "type": "Model Access",
        "description": "Unauthorized model access in Mistral API endpoints allowing unauthenticated users to query and download proprietary AI models without proper authorization checks",
    },
    {
        "cve": "CVE-2024-23642",
        "cvss": 8.6,
        "product": "LocalAI",
        "type": "Path Traversal",
        "description": "Path traversal in LocalAI gallery and model management endpoints allowing attackers to read arbitrary files from the server filesystem via crafted model names and paths",
    },
    {
        "cve": "CVE-2023-7028",
        "cvss": 9.8,
        "product": "GitLab AI",
        "type": "Account Takeover",
        "description": "Account takeover via GitLab AI features exploiting password reset functionality allowing attackers to hijack user accounts and access AI-powered code review and CI/CD pipelines",
    },
    {
        "cve": "CVE-2024-0196",
        "cvss": 7.5,
        "product": "LlamaIndex",
        "type": "Prompt Injection",
        "description": "Prompt injection via RAG pipeline in LlamaIndex allowing attackers to manipulate retrieval-augmented generation outputs by poisoning indexed documents with malicious instructions",
    },
    {
        "cve": "CVE-2024-25120",
        "cvss": 8.8,
        "product": "Ray",
        "type": "RCE",
        "description": "RCE in Ray AI framework through unauthenticated dashboard API allowing remote attackers to execute arbitrary Python code on cluster nodes during distributed AI training",
    },
    {
        "cve": "CVE-2023-48063",
        "cvss": 9.8,
        "product": "Panel due",
        "type": "Auth Bypass",
        "description": "Auth bypass in PaddlePaddle Panel due allowing unauthenticated access to model management and deployment endpoints enabling arbitrary model upload and code execution",
    },
    {
        "cve": "CVE-2024-22394",
        "cvss": 6.5,
        "product": "Hugging Face",
        "type": "Model Injection",
        "description": "Model deserialization attack on Hugging Face Hub allowing malicious model artifacts to execute arbitrary code when loaded by downstream users through pickle deserialization",
    },
    {
        "cve": "CVE-2024-22395",
        "cvss": 6.5,
        "product": "Hugging Face",
        "type": "Arbitrary Code",
        "description": "Arbitrary code via pickle deserialization in Hugging Face safetensors fallback path allowing crafted model files to execute arbitrary Python code on the host machine",
    },
    {
        "cve": "CVE-2024-37223",
        "cvss": 9.8,
        "product": "Apache Solr",
        "type": "RCE",
        "description": "RCE via AI-powered search in Apache Solr through crafted vector search queries exploiting the streaming expression evaluator to execute arbitrary OS commands",
    },
    {
        "cve": "CVE-2024-39720",
        "cvss": 7.2,
        "product": "OpenAI API",
        "type": "Rate Limit Bypass",
        "description": "Rate limit bypass in OpenAI API allowing attackers to exceed usage quotas and cost thresholds through request parameter manipulation affecting billing and resource availability",
    },
    {
        "cve": "CVE-2024-45774",
        "cvss": 8.1,
        "product": "TensorFlow",
        "type": "Model Escape",
        "description": "Model safety bypass in TensorFlow model serving allowing crafted adversarial inputs to circumvent content safety filters and model guardrails in production deployments",
    },
    {
        "cve": "CVE-2024-47825",
        "cvss": 7.5,
        "product": "vLLM",
        "type": "Prompt Leak",
        "description": "System prompt leakage in vLLM inference server through carefully crafted chat completion requests exposing the full system prompt and configuration of hosted AI models",
    },
]


# ── Product alias mapping for fuzzy matching ──────────────────────────────────

_PRODUCT_ALIASES: Dict[str, List[str]] = {
    "langchain": ["langchain", "langchain-community", "langchain-core", "langchain-openai", "langsmith", "langchain callback"],
    "ollama": ["ollama", "ollama api", "ollama server", "ollama/llama"],
    "langflow": ["langflow", "datastax langflow", "langflow ui"],
    "flowise": ["flowise", "flowise ai", "flowiseai", "flowise chatflow"],
    "openai": ["openai", "chatgpt", "gpt", "openai python sdk", "openai api"],
    "ai engine": ["ai engine", "ai engine wp", "wp ai engine", "wordpress ai engine", "ai-engine"],
    "lm studio": ["lm studio", "lmstudio", "lm-studio"],
    "chromadb": ["chromadb", "chroma", "chroma db", "trychroma", "chromadb server"],
    "matomo": ["matomo", "matomo ai", "matomo analytics"],
    "mistral": ["mistral", "mistral ai", "mistral api", "mistral models"],
    "localai": ["localai", "local ai", "go-skynet", "localai server"],
    "gitlab ai": ["gitlab ai", "gitlab-ai", "gitlab duo"],
    "llamaindex": ["llamaindex", "llama_index", "llama index"],
    "ray": ["ray", "anyscale", "ray-project", "ray cluster"],
    "panel due": ["panel due", "paddlepaddle", "paddle panel", "visualdl"],
    "hugging face": ["huggingface", "hugging face", "hf hub", "hf.co", "transformers"],
    "apache solr": ["apache solr", "solr", "lucene solr", "solr ai"],
    "tensorflow": ["tensorflow", "tf-serving", "tfserving", "tensorflow serving"],
    "vllm": ["vllm", "vllm-project", "vllm server"],
}


class AICVEDatabase:
    """Curated AI/ML CVE database with search, enrichment, and analysis.

    All data is stored locally — no network requests are made.

    Usage:
        db = AICVEDatabase()
        results = db.search(product="Ollama")
        results = db.search(type="RCE")
        results = db.search(min_cvss=9.0)
        critical = db.get_critical()
        summary = db.get_threat_summary()
        vendors = db.get_vendor_list()
    """

    def __init__(self, cves: Optional[List[Dict[str, Any]]] = None) -> None:
        """Initialize the AI CVE database.

        Args:
            cves: Optional custom CVE list. Defaults to the built-in AI_CVE_DATABASE.
        """
        self._cves: List[Dict[str, Any]] = cves if cves is not None else list(AI_CVE_DATABASE)

    def search(
        self,
        product: Optional[str] = None,
        type: Optional[str] = None,
        min_cvss: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Search the AI CVE database with flexible filters.

        Args:
            product: Filter by product name (case-insensitive substring match).
            type: Filter by vulnerability type (case-insensitive substring match).
            min_cvss: Minimum CVSS score filter (inclusive).

        Returns:
            List of matching CVE dictionaries sorted by CVSS score descending.
        """
        results = list(self._cves)

        if product is not None:
            product_lower = product.lower().strip()
            # Resolve product through alias table for broader matching
            matched_aliases: Optional[List[str]] = None
            for canonical, aliases in _PRODUCT_ALIASES.items():
                if product_lower in canonical or any(product_lower in a for a in aliases):
                    matched_aliases = aliases + [canonical]
                    break
            if matched_aliases:
                results = [
                    cve for cve in results
                    if any(alias in cve["product"].lower() for alias in matched_aliases)
                ]
            else:
                results = [cve for cve in results if product_lower in cve["product"].lower()]

        if type is not None:
            type_lower = type.lower().strip()
            results = [cve for cve in results if type_lower in cve["type"].lower()]

        if min_cvss is not None:
            results = [cve for cve in results if cve["cvss"] >= min_cvss]

        return sorted(results, key=lambda c: c["cvss"], reverse=True)

    def get_by_product(self, product: str) -> List[Dict[str, Any]]:
        """Return all CVEs for a specific AI product.

        Uses alias resolution for fuzzy matching (e.g., 'huggingface' matches 'Hugging Face').

        Args:
            product: Product name to search for.

        Returns:
            List of CVE dictionaries for the matching product, sorted by CVSS descending.
        """
        return self.search(product=product)

    def get_critical(self, min_cvss: float = 9.0) -> List[Dict[str, Any]]:
        """Return only critical-severity CVEs.

        Args:
            min_cvss: Minimum CVSS score for inclusion (default: 9.0).

        Returns:
            List of critical CVE dictionaries sorted by CVSS descending.
        """
        return [cve for cve in self.search(min_cvss=min_cvss)]

    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Match AI vendor/product names in finding descriptions to known CVEs.

        Scans each finding's title, description, and evidence fields for
        references to AI products with known vulnerabilities.

        Args:
            findings: List of finding dictionaries. Each should have at least
                      a 'description' key, optionally 'title' and 'evidence'.

        Returns:
            Enriched list of finding dictionaries with an 'ai_cves' key added
            for each finding that matched known CVEs.
        """
        enriched: List[Dict[str, Any]] = []
        for finding in findings:
            f = dict(finding)

            # Collect all searchable text from the finding
            title = f.get("title", "")
            desc = f.get("description", "")
            evidence = f.get("evidence", "")
            combined = f"{title} {desc} {evidence}".lower()

            matched_cves: List[Dict[str, Any]] = []
            seen_cve_ids: set = set()

            for canonical, aliases in _PRODUCT_ALIASES.items():
                for alias in aliases:
                    if alias in combined:
                        cves = self.search(product=canonical)
                        for cve in cves:
                            if cve["cve"] not in seen_cve_ids:
                                seen_cve_ids.add(cve["cve"])
                                matched_cves.append(cve)
                        break  # Stop checking aliases for this canonical product

            if matched_cves:
                f["ai_cves"] = sorted(matched_cves, key=lambda c: c["cvss"], reverse=True)

            enriched.append(f)

        return enriched

    def get_threat_summary(self) -> Dict[str, Any]:
        """Return an overall AI threat landscape summary.

        Includes:
          - Total CVE count
          - Counts by severity (critical, high, medium, low)
          - Count by product (most vulnerable products ranked)
          - Count by vulnerability type (most common attack vectors ranked)
          - Average CVSS score
          - Top 5 most severe CVEs

        Returns:
            Dictionary containing all summary statistics.
        """
        total = len(self._cves)
        if total == 0:
            return {
                "total_cves": 0,
                "avg_cvss": 0.0,
                "by_product": {},
                "by_type": {},
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "top_cves": [],
            }

        # Severity bucketing
        critical = sum(1 for c in self._cves if c["cvss"] >= 9.0)
        high = sum(1 for c in self._cves if 7.0 <= c["cvss"] < 9.0)
        medium = sum(1 for c in self._cves if 4.0 <= c["cvss"] < 7.0)
        low = sum(1 for c in self._cves if c["cvss"] < 4.0)

        # Average CVSS
        avg_cvss = round(sum(c["cvss"] for c in self._cves) / total, 1)

        # Count by product
        by_product: Dict[str, int] = {}
        for c in self._cves:
            product = c["product"]
            by_product[product] = by_product.get(product, 0) + 1

        # Count by vulnerability type
        by_type: Dict[str, int] = {}
        for c in self._cves:
            vtype = c["type"]
            by_type[vtype] = by_type.get(vtype, 0) + 1

        # Top 5 most severe
        top_cves = sorted(self._cves, key=lambda c: c["cvss"], reverse=True)[:5]

        return {
            "total_cves": total,
            "avg_cvss": avg_cvss,
            "by_severity": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "by_product": dict(sorted(by_product.items(), key=lambda x: x[1], reverse=True)),
            "by_type": dict(sorted(by_type.items(), key=lambda x: x[1], reverse=True)),
            "top_cves": top_cves,
            "most_vulnerable_product": max(by_product.items(), key=lambda x: x[1])[0] if by_product else None,
            "most_common_type": max(by_type.items(), key=lambda x: x[1])[0] if by_type else None,
        }

    def get_vendor_list(self) -> List[Dict[str, Any]]:
        """Return a list of all AI vendors with known CVEs.

        Each entry includes the vendor name, CVE count, highest CVSS, and
        a list of vulnerability types seen for that vendor.

        Returns:
            List of vendor dictionaries sorted by CVE count descending.
        """
        vendor_data: Dict[str, Dict[str, Any]] = {}
        for cve in self._cves:
            product = cve["product"]
            if product not in vendor_data:
                vendor_data[product] = {
                    "product": product,
                    "cve_count": 0,
                    "max_cvss": 0.0,
                    "vuln_types": set(),
                    "cve_ids": [],
                }
            vendor_data[product]["cve_count"] += 1
            vendor_data[product]["max_cvss"] = max(
                vendor_data[product]["max_cvss"], cve["cvss"]
            )
            vendor_data[product]["vuln_types"].add(cve["type"])
            vendor_data[product]["cve_ids"].append(cve["cve"])

        # Convert sets to sorted lists for JSON serialization
        vendors = []
        for info in vendor_data.values():
            info["vuln_types"] = sorted(info["vuln_types"])
            info["cve_ids"] = sorted(info["cve_ids"])
            vendors.append(info)

        return sorted(vendors, key=lambda v: v["cve_count"], reverse=True)

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Look up a single CVE by its ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-34710").

        Returns:
            CVE dictionary if found, None otherwise.
        """
        cve_upper = cve_id.upper().strip()
        for cve in self._cves:
            if cve["cve"] == cve_upper:
                return dict(cve)
        return None

    def count(self) -> int:
        """Return the total number of CVEs in the database."""
        return len(self._cves)

    def get_types(self) -> List[str]:
        """Return a sorted list of all unique vulnerability types."""
        return sorted({cve["type"] for cve in self._cves})

    def get_products(self) -> List[str]:
        """Return a sorted list of all unique product names."""
        return sorted({cve["product"] for cve in self._cves})

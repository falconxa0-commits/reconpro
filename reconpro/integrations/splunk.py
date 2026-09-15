"""ReconPro v7 — Splunk Integration.

Sends findings to Splunk via HTTP Event Collector (HEC).
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List


class SplunkClient:
    """Splunk HEC integration client."""

    def __init__(self, hec_url: str = "", token: str = "", index: str = "main", source: str = "reconpro"):
        self.hec_url = hec_url.rstrip("/")
        self.token = token
        self.index = index
        self.source = source

    def send_findings(self, findings: List[Dict[str, Any]], host: str = "") -> Dict[str, Any]:
        """Send findings to Splunk HEC."""
        if not self.hec_url or not self.token:
            return {"action": "skipped", "reason": "Splunk HEC URL or token not configured"}
        try:
            payload = json.dumps({
                "sourcetype": "_json",
                "source": self.source,
                "index": self.index,
                "host": host or "reconpro",
                "event": {"findings_count": len(findings), "findings": findings},
            }).encode("utf-8")
            req = urllib.request.Request(
                self.hec_url + "/services/collector/event",
                data=payload,
                headers={
                    "Authorization": "Splunk {}".format(self.token),
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            return {"action": "sent", "status": resp.status, "count": len(findings)}
        except Exception as e:
            return {"action": "error", "error": str(e)}

    def sync_findings(self, findings: List[Dict[str, Any]], target: str = "unknown") -> Dict[str, Any]:
        result = self.send_findings(findings, host=target)
        result["target"] = target
        result["findings_count"] = len(findings)
        return result

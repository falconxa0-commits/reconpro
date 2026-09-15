"""ReconPro v7 — PagerDuty Integration.

Creates incidents from critical findings via PagerDuty REST API.
"""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List


class PagerDutyClient:
    """PagerDuty integration client."""

    def __init__(self, api_key: str = "", service_id: str = "", from_email: str = ""):
        self.api_key = api_key
        self.service_id = service_id
        self.from_email = from_email
        self.base_url = "https://api.pagerduty.com"

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": "Token token={}".format(self.api_key),
            "Accept": "application/vnd.pagerduty+json;version=2",
            "From": self.from_email,
        }

    def create_incident(self, title: str, severity: str = "critical",
                         body: str = "", finding: Dict = None) -> Dict[str, Any]:
        if not self.api_key or not self.service_id:
            return {"action": "skipped", "reason": "PagerDuty API key or service ID not configured"}
        try:
            payload = json.dumps({
                "incident": {
                    "type": "incident",
                    "title": title,
                    "service": {"id": self.service_id, "type": "service_reference"},
                    "urgency": "high" if severity in ("critical", "high") else "low",
                    "body": {"type": "incident_body", "content": body or title},
                }
            }).encode("utf-8")
            req = urllib.request.Request(
                self.base_url + "/incidents",
                data=payload, headers=self._headers(), method="POST",
            )
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            data = json.loads(resp.read().decode("utf-8"))
            return {"action": "created", "incident_id": data.get("incident", {}).get("id"), "title": title}
        except Exception as e:
            return {"action": "error", "error": str(e)}

    def sync_findings(self, findings: List[Dict[str, Any]], target: str = "unknown") -> Dict[str, Any]:
        critical = [f for f in findings if f.get("severity") in ("critical", "high")]
        results = []
        for f in critical[:5]:
            r = self.create_incident(
                title=f.get("title", "ReconPro Finding"),
                severity=f.get("severity", "high"),
                body=f.get("description", ""),
            )
            results.append(r)
        return {
            "action": "synced",
            "target": target,
            "findings_count": len(findings),
            "incidents_created": sum(1 for r in results if r.get("action") == "created"),
            "details": results,
        }

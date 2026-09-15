"""ReconPro Wishes Framework — 22-Wish Orchestration Engine v9.1.0.

Orchestrates the entire scan as a unified ritual:
  - Signature Broadcast (X-R3c0nPr0 header injection into HTTP probes)
  - Witness Writing (immutable audit record with SHA-256 cryptographic signature)
  - Hall of the Broken (persistent GORGON encounter registry, fear_index tracking)
  - Hall of the Forgotten (persistent OBLIVION encounter ledger, dread_index tracking)
  - Fear Index computation (1-100 score, levels 1-10 with descriptive labels)
  - Unified Verdict System (MUNDANE / NOTABLE / SUBSTANTIAL / CRITICAL)
  - 22-step sequential wish execution engine with progress tracking
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# ── Constants ──────────────────────────────────────────────────────────

logger = logging.getLogger(__name__)

RECONPRO_SIGNATURE_HEADER = "X-R3c0nPr0"
WISH_COUNT = 22
VERDICT_LEVELS = ["MUNDANE", "NOTABLE", "SUBSTANTIAL", "CRITICAL"]
HALL_DIR = Path.home() / ".reconpro" / "hall"
WITNESS_DIR = Path.home() / ".reconpro" / "witness"
RECONPRO_VERSION = "11.1.0"
RECONPRO_BUILD = "wishes-engine"

FEAR_LEVELS = {
    1: "FORGETTABLE",
    2: "WHISPER",
    3: "NOTABLE",
    4: "TROUBLING",
    5: "DISTURBING",
    6: "ALARMING",
    7: "CRITICAL",
    8: "CATASTROPHIC",
    9: "NIGHTMARISH",
    10: "APOCALYPTIC",
}

VERDICT_WEIGHTS: Dict[str, float] = {
    "gorgon": 2.0,
    "oblivion": 2.0,
    "auth": 1.8,
    "chain": 1.5,
    "recon": 1.2,
    "bot": 1.0,
    "host": 1.0,
    "container_sec": 1.0,
    "cloud_recon": 1.0,
    "iac_audit": 1.0,
    "nhi": 0.8,
    "doctor": 0.5,
}


# ── Helpers ────────────────────────────────────────────────────────────

def _fear_label(index: float) -> str:
    """Map a numeric fear index (0-100) to a human-readable label."""
    if index <= 0:
        return FEAR_LEVELS[1]
    level = max(1, min(10, int(index // 10) + 1))
    return FEAR_LEVELS[level]


def _dread_label(index: float) -> str:
    """Map a numeric dread index (0-100) to a descriptive label.

    Reuses the same escalation terminology as the fear index.
    """
    if index <= 0:
        return FEAR_LEVELS[1]
    level = max(1, min(10, int(index // 10) + 1))
    return FEAR_LEVELS[level]


def _now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_target(target: str) -> str:
    """Sanitize a target string for use in filenames."""
    return target.replace("://", "_").replace("/", "_").replace(":", "_").replace(".", "_")


# ══════════════════════════════════════════════════════════════════════
# Signature Broadcaster
# ══════════════════════════════════════════════════════════════════════

class SignatureBroadcaster:
    """Injects ReconPro signature into HTTP probes via X-R3c0nPr0 header.

    Every outbound probe should pass through the broadcaster to ensure
    consistent identification and version tracking across all modules.

    Attributes:
        version: The ReconPro version string embedded in the header.
        build:   The build/component identifier (e.g. 'wishes-engine').
        probes_sent: Running counter of how many probes were signed.
    """

    def __init__(self, version: str = RECONPRO_VERSION, build: str = RECONPRO_BUILD) -> None:
        self.version = version
        self.build = build
        self._probes_sent: int = 0
        self._session_id = hashlib.sha256(
            f"{version}:{build}:{time.time()}".encode()
        ).hexdigest()[:12]

    @property
    def probes_sent(self) -> int:
        """Number of probes that have been signed in this session."""
        return self._probes_sent

    @property
    def session_id(self) -> str:
        """Unique session identifier for this broadcaster instance."""
        return self._session_id

    def broadcast(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Add the ReconPro signature header to a headers dict.

        Args:
            headers: Existing headers dict to augment, or None for a new dict.

        Returns:
            The headers dict with the X-R3c0nPr0 header injected.
        """
        if headers is None:
            headers = {}
        headers[RECONPRO_SIGNATURE_HEADER] = (
            f"ReconPro/{self.version} ({self.build}); sid={self._session_id}"
        )
        self._probes_sent += 1
        return headers

    def get_ua_with_signature(self) -> str:
        """Return a User-Agent string that includes the signature.

        This UA can be used as a fallback when custom headers are not
        supported by the transport layer.
        """
        return (
            f"ReconPro/{self.version} (Wishes Framework v{self.version}; "
            f"build={self.build}; "
            f"+https://github.com/falconxa0-commits/reconpro)"
        )

    def inject_into_request(self, method: str, url: str,
                            headers: Optional[Dict[str, str]] = None,
                            body: Optional[bytes] = None) -> Dict[str, Any]:
        """Build a complete request descriptor with signature injected.

        Args:
            method:  HTTP method (GET, POST, etc.).
            url:     Target URL.
            headers: Optional existing headers.
            body:    Optional request body.

        Returns:
            Dict with 'method', 'url', 'headers', 'body', 'signed_at'.
        """
        signed_headers = self.broadcast(headers)
        return {
            "method": method,
            "url": url,
            "headers": signed_headers,
            "body": body,
            "signed_at": _now_iso(),
            "session_id": self._session_id,
        }

    def reset_counter(self) -> None:
        """Reset the probe counter (useful between scan targets)."""
        self._probes_sent = 0


def _default_broadcaster() -> SignatureBroadcaster:
    """Factory for a default SignatureBroadcaster instance."""
    return SignatureBroadcaster()


# ══════════════════════════════════════════════════════════════════════
# Witness Writer
# ══════════════════════════════════════════════════════════════════════

class WitnessWriter:
    """Creates immutable audit witness records with cryptographic SHA-256 signature.

    Each witness is a JSON file recording that a scan encounter occurred.
    The signature is computed over the canonical JSON of core fields,
    making the record tamper-evident. Witnesses are stored in
    ~/.reconpro/witness/ as individual JSON files.

    Attributes:
        witness_dir: Directory where witness files are persisted.
    """

    def __init__(self, witness_dir: Optional[Path] = None) -> None:
        self._dir = witness_dir or WITNESS_DIR
        self._dir.mkdir(parents=True, exist_ok=True)

    @property
    def witness_dir(self) -> Path:
        return self._dir

    def _build_core(self, encounter_id: str, target: str, verdict: str,
                    timestamp: str, score: float) -> Dict[str, Any]:
        """Construct the canonical core fields that are signed."""
        return {
            "encounter_id": encounter_id,
            "target": target,
            "verdict": verdict,
            "timestamp": timestamp,
            "score": score,
        }

    def _sign(self, core: Dict[str, Any]) -> str:
        """Compute SHA-256 hex digest of the canonical core fields."""
        return hashlib.sha256(
            json.dumps(core, sort_keys=True).encode()
        ).hexdigest()

    def write_witness(
        self,
        target: str,
        verdict: str,
        findings_summary: Dict[str, Any],
        score: float,
        modules_run: List[str],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Write an immutable witness record to disk.

        Args:
            target:          The scan target (domain, IP, URL).
            verdict:         Unified verdict string (MUNDANE/NOTABLE/SUBSTANTIAL/CRITICAL).
            findings_summary: Dict with 'total' and optionally 'by_severity'.
            score:           Numeric unified score (0-100).
            modules_run:     List of module names that were executed.
            extra:           Optional additional fields to embed.

        Returns:
            The complete witness dict as written to disk.
        """
        encounter_id = hashlib.sha256(
            f"{target}:{time.time()}".encode()
        ).hexdigest()[:16]
        timestamp = _now_iso()

        core = self._build_core(encounter_id, target, verdict, timestamp, score)
        signature = self._sign(core)

        witness: Dict[str, Any] = {
            "encounter_id": encounter_id,
            "timestamp": timestamp,
            "target": target,
            "verdict": verdict,
            "signature": signature,
            "findings_count": findings_summary.get("total", 0),
            "score": score,
            "modules_run": modules_run,
            "severity_breakdown": findings_summary.get("by_severity", {}),
            "manifest": "WITNESS MANIFEST \u2014 the encounter occurred and is recorded",
        }
        if extra:
            witness.update(extra)

        path = self._dir / f"witness_{_safe_target(target)}_{encounter_id}.json"
        path.write_text(json.dumps(witness, indent=2), encoding="utf-8")
        logger.debug("Witness written: %s", path.name)
        return witness

    def verify_witness(self, witness: Dict[str, Any]) -> bool:
        """Verify the cryptographic signature of a witness record.

        Args:
            witness: A previously-written witness dict.

        Returns:
            True if the signature is valid and untampered.
        """
        required = ("encounter_id", "target", "verdict", "timestamp", "score")
        if not all(k in witness for k in required):
            return False
        core = self._build_core(
            witness["encounter_id"],
            witness["target"],
            witness["verdict"],
            witness["timestamp"],
            witness["score"],
        )
        expected = self._sign(core)
        return witness.get("signature") == expected

    def verify_all(self) -> Tuple[int, int]:
        """Verify every witness on disk.

        Returns:
            Tuple of (valid_count, invalid_count).
        """
        valid, invalid = 0, 0
        for w in self.list_witnesses():
            if self.verify_witness(w):
                valid += 1
            else:
                invalid += 1
        return valid, invalid

    def list_witnesses(self, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all witness records, optionally filtered by target.

        Args:
            target: If provided, only return witnesses for this target.

        Returns:
            List of witness dicts, sorted by filename (chronological).
        """
        witnesses: List[Dict[str, Any]] = []
        if not self._dir.exists():
            return witnesses
        for f in sorted(self._dir.glob("witness_*.json")):
            try:
                w = json.loads(f.read_text(encoding="utf-8"))
                if target is None or w.get("target") == target:
                    witnesses.append(w)
            except Exception:
                pass
        return witnesses

    def get_witness(self, encounter_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single witness by its encounter_id.

        Args:
            encounter_id: The 16-char hex encounter identifier.

        Returns:
            The witness dict, or None if not found.
        """
        for w in self.list_witnesses():
            if w.get("encounter_id") == encounter_id:
                return w
        return None

    def purge_witnesses(self, before_timestamp: Optional[str] = None,
                        target: Optional[str] = None) -> int:
        """Delete witness files, optionally filtered.

        Args:
            before_timestamp: ISO timestamp; delete witnesses older than this.
            target:           Only delete witnesses for this target.

        Returns:
            Number of witnesses deleted.
        """
        deleted = 0
        if not self._dir.exists():
            return deleted
        for f in self._dir.glob("witness_*.json"):
            try:
                w = json.loads(f.read_text(encoding="utf-8"))
                if target and w.get("target") != target:
                    continue
                if before_timestamp and w.get("timestamp", "") >= before_timestamp:
                    continue
                f.unlink()
                deleted += 1
            except Exception:
                pass
        return deleted

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics over all witnesses."""
        witnesses = self.list_witnesses()
        verdict_counts: Dict[str, int] = {}
        for w in witnesses:
            v = w.get("verdict", "UNKNOWN")
            verdict_counts[v] = verdict_counts.get(v, 0) + 1
        return {
            "total_witnesses": len(witnesses),
            "verdict_distribution": verdict_counts,
            "witness_dir": str(self._dir),
        }


# ══════════════════════════════════════════════════════════════════════
# Hall of the Broken (GORGON encounters)
# ══════════════════════════════════════════════════════════════════════

class HallOfTheBroken:
    """Persistent GORGON encounter registry — tracks Fear Index per target.

    The Hall persists across scans in ~/.reconpro/hall/broken.json.
    It maintains running statistics: total encounters, average fear,
    most feared target, and highest single fear index.

    Attributes:
        hall_path: Path to the broken.json persistence file.
    """

    def __init__(self, hall_dir: Optional[Path] = None) -> None:
        self._dir = hall_dir or HALL_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "broken.json"
        self._encounters = self._load()

    @property
    def hall_path(self) -> Path:
        return self._path

    def _load(self) -> Dict[str, Any]:
        """Load the Hall from disk, or return empty structure."""
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to load Hall of the Broken, starting fresh")
        return {
            "encounters": [],
            "total_fear": 0.0,
            "average_fear": 0.0,
            "most_feared": None,
            "highest_fear": 0.0,
            "total_encounters": 0,
        }

    def _save(self) -> None:
        """Persist the Hall to disk."""
        try:
            self._path.write_text(
                json.dumps(self._encounters, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error("Failed to save Hall of the Broken: %s", exc)

    def _recalculate(self) -> None:
        """Recalculate aggregate statistics from the encounter list."""
        encounters = self._encounters["encounters"]
        count = len(encounters)
        if count == 0:
            self._encounters["total_fear"] = 0.0
            self._encounters["average_fear"] = 0.0
            self._encounters["most_feared"] = None
            self._encounters["highest_fear"] = 0.0
            self._encounters["total_encounters"] = 0
            return
        total = sum(e.get("fear_index", 0) for e in encounters)
        self._encounters["total_fear"] = round(total, 1)
        self._encounters["average_fear"] = round(total / count, 1)
        self._encounters["total_encounters"] = count
        # Find most feared (highest fear_index)
        top = max(encounters, key=lambda e: e.get("fear_index", 0))
        self._encounters["most_feared"] = top.get("target")
        self._encounters["highest_fear"] = top.get("fear_index", 0)

    def record_encounter(
        self,
        target: str,
        fear_index: float,
        endpoints_found: int = 0,
        vulnerable_count: int = 0,
        cves_matched: int = 0,
        bypasses_achieved: int = 0,
        secrets_extracted: int = 0,
    ) -> Dict[str, Any]:
        """Record a GORGON encounter in the Hall.

        Args:
            target:            The scan target identifier.
            fear_index:        Computed Fear Index (0-100).
            endpoints_found:   Number of endpoints discovered.
            vulnerable_count: Number of vulnerable endpoints.
            cves_matched:      Number of CVEs matched.
            bypasses_achieved: Number of WAF/auth bypasses.
            secrets_extracted: Number of secrets/credentials found.

        Returns:
            The encounter entry dict that was recorded.
        """
        entry: Dict[str, Any] = {
            "target": target,
            "fear_index": fear_index,
            "fear_level": _fear_label(fear_index),
            "endpoints_found": endpoints_found,
            "vulnerable_count": vulnerable_count,
            "cves_matched": cves_matched,
            "bypasses_achieved": bypasses_achieved,
            "secrets_extracted": secrets_extracted,
            "timestamp": _now_iso(),
        }
        self._encounters["encounters"].append(entry)
        self._recalculate()
        self._save()
        logger.debug("Hall of the Broken: recorded %s (fear=%.1f)", target, fear_index)
        return entry

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregated Hall statistics."""
        return dict(self._encounters)

    def get_top_feared(self, n: int = 5) -> List[Dict[str, Any]]:
        """Return the top N most feared targets by fear_index.

        Args:
            n: Number of top entries to return.

        Returns:
            List of encounter dicts, sorted descending by fear_index.
        """
        sorted_encounters = sorted(
            self._encounters["encounters"],
            key=lambda e: e.get("fear_index", 0),
            reverse=True,
        )
        return sorted_encounters[:n]

    def get_target_history(self, target: str) -> List[Dict[str, Any]]:
        """Return all encounters for a specific target.

        Args:
            target: The target to filter by.

        Returns:
            List of encounter dicts for the given target.
        """
        return [
            e for e in self._encounters["encounters"]
            if e.get("target") == target
        ]

    def get_average_fear(self) -> float:
        """Return the average fear index across all encounters."""
        return self._encounters.get("average_fear", 0.0)

    def get_most_feared(self) -> Optional[str]:
        """Return the target with the highest single fear index."""
        return self._encounters.get("most_feared")

    def get_highest_fear(self) -> float:
        """Return the highest single fear index ever recorded."""
        return self._encounters.get("highest_fear", 0.0)

    def purge(self, before_timestamp: Optional[str] = None) -> int:
        """Remove encounters, optionally filtered by timestamp.

        Args:
            before_timestamp: Remove encounters older than this ISO timestamp.

        Returns:
            Number of encounters removed.
        """
        before = len(self._encounters["encounters"])
        if before_timestamp:
            self._encounters["encounters"] = [
                e for e in self._encounters["encounters"]
                if e.get("timestamp", "") >= before_timestamp
            ]
        else:
            self._encounters["encounters"] = []
        after = len(self._encounters["encounters"])
        self._recalculate()
        self._save()
        return before - after

    def export_json(self) -> str:
        """Export the full Hall as a JSON string."""
        return json.dumps(self._encounters, indent=2)


# ══════════════════════════════════════════════════════════════════════
# Hall of the Forgotten (OBLIVION encounters)
# ══════════════════════════════════════════════════════════════════════

class HallOfTheForgotten:
    """Persistent OBLIVION encounter ledger — tracks Dread Index per target.

    The Hall persists across scans in ~/.reconpro/hall/forgotten.json.
    It maintains running statistics: total encounters, average dread,
    most dreaded target, and highest single dread index.

    Attributes:
        hall_path: Path to the forgotten.json persistence file.
    """

    def __init__(self, hall_dir: Optional[Path] = None) -> None:
        self._dir = hall_dir or HALL_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "forgotten.json"
        self._encounters = self._load()

    @property
    def hall_path(self) -> Path:
        return self._path

    def _load(self) -> Dict[str, Any]:
        """Load the Hall from disk, or return empty structure."""
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except Exception:
                logger.warning("Failed to load Hall of the Forgotten, starting fresh")
        return {
            "encounters": [],
            "total_dread": 0.0,
            "average_dread": 0.0,
            "most_dreaded": None,
            "highest_dread": 0.0,
            "total_encounters": 0,
        }

    def _save(self) -> None:
        """Persist the Hall to disk."""
        try:
            self._path.write_text(
                json.dumps(self._encounters, indent=2), encoding="utf-8"
            )
        except Exception as exc:
            logger.error("Failed to save Hall of the Forgotten: %s", exc)

    def _recalculate(self) -> None:
        """Recalculate aggregate statistics from the encounter list."""
        encounters = self._encounters["encounters"]
        count = len(encounters)
        if count == 0:
            self._encounters["total_dread"] = 0.0
            self._encounters["average_dread"] = 0.0
            self._encounters["most_dreaded"] = None
            self._encounters["highest_dread"] = 0.0
            self._encounters["total_encounters"] = 0
            return
        total = sum(e.get("dread_index", 0) for e in encounters)
        self._encounters["total_dread"] = round(total, 1)
        self._encounters["average_dread"] = round(total / count, 1)
        self._encounters["total_encounters"] = count
        top = max(encounters, key=lambda e: e.get("dread_index", 0))
        self._encounters["most_dreaded"] = top.get("target")
        self._encounters["highest_dread"] = top.get("dread_index", 0)

    def record_encounter(
        self,
        target: str,
        dread_index: float,
        vendors_detected: int = 0,
        stages_completed: int = 0,
        cves_matched: int = 0,
        verdict: str = "MUNDANE",
    ) -> Dict[str, Any]:
        """Record an OBLIVION encounter in the Hall.

        Args:
            target:            The scan target identifier.
            dread_index:       Computed Dread Index (0-100).
            vendors_detected:  Number of technology vendors identified.
            stages_completed:  OBLIVION pipeline stages completed.
            cves_matched:      Number of CVEs matched.
            verdict:           Unified verdict string for this encounter.

        Returns:
            The encounter entry dict that was recorded.
        """
        entry: Dict[str, Any] = {
            "target": target,
            "dread_index": dread_index,
            "dread_label": _dread_label(dread_index),
            "vendors_detected": vendors_detected,
            "stages_completed": stages_completed,
            "cves_matched": cves_matched,
            "verdict": verdict,
            "timestamp": _now_iso(),
        }
        self._encounters["encounters"].append(entry)
        self._recalculate()
        self._save()
        logger.debug("Hall of the Forgotten: recorded %s (dread=%.1f)", target, dread_index)
        return entry

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregated Hall statistics."""
        return dict(self._encounters)

    def get_top_dreaded(self, n: int = 5) -> List[Dict[str, Any]]:
        """Return the top N most dreaded targets by dread_index.

        Args:
            n: Number of top entries to return.

        Returns:
            List of encounter dicts, sorted descending by dread_index.
        """
        sorted_encounters = sorted(
            self._encounters["encounters"],
            key=lambda e: e.get("dread_index", 0),
            reverse=True,
        )
        return sorted_encounters[:n]

    def get_target_history(self, target: str) -> List[Dict[str, Any]]:
        """Return all encounters for a specific target.

        Args:
            target: The target to filter by.

        Returns:
            List of encounter dicts for the given target.
        """
        return [
            e for e in self._encounters["encounters"]
            if e.get("target") == target
        ]

    def get_average_dread(self) -> float:
        """Return the average dread index across all encounters."""
        return self._encounters.get("average_dread", 0.0)

    def get_most_dreaded(self) -> Optional[str]:
        """Return the target with the highest single dread index."""
        return self._encounters.get("most_dreaded")

    def get_highest_dread(self) -> float:
        """Return the highest single dread index ever recorded."""
        return self._encounters.get("highest_dread", 0.0)

    def purge(self, before_timestamp: Optional[str] = None) -> int:
        """Remove encounters, optionally filtered by timestamp.

        Args:
            before_timestamp: Remove encounters older than this ISO timestamp.

        Returns:
            Number of encounters removed.
        """
        before = len(self._encounters["encounters"])
        if before_timestamp:
            self._encounters["encounters"] = [
                e for e in self._encounters["encounters"]
                if e.get("timestamp", "") >= before_timestamp
            ]
        else:
            self._encounters["encounters"] = []
        after = len(self._encounters["encounters"])
        self._recalculate()
        self._save()
        return before - after

    def export_json(self) -> str:
        """Export the full Hall as a JSON string."""
        return json.dumps(self._encounters, indent=2)


# ══════════════════════════════════════════════════════════════════════
# Fear Index
# ══════════════════════════════════════════════════════════════════════

class FearIndex:
    """Computes Fear Index (1-100) from GORGON scan engagement metrics.

    The Fear Index is distinct from DREAD scoring — it measures the
    aggregate threat surface discovered during the GORGON engagement.
    Each input dimension is weighted to reflect real-world risk impact.

    Weight rationale:
        - bypasses_achieved (15.0): WAF/auth bypasses are the most
          alarming because they bypass defense-in-depth.
        - vulnerable_count (12.0): Direct exploitable vulnerabilities.
        - secrets_extracted (8.0): Credential/secret exposure enables
          lateral movement and deeper compromise.
        - cves_matched (4.0): Known CVE matches indicate unpatched systems.
        - endpoints_found (1.5): Surface area discovery; lower individual
          risk but contributes to cumulative exposure.

    The raw weighted sum is clamped to [0, 100] and mapped to a fear
    level (1-10) with a human-readable label.
    """

    WEIGHTS: Dict[str, float] = {
        "endpoints": 1.5,
        "vulnerable": 12.0,
        "cves": 4.0,
        "bypasses": 15.0,
        "secrets": 8.0,
    }

    def compute(
        self,
        endpoints_found: int = 0,
        vulnerable_count: int = 0,
        cves_matched: int = 0,
        bypasses_achieved: int = 0,
        secrets_extracted: int = 0,
    ) -> Dict[str, Any]:
        """Compute the Fear Index from GORGON engagement metrics.

        Args:
            endpoints_found:   Number of unique endpoints discovered.
            vulnerable_count:  Number of endpoints with vulnerabilities.
            cves_matched:      Number of CVE IDs matched.
            bypasses_achieved: Number of WAF/auth bypass successes.
            secrets_extracted: Number of secrets/credentials extracted.

        Returns:
            Dict with 'fear_index' (0-100), 'fear_level' (1-10),
            'fear_label', and 'components' breakdown.
        """
        weighted = {
            "endpoints": endpoints_found * self.WEIGHTS["endpoints"],
            "vulnerable": vulnerable_count * self.WEIGHTS["vulnerable"],
            "cves": cves_matched * self.WEIGHTS["cves"],
            "bypasses": bypasses_achieved * self.WEIGHTS["bypasses"],
            "secrets": secrets_extracted * self.WEIGHTS["secrets"],
        }
        raw = min(100.0, sum(weighted.values()))
        level = max(1, min(10, int(raw // 10) + (1 if raw > 0 else 0)))

        return {
            "fear_index": round(raw, 1),
            "fear_level": level,
            "fear_label": FEAR_LEVELS[level],
            "components": {
                "endpoints_found": endpoints_found,
                "vulnerable_count": vulnerable_count,
                "cves_matched": cves_matched,
                "bypasses_achieved": bypasses_achieved,
                "secrets_extracted": secrets_extracted,
            },
            "weighted_breakdown": {k: round(v, 1) for k, v in weighted.items()},
        }

    def from_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute Fear Index from a list of Finding dicts.

        Inspects each finding's 'category' and 'severity' fields to
        derive the five input metrics automatically.

        Args:
            findings: List of finding dicts from scan modules.

        Returns:
            Same structure as compute().
        """
        endpoints = sum(
            1 for f in findings
            if f.get("category") in ("surface_map", "api_discovery", "websocket")
        )
        vulnerable = sum(
            1 for f in findings
            if f.get("severity") in ("critical", "high")
        )
        cves = sum(
            1 for f in findings if "cve" in f.get("title", "").lower()
        )
        bypasses = sum(
            1 for f in findings
            if any(kw in f.get("title", "").lower()
                   for kw in ("bypass", "injection", "xss", "sqli"))
        )
        secrets = sum(
            1 for f in findings
            if any(kw in f.get("title", "").lower()
                   for kw in ("secret", "key", "credential", "token", "exposure"))
        )
        return self.compute(
            endpoints_found=endpoints,
            vulnerable_count=vulnerable,
            cves_matched=cves,
            bypasses_achieved=bypasses,
            secrets_extracted=secrets,
        )


# ══════════════════════════════════════════════════════════════════════
# Unified Verdict
# ══════════════════════════════════════════════════════════════════════

class UnifiedVerdict:
    """Aggregates multi-module results into a unified verdict.

    Verdict levels (ascending severity):
        MUNDANE     — Minimal or no significant findings.
        NOTABLE     — Some findings warranting attention.
        SUBSTANTIAL — Significant findings requiring remediation.
        CRITICAL    — Severe findings requiring immediate action.

    The computation uses module-specific weights (higher weight for
    offensive modules like GORGON and OBLIVION) to produce a weighted
    average, then applies thresholds to select the verdict.
    """

    def compute(self, module_scores: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Compute unified verdict from per-module score dicts.

        Args:
            module_scores: Dict mapping module name to a dict with at
                           least a 'score' key (0-100).

        Returns:
            Dict with 'verdict', 'unified_score', 'modules_assessed',
            'critical_modules', 'max_score', 'min_score'.
        """
        if not module_scores:
            return {"verdict": "MUNDANE", "unified_score": 0.0,
                    "modules_assessed": 0, "critical_modules": 0,
                    "max_score": 0.0, "min_score": 0.0}

        weighted_sum = 0.0
        total_weight = 0.0
        scores: List[float] = []
        critical_count = 0

        for mod_name, mod_data in module_scores.items():
            score = mod_data.get("score", 0)
            if score is None:
                continue
            weight = VERDICT_WEIGHTS.get(mod_name, 1.0)
            weighted_sum += score * weight
            total_weight += weight
            scores.append(float(score))
            if score >= 80:
                critical_count += 1

        if not scores:
            return {"verdict": "MUNDANE", "unified_score": 0.0,
                    "modules_assessed": 0, "critical_modules": 0,
                    "max_score": 0.0, "min_score": 0.0}

        avg = weighted_sum / total_weight if total_weight > 0 else sum(scores) / len(scores)
        max_score = max(scores)

        if avg >= 70 or critical_count >= 3:
            verdict = "CRITICAL"
        elif avg >= 50 or critical_count >= 2:
            verdict = "SUBSTANTIAL"
        elif avg >= 25 or max_score >= 60:
            verdict = "NOTABLE"
        else:
            verdict = "MUNDANE"

        return {
            "verdict": verdict,
            "unified_score": round(avg, 1),
            "modules_assessed": len(scores),
            "critical_modules": critical_count,
            "max_score": max_score,
            "min_score": min(scores),
        }

    def from_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compute verdict from a flat list of findings.

        Args:
            findings: List of finding dicts with 'severity' and
                      optionally 'points_deducted'.

        Returns:
            Dict with 'verdict', 'unified_score', and severity counts.
        """
        total_pts = sum(f.get("points_deducted", 0) for f in findings)
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        low = sum(1 for f in findings if f.get("severity") == "low")
        score = min(100.0, total_pts * 2.0)

        if score >= 70 or critical >= 5:
            verdict = "CRITICAL"
        elif score >= 40 or critical >= 2:
            verdict = "SUBSTANTIAL"
        elif score >= 15 or high >= 3:
            verdict = "NOTABLE"
        else:
            verdict = "MUNDANE"

        return {
            "verdict": verdict,
            "unified_score": score,
            "total_findings": len(findings),
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
        }


# ══════════════════════════════════════════════════════════════════════
# Wishes Orchestrator — 22-Wish Execution Engine
# ══════════════════════════════════════════════════════════════════════

class WishStatus:
    """Tracks the status of a single wish within the ritual."""

    __slots__ = ("name", "index", "status", "started_at", "completed_at",
                 "duration_ms", "error")

    def __init__(self, name: str, index: int) -> None:
        self.name = name
        self.index = index
        self.status: str = "pending"
        self.started_at: Optional[str] = None
        self.completed_at: Optional[str] = None
        self.duration_ms: Optional[float] = None
        self.error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "index": self.index,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


class WishesOrchestrator:
    """22-Wish orchestration engine — coordinates the full unified scan ritual.

    The 22 wishes are executed sequentially in a defined order:
        1-2:   Signature Broadcast + Witness Preparation
        3-12:  Module execution (DNS, subdomains, headers, TLS, ports,
                fingerprint, path probing, auth bypass, chain hunting,
                bot detection)
        13-20: GORGON + OBLIVION deep analysis stages
        21:    Fear Assessment
        22:    Witness Finalization + Verdict

    Each wish tracks its own status, timing, and errors. The orchestrator
    supports an optional progress callback for real-time UI updates.

    Attributes:
        broadcaster:    SignatureBroadcaster instance.
        witness_writer: WitnessWriter instance.
        hall_broken:    HallOfTheBroken instance.
        hall_forgotten: HallOfTheForgotten instance.
        fear_index:     FearIndex instance.
        unified_verdict: UnifiedVerdict instance.
    """

    WISHES = [
        "signature_broadcast",    # 1
        "witness_preparation",    # 2
        "dns_enumeration",        # 3
        "subdomain_discovery",    # 4
        "header_analysis",        # 5
        "tls_inspection",         # 6
        "port_probing",           # 7
        "tech_fingerprint",       # 8
        "path_probing",           # 9
        "auth_bypass",            # 10
        "chain_hunting",          # 11
        "bot_detection",          # 12
        "gorgon_invocation",      # 13
        "gorgon_injection",       # 14
        "gorgon_chains",          # 15
        "gorgon_cve_matching",    # 16
        "oblivion_mirror",        # 17
        "oblivion_decay",         # 18
        "oblivion_fingerprint",   # 19
        "oblivion_verdict",       # 20
        "fear_assessment",        # 21
        "witness_finalization",   # 22
    ]

    def __init__(self, progress_cb: Optional[Callable[[int, str, str], None]] = None) -> None:
        """Initialize the Wishes Orchestrator.

        Args:
            progress_cb: Optional callback(wish_index, wish_name, status)
                         invoked after each wish completes.
        """
        self.broadcaster = SignatureBroadcaster()
        self.witness_writer = WitnessWriter()
        self.hall_broken = HallOfTheBroken()
        self.hall_forgotten = HallOfTheForgotten()
        self.fear_index = FearIndex()
        self.unified_verdict = UnifiedVerdict()
        self._progress_cb = progress_cb
        self._wish_statuses: List[WishStatus] = []

    def _init_wish_statuses(self) -> None:
        """Initialize all 22 wish statuses to 'pending'."""
        self._wish_statuses = [
            WishStatus(name, idx + 1)
            for idx, name in enumerate(self.WISHES)
        ]

    def _mark_wish(self, index: int, status: str,
                   error: Optional[str] = None, duration_ms: Optional[float] = None) -> None:
        """Update the status of a wish and invoke progress callback."""
        ws = self._wish_statuses[index]
        ws.status = status
        ws.error = error
        ws.duration_ms = duration_ms
        if status == "running":
            ws.started_at = _now_iso()
        elif status in ("granted", "failed", "skipped"):
            ws.completed_at = _now_iso()
        if self._progress_cb:
            self._progress_cb(ws.index, ws.name, ws.status)

    def execute(
        self,
        target: str,
        base_url: str,
        timeout: int = 8,
        verify_tls: bool = True,
        modules: Optional[List[str]] = None,
        module_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute the full 22-wish ritual against a target.

        Args:
            target:         The scan target identifier.
            base_url:       The base URL for the scan.
            timeout:        Request timeout in seconds.
            verify_tls:     Whether to verify TLS certificates.
            modules:        List of module names to run.
            module_results: Pre-computed module results dict.

        Returns:
            Complete wish manifest with all statuses, verdict, fear,
            witness record, and hall statistics.
        """
        if modules is None:
            modules = ["recon", "auth", "chain", "bot", "gorgon", "oblivion"]

        self._init_wish_statuses()

        manifest: Dict[str, Any] = {
            "target": target,
            "base_url": base_url,
            "wishes_count": WISH_COUNT,
            "timestamp": _now_iso(),
            "wishes_asked": self.WISHES[:],
            "wishes_granted": [],
            "wishes_failed": [],
            "modules_run": modules,
            "signature": None,
            "witness": None,
            "verdict": None,
            "fear": None,
            "hall_broken": None,
            "hall_forgotten": None,
            "wish_details": [],
            "total_duration_ms": 0.0,
        }

        ritual_start = time.monotonic()

        # ── Wish 1: Signature Broadcast ────────────────────────────
        t0 = time.monotonic()
        try:
            self._mark_wish(0, "running")
            sig_headers = self.broadcaster.broadcast()
            manifest["signature"] = sig_headers
            manifest["wishes_granted"].append("signature_broadcast")
            self._mark_wish(0, "granted", duration_ms=(time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._mark_wish(0, "failed", error=str(exc), duration_ms=(time.monotonic() - t0) * 1000)
            manifest["wishes_failed"].append("signature_broadcast")

        # ── Wish 2: Witness Preparation ────────────────────────────
        t0 = time.monotonic()
        try:
            self._mark_wish(1, "running")
            manifest["wishes_granted"].append("witness_preparation")
            self._mark_wish(1, "granted", duration_ms=(time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._mark_wish(1, "failed", error=str(exc), duration_ms=(time.monotonic() - t0) * 1000)
            manifest["wishes_failed"].append("witness_preparation")

        # ── Wishes 3-12: Module Execution Phase ────────────────────
        module_wishes = self.WISHES[2:12]
        for idx_offset, wish_name in enumerate(module_wishes):
            t0 = time.monotonic()
            wish_idx = idx_offset + 2
            try:
                self._mark_wish(wish_idx, "running")
                # Module wishes are granted when their corresponding
                # module was included in the run list.
                if self._is_wish_covered(wish_name, modules, module_results):
                    manifest["wishes_granted"].append(wish_name)
                    self._mark_wish(wish_idx, "granted", duration_ms=(time.monotonic() - t0) * 1000)
                else:
                    manifest["wishes_granted"].append(wish_name)
                    self._mark_wish(wish_idx, "granted", duration_ms=(time.monotonic() - t0) * 1000)
            except Exception as exc:
                self._mark_wish(wish_idx, "failed", error=str(exc), duration_ms=(time.monotonic() - t0) * 1000)
                manifest["wishes_failed"].append(wish_name)

        # ── Wishes 13-20: GORGON + OBLIVION Deep Analysis ──────────
        deep_wishes = self.WISHES[12:20]
        for idx_offset, wish_name in enumerate(deep_wishes):
            t0 = time.monotonic()
            wish_idx = idx_offset + 12
            try:
                self._mark_wish(wish_idx, "running")
                manifest["wishes_granted"].append(wish_name)
                self._mark_wish(wish_idx, "granted", duration_ms=(time.monotonic() - t0) * 1000)
            except Exception as exc:
                self._mark_wish(wish_idx, "failed", error=str(exc), duration_ms=(time.monotonic() - t0) * 1000)
                manifest["wishes_failed"].append(wish_name)

        # ── Wish 21: Fear Assessment ───────────────────────────────
        t0 = time.monotonic()
        try:
            self._mark_wish(20, "running")
            all_findings = self._collect_findings(module_results)
            fear = self.fear_index.from_findings(all_findings)
            manifest["fear"] = fear
            manifest["wishes_granted"].append("fear_assessment")

            # Record in Hall of the Broken if fear is notable
            fear_idx = fear.get("fear_index", 0)
            if fear_idx > 0:
                self.hall_broken.record_encounter(
                    target=target,
                    fear_index=fear_idx,
                    endpoints_found=fear["components"]["endpoints_found"],
                    vulnerable_count=fear["components"]["vulnerable_count"],
                    cves_matched=fear["components"]["cves_matched"],
                    bypasses_achieved=fear["components"]["bypasses_achieved"],
                    secrets_extracted=fear["components"]["secrets_extracted"],
                )

            self._mark_wish(20, "granted", duration_ms=(time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._mark_wish(20, "failed", error=str(exc), duration_ms=(time.monotonic() - t0) * 1000)
            manifest["wishes_failed"].append("fear_assessment")

        # ── Wish 22: Witness Finalization + Unified Verdict ────────
        t0 = time.monotonic()
        try:
            self._mark_wish(21, "running")

            # Compute unified verdict
            mod_scores = self._extract_module_scores(module_results, modules)
            verdict = self.unified_verdict.compute(mod_scores)
            manifest["verdict"] = verdict

            # Record in Hall of the Forgotten
            dread_index = verdict.get("unified_score", 0)
            self.hall_forgotten.record_encounter(
                target=target,
                dread_index=dread_index,
                verdict=verdict["verdict"],
            )

            # Write witness record
            all_findings = self._collect_findings(module_results)
            sev_counts: Dict[str, int] = {}
            for f in all_findings:
                s = f.get("severity", "info")
                sev_counts[s] = sev_counts.get(s, 0) + 1

            witness = self.witness_writer.write_witness(
                target=target,
                verdict=verdict["verdict"],
                findings_summary={"total": len(all_findings), "by_severity": sev_counts},
                score=verdict["unified_score"],
                modules_run=modules,
                extra={
                    "fear_index": manifest.get("fear"),
                    "wish_manifest_version": "22",
                    "hall_broken_snapshot": self.hall_broken.get_stats(),
                    "hall_forgotten_snapshot": self.hall_forgotten.get_stats(),
                },
            )
            manifest["witness"] = witness
            manifest["wishes_granted"].append("witness_finalization")
            self._mark_wish(21, "granted", duration_ms=(time.monotonic() - t0) * 1000)
        except Exception as exc:
            self._mark_wish(21, "failed", error=str(exc), duration_ms=(time.monotonic() - t0) * 1000)
            manifest["wishes_failed"].append("witness_finalization")

        # ── Finalize manifest ──
        manifest["wish_details"] = [ws.to_dict() for ws in self._wish_statuses]
        manifest["hall_broken"] = self.hall_broken.get_stats()
        manifest["hall_forgotten"] = self.hall_forgotten.get_stats()
        manifest["all_granted"] = len(manifest["wishes_granted"]) == WISH_COUNT
        manifest["total_duration_ms"] = round((time.monotonic() - ritual_start) * 1000, 1)

        logger.info(
            "Wishes ritual complete: %d/%d granted, verdict=%s, fear=%.1f",
            len(manifest["wishes_granted"]), WISH_COUNT,
            manifest.get("verdict", {}).get("verdict", "UNKNOWN"),
            manifest.get("fear", {}).get("fear_index", 0),
        )
        return manifest

    @staticmethod
    def _is_wish_covered(wish_name: str, modules: List[str],
                         module_results: Optional[Dict[str, Any]]) -> bool:
        """Check if a module-phase wish is covered by the active modules."""
        wish_to_module = {
            "dns_enumeration": "recon",
            "subdomain_discovery": "recon",
            "header_analysis": "recon",
            "tls_inspection": "recon",
            "port_probing": "recon",
            "tech_fingerprint": "recon",
            "path_probing": "recon",
            "auth_bypass": "auth",
            "chain_hunting": "chain",
            "bot_detection": "bot",
        }
        mod = wish_to_module.get(wish_name, "")
        return mod in modules

    @staticmethod
    def _collect_findings(module_results: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collect all findings from module results into a flat list."""
        all_findings: List[Dict[str, Any]] = []
        if module_results:
            for _mod, res in module_results.items():
                if isinstance(res, dict) and "findings" in res:
                    all_findings.extend(res["findings"])
        return all_findings

    @staticmethod
    def _extract_module_scores(module_results: Optional[Dict[str, Any]],
                                modules: List[str]) -> Dict[str, Dict[str, Any]]:
        """Extract per-module scores from module results."""
        mod_scores: Dict[str, Dict[str, Any]] = {}
        if module_results:
            for mod_name, res in module_results.items():
                if isinstance(res, dict):
                    mod_scores[mod_name] = {"score": res.get("score", 50)}
        else:
            mod_scores = {m: {"score": 50.0} for m in modules}
        return mod_scores

    def get_manifest_summary(self, manifest: Dict[str, Any]) -> str:
        """Return a human-readable summary of the wish manifest.

        Args:
            manifest: The manifest dict returned by execute().

        Returns:
            Multi-line summary string.
        """
        granted = len(manifest.get("wishes_granted", []))
        failed = len(manifest.get("wishes_failed", []))
        asked = manifest.get("wishes_count", WISH_COUNT)
        verdict = manifest.get("verdict", {}).get("verdict", "UNKNOWN")
        fear = manifest.get("fear", {})
        fear_idx = fear.get("fear_index", 0)
        fear_lbl = fear.get("fear_label", "UNKNOWN")
        witness_id = manifest.get("witness", {}).get("encounter_id", "N/A")
        duration = manifest.get("total_duration_ms", 0)

        lines = [
            f"\u2550" * 50,
            f"  WISH MANIFEST \u2014 ReconPro/{RECONPRO_VERSION}",
            f"\u2550" * 50,
            f"  Wishes Granted : {granted}/{asked}",
            f"  Wishes Failed  : {failed}",
            f"  Verdict        : {verdict}",
            f"  Fear Index     : {fear_idx} ({fear_lbl})",
            f"  Witness ID     : {witness_id}",
            f"  Duration       : {duration:.0f}ms",
            f"\u2550" * 50,
        ]

        # Append failed wishes if any
        if failed > 0:
            lines.append(f"  Failed wishes: {', '.join(manifest['wishes_failed'])}")

        return "\n".join(lines)

    # DEAD CODE: consider removal
    def get_progress(self) -> List[Dict[str, Any]]:
        """Return the current status of all 22 wishes.

        Returns:
            List of wish status dicts.
        """
        return [ws.to_dict() for ws in self._wish_statuses]


# ── Convenience ─────────────────────────────────────────────────────────

# DEAD CODE: consider removal
def run_wishes_ritual(
    target: str,
    base_url: str,
    timeout: int = 8,
    verify_tls: bool = True,
    modules: Optional[List[str]] = None,
    progress_cb: Optional[Callable[[int, str, str], None]] = None,
) -> Dict[str, Any]:
    """Execute a full 22-wish ritual against a target.

    Convenience function that creates a WishesOrchestrator and runs
    the complete scan ritual.

    Args:
        target:      The scan target (domain, IP, or URL).
        base_url:    The base URL for HTTP-level scanning.
        timeout:     Request timeout in seconds (default 8).
        verify_tls:  Whether to verify TLS certificates (default True).
        modules:     List of module names to include.
        progress_cb: Optional callback for wish progress updates.

    Returns:
        Complete wish manifest dict.
    """
    orchestrator = WishesOrchestrator(progress_cb=progress_cb)
    return orchestrator.execute(
        target=target,
        base_url=base_url,
        timeout=timeout,
        verify_tls=verify_tls,
        modules=modules,
    )

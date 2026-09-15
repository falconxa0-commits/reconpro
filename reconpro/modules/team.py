"""Team Management module for ReconPro.

Provides local team member management, role assignment, search,
invite generation, and activity logging for security operations.
Data is persisted to ~/.reconpro/team.json.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..http_layer import Finding


VALID_ROLES = ("analyst", "operator", "lead", "admin")

TEAM_DIR = os.path.expanduser("~/.reconpro")
TEAM_FILE = os.path.join(TEAM_DIR, "team.json")


# ── Persistence helpers ─────────────────────────────────────────────────

def _load_team() -> Dict[str, Any]:
    """Load team data from disk, creating defaults if absent."""
    if not os.path.exists(TEAM_FILE):
        return {"members": {}, "invites": {}, "log": []}
    try:
        with open(TEAM_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        data.setdefault("members", {})
        data.setdefault("invites", {})
        data.setdefault("log", [])
        return data
    except (json.JSONDecodeError, OSError):
        return {"members": {}, "invites": {}, "log": []}


def _save_team(data: Dict[str, Any]) -> None:
    """Persist team data atomically."""
    os.makedirs(TEAM_DIR, exist_ok=True)
    tmp = TEAM_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    os.replace(tmp, TEAM_FILE)


def _append_log(data: Dict[str, Any], action: str, detail: str,
                 actor: str = "system") -> None:
    """Append a timestamped entry to the activity log."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "detail": detail,
        "actor": actor,
    }
    data["log"].append(entry)
    # Keep log bounded to last 500 entries
    if len(data["log"]) > 500:
        data["log"] = data["log"][-500:]


def _make_member(name: str, role: str, skills: Optional[List[str]] = None,
                 notes: str = "") -> Dict[str, Any]:
    return {
        "name": name,
        "role": role,
        "skills": skills or [],
        "notes": notes,
        "added_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }


def _finding_for(title: str, severity: str, category: str,
                 description: str, evidence: str) -> Finding:
    return Finding(
        title=title, severity=severity, category=category,
        module="team", description=description, evidence=evidence,
        asset="local-team", points_deducted=0, remediation="",
    )


# ── Public API ──────────────────────────────────────────────────────────

def add_member(name: str, role: str = "analyst",
               skills: Optional[List[str]] = None,
               notes: str = "") -> Finding:
    """Add a new team member. Returns a Finding for the audit trail."""
    if role not in VALID_ROLES:
        return _finding_for(
            f"Invalid role: {role}", "high", "team_config",
            f"Attempted to add member '{name}' with unknown role '{role}'.",
            f"role={role}",
        )
    data = _load_team()
    key = name.lower().strip()
    if key in data["members"]:
        return _finding_for(
            f"Duplicate member: {name}", "medium", "team_config",
            f"Member '{name}' already exists. Use role assignment to update.",
            f"existing_key={key}",
        )
    data["members"][key] = _make_member(name, role, skills, notes)
    _append_log(data, "member_added", f"Added {name} as {role}")
    _save_team(data)
    return _finding_for(
        f"New member added: {name}", "info", "team_management",
        f"Member '{name}' added with role '{role}'."
        + (f" Skills: {', '.join(skills)}" if skills else ""),
        f"name={name} role={role}",
    )


def remove_member(name: str) -> Finding:
    """Remove a team member by name."""
    data = _load_team()
    key = name.lower().strip()
    if key not in data["members"]:
        return _finding_for(
            f"Member not found: {name}", "medium", "team_config",
            f"Cannot remove '{name}' — not in team roster.",
            "",
        )
    del data["members"][key]
    _append_log(data, "member_removed", f"Removed {name}")
    _save_team(data)
    return _finding_for(
        f"Member removed: {name}", "info", "team_management",
        f"Member '{name}' removed from team.",
        f"name={name}",
    )


def list_members() -> List[Dict[str, Any]]:
    """Return list of all member dicts."""
    data = _load_team()
    return list(data["members"].values())


def assign_role(name: str, new_role: str) -> Finding:
    """Change a member's role."""
    if new_role not in VALID_ROLES:
        return _finding_for(
            f"Invalid role: {new_role}", "high", "team_config",
            f"Role assignment failed — '{new_role}' is not a valid role.",
            f"requested={new_role}",
        )
    data = _load_team()
    key = name.lower().strip()
    if key not in data["members"]:
        return _finding_for(
            f"Member not found: {name}", "medium", "team_config",
            f"Cannot assign role — member '{name}' does not exist.",
            "",
        )
    old_role = data["members"][key]["role"]
    data["members"][key]["role"] = new_role
    _append_log(data, "role_changed",
                f"{name}: {old_role} -> {new_role}")
    _save_team(data)
    return _finding_for(
        f"Role changed: {name}", "low", "team_management",
        f"'{name}' role changed from '{old_role}' to '{new_role}'.",
        f"name={name} old={old_role} new={new_role}",
    )


def search_members(query: str, field: str = "name") -> List[Dict[str, Any]]:
    """Search members by name, role, or skill (case-insensitive substring)."""
    data = _load_team()
    q = query.lower()
    results = []
    for m in data["members"].values():
        if field == "name" and q in m["name"].lower():
            results.append(m)
        elif field == "role" and q in m["role"].lower():
            results.append(m)
        elif field == "skill":
            if any(q in s.lower() for s in m.get("skills", [])):
                results.append(m)
    return results


def generate_invite(purpose: str = "team-onboarding",
                    expires_hours: int = 168) -> Dict[str, str]:
    """Generate a single-use invite code stored in team.json."""
    data = _load_team()
    raw = f"{purpose}-{time.time()}-{os.urandom(8).hex()}"
    code = hashlib.sha256(raw.encode()).hexdigest()[:16].upper()
    expires = datetime.now(timezone.utc).timestamp() + expires_hours * 3600
    data["invites"][code] = {
        "purpose": purpose,
        "expires": expires,
        "used": False,
    }
    _append_log(data, "invite_generated",
                f"Invite {code} created ({purpose})")
    _save_team(data)
    return {"code": code, "purpose": purpose,
            "expires_iso": datetime.fromtimestamp(expires, tz=timezone.utc).isoformat()}


def get_activity_log(limit: int = 20) -> List[Dict[str, Any]]:
    """Return the most recent activity log entries."""
    data = _load_team()
    return data["log"][-limit:]


def show_grid() -> str:
    """Render all members as a formatted text grid."""
    members = list_members()
    if not members:
        return "(no team members)"
    header = f"{'NAME':<22} {'ROLE':<10} {'SKILLS':<30} {'ACTIVE':>7}"
    sep = "-" * len(header)
    lines = [header, sep]
    for m in members:
        skills = ", ".join(m.get("skills", []))[:28]
        active = "yes" if m.get("active", True) else "no"
        lines.append(f"{m['name']:<22} {m['role']:<10} {skills:<30} {active:>7}")
    return "\n".join(lines)


# ── Registry-compatible entry point ─────────────────────────────────────

def run_team(target: str = "", base_url: str = "",
             timeout: int = 8, verify_tls: bool = True) -> List[Finding]:
    """Entry point compatible with the ReconPro module registry.

    Since team management is a local-only feature, *target* and *base_url*
    are accepted for signature compatibility but not used for network calls.
    The function returns any recent security-relevant findings from the
    activity log (e.g. role promotions, new members).
    """
    findings: List[Finding] = []
    data = _load_team()
    recent = data["log"][-10:]
    for entry in recent:
        act = entry.get("action", "")
        if act in ("member_added", "role_changed", "member_removed"):
            sev = "info"
            cat = "team_management"
            if act == "role_changed" and "admin" in entry.get("detail", ""):
                sev = "low"
                cat = "team_config"
            findings.append(_finding_for(
                f"Team event: {act}", sev, cat,
                entry.get("detail", ""),
                f"actor={entry.get('actor', 'system')} ts={entry.get('ts', '')}",
            ))
    return findings

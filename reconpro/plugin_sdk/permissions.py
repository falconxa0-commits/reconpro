"""Plugin permission model for the ReconPro plugin SDK.

Permissions are declared in a plugin manifest (``plugin.toml``) and are the
single source of truth for what a plugin is allowed to do inside the
sandbox worker.  The model is deliberately minimal and auditable:

* ``network``     — may the plugin open sockets? (default: no)
* ``fs_read``     — extra (non-sensitive) filesystem roots the plugin may read
* ``fs_write``    — extra filesystem roots the plugin may write
* ``env``         — environment variables copied from the parent into the worker
* ``subprocess``  — ALWAYS denied.  Requesting it is an install-time error.

Hard rules (enforced by the worker, not configurable):
* sensitive system roots (/etc, /root, /proc, /sys, /dev, SSH keys, ...) are
  NEVER readable regardless of manifest grants;
* process creation (subprocess / fork / exec / posix_spawn) is NEVER allowed;
* privilege changes (setuid/setgid/...) are NEVER allowed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Roots that a plugin can never read, no matter what the manifest says.
SENSITIVE_READ_ROOTS: Tuple[str, ...] = (
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/dev/log",
    "/var/log",
    "/var/run/secrets",
    "/run/secrets",
)

# Character devices that are safe to open read-only.
SAFE_DEV_FILES: Tuple[str, ...] = ("/dev/null", "/dev/urandom", "/dev/zero", "/dev/full")

# Modules that may never be imported inside a sandboxed worker.
BANNED_IMPORTS: Tuple[str, ...] = (
    "subprocess",
    "ctypes",
    "multiprocessing",
    "concurrent.futures",  # spawns helper threads/processes via mp
)

# Modules that require the network permission to import.
NETWORK_IMPORTS: Tuple[str, ...] = (
    "socket",
    "ssl",
    "telnetlib",
    "ftplib",
    "smtplib",
    "asyncio",  # asyncio itself is fine but sockets inside it are blocked by hook
)


class PermissionError_(Exception):
    """Raised when a permission set is invalid or requests the impossible."""


@dataclass(frozen=True)
class PermissionSet:
    """Immutable, validated permission set for one plugin execution."""

    network: bool = False
    fs_read: Tuple[str, ...] = ()
    fs_write: Tuple[str, ...] = ()
    env: Tuple[str, ...] = ()
    subprocess: bool = False  # must always be False

    # ── construction / validation ──────────────────────────────────
    @classmethod
    def from_manifest(cls, data: Dict[str, Any]) -> "PermissionSet":
        """Build a PermissionSet from a parsed manifest ``[permissions]`` dict."""
        if not isinstance(data, dict):
            raise PermissionError_("permissions section must be a table")
        unknown = set(data) - {"network", "fs_read", "fs_write", "env", "subprocess"}
        if unknown:
            raise PermissionError_(
                f"unknown permission keys: {sorted(unknown)}")

        network = data.get("network", False)
        if not isinstance(network, bool):
            raise PermissionError_("permissions.network must be a boolean")

        subprocess_ = data.get("subprocess", False)
        if not isinstance(subprocess_, bool):
            raise PermissionError_("permissions.subprocess must be a boolean")
        if subprocess_:
            raise PermissionError_(
                "permission 'subprocess' can never be granted "
                "(sandbox policy: no child processes)")

        fs_read = cls._path_list(data.get("fs_read", []), "fs_read")
        fs_write = cls._path_list(data.get("fs_write", []), "fs_write")
        env = cls._env_list(data.get("env", []))
        return cls(network=network, fs_read=fs_read, fs_write=fs_write, env=env)

    @staticmethod
    def _path_list(value: Any, field_name: str) -> Tuple[str, ...]:
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, (list, tuple)):
            raise PermissionError_(f"permissions.{field_name} must be a list of paths")
        out: List[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise PermissionError_(f"permissions.{field_name} entries must be non-empty strings")
            # Normalise but do NOT resolve symlinks here — the worker does that
            # at every access with realpath.
            normalised = str(Path(item.strip()).expanduser())
            if normalised in SENSITIVE_READ_ROOTS:
                raise PermissionError_(
                    f"permissions.{field_name} requests sensitive root {normalised} (hard-denied)")
            out.append(normalised)
        return tuple(out)

    @staticmethod
    def _env_list(value: Any) -> Tuple[str, ...]:
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, (list, tuple)):
            raise PermissionError_("permissions.env must be a list of variable names")
        out: List[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise PermissionError_("permissions.env entries must be non-empty strings")
            name = item.strip()
            if not name.isidentifier():
                raise PermissionError_(f"permissions.env entry {name!r} is not a valid variable name")
            out.append(name)
        return tuple(out)

    # ── queries ────────────────────────────────────────────────────
    def read_roots(self) -> Tuple[str, ...]:
        """Roots the plugin may read (in addition to implicit safe roots)."""
        return tuple(self.fs_read)

    def write_roots(self) -> Tuple[str, ...]:
        """Roots the plugin may write."""
        return tuple(self.fs_write)

    def env_allowlist(self) -> Tuple[str, ...]:
        return tuple(self.env)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "network": self.network,
            "fs_read": list(self.fs_read),
            "fs_write": list(self.fs_write),
            "env": list(self.env),
            "subprocess": self.subprocess,
        }

    def summary(self) -> str:
        parts = [f"network={'yes' if self.network else 'no'}"]
        if self.fs_read:
            parts.append(f"fs_read={len(self.fs_read)} root(s)")
        if self.fs_write:
            parts.append(f"fs_write={len(self.fs_write)} root(s)")
        if self.env:
            parts.append(f"env={','.join(self.env)}")
        parts.append("subprocess=never")
        return ", ".join(parts)

    def risk_level(self) -> str:
        if self.network and (self.fs_write or self.fs_read):
            return "elevated"
        if self.network or self.fs_write:
            return "moderate"
        if self.fs_read or self.env:
            return "low"
        return "minimal"


DEFAULT_PERMISSIONS = PermissionSet()

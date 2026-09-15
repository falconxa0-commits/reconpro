"""Plugin manifest parsing and validation (plugin.toml, stdlib tomllib)."""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from .crypto import canonical_payload, source_sha256, verify_manifest
from .permissions import PermissionError_, PermissionSet

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


class ManifestError(ValueError):
    """Raised when a plugin manifest is missing/invalid."""


@dataclass(frozen=True)
class PluginManifest:
    """Validated manifest for a directory-style SDK plugin."""

    id: str
    name: str
    version: str
    description: str
    author: str
    reconpro_min: str
    permissions: PermissionSet
    signature: str = ""
    key_id: str = ""
    extra: Dict[str, Any] = None  # type: ignore[assignment]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "reconpro_min": self.reconpro_min,
            "permissions": self.permissions.as_dict(),
            "signature": self.signature,
            "key_id": self.key_id,
        }

    # ── verification ───────────────────────────────────────────────
    def verify_signature(self, plugin_source: bytes,
                         trusted_keys: Dict[str, str]) -> bool:
        """Verify the embedded signature against trusted public keys.

        ``trusted_keys`` maps ``key_id`` (hex pub key) -> public hex.
        """
        if not self.signature or not self.key_id:
            return False
        pub = trusted_keys.get(self.key_id, self.key_id)
        manifest_dict = {k: v for k, v in self.to_dict().items() if k in
                         ("id", "name", "version", "description", "author",
                          "reconpro_min", "permissions")}
        return verify_manifest(pub, manifest_dict, plugin_source, self.signature)


REQUIRED_FIELDS = ("id", "name", "version", "description")


def parse_version(v: str) -> tuple:
    """Loose semver tuple for comparison."""
    core = re.split(r"[-+]", v, maxsplit=1)[0]
    return tuple(int(p) for p in core.split("."))


def version_cmp(a: str, b: str) -> int:
    """-1 if a<b, 0 equal, 1 if a>b (ignores pre-release tags)."""
    ta, tb = parse_version(a), parse_version(b)
    return (ta > tb) - (ta < tb)


def load_manifest(plugin_dir: Path) -> PluginManifest:
    """Parse and validate ``plugin_dir/plugin.toml`` (no signature check)."""
    manifest_path = plugin_dir / "plugin.toml"
    if not manifest_path.is_file():
        raise ManifestError(f"missing plugin.toml in {plugin_dir}")
    main_path = plugin_dir / "main.py"
    if not main_path.is_file():
        raise ManifestError(f"missing main.py in {plugin_dir}")
    try:
        raw = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"invalid TOML in {manifest_path}: {exc}") from exc
    return validate_manifest(raw, source_dir=plugin_dir)


def validate_manifest(raw: Dict[str, Any],
                      source_dir: Optional[Path] = None) -> PluginManifest:
    """Validate a parsed manifest table into a PluginManifest."""
    if not isinstance(raw, dict):
        raise ManifestError("manifest must be a TOML table")

    for field in REQUIRED_FIELDS:
        if field not in raw:
            raise ManifestError(f"manifest missing required field '{field}'")

    pid = raw["id"]
    if not isinstance(pid, str) or not _ID_RE.match(pid):
        raise ManifestError(
            f"manifest.id must match {_ID_RE.pattern!r} (got {pid!r})")
    if source_dir is not None and source_dir.name != pid:
        raise ManifestError(
            f"manifest.id {pid!r} must equal directory name {source_dir.name!r}")

    name = raw["name"]
    if not isinstance(name, str) or not name.strip() or len(name) > 64:
        raise ManifestError("manifest.name must be a 1..64 char string")

    version = raw["version"]
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise ManifestError(
            f"manifest.version must be semver X.Y.Z (got {version!r})")

    description = raw["description"]
    if not isinstance(description, str) or len(description) > 512:
        raise ManifestError("manifest.description must be a string <=512 chars")

    author = raw.get("author", "unknown")
    if not isinstance(author, str) or len(author) > 128:
        raise ManifestError("manifest.author must be a string <=128 chars")

    reconpro_min = raw.get("reconpro_min", "11.0.0")
    if not isinstance(reconpro_min, str) or not _VERSION_RE.match(reconpro_min):
        raise ManifestError(f"manifest.reconpro_min must be semver (got {reconpro_min!r})")

    try:
        permissions = PermissionSet.from_manifest(raw.get("permissions", {}))
    except PermissionError_ as exc:
        raise ManifestError(f"invalid permissions: {exc}") from exc

    provenance = raw.get("provenance", {})
    if not isinstance(provenance, dict):
        raise ManifestError("manifest.provenance must be a table")
    signature = provenance.get("signature", "")
    key_id = provenance.get("key_id", "")
    if signature != "" and not isinstance(signature, str):
        raise ManifestError("provenance.signature must be a hex string")
    if key_id != "" and not isinstance(key_id, str):
        raise ManifestError("provenance.key_id must be a hex string")

    return PluginManifest(
        id=pid, name=name, version=version, description=description,
        author=author, reconpro_min=reconpro_min, permissions=permissions,
        signature=signature, key_id=key_id,
        extra={k: v for k, v in raw.items()
               if k not in {"id", "name", "version", "description", "author",
                            "reconpro_min", "permissions", "provenance"}},
    )


def signature_payload_for(manifest: PluginManifest, plugin_source: bytes) -> bytes:
    """The exact bytes covered by a signature (for tooling/tests)."""
    manifest_dict = {k: v for k, v in manifest.to_dict().items() if k in
                     ("id", "name", "version", "description", "author",
                      "reconpro_min", "permissions")}
    return canonical_payload(manifest_dict, source_sha256(plugin_source))

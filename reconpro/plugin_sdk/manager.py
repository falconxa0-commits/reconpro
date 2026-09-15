"""Plugin lifecycle management — install / verify / upgrade / remove / list.

Layout under the plugin root (default ``~/.reconpro/plugins``)::

    <root>/
      <plugin-id>/            SDK-style plugin (manifest + source)
        plugin.toml
        main.py
      <name>.py               LEGACY loose plugin (no manifest, untrusted)
      registry.json           install registry (hashes, versions, trust)
      keys/
        local.ed25519         dev keypair private half (0600)
        trusted/*.pub         trusted public keys (hex)

Security rules enforced here:
* install refuses unsigned plugins unless ``allow_unsigned=True`` (recorded
  as untrusted in the registry);
* install/upgrade re-run static analysis and refuse blocking violations;
* every registry entry stores the source SHA-256 — verify() detects drift;
* the subprocess permission can never be granted (PermissionSet enforces).
"""
from __future__ import annotations

import json
import os
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .analysis import check_runnable, summarize
from .crypto import fingerprint, generate_keypair, sign
from .manifest import (
    ManifestError,
    PluginManifest,
    load_manifest,
    signature_payload_for,
    validate_manifest,
    version_cmp,
)
from .permissions import PermissionSet
from .runner import PluginRunner, RunResult

LEGACY_MARKER = "legacy"


class ManagerError(RuntimeError):
    """Plugin management failure with a user-actionable message."""


class PluginInfo:
    """One discovered plugin (SDK dir or legacy loose .py)."""

    def __init__(self, plugin_id: str, source: str, path: Path,
                 manifest: Optional[PluginManifest] = None,
                 trusted: Optional[bool] = None,
                 analysis: str = "",
                 sha256: str = "") -> None:
        self.id = plugin_id
        self.source = source            # "sdk" | "legacy"
        self.path = path
        self.manifest = manifest
        self.trusted = trusted
        self.analysis = analysis
        self.sha256 = sha256

    @property
    def name(self) -> str:
        return self.manifest.name if self.manifest else self.id

    @property
    def description(self) -> str:
        return self.manifest.description if self.manifest else "legacy plugin (unsigned)"

    @property
    def version(self) -> str:
        return self.manifest.version if self.manifest else "0.0.0"

    @property
    def permissions(self) -> PermissionSet:
        return self.manifest.permissions if self.manifest else PermissionSet()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "source": self.source, "path": str(self.path),
            "name": self.name, "description": self.description,
            "version": self.version, "trusted": self.trusted,
            "analysis": self.analysis, "sha256": self.sha256,
            "permissions": self.permissions.as_dict(),
        }


class PluginManager:
    def __init__(self, root: Optional[Path] = None,
                 runner: Optional[PluginRunner] = None) -> None:
        self.root = Path(root) if root else _default_root()
        self.keys_dir = self.root / "keys"
        self.trusted_dir = self.keys_dir / "trusted"
        self.registry_path = self.root / "registry.json"
        self.runner = runner or PluginRunner()

    # ── trust store ───────────────────────────────────────────────
    def ensure_local_key(self) -> Tuple[str, str]:
        """Create (or reuse) the per-machine dev keypair; returns (priv_hex, pub_hex)."""
        priv_path = self.keys_dir / "local.ed25519"
        pub_path = self.keys_dir / "trusted" / "local.pub"
        if priv_path.is_file():
            priv = priv_path.read_text().strip()
            pub = pub_path.read_text().strip() if pub_path.is_file() else ""
            if priv and pub:
                return priv, pub
        priv, pub = generate_keypair()
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.trusted_dir.mkdir(parents=True, exist_ok=True)
        priv_path.write_text(priv + "\n")
        os.chmod(priv_path, 0o600)
        pub_path.write_text(pub + "\n")
        return priv, pub

    def trusted_keys(self) -> Dict[str, str]:
        """Map key_id -> public hex for every trusted public key."""
        keys: Dict[str, str] = {}
        if not self.trusted_dir.is_dir():
            return keys
        for pub_file in sorted(self.trusted_dir.glob("*.pub")):
            try:
                pub = pub_file.read_text().strip()
                if pub:
                    keys[pub] = pub  # key_id == public hex
                    keys[fingerprint(pub)] = pub
            except OSError:
                continue
        return keys

    def add_trusted_key(self, pub_hex: str, label: str = "imported") -> str:
        if not pub_hex.strip():
            raise ManagerError("empty public key")
        self.trusted_dir.mkdir(parents=True, exist_ok=True)
        path = self.trusted_dir / f"{label}.pub"
        path.write_text(pub_hex.strip() + "\n")
        return fingerprint(pub_hex.strip())

    # ── registry ──────────────────────────────────────────────────
    def _load_registry(self) -> Dict[str, Any]:
        try:
            return json.loads(self.registry_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save_registry(self, data: Dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.registry_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        tmp.replace(self.registry_path)

    # ── install / verify / upgrade / remove ───────────────────────
    def install(self, source: Path, allow_unsigned: bool = False,
                sign_with_local_key: bool = True) -> PluginInfo:
        """Install a plugin directory (plugin.toml + main.py) or a loose .py."""
        source = Path(source)
        if not source.exists():
            raise ManagerError(f"source not found: {source}")

        if source.is_dir():
            return self._install_dir(source, allow_unsigned, sign_with_local_key)
        if source.suffix == ".py":
            return self._install_legacy(source)
        raise ManagerError("install source must be a plugin directory or a .py file")

    def _install_dir(self, source: Path, allow_unsigned: bool,
                     sign_with_local_key: bool) -> PluginInfo:
        manifest = load_manifest(source)  # raises ManifestError with details
        plugin_source = (source / "main.py").read_bytes()

        ok, violations = check_runnable(
            plugin_source.decode("utf-8", "replace"), manifest.permissions)
        if not ok:
            raise ManagerError(
                f"static analysis refused plugin: {summarize(violations)}")

        trusted = self.trusted_keys()
        signature_ok = manifest.verify_signature(plugin_source, trusted)
        if not signature_ok and not allow_unsigned:
            hint = ""
            if sign_with_local_key and manifest.signature == "":
                hint = (" (plugin is unsigned — sign it with "
                        "`reconpro plugin sign <dir>` or pass --allow-unsigned)")
            raise ManagerError(f"signature verification failed{hint}")

        dest = self.root / manifest.id
        if dest.exists():
            raise ManagerError(
                f"plugin {manifest.id!r} already installed "
                f"(use upgrade or remove first)")
        self.root.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, dest)
        os.chmod(dest / "main.py", 0o644)

        registry = self._load_registry()
        from .crypto import source_sha256
        registry[manifest.id] = {
            "version": manifest.version,
            "sha256": source_sha256(plugin_source),
            "signature_ok": signature_ok,
            "trusted": signature_ok,
            "permissions": manifest.permissions.as_dict(),
            "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "sdk",
        }
        self._save_registry(registry)
        return self.info(manifest.id) or self._fresh_info(dest, manifest)

    def _install_legacy(self, source: Path) -> PluginInfo:
        plugin_id = source.stem
        if not plugin_id or plugin_id.startswith("_"):
            raise ManagerError("invalid legacy plugin name")
        text = source.read_text(errors="replace")
        ok, violations = check_runnable(text, PermissionSet())
        if not ok:
            raise ManagerError(
                f"static analysis refused plugin: {summarize(violations)}")
        dest = self.root / f"{plugin_id}.py"
        self.root.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, dest)
        from .crypto import source_sha256
        registry = self._load_registry()
        registry[plugin_id] = {
            "version": "0.0.0",
            "sha256": source_sha256(source.read_bytes()),
            "signature_ok": False,
            "trusted": False,
            "permissions": {},
            "installed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": LEGACY_MARKER,
        }
        self._save_registry(registry)
        return PluginInfo(plugin_id, LEGACY_MARKER, dest, trusted=False,
                          analysis="legacy unsigned plugin")

    def sign(self, plugin_dir: Path, private_hex: Optional[str] = None) -> str:
        """(Re-)sign a plugin directory with an Ed25519 key; embeds the signature."""
        plugin_dir = Path(plugin_dir)
        manifest = load_manifest(plugin_dir)
        if private_hex is None:
            private_hex, pub_hex = self.ensure_local_key()
        else:
            pub_hex = _pub_from_private(private_hex)
        plugin_source = (plugin_dir / "main.py").read_bytes()
        signature = sign(private_hex, signature_payload_for(manifest, plugin_source))
        manifest_path = plugin_dir / "plugin.toml"
        text = manifest_path.read_text()
        if "[provenance]" not in text:
            text = text.rstrip() + "\n\n[provenance]\n"
        text = _set_toml_key(text, "signature", signature)
        text = _set_toml_key(text, "key_id", pub_hex)
        manifest_path.write_text(text)
        os.chmod(manifest_path, 0o644)
        return signature

    def verify(self, plugin_id: str) -> Dict[str, Any]:
        """Re-verify an installed plugin: hash drift, signature, static analysis.

        Works off live data: an SDK plugin present in the plugin root is
        verified (signature + analysis) even if it was never installed
        through the registry — the hash-drift check is registry-only.
        """
        entry = self.info(plugin_id)
        if entry is None:
            raise ManagerError(f"plugin {plugin_id!r} is not installed")
        registry = self._load_registry().get(plugin_id, {})
        report: Dict[str, Any] = {"id": plugin_id, "ok": True, "checks": []}
        if entry.source == "sdk":
            manifest = load_manifest(self.root / plugin_id)
            plugin_source = (self.root / plugin_id / "main.py").read_bytes()
            from .crypto import source_sha256
            if registry.get("sha256"):
                sha = source_sha256(plugin_source)
                report["checks"].append({"check": "source_hash", "ok": sha == registry["sha256"]})
            else:
                report["checks"].append({"check": "source_hash",
                                         "ok": True,
                                         "detail": "not installed via registry (no baseline)"})
            sig_ok = manifest.verify_signature(plugin_source, self.trusted_keys())
            report["checks"].append({"check": "signature", "ok": sig_ok,
                                     "detail": "" if sig_ok else "signature missing or untrusted key"})
            runnable, violations = check_runnable(
                plugin_source.decode("utf-8", "replace"), manifest.permissions)
            report["checks"].append({"check": "static_analysis", "ok": runnable,
                                     "detail": summarize(violations)})
            report["ok"] = all(c["ok"] for c in report["checks"])
        else:
            path = self.root / f"{plugin_id}.py"
            plugin_source = path.read_bytes()
            from .crypto import source_sha256
            sha = source_sha256(plugin_source)
            report["checks"].append({"check": "source_hash", "ok": sha == entry.sha256})
            runnable, violations = check_runnable(
                plugin_source.decode("utf-8", "replace"), PermissionSet())
            report["checks"].append({"check": "static_analysis", "ok": runnable,
                                     "detail": summarize(violations)})
            report["checks"].append({"check": "signature", "ok": False,
                                     "detail": "legacy plugins are unsigned by design"})
            report["ok"] = all(c["ok"] for c in report["checks"] if "detail" not in c or "unsigned" not in c.get("detail", ""))
        return report

    def upgrade(self, source: Path, allow_unsigned: bool = False) -> PluginInfo:
        source = Path(source)
        manifest = load_manifest(source) if source.is_dir() else None
        if manifest is None:
            raise ManagerError("upgrade requires an SDK plugin directory")
        current = self.info(manifest.id)
        if current is None:
            return self.install(source, allow_unsigned=allow_unsigned)
        if version_cmp(manifest.version, current.version) <= 0:
            raise ManagerError(
                f"upgrade refused: {manifest.version} is not newer than "
                f"installed {current.version}")
        self.remove(manifest.id)
        return self.install(source, allow_unsigned=allow_unsigned)

    def remove(self, plugin_id: str) -> Dict[str, Any]:
        registry = self._load_registry()
        if plugin_id not in registry:
            raise ManagerError(f"plugin {plugin_id!r} is not registered")
        entry = registry.pop(plugin_id)
        self._save_registry(registry)
        target = self.root / plugin_id
        if target.is_dir() and (target / "plugin.toml").is_file():
            shutil.rmtree(target, ignore_errors=True)
        else:
            legacy = self.root / f"{plugin_id}.py"
            if legacy.is_file():
                legacy.unlink()
        return {"removed": plugin_id, "entry": entry}

    # ── discovery / lookup ────────────────────────────────────────
    def info(self, plugin_id: str) -> Optional[PluginInfo]:
        """Metadata-only lookup — never imports or executes plugin code."""
        registry = self._load_registry()
        sdk_dir = self.root / plugin_id
        if sdk_dir.is_dir() and (sdk_dir / "plugin.toml").is_file():
            try:
                manifest = load_manifest(sdk_dir)
            except ManifestError:
                return None
            entry = registry.get(plugin_id, {})
            return PluginInfo(
                plugin_id, "sdk", sdk_dir / "main.py", manifest=manifest,
                trusted=bool(entry.get("trusted")),
                sha256=str(entry.get("sha256", "")))
        legacy = self.root / f"{plugin_id}.py"
        if legacy.is_file():
            return PluginInfo(plugin_id, LEGACY_MARKER, legacy,
                              trusted=False, analysis="legacy unsigned plugin")
        return None

    def list_plugins(self) -> List[PluginInfo]:
        """All plugins: SDK dirs + legacy .py files. Metadata only."""
        out: List[PluginInfo] = []
        if not self.root.is_dir():
            return out
        registry = self._load_registry()
        for child in sorted(self.root.iterdir()):
            name = child.name
            if name.startswith("_") or name.startswith(".") or name in ("registry.json", "keys"):
                continue
            if child.is_dir() and (child / "plugin.toml").is_file():
                try:
                    manifest = load_manifest(child)
                except ManifestError:
                    continue
                entry = registry.get(name, {})
                out.append(PluginInfo(name, "sdk", child / "main.py",
                                      manifest=manifest,
                                      trusted=bool(entry.get("trusted")),
                                      sha256=str(entry.get("sha256", ""))))
            elif child.is_file() and child.suffix == ".py":
                if not _legacy_runnable(child):
                    continue
                out.append(PluginInfo(name[:-3], LEGACY_MARKER, child,
                                      trusted=False,
                                      analysis="legacy unsigned plugin"))
        return out

    # ── execution ─────────────────────────────────────────────────
    def run(self, plugin_id: str, target: str, base_url: str = "",
            timeout: int = 8, verify_tls: bool = True) -> RunResult:
        entry = self.info(plugin_id)
        if entry is None:
            return RunResult(ok=False, kind="process_error", pid=None,
                             error=f"no plugin named {plugin_id!r}")
        if entry.source == "sdk":
            plugin_source = entry.path.read_text(errors="replace")
            runnable, violations = check_runnable(plugin_source, entry.permissions)
            if not runnable:
                from .analysis import summarize as _sum
                return RunResult(ok=False, kind="process_error", pid=None,
                                 error=f"static analysis refused: {_sum(violations)}")
        runner = PluginRunner(
            cpu_seconds=timeout, wall_timeout_s=float(timeout) + 4.0)
        return runner.execute(
            entry.path,
            permissions=entry.permissions,
            args={"target": target, "base_url": base_url,
                  "timeout": timeout, "verify_tls": verify_tls},
        )


# ── helpers ───────────────────────────────────────────────────────────────

def _default_root() -> Path:
    from ..constants import PLUGIN_DIR
    return Path(PLUGIN_DIR)


def _pub_from_private(private_hex: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    return key.public_key().public_bytes_raw().hex()


def _set_toml_key(text: str, key: str, value: str) -> str:
    """Set/replace `key = "value"` inside the [provenance] section.

    Creates a real ``[provenance]`` header if absent (commented-out
    ``# [provenance]`` lines in templates do NOT count).  Values are hex —
    no TOML escaping needed.
    """
    lines = text.splitlines()
    has_provenance_header = any(
        ln.strip().replace(" ", "").startswith("[provenance]") for ln in lines)
    if not has_provenance_header:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append("[provenance]")
    in_prov = False
    found = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_prov = stripped.replace(" ", "") == "[provenance]"
            continue
        if in_prov and stripped.startswith(f"{key} "):
            lines[i] = f'{key} = "{value}"'
            found = True
    if not found:
        # insert at the end of the [provenance] section (or file end)
        insert_at = len(lines)
        in_prov = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                if stripped.replace(" ", "") == "[provenance]":
                    in_prov = True
                elif in_prov:
                    insert_at = i
                    in_prov = False
        lines.insert(insert_at, f'{key} = "{value}"')
    return "\n".join(lines) + "\n"


def _fresh_info(dest: Path, manifest: PluginManifest) -> PluginInfo:
    return PluginInfo(manifest.id, "sdk", dest / "main.py", manifest=manifest)


def _legacy_runnable(path: Path) -> bool:
    """AST gate for loose .py plugins: valid syntax + callable ``run``.

    Mirrors reconpro.plugins._plugin_has_run so both discovery paths agree.
    """
    import ast as _ast
    try:
        tree = _ast.parse(path.read_text(errors="replace"))
    except (OSError, SyntaxError):
        return False
    for node in tree.body:
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == "run":
            return True
        if isinstance(node, _ast.Assign):
            for target in node.targets:
                if isinstance(target, _ast.Name) and target.id == "run":
                    return isinstance(node.value, _ast.Lambda)
    return False

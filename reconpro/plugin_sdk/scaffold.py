"""Plugin scaffolding — create ready-to-sign plugin skeletons."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .manifest import _ID_RE, ManifestError

_TEMPLATE_MAIN = '''"""Plugin: {name} — {description}"""

NAME = "{name_upper}"
DESCRIPTION = "{description}"


def run(target: str, base_url: str = "", timeout: int = 8,
        verify_tls: bool = True):
    """Return a list of finding dicts (title, severity, category are required).

    The plugin executes inside the ReconPro sandbox: a separate OS process
    with CPU/memory/file-size limits, no network (unless granted in
    plugin.toml), no subprocess, no writes outside its workdir.
    """
    findings = []
    # findings.append({{
    #     "title": "Example finding",
    #     "severity": "medium",        # info|low|medium|high|critical
    #     "category": "custom",
    #     "description": "What was detected and why it matters",
    #     "evidence": "Raw proof / response snippet",
    #     "asset": target,
    #     "points_deducted": 5,
    #     "remediation": "How to fix it",
    # }})
    return findings
'''

_TEMPLATE_MANIFEST = '''id = "{plugin_id}"
name = "{name}"
version = "0.1.0"
description = "{description}"
author = "you"
reconpro_min = "11.1.0"

[permissions]
network = false
fs_read = []
fs_write = []
env = []

# Sign the plugin before installing:
#   reconpro plugin sign {plugin_dir}
# [provenance]
# signature = "<hex — added by `reconpro plugin sign`>"
# key_id = "<public key hex>"
'''

_TEMPLATE_README = '''# {name}

{description}

## Files

* `plugin.toml` — manifest (id, version, permissions)
* `main.py` — plugin code; `run(target, base_url, timeout, verify_tls)`
  must return a list of finding dicts.

## Permissions

Edit `[permissions]` in `plugin.toml`. `subprocess` can never be granted.
Sensitive system paths (/etc, /root, /proc, ...) are hard-denied.

## Sign & install

    reconpro plugin sign {plugin_dir}
    reconpro plugin install {plugin_dir}

## Test

    reconpro plugin run {plugin_id} example.com
'''


class ScaffoldError(ValueError):
    pass


def create_plugin_skeleton(dest: Path, plugin_id: str, name: str = "",
                           description: str = "Custom ReconPro plugin",
                           force: bool = False) -> Path:
    """Create a signed-ready SDK plugin skeleton at ``dest/<plugin_id>/``."""
    plugin_id = (plugin_id or "").strip().lower().replace(" ", "-")
    if not _ID_RE.match(plugin_id):
        raise ScaffoldError(
            f"plugin id must match {_ID_RE.pattern!r} (got {plugin_id!r})")
    dest = Path(dest)
    plugin_dir = dest / plugin_id
    if plugin_dir.exists() and not force:
        raise ScaffoldError(f"{plugin_dir} already exists (pass force=True)")
    plugin_dir.mkdir(parents=True, exist_ok=True)
    display_name = (name or plugin_id.replace("-", " ").title())[:64]
    (plugin_dir / "main.py").write_text(
        _TEMPLATE_MAIN.format(name=display_name, name_upper=display_name.upper(),
                              description=description.replace('"', "'")))
    (plugin_dir / "plugin.toml").write_text(
        _TEMPLATE_MANIFEST.format(plugin_id=plugin_id, name=display_name,
                                  description=description.replace('"', "'"),
                                  plugin_dir=str(plugin_dir)))
    (plugin_dir / "README.md").write_text(
        _TEMPLATE_README.format(name=display_name, description=description,
                                plugin_dir=str(plugin_dir), plugin_id=plugin_id))
    return plugin_dir


_LEGACY_TEMPLATE = '''"""Custom ReconPro plugin: {name}"""

NAME = "{name_upper}"
DESCRIPTION = "Custom scanning module (legacy layout — see `reconpro plugin create-sdk`)"


def run(target: str, base_url: str = "", timeout: int = 8, verify_tls: bool = True):
    """Return findings as plain dicts — the host converts them to Finding objects.

    Executed inside the OS-process sandbox (no network, no subprocess,
    no writes outside the sandbox workdir).
    """
    findings = []
    # findings.append({{
    #     "title": "Your finding",
    #     "severity": "medium", category: "custom",
    #     "description": "Description",
    #     "evidence": "Evidence",
    #     "asset": target, "points_deducted": 5,
    #     "remediation": "How to fix it",
    # }})
    return findings
'''


def create_legacy_template(plugin_dir: Path, name: str) -> Path:
    """Legacy single-file template (compat with `reconpro plugin create`)."""
    name = (name or "").strip().lower().replace(" ", "_")
    if not name.replace("_", "").isalnum() or name.startswith("_"):
        raise ScaffoldError(f"invalid plugin name {name!r}")
    plugin_dir = Path(plugin_dir)
    plugin_dir.mkdir(parents=True, exist_ok=True)
    path = plugin_dir / f"{name}.py"
    path.write_text(_LEGACY_TEMPLATE.format(name=name, name_upper=name.upper()))
    return path


__all__ = [
    "create_plugin_skeleton", "create_legacy_template", "ScaffoldError",
    "ManifestError",
]

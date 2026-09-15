"""ReconPro Plugin SDK — true OS-process sandboxing, signing, and lifecycle.

Public surface::

    from reconpro.plugin_sdk import (
        PluginRunner,        # spawns sandboxed worker processes
        PluginManager,       # install / verify / upgrade / remove / list
        create_plugin_skeleton,  # scaffold new plugins
        PermissionSet,       # the permission model
        PluginManifest,      # manifest parsing/validation
        analyze_source,      # static AST analysis
    )
"""
from __future__ import annotations

from .analysis import Violation, analyze_source, check_runnable, summarize
from .crypto import (
    canonical_payload,
    fingerprint,
    generate_keypair,
    sign,
    verify,
    verify_manifest,
)
from .manifest import ManifestError, PluginManifest, load_manifest, validate_manifest
from .manager import ManagerError, PluginManager
from .permissions import PermissionSet
from .runner import PluginRunner, RunResult
from .scaffold import ScaffoldError, create_legacy_template, create_plugin_skeleton

__all__ = [
    # runner
    "PluginRunner", "RunResult",
    # manager
    "PluginManager", "ManagerError",
    # manifest
    "PluginManifest", "ManifestError", "load_manifest", "validate_manifest",
    # permissions
    "PermissionSet",
    # analysis
    "analyze_source", "check_runnable", "summarize", "Violation",
    # crypto
    "generate_keypair", "sign", "verify", "verify_manifest",
    "canonical_payload", "fingerprint",
    # scaffold
    "create_plugin_skeleton", "create_legacy_template", "ScaffoldError",
]

__version__ = "1.0.0"

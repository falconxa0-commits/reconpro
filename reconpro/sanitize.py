"""ReconPro Sanitization API.

Convenience imports from security.py for easy use:
    from reconpro.sanitize import sanitize_target, sanitize_path, detect_secrets
"""
from .security import (
    sanitize_target,
    sanitize_path,
    sanitize_filename,
    sanitize_html,
    sanitize_shell,
    sanitize_log,
    detect_secrets_in_text,
    safe_json_parse,
    safe_url_parse,
    SecurityAuditLogger,
    classify_threat,
)

__all__ = [
    "sanitize_target",
    "sanitize_path",
    "sanitize_filename",
    "sanitize_html",
    "sanitize_shell",
    "sanitize_log",
    "detect_secrets_in_text",
    "safe_json_parse",
    "safe_url_parse",
    "SecurityAuditLogger",
    "classify_threat",
]

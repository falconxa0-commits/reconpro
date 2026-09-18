"""reconpro_sdk — typed, stdlib-only Python SDK around the ReconPro CLI (>= 11.2.0).

Stability tier: **Stable** (see sdks/POLICY.md).
"""

from .client import ReconProClient
from .exceptions import (
    BIN_NOT_FOUND,
    ERROR_CODES,
    INVALID_JSON,
    INVALID_TARGET,
    NON_ZERO_EXIT,
    TIMEOUT,
    UNSUPPORTED_FORMAT,
    SdkError,
    TargetValidationError,
    UnsupportedFormatError,
)
from .models import (
    PARTIAL_TARGET,
    UNREACHABLE_TARGET,
    VERIFIED_TARGET,
    EXIT_INTERRUPTED,
    EXIT_RUNTIME_ERROR,
    EXIT_SUCCESS,
    EXIT_USAGE_ERROR,
    Finding,
    ScanMetadata,
    ScanResult,
    TargetValidation,
    VALID_TARGET_STATES,
)

__version__ = "1.0.0"

__all__ = [
    "ReconProClient",
    "SdkError",
    "TargetValidationError",
    "UnsupportedFormatError",
    "ScanResult",
    "Finding",
    "TargetValidation",
    "ScanMetadata",
    "VERIFIED_TARGET",
    "PARTIAL_TARGET",
    "UNREACHABLE_TARGET",
    "VALID_TARGET_STATES",
    "EXIT_SUCCESS",
    "EXIT_RUNTIME_ERROR",
    "EXIT_USAGE_ERROR",
    "EXIT_INTERRUPTED",
    # error codes
    "BIN_NOT_FOUND",
    "TIMEOUT",
    "NON_ZERO_EXIT",
    "INVALID_JSON",
    "INVALID_TARGET",
    "UNSUPPORTED_FORMAT",
    "ERROR_CODES",
    "__version__",
]

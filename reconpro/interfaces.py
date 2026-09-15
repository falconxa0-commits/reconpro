"""ReconPro v11 — Interface Definitions.

Protocols and abstract base classes that define module contracts.
Modules CAN implement these for type safety but are NOT required to.

This preserves backward compatibility while enabling static analysis.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Protocol, TypeAlias, runtime_checkable  # DEAD CODE: consider removal


# ── Type Aliases ─────────────────────────────────────────────────────────

Findings: TypeAlias = list
ScanResult: TypeAlias = dict
Severity: TypeAlias = str  # "critical" | "high" | "medium" | "low" | "info"
Grade: TypeAlias = str     # "A+" | "A" | "B" | "C" | "D" | "F"
Target: TypeAlias = str
ModuleID: TypeAlias = str


# ── Protocols (structural subtyping — duck typing with static checks) ─────

@runtime_checkable
class ScanModule(Protocol):
    """Protocol for all scanning modules.

    Standard signature:
        def run_module(target: str, base_url: str, timeout: int = 8,
                      verify_tls: bool = True) -> List[Finding]
    """
    def __call__(self, target: str, base_url: str, timeout: int = 8,
                verify_tls: bool = True) -> list: ...


@runtime_checkable
class FindingProcessor(Protocol):
    """Protocol for post-scan finding processors."""
    def process(self, findings: List[Any]) -> List[Any]: ...


@runtime_checkable
class ReportGenerator(Protocol):
    """Protocol for report generators."""
    def generate(self, data: Dict[str, Any], output_path: str) -> str: ...


@runtime_checkable
class EventEmitter(Protocol):
    """Protocol for event/callback systems."""
    def emit(self, event_type: str, **kwargs) -> Any: ...
    def on(self, event_type: str, callback) -> None: ...
    def off(self, event_type: str, callback) -> None: ...


@runtime_checkable
class ConfigurationProvider(Protocol):
    """Protocol for configuration sources."""
    def get(self, key: str, default: Any = None) -> Any: ...
    def set(self, key: str, value: Any) -> None: ...
    def has(self, key: str) -> bool: ...


# ── Abstract Base Classes (nominal subtyping — explicit inheritance) ─────

class PluginInterface(ABC):
    """Abstract base class for plugins seeking stronger type safety.

    Plugins can inherit from this for automatic interface compliance,
    but it is NOT required — plain functions still work.
    """
    @abstractmethod
    def run(self, target: str, base_url: str = "", timeout: int = 8,
            verify_tls: bool = True) -> list:
        """Execute the plugin scan. Must return list of findings."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin display name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Plugin description."""
        ...

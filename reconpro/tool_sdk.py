"""Agent Tool Plugin SDK for ReconPro.

Allows users to extend the Nexus Agent with custom tools via:
  1. Python plugin files in ~/.reconpro/tools/*.py (using the @tool decorator)
  2. External CLI tool definitions in ~/.reconpro/tools.yaml

This module is intentionally zero-dependency -- pure Python stdlib only.
No PyYAML, no third-party packages required.

Usage (plugin author):
    from reconpro.tool_sdk import tool

    @tool(name="dns_lookup", description="Resolve DNS for a domain",
          parameters={...}, examples=["Look up example.com"])
    def dns_lookup(target: str) -> str:
        ...
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import re
import shlex
import shutil
import subprocess
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════════
#  TOOLS DIRECTORY
# ══════════════════════════════════════════════════════════════════════

TOOLS_DIR: Path = Path.home() / ".reconpro" / "tools"
TOOLS_YAML: Path = TOOLS_DIR / "tools.yaml"


# ══════════════════════════════════════════════════════════════════════
#  @tool DECORATOR
# ══════════════════════════════════════════════════════════════════════

def tool(
    func: Optional[Callable] = None,
    *,
    name: str = "",
    description: str = "",
    parameters: Optional[Dict[str, Any]] = None,
    examples: Optional[List[str]] = None,
    source: str = "plugin",
) -> Callable:
    """Decorator that attaches ToolSpec metadata to a function.

    Supports three call styles::

        @tool
        def my_tool(...): ...

        @tool()
        def my_tool(...): ...

        @tool(name="scan", description="Run scan", ...)
        def my_tool(...): ...

    Parameters
    ----------
    func : callable | None
        When used bare (``@tool``), the function is passed directly.
    name : str
        Tool identifier. Defaults to the function name.
    description : str
        One-line description for the LLM. Defaults to the function docstring.
    parameters : dict | None
        JSON Schema dict describing inputs. If ``None``, inferred from the
        function signature via ``_infer_schema``.
    examples : list[str] | None
        Natural-language example invocations for the LLM.
    source : str
        Origin tag: ``"builtin"``, ``"plugin"``, or ``"external"``.

    Returns
    -------
    Callable
        The original function, with ``_reconpro_tool`` attribute set.
    """
    # Bare @tool without parentheses: func is the actual function
    if func is not None:
        return _attach_spec(
            func,
            name=name,
            description=description,
            parameters=parameters,
            examples=examples,
            source=source,
        )

    # @tool(...) with arguments: return a decorator closure
    def decorator(fn: Callable) -> Callable:
        return _attach_spec(
            fn,
            name=name,
            description=description,
            parameters=parameters,
            examples=examples,
            source=source,
        )
    return decorator


def _attach_spec(
    func: Callable,
    *,
    name: str = "",
    description: str = "",
    parameters: Optional[Dict[str, Any]] = None,
    examples: Optional[List[str]] = None,
    source: str = "plugin",
) -> Callable:
    """Attach a ToolSpec to *func* and return the function unchanged."""
    resolved_name = name or func.__name__
    resolved_desc = description or (func.__doc__ or "").strip().split("\n")[0]
    resolved_params = parameters if parameters is not None else _infer_schema(func)
    resolved_examples = examples or []

    spec = ToolSpec(
        name=resolved_name,
        description=resolved_desc,
        parameters=resolved_params,
        examples=resolved_examples,
        source=source,
        handler=func,
    )
    func._reconpro_tool = spec  # type: ignore[attr-defined]
    return func


def _infer_schema(func: Callable) -> Dict[str, Any]:
    """Build a minimal JSON Schema from a function's type annotations.

    Supports ``str``, ``int``, ``float``, ``bool`` and ``list``.  Everything
    else defaults to ``"string"``.
    """
    sig = inspect.signature(func)
    properties: Dict[str, Any] = {}
    required: List[str] = []

    for pname, param in sig.parameters.items():
        if pname in ("self", "cls"):
            continue
        ptype = "string"
        annotation = param.annotation
        if annotation is not inspect.Parameter.empty:
            if annotation is int:
                ptype = "integer"
            elif annotation is float:
                ptype = "number"
            elif annotation is bool:
                ptype = "boolean"
            elif annotation is list:
                ptype = "array"
            elif hasattr(annotation, "__origin__") and annotation.__origin__ is list:
                ptype = "array"
        properties[pname] = {"type": ptype, "description": f"Parameter: {pname}"}
        if param.default is inspect.Parameter.empty:
            required.append(pname)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


# ══════════════════════════════════════════════════════════════════════
#  ToolSpec DATACLASS
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ToolSpec:
    """Metadata describing a tool the Nexus Agent can invoke.

    Attributes:
        name:        Unique tool identifier (e.g. ``"nmap_scan"``).
        description: Human-readable one-liner for the LLM.
        parameters:  JSON Schema dict describing the tool's inputs.
        examples:    List of natural-language example invocations.
        source:      Where this tool came from: ``"builtin"``, ``"plugin"``, or ``"external"``.
        handler:     The actual callable, or ``None`` for unlinked external specs.
    """
    name: str
    description: str
    parameters: Dict[str, Any]
    examples: List[str]
    source: str = "plugin"
    handler: Optional[Callable[..., str]] = None

    def to_tool_dict(self) -> Dict[str, Any]:
        """Return a flat ``{param: {type, description}}`` dict."""
        props = self.parameters.get("properties", {})
        return {
            pname: {
                "type": pval.get("type", "string"),
                "description": pval.get("description", ""),
            }
            for pname, pval in props.items()
        }

    def to_openai_tool(self) -> Dict[str, Any]:
        """Return OpenAI function-calling schema."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_anthropic_tool(self) -> Dict[str, Any]:
        """Return Anthropic ``input_schema`` dict."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


# ══════════════════════════════════════════════════════════════════════
#  EXTERNAL TOOL HANDLER
# ══════════════════════════════════════════════════════════════════════

class ExternalToolHandler:
    """Wraps an external CLI command as a callable tool.

    Parameters
    ----------
    name : str
        Tool identifier.
    command : str
        Command template with ``{param}`` placeholders that are substituted
        at call-time from keyword arguments.
    parser : str
        One of ``"json"``, ``"regex"``, or ``"raw"``.
    parse_pattern : str | None
        Required when ``parser="regex"``.  A Python regex applied to stdout;
        first capture group (``group(1)``) is returned, or the full match
        if no groups exist.
    description : str
        Human-readable description.
    timeout : int
        subprocess timeout in seconds (default 60).
    """

    def __init__(
        self,
        name: str,
        command: str,
        parser: str = "raw",
        parse_pattern: Optional[str] = None,
        description: str = "",
        timeout: int = 60,
    ) -> None:
        self.name = name
        self.command = command
        self.parser = parser
        self.parse_pattern = parse_pattern
        self.description = description
        self.timeout = timeout

    # ── invocation ──────────────────────────────────────────────────

    def __call__(self, **kwargs: Any) -> str:
        """Execute the CLI command, parse output, return result string.

        SECURITY: the command is tokenised with :func:`shlex.split` and
        executed as an argument list with ``shell=False`` — no shell is
        ever spawned, so neither the tools.yaml template nor substituted
        keyword values can inject shell operators.
        """
        try:
            cmd = self._substitute(kwargs)
            if isinstance(cmd, str):
                try:
                    argv = shlex.split(cmd)
                except ValueError as exc:
                    return f"[ERROR] {self.name}: unparsable command: {exc}"
            else:
                argv = list(cmd)
            if not argv:
                return f"[ERROR] {self.name}: empty command"
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                shell=False,
            )
            if result.returncode != 0:
                err = result.stderr.strip() or f"exit code {result.returncode}"
                return f"[ERROR] {self.name}: {err}"
            return self._parse(result.stdout)
        except subprocess.TimeoutExpired:
            return f"[ERROR] {self.name}: timed out after {self.timeout}s"
        except FileNotFoundError:
            binary = self.command.split()[0] if isinstance(self.command, str) else str(self.command[0])
            return f"[ERROR] {self.name}: command not found: {binary}"
        except Exception as exc:
            return f"[ERROR] {self.name}: {exc}"

    # ── internal helpers ─────────────────────────────────────────────

    def _substitute(self, kwargs: Dict[str, Any]) -> str:
        """Replace ``{key}`` placeholders in the command template."""
        cmd = self.command
        for key, value in kwargs.items():
            cmd = cmd.replace(f"{{{key}}}", str(value))
        # Check for remaining unsubstituted placeholders
        remaining = re.findall(r"\{(\w+)\}", cmd)
        if remaining:
            # Silently drop unreplaced placeholders by replacing with empty
            for key in remaining:
                cmd = cmd.replace(f"{{{key}}}", "")
        return cmd

    def _parse(self, stdout: str) -> str:
        """Parse stdout according to the configured parser mode."""
        text = stdout.strip()
        if not text:
            return f"[EMPTY] {self.name}: no output"

        if self.parser == "json":
            try:
                parsed = json.loads(text)
                if isinstance(parsed, (dict, list)):
                    return json.dumps(parsed, indent=2, ensure_ascii=False)
                return str(parsed)
            except json.JSONDecodeError:
                # Try extracting JSON from mixed output
                match = re.search(r"\{.*\}|\[.*\]", text, re.DOTALL)
                if match:
                    try:
                        parsed = json.loads(match.group())
                        return json.dumps(parsed, indent=2, ensure_ascii=False)
                    except json.JSONDecodeError:
                        pass
                return text

        if self.parser == "regex" and self.parse_pattern:
            match = re.search(self.parse_pattern, text, re.MULTILINE | re.DOTALL)
            if match:
                if match.groups():
                    return match.group(1)
                return match.group(0)
            return f"[NO MATCH] {self.name}: pattern '{self.parse_pattern}' not found in output"

        # raw
        return text


# ══════════════════════════════════════════════════════════════════════
#  PLUGIN TOOL LOADER
# ══════════════════════════════════════════════════════════════════════

class PluginToolLoader:
    """Discovers and loads tools from Python plugins and external CLI configs.

    Plugin files live in ``~/.reconpro/tools/*.py`` and must use the ``@tool``
    decorator to register functions.  External tools are defined in
    ``~/.reconpro/tools.yaml``.
    """

    def __init__(self) -> None:
        self._plugin_tools: List[ToolSpec] = []
        self._external_tools: List[ToolSpec] = []

    # ── plugin discovery ─────────────────────────────────────────────

    def discover_plugin_tools(self) -> List[ToolSpec]:
        """Scan ``~/.reconpro/tools/*.py``, import each, collect ``@tool`` functions.

        Returns a list of :class:`ToolSpec` found across all plugin files.
        Files that fail to import are silently skipped (errors are not raised).
        """
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        tools: List[ToolSpec] = []

        for py_file in sorted(TOOLS_DIR.glob("*.py")):
            if py_file.name.startswith("_") or py_file.name == "tools.py":
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"reconpro_tool_{py_file.stem}", py_file
                )
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                # Walk module attributes looking for _reconpro_tool
                for attr_name in dir(mod):
                    obj = getattr(mod, attr_name, None)
                    if callable(obj) and hasattr(obj, "_reconpro_tool"):
                        tool_spec = getattr(obj, "_reconpro_tool")
                        if isinstance(tool_spec, ToolSpec):
                            tools.append(tool_spec)
            except Exception:
                continue

        self._plugin_tools = tools
        return tools

    # ── external tools.yaml discovery ────────────────────────────────

    def discover_external_tools(self) -> List[ToolSpec]:
        """Read ``~/.reconpro/tools.yaml`` and build :class:`ToolSpec` entries.

        Uses a simple hand-written line parser — **no PyYAML dependency**.

        Expected format (whitespace-insensitive keys, values after colon)::

            # Comment lines and blank lines are ignored.
            name: nuclei_scan
            description: Run nuclei vulnerability scanner
            command: nuclei -u {target} -json
            parser: json
            ---
            name: ffuf_fuzz
            description: Fuzz directories with ffuf
            command: ffuf -u {target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all
            parser: raw
            ---
            name: sqlmap_scan
            description: SQL injection testing with sqlmap
            command: sqlmap -u {target} --batch --output-dir=/tmp/sqlmap_out/{target}
            parser: raw

        Entries are separated by ``---``.
        """
        tools: List[ToolSpec] = []
        if not TOOLS_YAML.exists():
            self._external_tools = tools
            return tools

        try:
            raw = TOOLS_YAML.read_text(encoding="utf-8")
        except OSError:
            self._external_tools = tools
            return tools

        # Parse blocks separated by "---"
        blocks = raw.split("---")
        for block in blocks:
            entry = self._parse_yaml_block(block)
            if entry and "name" in entry:
                handler = ExternalToolHandler(
                    name=entry["name"],
                    command=entry.get("command", ""),
                    parser=entry.get("parser", "raw"),
                    parse_pattern=entry.get("parse_pattern"),
                    description=entry.get("description", ""),
                )
                tools.append(ToolSpec(
                    name=entry["name"],
                    description=entry.get("description", ""),
                    parameters=self._external_tool_params(entry.get("command", "")),
                    examples=entry.get("examples", []),
                    source="external",
                    handler=handler,
                ))

        self._external_tools = tools
        return tools

    @staticmethod
    def _parse_yaml_block(block: str) -> Dict[str, Any]:
        """Parse a single YAML-like block into a flat dict.

        Recognised keys: ``name``, ``description``, ``command``, ``parser``,
        ``parse_pattern``, ``examples``.  Values are stripped of leading
        whitespace.  Comment lines (``#``) and blank lines are ignored.
        """
        result: Dict[str, Any] = {}
        for line in block.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            colon_idx = stripped.find(":")
            if colon_idx == -1:
                continue
            key = stripped[:colon_idx].strip().lower()
            value = stripped[colon_idx + 1:].strip()
            if key == "examples":
                # examples: [ex1, ex2]  or  examples: a single example
                if value.startswith("[") and value.endswith("]"):
                    try:
                        result[key] = json.loads(value)
                    except json.JSONDecodeError:
                        result[key] = [value]
                else:
                    result[key] = [value]
            elif key in ("name", "description", "command", "parser", "parse_pattern"):
                result[key] = value
        return result

    @staticmethod
    def _external_tool_params(command: str) -> Dict[str, Any]:
        """Extract ``{placeholder}`` names from a command template and build
        a JSON Schema with them as required string parameters."""
        placeholders = re.findall(r"\{(\w+)\}", command)
        properties: Dict[str, Any] = {}
        required: List[str] = []
        for ph in sorted(set(placeholders)):
            properties[ph] = {"type": "string", "description": f"Parameter: {ph}"}
            required.append(ph)
        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    # ── combined loader ──────────────────────────────────────────────

    def load_all(self) -> List[ToolSpec]:
        """Discover plugin and external tools, return combined list.

        Plugin tools take priority over external tools with the same name:
        duplicates from external are silently dropped.
        """
        plugin = self.discover_plugin_tools()
        external = self.discover_external_tools()
        seen: set = {spec.name for spec in plugin}
        combined = list(plugin)
        for spec in external:
            if spec.name not in seen:
                combined.append(spec)
                seen.add(spec.name)
        return combined


# ══════════════════════════════════════════════════════════════════════
#  TEMPLATE GENERATORS
# ══════════════════════════════════════════════════════════════════════

# DEAD CODE: consider removal
def create_tool_template(name: str) -> str:
    """Write a Python plugin tool template to ``~/.reconpro/tools/{name}.py``.

    Returns the absolute path of the created file.
    """
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    target_path = TOOLS_DIR / f"{name}.py"
    if target_path.exists():
        raise FileExistsError(f"Tool file already exists: {target_path}")

    template = textwrap.dedent(f"""\
    \"\"\"Custom ReconPro tool: {name}\"\"\"
    from reconpro.tool_sdk import tool

    @tool(
        name="{name}",
        description="Describe what this tool does in one sentence.",
        parameters={{
            "type": "object",
            "properties": {{
                "target": {{
                    "type": "string",
                    "description": "The target domain or IP",
                }},
            }},
            "required": ["target"],
        }},
        examples=["Run {name} on example.com"],
    )
    def {name}(target: str) -> str:
        \"\"\"Execute the {name} tool against *target*.\"\"\"
        # Replace with your tool logic
        return f"[{name}] Result for {{target}}: not yet implemented"
    """)
    target_path.write_text(template, encoding="utf-8")
    return str(target_path)


def create_tools_yaml_template() -> str:
    """Write an example ``tools.yaml`` to ``~/.reconpro/tools/tools.yaml``.

    Returns the absolute path of the created file.
    """
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    if TOOLS_YAML.exists():
        raise FileExistsError(f"tools.yaml already exists: {TOOLS_YAML}")

    template = textwrap.dedent("""\
    # ReconPro External Tool Definitions
    # ====================================
    # Each block defines one external CLI tool the Nexus Agent can invoke.
    # Fields: name, description, command (with {param} placeholders), parser
    # Parser modes: json | regex | raw
    # Separate tools with "---"

    name: nuclei_scan
    description: Run nuclei vulnerability scanner against a target
    command: nuclei -u {target} -json
    parser: json

    ---
    name: ffuf_fuzz
    description: Fuzz web directories with ffuf
    command: ffuf -u {target}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc all
    parser: raw

    ---
    name: sqlmap_scan
    description: Automated SQL injection testing with sqlmap
    command: sqlmap -u {target} --batch --level=3 --risk=2
    parser: raw

    ---
    name: subfinder_enum
    description: Enumerate subdomains using subfinder
    command: subfinder -d {target} -silent
    parser: raw

    ---
    name: httpx_probe
    description: Probe live HTTP services with httpx
    command: httpx -u {target} -silent -json
    parser: json
    """)
    TOOLS_YAML.write_text(template, encoding="utf-8")
    return str(TOOLS_YAML)


# ══════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════

def register_builtin_tools(
    registry: Dict[str, ToolSpec],
    tool_specs: Optional[List[ToolSpec]] = None,
) -> None:
    """Register built-in tool specs into a name -> ToolSpec registry dict.

    Existing entries are **not** overwritten unless explicitly re-registered.
    If *tool_specs* is ``None``, the registry is returned unchanged (this
    allows callers to register builtins from any iterable source).
    """
    if tool_specs is None:
        return
    for spec in tool_specs:
        if spec.source == "builtin" or spec.name not in registry:
            registry[spec.name] = spec


def list_available_tools() -> List[ToolSpec]:
    """Convenience function that loads all tools and returns a flat list.

    This is a one-shot discovery: it instantiates a fresh
    :class:`PluginToolLoader`, calls :meth:`load_all`, and returns the
    result.  For repeated use, keep a ``PluginToolLoader`` instance.
    """
    loader = PluginToolLoader()
    return loader.load_all()


# ══════════════════════════════════════════════════════════════════════
#  MODULE-LEVEL EXPORTS
# ══════════════════════════════════════════════════════════════════════

__all__ = [
    "tool",
    "ToolSpec",
    "PluginToolLoader",
    "ExternalToolHandler",
    "create_tool_template",
    "create_tools_yaml_template",
    "register_builtin_tools",
    "list_available_tools",
    "TOOLS_DIR",
    "TOOLS_YAML",
]


# ── External Tool Integrations ────────────────────────────────────────────

def detect_nmap() -> Optional[str]:
    """Detect nmap installation. Returns version string or None."""
    import shutil, subprocess
    if not shutil.which("nmap"):
        return None
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split("\n"):
            if "Nmap version" in line:
                return line.strip()
        return "nmap (version detected)"
    except Exception:
        return None

def detect_masscan() -> Optional[str]:
    """Detect masscan installation."""
    import shutil
    return shutil.which("masscan")

def detect_nuclei() -> Optional[str]:
    """Detect nuclei installation."""
    import shutil, subprocess
    if not shutil.which("nuclei"):
        return None
    try:
        result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=5)
        return result.stdout.strip() or "nuclei (detected)"
    except Exception:
        return None

def detect_zap() -> Optional[str]:
    """Detect OWASP ZAP installation."""
    import shutil
    for cmd in ["zap-cli", "zap.sh", "owasp-zap"]:
        if shutil.which(cmd):
            return cmd
    return None

def detect_external_tools() -> Dict[str, Optional[str]]:
    """Detect all supported external security tools."""
    return {
        "nmap": detect_nmap(),
        "masscan": detect_masscan(),
        "nuclei": detect_nuclei(),
        "zap": detect_zap(),
    }

def run_nmap_scan(target: str, ports: str = "1-1000", arguments: str = "-sV -sC") -> Optional[str]:
    """Run nmap scan and return output."""
    import subprocess
    if not detect_nmap():
        return None
    try:
        result = subprocess.run(
            ["nmap"] + arguments.split() + ["-p", ports, target],
            capture_output=True, text=True, timeout=300,
        )
        return result.stdout
    except Exception as e:
        return f"Error: {e}"

"""ReconPro v9.0.1 — ANSI Terminal Capture.

Context manager that wraps stdout to capture all output (including
ANSI escape sequences) while still displaying it live.

Usage:
    from reconpro.ansi_capture import ANSICapture, replay_ansi, strip_ansi

    with ANSICapture() as capture:
        print("\\033[31mRed text\\033[0m")
        print("Normal text")
    capture.save("output.ansi")
    print(f"Lines captured: {capture.count_lines()}")

    # Replay later
    replay_ansi("output.ansi")

    # Get plain text
    plain = strip_ansi(capture.get_output())
"""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path
from typing import List, Optional


# ── ANSI helpers ────────────────────────────────────────────────────────

_ANSI_RE = re.compile(
    r'\x1b\[[0-9;?]*[a-zA-Z]'          # CSI sequences
    r'|\x1b[()][a-zA-Z0-9]'            # Character sets
    r'|\x1b[0-9]?[a-zA-Z]'             # Two-character sequences
    r'|\x07'                             # BEL
    r'|\x1b[<=?>]'                       # Mode sequences
    r'|\x1b\[[0-9;]*m'                 # SGR (color/style)
    r'|\x1b\][^\x07]*?'         # OSC sequences
    r'|\x1b\[[0-9;]*[HJfABCD]'        # Cursor movement
    r'|\x1b\[\?[0-9;]*[hl]'           # Mode set/reset
    r'|\x1b[\[()][^a-zA-Z]*[a-zA-Z]'  # Catch-all ESC sequences
)


# DEAD CODE: consider removal
# DEAD CODE: consider removal
def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for plain text extraction.

    Strips all CSI, OSC, and two-character escape sequences from
    the input string, returning clean plain text.

    Args:
        text: String potentially containing ANSI escape sequences.

    Returns:
        Plain text with all ANSI sequences removed.
    """
    return _ANSI_RE.sub('', text)


def replay_ansi(path: str) -> None:
    """Read an .ansi file and print it to terminal for replay.

    Args:
        path: Path to the .ansi capture file.
    """
    path_obj = Path(path)
    if not path_obj.exists():
        print(f"[ANSICapture] File not found: {path}")
        return
    content = path_obj.read_text(encoding='utf-8')
    sys.stdout.write(content)
    sys.stdout.flush()


# ── Tee-like Stream Wrapper ────────────────────────────────────────────

class _TeeStream(io.TextIOBase):
    """Stream wrapper that captures all output while still writing
    to the original stream. Preserves ANSI escape sequences verbatim."""

    def __init__(self, original: io.TextIOBase) -> None:
        self._original = original
        self._chunks: List[str] = []
        self._closed = False

    def write(self, s: str) -> int:
        if self._closed:
            return 0
        self._chunks.append(s)
        return self._original.write(s)

    def flush(self) -> None:
        if not self._closed:
            self._original.flush()

    def isatty(self) -> bool:
        return self._original.isatty()

    def fileno(self) -> int:
        return self._original.fileno()

    def readable(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def close(self) -> None:
        self._closed = True
        self.flush()

    @property
    def encoding(self) -> str:
        return getattr(self._original, 'encoding', 'utf-8') or 'utf-8'

    @property
    def mode(self) -> str:
        return getattr(self._original, 'mode', 'w')

    @property
    def name(self) -> str:
        return f'<ANSICapture.{getattr(self._original, "name", "stdout")}>'

    def get_captured(self) -> str:
        """Return the full captured content as a single string."""
        return ''.join(self._chunks)


# ── Main Capture Class ─────────────────────────────────────────────────

class ANSICapture:
    """Context manager that captures all terminal output (including ANSI)
    while still displaying it live.

    Usage:
        with ANSICapture() as capture:
            print("\\033[32mGreen output\\033[0m")
        capture.save("session.ansi")
        print(capture.count_lines())
    """

    def __init__(self, capture_stderr: bool = False) -> None:
        self._capture_stderr = capture_stderr
        self._stdout_tee: Optional[_TeeStream] = None
        self._stderr_tee: Optional[_TeeStream] = None
        self._orig_stdout: Optional[io.TextIOBase] = None
        self._orig_stderr: Optional[io.TextIOBase] = None

    def __enter__(self) -> "ANSICapture":
        # Capture stdout
        self._orig_stdout = sys.stdout
        self._stdout_tee = _TeeStream(sys.stdout)
        sys.stdout = self._stdout_tee  # type: ignore[assignment]
        # Capture stderr if requested
        if self._capture_stderr:
            self._orig_stderr = sys.stderr
            self._stderr_tee = _TeeStream(sys.stderr)
            sys.stderr = self._stderr_tee  # type: ignore[assignment]
        return self

    def __exit__(self, *args: object) -> None:
        if self._orig_stdout is not None and self._stdout_tee is not None:
            sys.stdout = self._orig_stdout
            self._stdout_tee.close()
        if self._orig_stderr is not None and self._stderr_tee is not None:
            sys.stderr = self._orig_stderr
            self._stderr_tee.close()

    def get_output(self) -> str:
        """Return all captured output (with ANSI sequences intact)."""
        parts: List[str] = []
        if self._stdout_tee is not None:
            parts.append(self._stdout_tee.get_captured())
        if self._stderr_tee is not None:
            parts.append(self._stderr_tee.get_captured())
        return ''.join(parts)

    def save(self, path: str) -> Path:
        """Save captured output to an .ansi file.

        Automatically appends .ansi extension if not already present.
        Prepends a reset sequence for clean replay.

        Args:
            path: Destination file path.

        Returns:
            Path to the saved file.
        """
        path_obj = Path(path)
        if not path_obj.suffix or path_obj.suffix != '.ansi':
            path_obj = path_obj.with_suffix(path_obj.suffix + '.ansi')
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        content = self.get_output()
        path_obj.write_text('\x1b[0m' + content, encoding='utf-8')
        return path_obj

    def count_lines(self) -> int:
        """Return the number of lines in the captured output.

        Counts newline characters; an empty capture returns 0.
        """
        text = self.get_output()
        if not text:
            return 0
        return text.count('\n') + (1 if not text.endswith('\n') else 0)

    @staticmethod
    def list_captures(directory: str = '.') -> List[Path]:
        """List all .ansi capture files in a directory (recursive)."""
        return sorted(Path(directory).glob('**/*.ansi'))

"""Safe archive extraction for ReconPro (zip-slip / zip-bomb defence).

Security contract
-----------------
* member paths are validated: absolute paths, ``..`` traversal and
  drive-relative names (``C:foo``) are rejected,
* symlink and hard-link members are rejected,
* decompressed sizes are capped per member AND in aggregate
  (default 100 MiB) — the classic zip-bomb defence,
* files are created with restrictive permissions (0o600) and directories
  with 0o700, so extracted content can never become world-writable.
"""

from __future__ import annotations

import os
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Union

__all__ = ["UnsafeArchiveError", "safe_extract_zip", "safe_extract_tar", "MAX_TOTAL_BYTES"]

MAX_TOTAL_BYTES: int = 100 * 1024 * 1024  # 100 MiB aggregate decompressed cap
MAX_MEMBER_BYTES: int = 100 * 1024 * 1024  # per-member cap (same by default)

PathLike = Union[str, Path]


class UnsafeArchiveError(ValueError):
    """Raised when an archive contains an unsafe member."""


def _validate_member_path(name: str) -> Path:
    """Return a resolved-safe relative path or raise UnsafeArchiveError."""
    if not name:
        raise UnsafeArchiveError("empty member name")
    # normalise separators (zipfile already uses '/', tarfile may use '\\')
    norm = name.replace("\\", "/")
    candidate = Path(norm)
    if candidate.is_absolute() or norm.startswith("/"):
        raise UnsafeArchiveError(f"absolute member path: {name!r}")
    # Windows drive-relative (C:foo) and UNC names
    if len(norm) >= 2 and norm[1] == ":":
        raise UnsafeArchiveError(f"drive-relative member path: {name!r}")
    parts = candidate.parts
    if any(p == ".." for p in parts):
        raise UnsafeArchiveError(f"path traversal in member: {name!r}")
    return candidate


def _check_caps(member_size: int, running_total: int, name: str) -> int:
    if member_size > MAX_MEMBER_BYTES:
        raise UnsafeArchiveError(
            f"member {name!r} decompresses to {member_size} bytes "
            f"(cap {MAX_MEMBER_BYTES})"
        )
    total = running_total + member_size
    if total > MAX_TOTAL_BYTES:
        raise UnsafeArchiveError(
            f"archive exceeds aggregate decompressed cap of {MAX_TOTAL_BYTES} bytes"
        )
    return total


def safe_extract_zip(zf: zipfile.ZipFile, dest: PathLike,
                     max_total: int = MAX_TOTAL_BYTES) -> list[Path]:
    """Safely extract every member of *zf* into *dest*.

    Returns the list of extracted file paths.  Raises UnsafeArchiveError on
    absolute/traversal/link members or when the decompressed-size caps are
    exceeded — and raises *before* any file is written when metadata
    allows (zipfile member sizes are checked from the central directory
    before extraction starts).
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    infos = zf.infolist()
    if not infos:
        return extracted

    # Pre-flight: validate names, link targets and sizes from metadata.
    total = 0
    for info in infos:
        rel = _validate_member_path(info.filename)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise UnsafeArchiveError(f"symlink member: {info.filename!r}")
        if max_total:
            total = _check_caps(info.file_size, total, info.filename)

    for info in infos:
        rel = _validate_member_path(info.filename)
        target = dest / rel
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise UnsafeArchiveError(f"symlink member: {info.filename!r}")

        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            os.chmod(target, 0o700)
            continue

        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with zf.open(info) as src, open(target, "wb") as out:
            while True:
                chunk = src.read(64 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_MEMBER_BYTES:
                    raise UnsafeArchiveError(
                        f"member {info.filename!r} exceeds decompressed cap"
                    )
                out.write(chunk)
        os.chmod(target, 0o600)
        extracted.append(target)
    return extracted


def safe_extract_tar(tf: tarfile.TarFile, dest: PathLike,
                     max_total: int = MAX_TOTAL_BYTES) -> list[Path]:
    """Safely extract every member of *tf* into *dest* (tarfile variant)."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    members = tf.getmembers()
    if not members:
        return extracted

    total = 0
    for m in members:
        rel = _validate_member_path(m.name)
        if m.issym() or m.islnk():
            raise UnsafeArchiveError(f"link member: {m.name!r}")
        if m.isreg():
            if max_total:
                total = _check_caps(m.size, total, m.name)
        elif m.isdir():
            pass
        else:  # char/block devices, fifos — never extract
            raise UnsafeArchiveError(f"special member type: {m.name!r}")

    for m in members:
        rel = _validate_member_path(m.name)
        target = dest / rel
        if m.isdir():
            target.mkdir(parents=True, exist_ok=True)
            os.chmod(target, 0o700)
            continue
        if not m.isreg():
            raise UnsafeArchiveError(f"special member type: {m.name!r}")

        target.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(m)
        if src is None:
            continue
        written = 0
        with src, open(target, "wb") as out:
            while True:
                chunk = src.read(64 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_MEMBER_BYTES:
                    raise UnsafeArchiveError(
                        f"member {m.name!r} exceeds decompressed cap"
                    )
                out.write(chunk)
        os.chmod(target, 0o600)
        extracted.append(target)
    return extracted

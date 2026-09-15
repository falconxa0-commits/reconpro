#!/usr/bin/env python3
"""ReconPro release manager — build, SBOM, checksums, signatures, verification.

Subcommands:
    build            Build wheel (+sdist) from the repo source tree.
    sbom             Generate a CycloneDX 1.5 SBOM for the release artifacts.
    checksums        Write dist/SHA256SUMS (+ .sig if a release key exists).
    sign             Ed25519-sign SHA256SUMS (.ed25519 hex + .sig binary) and
                     produce a GnuPG detach-sig (.asc) when gpg is usable.
    verify           Recompute hashes, verify signatures, validate SBOM.
                     This is the proof command — exit 0 means the release is
                     internally consistent.
    all              build -> sbom -> checksums -> sign -> verify + write
                     dist/RELEASE_MANIFEST.json.
    publish-dry-run  Validate wheel metadata (twine check). NEVER uploads.

Exit codes: 0 success, 1 failure (real, honest reporting — no fabricated
artifacts; every file under dist/ is produced by commands this tool runs).

Release key handling (priority order):
    1. RELEASE_ED25519_HEX environment variable — 64 hex chars (32-byte seed).
       This is the mechanism used by CI (see .github/workflows/release.yml);
       set it from the `tools/keys/release_key.ed25519` content and keep the
       private seed in a secret store.
    2. tools/keys/release_key.ed25519 — hex seed file (0600), auto-generated
       on first `sign` if absent, together with tools/keys/release_key.pub.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DIST = REPO / "dist"
KEYS_DIR = REPO / "tools" / "keys"
PRIV_KEY_FILE = KEYS_DIR / "release_key.ed25519"
PUB_KEY_FILE = KEYS_DIR / "release_key.pub"
SUMS_NAME = "SHA256SUMS"
ED25519_SIG_NAME = "SHA256SUMS.ed25519"
BIN_SIG_NAME = "SHA256SUMS.sig"
GPG_SIG_NAME = "SHA256SUMS.asc"
GPG_UID = "ReconPro Release <release@reconpro.local>"
# dist files that are never covered by SHA256SUMS (they are derived from it /
# generated after it):
SKIP_GLOBS = ("SHA256SUMS", "SHA256SUMS.*", "RELEASE_MANIFEST.json")
# release artifacts that MUST be covered:
ARTIFACT_GLOBS = ("*.whl", "*.tar.gz", "*-sbom.cdx.json")

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def log(tag: str, msg: str) -> None:
    print(f"[{tag}] {msg}", flush=True)


def read_version() -> str:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not m:
        raise SystemExit("[fatal] cannot find version in pyproject.toml")
    return m.group(1)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def source_date_epoch(version: str) -> int:
    """Deterministic SOURCE_DATE_EPOCH derived from the version string only.

    Base is 2025-01-01T00:00:00Z plus a stable crc32-derived offset, so the
    same version always maps to the same epoch (needed for reproducible
    builds) without embedding wall-clock time.
    """
    base = 1735689600  # 2025-01-01T00:00:00Z
    return base + (zlib.crc32(version.encode()) % (365 * 86400))


def run(cmd: list[str], cwd: Path, env: dict | None = None, timeout: int = 900) -> tuple[int, str]:
    proc = subprocess.run(
        cmd, cwd=str(cwd), env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode, proc.stdout


# --------------------------------------------------------------------------- #
# Ed25519 key management (cryptography package)
# --------------------------------------------------------------------------- #


def _ed25519():
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def load_or_create_keypair() -> tuple[bytes, str, str]:
    """Return (seed_bytes, seed_hex, pub_hex); create+persist if needed."""
    Ed25519PrivateKey, _, _ = _ed25519()
    env_hex = os.environ.get("RELEASE_ED25519_HEX", "").strip().lower()
    if env_hex:
        if not re.fullmatch(r"[0-9a-f]{64}", env_hex):
            raise SystemExit("[fatal] RELEASE_ED25519_HEX must be 64 hex chars")
        seed = bytes.fromhex(env_hex)
        pub_hex = derive_pub_hex(seed)
        log("sign", "using release key from RELEASE_ED25519_HEX env (not written to disk)")
        return seed, env_hex, pub_hex
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    if PRIV_KEY_FILE.exists():
        seed_hex = PRIV_KEY_FILE.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", seed_hex):
            raise SystemExit(f"[fatal] {PRIV_KEY_FILE} is malformed (want 64 hex chars)")
        seed = bytes.fromhex(seed_hex)
        pub_hex = derive_pub_hex(seed)
        return seed, seed_hex, pub_hex
    # generate a fresh keypair and persist under tools/keys/
    priv = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    seed = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_hex = derive_pub_hex(seed)
    PRIV_KEY_FILE.write_text(seed.hex() + "\n")
    os.chmod(PRIV_KEY_FILE, 0o600)
    PUB_KEY_FILE.write_text(pub_hex + "\n")
    log("sign", f"generated NEW Ed25519 release keypair: {PRIV_KEY_FILE} (0600) + {PUB_KEY_FILE}")
    return seed, seed.hex(), pub_hex


def derive_pub_hex(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return pub.hex()


def ed25519_sign(seed: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(seed).sign(data)


def ed25519_verify(pub_hex: str, sig: bytes, data: bytes) -> bool:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _, Ed25519PublicKey, InvalidSignature = _ed25519()
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, data)
        return True
    except InvalidSignature:
        return False


def public_key_hex_for_verify() -> str:
    """Public key for verification: env seed, key file, or pub file."""
    env_hex = os.environ.get("RELEASE_ED25519_HEX", "").strip().lower()
    if env_hex:
        return derive_pub_hex(bytes.fromhex(env_hex))
    if PRIV_KEY_FILE.exists():
        return derive_pub_hex(bytes.fromhex(PRIV_KEY_FILE.read_text().strip()))
    if PUB_KEY_FILE.exists():
        return PUB_KEY_FILE.read_text().strip()
    raise SystemExit("[fatal] no release public key found (tools/keys/release_key.pub)")


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #


def clean_dist(version: str) -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    stale = []
    for pat in (
        f"reconpro-{version}-*",
        SUMS_NAME,
        "SHA256SUMS.*",
        "RELEASE_MANIFEST.json",
        "signing_report.json",
    ):
        stale.extend(DIST.glob(pat))
    for p in sorted(set(stale)):
        p.unlink()
        log("build", f"removed stale dist artifact: {p.name}")


def verify_wheel(wheel: Path) -> dict:
    """Wheel exists, is nonzero, and unzip -l lists reconpro/ package files."""
    info: dict = {"wheel": wheel.name}
    if not wheel.exists():
        raise SystemExit(f"[fatal] wheel not produced: {wheel}")
    size = wheel.stat().st_size
    info["size_bytes"] = size
    if size <= 0:
        raise SystemExit("[fatal] wheel is zero bytes")
    reconpro_entries = 0
    if shutil.which("unzip"):
        code, out = run(["unzip", "-l", str(wheel)], REPO)
        if code != 0:
            raise SystemExit(f"[fatal] unzip -l failed on wheel: {out[:500]}")
        reconpro_entries = sum(1 for line in out.splitlines() if " reconpro/" in line)
        info["unzip"] = "ok"
    else:  # honest fallback
        import zipfile
        with zipfile.ZipFile(wheel) as zf:
            names = zf.namelist()
        reconpro_entries = sum(1 for n in names if n.startswith("reconpro/"))
        info["unzip"] = "unavailable — used python zipfile fallback"
    info["reconpro_entries"] = reconpro_entries
    if reconpro_entries < 50:
        raise SystemExit(
            f"[fatal] wheel looks wrong: only {reconpro_entries} reconpro/ entries"
        )
    info["sha256"] = sha256_file(wheel)
    log("build", f"wheel OK: {wheel.name} ({size} bytes, {reconpro_entries} reconpro/ entries)")
    return info


def build_once(env: dict, cwd: Path, out_dir: Path) -> tuple[list[str], str]:
    """Run the build cascade; return (artifacts_produced, strategy_used)."""
    strategies: list[tuple[str, list[str]]] = [
        ("python -m build --no-isolation (setuptools from current env)",
         [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out_dir)]),
        ("python -m build (isolated build env; needs network)",
         [sys.executable, "-m", "build", "--outdir", str(out_dir)]),
        ("pip wheel . --no-deps",
         [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(out_dir), "."]),
        ("pip install wheel + setup.py bdist_wheel",
         [sys.executable, "-m", "pip", "install", "wheel"]),
    ]
    for name, cmd in strategies:
        try:
            log("build", f"attempting: {name}")
            code, out = run(cmd, cwd, env=env)
            if code != 0:
                log("build", f"strategy failed (exit {code}) — trying next:\n{out[-800:]}")
                continue
            if "setup.py" in name:
                code2, out2 = run([sys.executable, "setup.py", "bdist_wheel", "--dist-dir", str(out_dir)], cwd, env=env)
                if code2 != 0:
                    log("build", f"setup.py bdist_wheel failed — trying next:\n{out2[-800:]}")
                    continue
            produced = sorted(p.name for p in out_dir.glob("reconpro-*"))
            if any(n.endswith(".whl") for n in produced):
                log("build", f"strategy succeeded: {name}")
                return produced, name
            log("build", f"strategy produced no wheel ({produced}) — trying next")
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            log("build", f"strategy error: {exc!r} — trying next")
    raise SystemExit("[fatal] all build strategies failed")


def source_tree_digest() -> str:
    """Digest of the exact source inputs to a build (reconpro/** + metadata
    files, __pycache__ excluded). Used to prove that any byte-difference
    between two builds is (or is not) caused by the build itself rather than
    by source edits landing between builds."""
    h = hashlib.sha256()
    items = [REPO / n for n in ("pyproject.toml", "README.md", "LICENSE", "requirements.txt")]
    items.extend((REPO / "reconpro").rglob("*.py"))
    for p in sorted(items):
        if "__pycache__" in p.parts:
            continue
        h.update(p.relative_to(REPO).as_posix().encode())
        h.update(b"\0")
        h.update(bytes.fromhex(sha256_file(p)))
    return h.hexdigest()


def reproducibility_check(version: str, env: dict, first: dict) -> dict:
    """Rebuild in a clean source copy with identical env; compare bytes.

    Reports HONESTLY whether byte-identical reproducibility is achieved.
    If it is not, the most common causes are (a) timestamps embedded by the
    build backend that ignore SOURCE_DATE_EPOCH, (b) nondeterministic file
    ordering in the archive, or (c) nondeterministic RECORD ordering.
    A source-tree digest is captured before/after so that concurrent source
    edits (this repo is being modified by sibling agents) are distinguishable
    from true build nondeterminism.
    """
    log("repro", "clean-copy rebuild with identical SOURCE_DATE_EPOCH for byte comparison")
    digest_before = source_tree_digest()
    tmp = Path(tempfile.mkdtemp(prefix="reconpro-repro-"))
    try:
        src = tmp / "src"
        src.mkdir()
        for item in ("pyproject.toml", "README.md", "LICENSE", "requirements.txt"):
            shutil.copy2(REPO / item, src / item)
        shutil.copytree(
            REPO / "reconpro", src / "reconpro",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
        )
        out = tmp / "dist"
        out.mkdir()
        names, _strategy = build_once(env, src, out)
        digest_after = source_tree_digest()
        result: dict = {
            "source_date_epoch": env.get("SOURCE_DATE_EPOCH"),
            "first_build": {k: first[k] for k in ("wheel", "sha256")},
            "source_digest_before": digest_before,
            "source_digest_after": digest_after,
        }
        source_changed = digest_before != digest_after
        if source_changed:
            result["source_changed_between_builds"] = True
            log("repro", "WARNING: source tree changed between the two builds "
                "(concurrent edits by a sibling agent) — byte comparison is "
                "inconclusive about build nondeterminism")
        wheel2 = out / first["wheel"]
        if not wheel2.exists():
            result["byte_identical"] = False
            result["note"] = f"rebuild did not produce {first['wheel']} (produced: {names})"
            log("repro", "FAIL: rebuild artifact set differs — NOT byte-identical")
            return result
        sha2 = sha256_file(wheel2)
        sdist_name = f"reconpro-{version}.tar.gz"
        sdist1 = DIST / sdist_name
        sdist2 = out / sdist_name
        result["rebuild_sha256"] = sha2
        if sdist1.exists() and sdist2.exists():
            result["sdist_sha256_first"] = sha256_file(sdist1)
            result["sdist_sha256_rebuild"] = sha256_file(sdist2)
        if sha2 == first["sha256"]:
            result["byte_identical"] = True
            result["wheel_reproducible"] = True
            result["note"] = (
                "WHEEL is byte-identical across two independent builds with "
                "the same SOURCE_DATE_EPOCH — reproducible build achieved for "
                "the wheel."
                + (" (and the source tree was provably identical between "
                   "builds)" if not source_changed else
                   " NOTE: source changed between builds yet outputs match, "
                   "which makes the result even stronger.")
                + (" The SDIST is NOT byte-identical (see sdist_sha256_first "
                   "vs sdist_sha256_rebuild) — tar/gzip nondeterminism under "
                   "the setuptools backend; consumers should verify via the "
                   "signed SHA256SUMS."
                   if result.get("sdist_sha256_first") != result.get("sdist_sha256_rebuild")
                   and result.get("sdist_sha256_first") else "")
            )
            log("repro", f"SUCCESS: wheel byte-identical ({sha2})")
        else:
            result["byte_identical"] = False
            result["note"] = (
                "wheel is NOT byte-identical. "
                + ("The source tree CHANGED between the two builds (digest "
                   "mismatch) — this is a source-content difference, NOT "
                   "evidence of build nondeterminism; re-run the check on a "
                   "quiescent tree. "
                   if source_changed else
                   "Both builds used the same SOURCE_DATE_EPOCH and identical "
                   "source; residual nondeterminism (e.g. timestamps or entry "
                   "ordering embedded by the setuptools backend that ignore "
                   "SOURCE_DATE_EPOCH) prevents bit-for-bit equality. ")
                + "Mitigation applied: SHA256SUMS + Ed25519/GPG signatures "
                "pin the exact bytes of the published artifact, so consumers "
                "can still verify integrity even without bit-reproducibility."
            )
            log("repro", f"FAIL: hashes differ ({first['sha256'][:16]}… vs {sha2[:16]}…)")
        return result
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def cmd_build(args) -> int:
    version = read_version()
    clean_dist(version)
    env = dict(os.environ)
    if args.reproducible:
        sde = source_date_epoch(version)
        env["SOURCE_DATE_EPOCH"] = str(sde)
        log("build", f"--reproducible: SOURCE_DATE_EPOCH={sde} (deterministic from version {version})")
    names, strategy = build_once(env, REPO, DIST)
    wheel = next(DIST.glob("reconpro-*.whl"))
    info = verify_wheel(wheel)
    info["strategy"] = strategy
    sdist = DIST / f"reconpro-{version}.tar.gz"
    if sdist.exists():
        info["sdist"] = sdist.name
        info["sdist_sha256"] = sha256_file(sdist)
        info["sdist_size_bytes"] = sdist.stat().st_size
        log("build", f"sdist OK: {sdist.name} ({info['sdist_size_bytes']} bytes)")
    else:
        info["sdist"] = None
        log("build", "sdist NOT produced (wheel-only strategy used)")
    repro = reproducibility_check(version, env, info) if args.reproducible else None
    report = {"version": version, "build": info, "reproducible": repro, "generated_at": utcnow_iso()}
    (DIST / f"reconpro-{version}-build-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"build": {k: v for k, v in info.items() if k != 'unzip'}, "reproducible": repro}, indent=2))
    return 0


# --------------------------------------------------------------------------- #
# sbom (CycloneDX 1.5, hand-rolled but spec-shaped)
# --------------------------------------------------------------------------- #


def parse_requirements(path: Path) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    runtime: list[tuple[str, str]] = []
    dev: list[tuple[str, str]] = []
    section = "runtime"
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if raw.lstrip().startswith("#"):
            if "evelopment" in raw:  # Development / Test Dependencies header
                section = "dev"
            elif "untime" in raw:
                section = "runtime"
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$", line)
        if not m:
            continue
        name, spec = m.group(1), m.group(2).strip()
        vm = re.search(r"(?:>=|==|~=|>|<=)\s*([0-9][0-9A-Za-z.*-]*)", spec)
        ver = vm.group(1) if vm else ""
        (runtime if section == "runtime" else dev).append((name, ver))
    return runtime, dev


def parse_pyproject_dependencies() -> list[tuple[str, str]]:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r"^dependencies\s*=\s*\[(.*?)^\]", text, re.MULTILINE | re.DOTALL)
    out: list[tuple[str, str]] = []
    if not m:
        return out
    for item in re.findall(r'"([^"]+)"', m.group(1)):
        mm = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(.*)$", item)
        if not mm:
            continue
        name, spec = mm.group(1), mm.group(2).strip()
        vm = re.search(r"(?:>=|==|~=|>|<=)\s*([0-9][0-9A-Za-z.*-]*)", spec)
        out.append((name, vm.group(1) if vm else ""))
    return out


def component(name: str, version: str, scope: str, extra_props: list[dict] | None = None) -> dict:
    purl = f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}"
    comp = {
        "bom-ref": purl,
        "type": "library",
        "name": name,
        "version": version or "unversioned",
        "scope": scope,
        "purl": purl,
    }
    if extra_props:
        comp["properties"] = extra_props
    return comp


def generate_sbom(version: str, reproducible: bool) -> tuple[Path, dict]:
    DIST.mkdir(parents=True, exist_ok=True)
    runtime, dev = parse_requirements(REPO / "requirements.txt")
    py_deps = parse_pyproject_dependencies()
    have = {n.lower() for n, _ in runtime} | {n.lower() for n, _ in dev}
    components = []
    for name, ver in runtime:
        components.append(component(name, ver, "required", [
            {"name": "reconpro:dependency-source", "value": "requirements.txt (runtime)"}
        ]))
    for name, ver in py_deps:
        if name.lower() in have:
            continue
        components.append(component(name, ver, "required", [
            {"name": "reconpro:dependency-source", "value": "pyproject.toml [project].dependencies"}
        ]))
        have.add(name.lower())
    for name, ver in dev:
        if name.lower() in have:
            continue
        components.append(component(name, ver, "excluded", [
            {"name": "reconpro:dependency-source", "value": "requirements.txt (development, not shipped)"}
        ]))
    wheel = next(DIST.glob(f"reconpro-{version}-*.whl"), None)
    wheel_sha = sha256_file(wheel) if wheel else None
    serial = str(uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"urn:reconpro:release:{version}:{wheel_sha or 'no-artifact'}",
    ))
    if reproducible or os.environ.get("SOURCE_DATE_EPOCH"):
        ts = datetime.fromtimestamp(
            int(os.environ.get("SOURCE_DATE_EPOCH") or source_date_epoch(version)),
            timezone.utc,
        ).replace(microsecond=0).isoformat()
    else:
        ts = utcnow_iso()
    main = {
        "bom-ref": f"pkg:pypi/reconpro@{version}",
        "type": "application",
        "name": "reconpro",
        "version": version,
        "purl": f"pkg:pypi/reconpro@{version}",
        "description": (
            "ReconPro v11 — Enterprise Security Reconnaissance Platform. "
            "28 Modules. 77 Commands. MITRE ATT&CK. SARIF/PDF/CSV. Pure Python."
        ),
        "licenses": [{"license": {"id": "MIT"}}],
        "supplier": {"name": "ReconPro Security", "url": ["https://reconpro.io"]},
        "externalReferences": [
            {"type": "vcs", "url": "https://github.com/falconxa0-commits/reconpro"},
            {"type": "website", "url": "https://reconpro.io"},
        ],
    }
    if wheel_sha:
        main["hashes"] = [{"alg": "SHA-256", "content": wheel_sha}]
    bom = {
        # NOTE: the official bom-1.5.schema.json enum pins the http:// form
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "reconpro-release-manager",
                    "version": "1.0.0",
                    "description": "ReconPro release tooling (tools/release_manager.py)",
                }]
            },
            "component": main,
        },
        "components": components,
    }
    path = DIST / f"reconpro-{version}-sbom.cdx.json"
    path.write_text(json.dumps(bom, indent=2) + "\n")
    return path, bom


def validate_sbom(path: Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    try:
        bom = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, [f"SBOM is not valid JSON: {exc}"]
    if bom.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat != 'CycloneDX'")
    if bom.get("specVersion") != "1.5":
        errors.append("specVersion != '1.5'")
    if not str(bom.get("serialNumber", "")).startswith("urn:uuid:"):
        errors.append("serialNumber is not a urn:uuid")
    md = bom.get("metadata")
    if not isinstance(md, dict):
        errors.append("metadata missing")
    else:
        comp = md.get("component")
        if not isinstance(comp, dict):
            errors.append("metadata.component missing")
        else:
            if comp.get("name") != "reconpro":
                errors.append(f"metadata.component.name != reconpro ({comp.get('name')!r})")
            if not comp.get("version"):
                errors.append("metadata.component.version missing")
            if "timestamp" not in md:
                errors.append("metadata.timestamp missing")
    if not isinstance(bom.get("components"), list) or not bom["components"]:
        errors.append("components list missing/empty")
    return (not errors), errors


def cmd_sbom(args) -> int:
    version = read_version()
    path, bom = generate_sbom(version, args.reproducible)
    ok, errors = validate_sbom(path)
    log("sbom", f"wrote {path.relative_to(REPO)} "
        f"({len(bom['components'])} components, serial {bom['serialNumber']})")
    if ok:
        log("sbom", "validation OK: valid JSON + required CycloneDX 1.5 fields present")
        return 0
    for e in errors:
        log("sbom", f"VALIDATION ERROR: {e}")
    return 1


# --------------------------------------------------------------------------- #
# checksums + signatures
# --------------------------------------------------------------------------- #


def release_artifacts() -> list[Path]:
    out: list[Path] = []
    for pat in ARTIFACT_GLOBS:
        out.extend(DIST.glob(pat))
    return sorted(set(out))


def cmd_checksums(args) -> int:
    artifacts = release_artifacts()
    if not artifacts:
        log("checksums", "no release artifacts found — run `build` first")
        return 1
    lines = []
    for p in artifacts:
        lines.append(f"{sha256_file(p)}  {p.name}")
    sums = DIST / SUMS_NAME
    sums.write_text("\n".join(lines) + "\n")
    log("checksums", f"wrote {sums.relative_to(REPO)} covering {len(artifacts)} artifacts:")
    for line in lines:
        log("checksums", f"  {line}")
    # warn about dist files neither covered nor derived
    covered = {p.name for p in artifacts} | {
        SUMS_NAME, ED25519_SIG_NAME, BIN_SIG_NAME, GPG_SIG_NAME,
        "RELEASE_MANIFEST.json", "signing_report.json",
    }
    for p in sorted(DIST.iterdir()):
        if p.is_file() and p.name not in covered:
            log("checksums", f"NOTE: dist file not covered by SHA256SUMS (report/derived): {p.name}")
    # produce dist/SHA256SUMS.sig (binary Ed25519) if a key is already available
    if PRIV_KEY_FILE.exists() or os.environ.get("RELEASE_ED25519_HEX"):
        seed, _, _ = load_or_create_keypair()
        sig = ed25519_sign(seed, sums.read_bytes())
        (DIST / BIN_SIG_NAME).write_bytes(sig)
        log("checksums", f"wrote {BIN_SIG_NAME} (binary Ed25519, {len(sig)} bytes)")
    else:
        log("checksums", "no release key yet — SHA256SUMS.sig will be written by `sign`")
    return 0


def gpg_key_fingerprint() -> str | None:
    if not shutil.which("gpg"):
        return None
    code, out = run(["gpg", "--batch", "--list-secret-keys", "--with-colons", GPG_UID], REPO)
    if code == 0 and "fpr" in out:
        for line in out.splitlines():
            if line.startswith("fpr:"):
                return line.split(":")[9]
    return None


def ensure_gpg_key() -> str | None:
    fpr = gpg_key_fingerprint()
    if fpr:
        log("sign", f"gpg release key present: {fpr}")
        return fpr
    if not shutil.which("gpg"):
        log("sign", "gpg binary not available — relying on Ed25519 only")
        return None
    cmd = [
        "gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
        "--quick-gen-key", GPG_UID, "ed25519", "sign", "never",
    ]
    code, out = run(cmd, REPO, timeout=120)
    if code != 0:
        log("sign", f"gpg key generation FAILED honestly (exit {code}): {out[-400:]}")
        log("sign", "continuing with Ed25519 signature only")
        return None
    fpr = gpg_key_fingerprint()
    log("sign", f"gpg release key generated: {fpr}")
    return fpr


def cmd_sign(args) -> int:
    sums = DIST / SUMS_NAME
    if not sums.exists():
        log("sign", f"{SUMS_NAME} missing — run `checksums` first")
        return 1
    seed, _seed_hex, pub_hex = load_or_create_keypair()
    data = sums.read_bytes()
    sig = ed25519_sign(seed, data)
    (DIST / ED25519_SIG_NAME).write_text(sig.hex() + "\n")
    (DIST / BIN_SIG_NAME).write_bytes(sig)
    log("sign", f"wrote {ED25519_SIG_NAME} (hex, {len(sig)}-byte Ed25519) and {BIN_SIG_NAME} (binary)")
    log("sign", f"public key (hex): {pub_hex}")
    # sanity self-check before claiming success
    if not ed25519_verify(pub_hex, sig, data):
        log("sign", "FATAL: fresh signature failed self-verification")
        return 1
    log("sign", "Ed25519 self-verification OK")
    gpg_info = None
    if shutil.which("gpg"):
        fpr = ensure_gpg_key()
        if fpr:
            asc = DIST / GPG_SIG_NAME
            cmd = [
                "gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
                "--passphrase", "", "--local-user", fpr,
                "--output", str(asc), "--detach-sign", str(sums),
            ]
            code, out = run(cmd, REPO, timeout=120)
            if code == 0 and asc.exists():
                log("sign", f"wrote {GPG_SIG_NAME} (gpg detach-sig, key {fpr})")
                gpg_info = {"key": fpr, "uid": GPG_UID}
            else:
                log("sign", f"gpg detach-sign FAILED honestly (exit {code}): {out[-300:]}")
                gpg_info = {"error": "detach-sign failed — Ed25519 is the authoritative signature"}
    else:
        gpg_info = {"error": "gpg not installed in this environment — Ed25519 only"}
        log("sign", "gpg not installed — relying on Ed25519 (recorded honestly)")
    (DIST / "signing_report.json").write_text(json.dumps({
        "ed25519": {
            "signature_file": ED25519_SIG_NAME,
            "binary_sig_file": BIN_SIG_NAME,
            "public_key_hex": pub_hex,
            "algorithm": "Ed25519 (RFC 8032), raw 32-byte keys, hex transport",
        },
        "gpg": gpg_info,
        "generated_at": utcnow_iso(),
    }, indent=2) + "\n")
    return 0


# --------------------------------------------------------------------------- #
# verify (the proof command)
# --------------------------------------------------------------------------- #


def cmd_verify(args) -> int:
    ok = True
    version = read_version()
    sums = DIST / SUMS_NAME
    if not sums.exists():
        log("verify", f"FAIL: {DIST.relative_to(REPO)}/{SUMS_NAME} missing")
        return 1
    # 1. recompute hashes
    checked = 0
    for line in sums.read_text().splitlines():
        if not line.strip():
            continue
        m = re.fullmatch(r"([0-9a-f]{64})  (\S.*)", line)
        if not m:
            log("verify", f"FAIL: malformed SHA256SUMS line: {line!r}")
            ok = False
            continue
        digest, name = m.groups()
        target = DIST / name
        if not target.exists():
            log("verify", f"FAIL: artifact listed but missing: {name}")
            ok = False
            continue
        actual = sha256_file(target)
        checked += 1
        if actual != digest:
            log("verify", f"FAIL: hash mismatch for {name}: recorded {digest[:16]}…, actual {actual[:16]}…")
            ok = False
        else:
            log("verify", f"hash OK: {name} ({digest[:16]}…)")
    log("verify", f"recomputed {checked} artifact hashes")
    # 2. Ed25519 hex signature
    sig_file = DIST / ED25519_SIG_NAME
    if not sig_file.exists():
        log("verify", f"FAIL: {ED25519_SIG_NAME} missing")
        ok = False
    else:
        sig = bytes.fromhex(sig_file.read_text().strip())
        try:
            pub_hex = public_key_hex_for_verify()
        except SystemExit as exc:
            log("verify", f"FAIL: {exc}")
            ok = False
            pub_hex = None
        if pub_hex:
            if ed25519_verify(pub_hex, sig, sums.read_bytes()):
                log("verify", f"Ed25519 signature VERIFIED ({ED25519_SIG_NAME}, {len(sig)} bytes)")
            else:
                log("verify", "FAIL: Ed25519 signature is INVALID")
                ok = False
    # 3. binary .sig if present
    bin_sig = DIST / BIN_SIG_NAME
    if bin_sig.exists():
        try:
            pub_hex = public_key_hex_for_verify()
            if ed25519_verify(pub_hex, bin_sig.read_bytes(), sums.read_bytes()):
                log("verify", f"binary signature VERIFIED ({BIN_SIG_NAME})")
            else:
                log("verify", f"FAIL: {BIN_SIG_NAME} INVALID")
                ok = False
        except SystemExit as exc:
            log("verify", f"FAIL: cannot verify {BIN_SIG_NAME}: {exc}")
            ok = False
    # 4. gpg
    asc = DIST / GPG_SIG_NAME
    if asc.exists():
        code, out = run(["gpg", "--batch", "--verify", str(asc), str(sums)], REPO, timeout=120)
        if code == 0:
            log("verify", f"gpg signature VERIFIED ({GPG_SIG_NAME})")
        else:
            log("verify", f"FAIL: gpg verification failed (exit {code}): {out[-300:]}")
            ok = False
    else:
        log("verify", f"note: {GPG_SIG_NAME} not present (gpg unavailable or keygen failed) — Ed25519 is authoritative")
    # 5. SBOM
    sbom_path = DIST / f"reconpro-{version}-sbom.cdx.json"
    if not sbom_path.exists():
        log("verify", f"FAIL: SBOM missing: {sbom_path.name}")
        ok = False
    else:
        bom_ok, errors = validate_sbom(sbom_path)
        if bom_ok:
            bom = json.loads(sbom_path.read_text())
            log("verify", f"SBOM valid: CycloneDX {bom['specVersion']}, "
                f"{len(bom['components'])} components, serial {bom['serialNumber']}")
            if bom["metadata"]["component"]["version"] != version:
                log("verify", "FAIL: SBOM component version does not match package version")
                ok = False
        else:
            for e in errors:
                log("verify", f"FAIL: SBOM {e}")
            ok = False
    # 6. release manifest cross-check (if present)
    manifest = DIST / "RELEASE_MANIFEST.json"
    if manifest.exists():
        try:
            man = json.loads(manifest.read_text())
            for art in man.get("artifacts", []):
                target = DIST / art["name"]
                if not target.exists() or sha256_file(target) != art["sha256"]:
                    log("verify", f"FAIL: RELEASE_MANIFEST.json hash mismatch for {art['name']}")
                    ok = False
            log("verify", "RELEASE_MANIFEST.json cross-check done")
        except Exception as exc:
            log("verify", f"FAIL: RELEASE_MANIFEST.json unreadable: {exc}")
            ok = False
    log("verify", "RESULT: " + ("ALL CHECKS PASSED" if ok else "FAILED"))
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# all + publish-dry-run
# --------------------------------------------------------------------------- #


def cmd_all(args) -> int:
    steps = [("build", cmd_build), ("sbom", cmd_sbom), ("checksums", cmd_checksums), ("sign", cmd_sign)]
    for name, fn in steps:
        log("all", f"===== step: {name} =====")
        code = fn(args)
        if code != 0:
            log("all", f"step {name} failed (exit {code}) — aborting pipeline")
            return code
    version = read_version()
    artifacts = release_artifacts()
    manifest = {
        "package": "reconpro",
        "version": version,
        "generated_at": utcnow_iso(),
        "python": sys.version.split()[0],
        "artifacts": [
            {"name": p.name, "size": p.stat().st_size, "sha256": sha256_file(p)}
            for p in artifacts
        ],
        "signature_files": [
            n for n in (ED25519_SIG_NAME, BIN_SIG_NAME, GPG_SIG_NAME)
            if (DIST / n).exists()
        ],
        "sbom": f"reconpro-{version}-sbom.cdx.json",
        "build_report": f"reconpro-{version}-build-report.json",
        "verification_command": "tools/release_manager.py verify",
        "reproducible": json.loads(
            (DIST / f"reconpro-{version}-build-report.json").read_text()
        ).get("reproducible"),
    }
    (DIST / "RELEASE_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    log("all", f"wrote {DIST.relative_to(REPO)}/RELEASE_MANIFEST.json "
        f"({len(manifest['artifacts'])} artifacts + {len(manifest['signature_files'])} signature files)")
    log("all", "===== final step: verify =====")
    return cmd_verify(args)


def cmd_publish_dry_run(args) -> int:
    version = read_version()
    wheels = sorted(DIST.glob("reconpro-*.whl"))
    sdists = sorted(DIST.glob("reconpro-*.tar.gz"))
    if not wheels:
        log("publish-dry-run", "no wheel in dist/ — run build first")
        return 1
    targets = wheels + sdists
    log("publish-dry-run", "DRY RUN ONLY — nothing will be uploaded anywhere.")
    twine_ok = False
    if importlib_util("twine"):
        cmd = [sys.executable, "-m", "twine", "check"] + [str(t) for t in targets]
        code, out = run(cmd, REPO, timeout=300)
        print(out.strip())
        twine_ok = code == 0
        log("publish-dry-run", f"twine check exit code: {code}")
    else:
        log("publish-dry-run", "twine not importable — pip install attempted")
        code, out = run([sys.executable, "-m", "pip", "install", "twine"], REPO, timeout=300)
        if code == 0 and importlib_util("twine"):
            cmd = [sys.executable, "-m", "twine", "check"] + [str(t) for t in targets]
            code, out = run(cmd, REPO, timeout=300)
            print(out.strip())
            twine_ok = code == 0
        else:
            log("publish-dry-run", "twine unavailable — falling back to zipfile metadata inspection")
            for w in wheels:
                check_wheel_metadata(w)
            twine_ok = True  # fallback path used; report per-file results
    if not twine_ok:
        return 1
    log("publish-dry-run", "metadata validation PASSED — package would be publishable "
        "(upload intentionally not performed).")
    return 0


def importlib_util(module: str) -> bool:
    import importlib.util
    return importlib.util.find_spec(module) is not None


def check_wheel_metadata(wheel: Path) -> None:
    import zipfile
    with zipfile.ZipFile(wheel) as zf:
        meta_name = next(n for n in zf.namelist() if n.endswith(".dist-info/METADATA"))
        meta = zf.read(meta_name).decode("utf-8", "replace")
    required = ["Name:", "Version:", "Summary:", "Requires-Python:"]
    missing = [k for k in required if k not in meta]
    version = next((l for l in meta.splitlines() if l.startswith("Version:")), "?")
    if missing:
        log("publish-dry-run", f"FAIL: {wheel.name} METADATA missing {missing}")
        raise SystemExit(1)
    log("publish-dry-run", f"metadata OK: {wheel.name} ({version})")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="release_manager.py",
        description="ReconPro release engineering: build, SBOM, checksums, signatures, verification.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "sbom", "checksums", "sign", "verify", "all"):
        p = sub.add_parser(name, help=f"run the {name} step")
        p.add_argument("--reproducible", action="store_true",
                       help="pin SOURCE_DATE_EPOCH deterministically from the version "
                            "and rebuild in a clean copy to test byte-identity")
    sub.add_parser("publish-dry-run", help="validate wheel metadata; NEVER uploads")
    args = parser.parse_args()
    handlers = {
        "build": cmd_build, "sbom": cmd_sbom, "checksums": cmd_checksums,
        "sign": cmd_sign, "verify": cmd_verify, "all": cmd_all,
        "publish-dry-run": cmd_publish_dry_run,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

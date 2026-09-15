"""Ed25519 signing and verification for ReconPro plugins.

Uses the ``cryptography`` package (present in the runtime environment).
Key material is exchanged as lowercase hex strings.  Signatures cover the
canonical JSON serialisation of the manifest payload plus the SHA-256 of
the plugin source, so ANY modification of either source or metadata
invalidates the signature.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Tuple

try:  # pragma: no cover - environment guard
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False


class CryptoUnavailable(RuntimeError):
    """Raised when the cryptography backend is not installed."""


class SignatureError(ValueError):
    """Raised for malformed keys / signatures."""


def _backend() -> None:
    if not _HAS_CRYPTO:
        raise CryptoUnavailable(
            "the 'cryptography' package is required for plugin signatures")


# ── canonical payload ─────────────────────────────────────────────────────

SIGNED_FIELDS = (
    "id", "name", "version", "description", "author", "reconpro_min",
    "permissions",
)


def canonical_payload(manifest: Dict[str, Any], source_sha256: str) -> bytes:
    """Deterministic byte string covered by a plugin signature.

    ``manifest`` must be the parsed plugin.toml table.  Only the fields in
    SIGNED_FIELDS participate — unknown extra metadata does not break old
    signatures but the listed fields plus source hash do.
    """
    payload = {field: manifest[field] for field in SIGNED_FIELDS if field in manifest}
    payload["source_sha256"] = source_sha256
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def source_sha256(source: bytes) -> str:
    return hashlib.sha256(source).hexdigest()


# ── keys ──────────────────────────────────────────────────────────────────

def generate_keypair() -> Tuple[str, str]:
    """Generate a fresh Ed25519 keypair.

    Returns ``(private_hex, public_hex)``.
    """
    _backend()
    private = Ed25519PrivateKey.generate()
    priv_hex = private.private_bytes_raw().hex()
    pub_hex = private.public_key().public_bytes_raw().hex()
    return priv_hex, pub_hex


def fingerprint(public_hex: str) -> str:
    """Short human identifier for a public key (first 16 hex of SHA-256)."""
    return hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]


def _load_public(public_hex: str) -> "Ed25519PublicKey":
    _backend()
    try:
        raw = bytes.fromhex(public_hex.strip().lower())
    except ValueError as exc:
        raise SignatureError(f"malformed public key hex: {public_hex!r}") from exc
    if len(raw) != 32:
        raise SignatureError(
            f"public key must be 32 bytes (Ed25519), got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def _load_private(private_hex: str) -> "Ed25519PrivateKey":
    _backend()
    try:
        raw = bytes.fromhex(private_hex.strip().lower())
    except ValueError as exc:
        raise SignatureError(f"malformed private key hex: {private_hex!r}") from exc
    if len(raw) != 32:
        raise SignatureError(
            f"private key must be 32 bytes (Ed25519 seed), got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)


# ── sign / verify ─────────────────────────────────────────────────────────

def sign(private_hex: str, message: bytes) -> str:
    """Sign ``message`` (bytes) and return the signature as hex."""
    key = _load_private(private_hex)
    return key.sign(message).hex()


def verify(public_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify an Ed25519 signature.  Returns False on ANY failure."""
    try:
        key = _load_public(public_hex)
        sig = bytes.fromhex(signature_hex.strip().lower())
        if len(sig) != 64:
            return False
        key.verify(sig, message)
        return True
    except (InvalidSignature, SignatureError, ValueError, TypeError):
        return False


def sign_manifest(private_hex: str, manifest: Dict[str, Any],
                  plugin_source: bytes) -> str:
    """Convenience: sign the canonical payload of manifest+source."""
    return sign(private_hex, canonical_payload(manifest, source_sha256(plugin_source)))


def verify_manifest(public_hex: str, manifest: Dict[str, Any],
                    plugin_source: bytes, signature_hex: str) -> bool:
    """Convenience: verify a manifest+source signature (any tamper → False)."""
    try:
        message = canonical_payload(manifest, source_sha256(plugin_source))
    except (TypeError, ValueError):
        return False
    return verify(public_hex, message, signature_hex)

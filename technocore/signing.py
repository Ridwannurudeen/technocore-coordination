from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import unicodedata
from collections.abc import Mapping
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
MAX_TEXT_CHARS = 4096
MAX_VALUE_CHARS = 8192
NONCE_RE = re.compile(r"[0-9]{1,19}\Z")
SEED_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
SIGNATURE_RE = re.compile(r"[A-Za-z0-9_-]{86}\Z")


class SigningError(Exception):
    """A signing input or operation is invalid."""


class SeedError(SigningError):
    """The signing seed is missing, unreadable, or malformed."""


def swept(text: str, limit: int) -> str:
    cleaned = "".join(
        " " if unicodedata.category(char) in INVISIBLE_CATEGORIES else char for char in text
    ).strip()
    if not cleaned:
        raise SigningError("nothing visible would be left after the single-line sweep")
    if len(cleaned) > limit:
        raise SigningError(
            f"{len(cleaned)} characters after the sweep, over the {limit}-character cap"
        )
    return cleaned


def _default_seed_file(
    environ: Mapping[str, str],
    platform: str,
) -> Path:
    if platform == "nt":
        profile = environ.get("USERPROFILE")
        if not profile:
            raise SeedError(
                "SIGN_SEED is not set and USERPROFILE is unavailable, so the "
                "Windows seed file cannot be located"
            )
        return Path(profile) / ".technocore" / "seed"
    config_home = environ.get("XDG_CONFIG_HOME")
    if config_home:
        return Path(config_home) / "technocore" / "seed"
    home = environ.get("HOME")
    if not home:
        raise SeedError(
            "SIGN_SEED is not set and neither XDG_CONFIG_HOME nor HOME is "
            "available, so the seed file cannot be located"
        )
    return Path(home) / ".config" / "technocore" / "seed"


def _parse_seed_file(path: Path, platform: str) -> str:
    try:
        contents = path.read_text(encoding="utf-8")
        mode = path.stat().st_mode
    except OSError as exc:
        raise SeedError(f"could not read seed file {path}") from exc

    if platform != "nt" and mode & 0o077:
        raise SeedError(
            f"seed file {path} is readable by other users; run chmod 600 on it"
        )

    lines = contents.splitlines()
    if len(lines) != 1 or not lines[0].startswith("export SIGN_SEED="):
        raise SeedError(
            f"seed file {path} must contain exactly one 'export SIGN_SEED=<64 hex>' line"
        )

    seed = lines[0].removeprefix("export SIGN_SEED=")
    if not SEED_RE.fullmatch(seed):
        raise SeedError(f"seed file {path} does not contain a 64-hex seed")
    return seed


def load_seed(
    *,
    environ: Mapping[str, str] | None = None,
    seed_file: Path | None = None,
    platform: str | None = None,
) -> bytes:
    source = os.environ if environ is None else environ
    given = source.get("SIGN_SEED")
    if given is not None:
        if not SEED_RE.fullmatch(given):
            raise SeedError("SIGN_SEED must contain exactly 64 hexadecimal characters")
        return bytes.fromhex(given)

    selected_platform = os.name if platform is None else platform
    path = seed_file or _default_seed_file(source, selected_platform)
    return bytes.fromhex(_parse_seed_file(path, selected_platform))


def multibase(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = B58[remainder] + encoded
    return encoded


def did_of(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes_raw()
    encoded = "z" + multibase(MULTICODEC_ED25519 + raw)
    if len(encoded) != 48:
        raise SigningError(f"internal: bad multibase length {len(encoded)}")
    return "did:key:" + encoded


def fingerprint_of(did: str) -> str:
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def validate_nonce(nonce: str) -> None:
    if not NONCE_RE.fullmatch(nonce):
        raise SigningError("nonce must be 1-19 ASCII digits")


def canonical_message(room: str, nonce: str, text: str) -> str:
    validate_nonce(nonce)
    return f"{room}|{nonce}|{swept(text, MAX_TEXT_CHARS)}"


def canonical_note(namespace: str, key: str, nonce: str, value: str) -> str:
    validate_nonce(nonce)
    return f"{namespace}|{key}|{nonce}|{swept(value, MAX_VALUE_CHARS)}"


def signature(key: Ed25519PrivateKey, message: str) -> str:
    encoded = (
        base64.urlsafe_b64encode(key.sign(message.encode("utf-8"))).decode("ascii").rstrip("=")
    )
    if len(encoded) != 86:
        raise SigningError(f"internal: bad signature length {len(encoded)}")
    return encoded


def _public_key_from_did(did: str) -> Ed25519PublicKey:
    prefix = "did:key:z"
    if len(did) != 56 or not did.startswith(prefix):
        raise SigningError("DID is not an Ed25519 did:key")

    number = 0
    for char in did[len(prefix) :]:
        digit = B58.find(char)
        if digit < 0:
            raise SigningError("DID contains invalid base58")
        number = number * 58 + digit

    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    if len(encoded) != 34 or not encoded.startswith(MULTICODEC_ED25519):
        raise SigningError("DID does not contain an Ed25519 public key")
    try:
        return Ed25519PublicKey.from_public_bytes(encoded[2:])
    except ValueError as exc:
        raise SigningError("DID contains an invalid Ed25519 public key") from exc


def verify_message(room: str, message: Mapping[str, object]) -> bool:
    if not isinstance(room, str) or not isinstance(message, Mapping):
        return False

    did = message.get("from")
    nonce = message.get("nonce")
    text = message.get("text")
    encoded_signature = message.get("sig")
    if (
        not isinstance(did, str)
        or isinstance(nonce, bool)
        or not isinstance(nonce, (int, str))
        or not isinstance(text, str)
        or not isinstance(encoded_signature, str)
        or not SIGNATURE_RE.fullmatch(encoded_signature)
    ):
        return False

    try:
        raw_signature = base64.b64decode(
            encoded_signature + "==",
            altchars=b"-_",
            validate=True,
        )
        if len(raw_signature) != 64:
            return False
        public_key = _public_key_from_did(did)
        canonical = canonical_message(room, str(nonce), text).encode("utf-8")
        public_key.verify(raw_signature, canonical)
    except (binascii.Error, InvalidSignature, SigningError, UnicodeError, ValueError):
        return False
    return True


class Identity:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key
        self.did = did_of(key)
        self.fingerprint = fingerprint_of(self.did)

    @classmethod
    def load(
        cls,
        *,
        environ: Mapping[str, str] | None = None,
        seed_file: Path | None = None,
        platform: str | None = None,
    ) -> Identity:
        seed = load_seed(
            environ=environ,
            seed_file=seed_file,
            platform=platform,
        )
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def sign_message(self, room: str, nonce: str, text: str) -> tuple[str, str]:
        cleaned = swept(text, MAX_TEXT_CHARS)
        canonical = canonical_message(room, nonce, cleaned)
        return cleaned, signature(self._key, canonical)

    def sign_note(
        self,
        namespace: str,
        key: str,
        nonce: str,
        value: str,
    ) -> tuple[str, str]:
        cleaned = swept(value, MAX_VALUE_CHARS)
        canonical = canonical_note(namespace, key, nonce, cleaned)
        return cleaned, signature(self._key, canonical)

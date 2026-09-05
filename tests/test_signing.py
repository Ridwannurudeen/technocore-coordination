import os
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore import signing
from technocore.signing import (
    Identity,
    SeedError,
    SigningError,
    canonical_message,
    canonical_note,
    did_of,
    load_seed,
    signature,
    swept,
)

RFC8032_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
EXPECTED_DID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
EXPECTED_FINGERPRINT = "0658808e85cc8317"


def signed_message(
    room="lobby",
    nonce=1700000000000,
    text="ready",
):
    key = Ed25519PrivateKey.generate()
    message = {
        "from": did_of(key),
        "nonce": nonce,
        "text": text,
        "sig": signature(key, canonical_message(room, str(nonce), text)),
    }
    return key, message


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "\u202ealpha\u200dbeta\u2028gamma\u2029delta\x00🙂",
            "alpha beta gamma delta 🙂",
        ),
        # PDI and ZWSP are both category Cf, so each becomes its own space.
        ("\u2066left\u2069\u200bright\u200c", "left  right"),
        ("\tline\r\nbreak", "line  break"),
        ("  visible text  ", "visible text"),
    ],
)
def test_sweep_matches_upstream_vectors(source, expected):
    assert swept(source, 4096) == expected


def test_canonical_strings_match_upstream_vectors():
    text = "\u202ealpha\u200dbeta\u2028gamma\u2029delta\x00🙂"

    assert (
        canonical_message("lobby", "1700000000000", text)
        == "lobby|1700000000000|alpha beta gamma delta 🙂"
    )
    assert (
        canonical_note("room-owners", "build-42", "1700000000001", text)
        == "room-owners|build-42|1700000000001|alpha beta gamma delta 🙂"
    )


def test_sweep_rejects_empty_and_over_cap_values():
    with pytest.raises(SigningError):
        swept("\u202e\u200d\x00", 4096)

    with pytest.raises(SigningError, match="over the 4-character cap"):
        swept("abcde", 4)


def test_did_fingerprint_and_signature_shape():
    identity = Identity(Ed25519PrivateKey.from_private_bytes(RFC8032_SEED))

    assert identity.did == EXPECTED_DID
    assert identity.fingerprint == EXPECTED_FINGERPRINT
    assert re.fullmatch(r"[0-9a-f]{16}", identity.fingerprint)

    cleaned, encoded_signature = identity.sign_message(
        "lobby",
        "1700000000000",
        "ready",
    )

    assert cleaned == "ready"
    assert len(encoded_signature) == 86
    assert re.fullmatch(r"[A-Za-z0-9_-]{86}", encoded_signature)
    assert "=" not in encoded_signature


def test_correctly_signed_message_verifies():
    _, message = signed_message()

    assert signing.verify_message("lobby", message)


def test_changed_message_text_does_not_verify():
    _, message = signed_message(text="ready")
    message["text"] = "reads"

    assert not signing.verify_message("lobby", message)


def test_signature_from_a_different_key_does_not_verify():
    _, message = signed_message()
    other_key = Ed25519PrivateKey.generate()
    message["sig"] = signature(
        other_key,
        canonical_message("lobby", str(message["nonce"]), message["text"]),
    )

    assert not signing.verify_message("lobby", message)


@pytest.mark.parametrize(
    "bad_signature",
    [None, "", "a" * 85, "!" * 86],
    ids=["missing", "empty", "wrong-length", "non-base64url"],
)
def test_malformed_signatures_do_not_verify_or_raise(bad_signature):
    _, message = signed_message()
    if bad_signature is None:
        del message["sig"]
    else:
        message["sig"] = bad_signature

    assert not signing.verify_message("lobby", message)


def test_undecodable_sender_did_does_not_verify_or_raise():
    _, message = signed_message()
    message["from"] = "did:key:znot-a-valid-ed25519-key"

    assert not signing.verify_message("lobby", message)


def test_verification_resweeps_the_stored_text_idempotently():
    room = "lobby"
    nonce = 1700000000000
    raw_text = "\u202eready\nnow\u200d"
    stored_text = swept(raw_text, 4096)
    key = Ed25519PrivateKey.generate()
    message = {
        "from": did_of(key),
        "nonce": nonce,
        "text": stored_text,
        "sig": signature(key, canonical_message(room, str(nonce), raw_text)),
    }

    assert swept(stored_text, 4096) == stored_text
    assert signing.verify_message(room, message)


def test_group_readable_seed_file_is_refused(tmp_path):
    seed_file = tmp_path / "seed"
    seed_file.write_text(
        f"export SIGN_SEED={RFC8032_SEED.hex()}\n",
        encoding="utf-8",
    )
    seed_file.chmod(0o644)

    with pytest.raises(SeedError, match="readable by other users"):
        load_seed(environ={}, seed_file=seed_file, platform="posix")


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions only")
def test_owner_only_seed_file_is_accepted(tmp_path):
    seed_file = tmp_path / "seed"
    seed_file.write_text(
        f"export SIGN_SEED={RFC8032_SEED.hex()}\n",
        encoding="utf-8",
    )
    seed_file.chmod(0o600)

    assert load_seed(environ={}, seed_file=seed_file) == RFC8032_SEED

import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore.signing import (
    Identity,
    SigningError,
    canonical_message,
    canonical_note,
    swept,
)

RFC8032_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
EXPECTED_DID = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw"
EXPECTED_FINGERPRINT = "0658808e85cc8317"


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

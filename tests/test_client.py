import io
import json
import logging
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore import client as client_module
from technocore.client import (
    MAX_SAFE_MILLISECOND_NONCE,
    Client,
    ConflictError,
    NetworkError,
    NonceResolutionError,
    ValidationError,
    validate_name,
)
from technocore.signing import Identity, SeedError

SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"


class StubClient(Client):
    def __init__(self, cache_path: Path, room_payload=None):
        super().__init__(
            "https://example.invalid",
            nonce_cache_path=cache_path,
        )
        self.room_payload = [] if room_payload is None else room_payload
        self.requests = []
        self.room_reads = []

    def read_room_json(self, room, **kwargs):
        self.room_reads.append((room, kwargs))
        if isinstance(self.room_payload, Exception):
            raise self.room_payload
        return self.room_payload

    def _request(self, path, *, query=None, json_body=None):
        self.requests.append((path, query, json_body))
        return "ok"


class FakeResponse:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.body


def identity():
    return Identity(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX)))


def posted_nonce(client):
    path, _, _ = client.requests[-1]
    parts = path.split("/")
    return int(parts[-2])


def test_remote_floor_beats_stale_local_cache_and_uses_fresh_max_window(
    tmp_path,
    monkeypatch,
):
    signer = identity()
    cache_path = tmp_path / "nonces.json"
    cache_path.write_text(
        json.dumps({f"{signer.did}|room:lobby": 1000}),
        encoding="utf-8",
    )
    client = StubClient(
        cache_path,
        [{"from": signer.did, "nonce": "5000"}],
    )
    monkeypatch.setattr(client_module.time, "time", lambda: 1.0)
    monkeypatch.setattr(client_module.time, "time_ns", lambda: 123456789)

    assert client.say_signed("lobby", "ready", signer) == "ok"
    assert posted_nonce(client) == 5001
    assert client.room_reads == [("lobby", {"limit": 200, "poll_counter": 123456789})]


def test_local_cache_beats_backward_clock(tmp_path, monkeypatch):
    signer = identity()
    cache_path = tmp_path / "nonces.json"
    cache_path.write_text(
        json.dumps({f"{signer.did}|room:lobby": 8000}),
        encoding="utf-8",
    )
    client = StubClient(cache_path)
    monkeypatch.setattr(client_module.time, "time", lambda: 2.0)

    client.say_signed("lobby", "ready", signer)

    assert posted_nonce(client) == 8001


def test_nonce_above_safe_millisecond_range_is_refused(tmp_path):
    signer = identity()
    client = StubClient(
        tmp_path / "nonces.json",
        [
            {
                "from": signer.did,
                "nonce": str(MAX_SAFE_MILLISECOND_NONCE + 1),
            }
        ],
    )

    with pytest.raises(
        NonceResolutionError,
        match="above the safe millisecond range",
    ):
        client.say_signed("lobby", "ready", signer)

    assert client.requests == []


def test_unreadable_room_refuses_write(tmp_path):
    client = StubClient(
        tmp_path / "nonces.json",
        NetworkError("offline"),
    )

    with pytest.raises(
        NonceResolutionError,
        match="could not read the room",
    ):
        client.say_signed("lobby", "ready", identity())

    assert client.requests == []


@pytest.mark.parametrize(
    "value",
    [
        "",
        "-room",
        "_room",
        "Uppercase",
        "has.dot",
        "has space",
        "a" * 49,
        "é",
    ],
)
def test_invalid_names_are_rejected(value):
    with pytest.raises(ValidationError):
        validate_name("room", value)


@pytest.mark.parametrize(
    "value",
    [
        "a",
        "room-1",
        "room_name",
        "0",
        "a" * 48,
    ],
)
def test_valid_names_are_accepted(value):
    validate_name("room", value)


def test_size_caps_are_enforced_before_http(tmp_path):
    client = StubClient(tmp_path / "nonces.json")

    with pytest.raises(ValidationError, match="4096-character cap"):
        client.say_signed("lobby", "x" * 4097, identity())

    with pytest.raises(ValidationError, match="8192-character cap"):
        client.note_set("status", "worker", "x" * 8193)

    assert client.requests == []


def test_wait_requires_since(tmp_path):
    client = StubClient(tmp_path / "nonces.json")

    with pytest.raises(
        ValidationError,
        match="wait may only be used together with since",
    ):
        client.read_room("lobby", wait=10)


def test_conflict_surfaces_current_value(tmp_path, monkeypatch):
    error = urllib.error.HTTPError(
        "https://example.invalid/kv/status/worker/set/new",
        409,
        "Conflict",
        {},
        io.BytesIO(b"current-worker"),
    )

    def raise_conflict(request):
        raise error

    monkeypatch.setattr(client_module.urllib.request, "urlopen", raise_conflict)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    with pytest.raises(ConflictError) as raised:
        client.note_set(
            "status",
            "worker",
            "new-worker",
            expected="old-worker",
        )

    assert raised.value.current_value == "current-worker"


def test_if_absent_uses_cas_query(tmp_path):
    client = StubClient(tmp_path / "nonces.json")

    assert (
        client.note_set(
            "status",
            "worker",
            "worker-7",
            if_absent=True,
        )
        == "ok"
    )

    path, query, body = client.requests[-1]
    assert path == "/kv/status/worker/set/worker-7"
    assert query == {"if_absent": "1"}
    assert body is None


def test_rate_limit_seconds_are_parsed_from_body(tmp_path, monkeypatch):
    calls = 0
    sleeps = []

    def urlopen(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "Too Many Requests",
                {"Retry-After": "99"},
                io.BytesIO(b"rate limited; retry after 1.25 seconds"),
            )
        return FakeResponse(b"ok")

    monkeypatch.setattr(client_module.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(client_module.time, "sleep", sleeps.append)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    assert client.note_get("status", "worker") == "ok"
    assert sleeps == [1.25]
    assert calls == 2


def test_seed_never_appears_in_exceptions_logs_or_urls(
    tmp_path,
    monkeypatch,
    caplog,
):
    signer = identity()
    client = StubClient(tmp_path / "nonces.json")
    caplog.set_level(logging.DEBUG)

    client.say_signed("lobby", "ready", signer)

    urls = []
    for path, query, _ in client.requests:
        url = client.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        urls.append(url)

    invalid_seed = SEED_HEX[:-1] + "g"
    with pytest.raises(SeedError) as raised:
        Identity.load(environ={"SIGN_SEED": invalid_seed})

    assert SEED_HEX not in str(raised.value)
    assert invalid_seed not in str(raised.value)
    assert all(SEED_HEX not in url for url in urls)
    assert all(invalid_seed not in url for url in urls)
    assert SEED_HEX not in caplog.text
    assert invalid_seed not in caplog.text


def test_cjk_output_survives_a_cp1252_console(tmp_path, monkeypatch, capsys):
    """A Windows console defaults to cp1252; CJK room text must not kill the command."""
    import sys

    from technocore import cli

    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252", errors="strict"))
    cli._force_utf8_output()
    cli._print_untrusted_text("中文房间 — 한국어 テスト")
    sys.stdout.flush()
    assert "中文房间".encode("utf-8") in raw.getvalue()


def test_room_owners_if_absent_write_uses_signed_path(tmp_path):
    client = Client(nonce_cache_path=tmp_path / "nonces.json")
    identity = object()

    with patch.object(
        client,
        "_signed_note_set",
        return_value="claimed",
    ) as signed_note_set:
        result = client.note_set(
            "room-owners",
            "d-test-room",
            "did:key:test",
            if_absent=True,
            identity=identity,
        )

    assert result == "claimed"
    signed_note_set.assert_called_once_with(
        "room-owners",
        "d-test-room",
        "did:key:test",
        expected=None,
        if_absent=True,
        identity=identity,
    )


def test_room_owners_if_absent_write_requires_identity(tmp_path):
    client = Client(nonce_cache_path=tmp_path / "nonces.json")

    with patch.object(client, "_request") as request:
        with pytest.raises(
            ValidationError,
            match="room-owners writes require the signing identity",
        ):
            client.note_set(
                "room-owners",
                "d-test-room",
                "did:key:test",
                if_absent=True,
            )

    request.assert_not_called()

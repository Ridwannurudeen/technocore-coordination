import http.client
import http.server
import io
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore import cli
from technocore import client as client_module
from technocore.client import (
    MAX_SAFE_MILLISECOND_NONCE,
    Client,
    ConflictError,
    HTTPStatusError,
    NetworkError,
    NonceResolutionError,
    ProtocolError,
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

    def _request(self, path, *, query=None, json_body=None, timeout=None):
        self.requests.append((path, query, json_body))
        return "ok"


class FakeResponse:
    def __init__(self, body: bytes, length=0):
        self.body = body
        self.length = length

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]


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

    def raise_conflict(request, timeout):
        raise error

    monkeypatch.setattr(client_module, "_open", raise_conflict)
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


def test_rate_limit_prefers_the_retry_after_header(tmp_path, monkeypatch):
    calls = 0
    sleeps = []

    def fake_open(request, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "Too Many Requests",
                {"Retry-After": "1.25"},
                io.BytesIO(b"rate limited; retry after 99 seconds"),
            )
        return FakeResponse(b"ok")

    monkeypatch.setattr(client_module, "_open", fake_open)
    monkeypatch.setattr(client_module.time, "sleep", sleeps.append)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    assert client.note_get("status", "worker") == "ok"
    assert sleeps == [1.25]
    assert calls == 2


def test_rate_limit_body_seconds_are_capped(tmp_path, monkeypatch):
    calls = 0
    sleeps = []

    def fake_open(request, timeout):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise urllib.error.HTTPError(
                request.full_url,
                429,
                "Too Many Requests",
                {},
                io.BytesIO(b"rate limited; retry after 100000 seconds"),
            )
        return FakeResponse(b"ok")

    monkeypatch.setattr(client_module, "_open", fake_open)
    monkeypatch.setattr(client_module.time, "sleep", sleeps.append)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    assert client.note_get("status", "worker") == "ok"
    assert sleeps == [60.0]


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


def test_long_poll_timeout_covers_the_wait_window(tmp_path, monkeypatch):
    timeouts = []

    def fake_open(request, timeout):
        timeouts.append(timeout)
        return FakeResponse(b"ok")

    monkeypatch.setattr(client_module, "_open", fake_open)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    client.read_room("lobby", since=0, wait=10)
    client.note_get("status", "worker")

    assert timeouts == [40.0, 30.0]


def test_socket_timeout_becomes_a_network_error(tmp_path, monkeypatch):
    def fake_open(request, timeout):
        raise TimeoutError("timed out")

    monkeypatch.setattr(client_module, "_open", fake_open)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    with pytest.raises(NetworkError, match="TimeoutError"):
        client.note_get("status", "worker")


def test_total_deadline_stops_a_trickling_response(tmp_path):
    body = b"0123456789"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                for byte in body:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.05)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, format, *args):
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = Client(
            f"http://127.0.0.1:{server.server_port}",
            nonce_cache_path=tmp_path / "nonces.json",
        )
        started = time.monotonic()
        with pytest.raises(NetworkError, match="TimeoutError"):
            client._request("/trickle", timeout=0.2)
        assert time.monotonic() - started < 0.4
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_deeply_nested_json_becomes_a_protocol_error(tmp_path, monkeypatch):
    body = ("[" * 100_000 + "0" + "]" * 100_000).encode("ascii")

    def fake_open(request, timeout):
        return FakeResponse(body)

    monkeypatch.setattr(client_module, "_open", fake_open)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    with pytest.raises(ProtocolError, match="not valid JSON"):
        client.read_room_json("lobby")


def test_redirects_are_not_followed_by_the_real_opener(tmp_path):
    requested = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requested.append(self.path)
            if self.path == "/kv/status/worker":
                self.send_response(302)
                self.send_header("Location", "/kv/status/worker/followed")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"followed"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = Client(
            f"http://127.0.0.1:{server.server_port}",
            nonce_cache_path=tmp_path / "nonces.json",
        )
        with pytest.raises(HTTPStatusError) as raised:
            client.note_get("status", "worker")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert raised.value.status == 302
    assert requested == ["/kv/status/worker"]


def test_unsigned_messages_without_a_nonce_do_not_block_the_floor(tmp_path):
    signer = identity()
    client = StubClient(tmp_path / "nonces.json")

    highest = client._highest_room_nonce(
        [
            {"from": signer.did, "text": "posted through the nick route"},
            {"from": signer.did, "nonce": 5},
        ],
        signer.did,
    )

    assert highest == 5


def test_oversized_response_is_refused(tmp_path, monkeypatch):
    def fake_open(request, timeout):
        return FakeResponse(b"x" * (client_module.MAX_RESPONSE_BYTES + 1))

    monkeypatch.setattr(client_module, "_open", fake_open)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    with pytest.raises(ProtocolError, match="8 MiB cap"):
        client.note_get("status", "worker")


def test_long_signed_note_falls_back_to_a_post(tmp_path, monkeypatch):
    signer = identity()
    requests = []

    def fake_open(request, timeout):
        requests.append(request)
        return FakeResponse(b"0" if len(requests) == 1 else b"ok")

    monkeypatch.setattr(client_module, "_open", fake_open)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )
    value = "\u754c" * 8192

    assert (
        client.note_set(
            "room-owners",
            "d-test-room",
            value,
            identity=signer,
        )
        == "ok"
    )

    written = requests[-1]
    path = urllib.parse.urlparse(written.full_url).path
    assert written.get_method() == "POST"
    assert path == "/kv/room-owners/d-test-room"
    assert "/set-signed/" not in path

    body = json.loads(written.data.decode("utf-8"))
    assert body["did"] == signer.did
    assert len(body["sig"]) == 86
    assert body["nonce"].isdigit()
    assert body["value"] == value


def test_expected_value_is_swept_like_the_stored_value(tmp_path):
    client = StubClient(tmp_path / "nonces.json")

    client.note_set("status", "worker", "reviewed", expected="a\nb")

    _, query, _ = client.requests[-1]
    assert query == {"if": "a b"}


def test_caller_oserror_is_not_relabelled_as_a_lock_failure(tmp_path):
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    with pytest.raises(OSError) as raised:
        with client._nonce_lock():
            raise OSError(28, "No space left on device")

    assert raised.value.errno == 28


def test_nonce_is_stored_even_when_the_response_is_lost(tmp_path):
    signer = identity()
    cache_path = tmp_path / "nonces.json"
    client = StubClient(cache_path)

    with patch.object(
        client,
        "_request",
        side_effect=HTTPStatusError(500, "boom"),
    ):
        with pytest.raises(HTTPStatusError):
            client.say_signed("lobby", "ready", signer)

    cache = json.loads(cache_path.read_text(encoding="utf-8"))
    assert cache[f"{signer.did}|room:lobby"] > 0


def test_malformed_nonce_cache_names_the_file(tmp_path):
    cache_path = tmp_path / "nonces.json"
    cache_path.write_text("{", encoding="utf-8")
    client = Client(
        "https://example.invalid",
        nonce_cache_path=cache_path,
    )

    with pytest.raises(NonceResolutionError) as raised:
        client._load_nonce("did:key:test", "room:lobby")

    assert str(cache_path) in str(raised.value)


def test_terminal_escapes_cannot_erase_the_untrusted_label(capsys):
    cli._print_untrusted_text("\x1b[2K\x1b[1Gspoofed")

    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert out.startswith("UNTRUSTED\t")
    assert "spoofed" in out


def test_http_error_controls_are_escaped_on_stderr(monkeypatch, capsys):
    body = "\x1b[2K\x9b2Kspoofed".encode("utf-8")

    def fake_open(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url,
            500,
            "Internal Server Error",
            {},
            io.BytesIO(body),
        )

    monkeypatch.setattr(client_module, "_open", fake_open)
    monkeypatch.setenv("TECHNOCORE_BASE_URL", "https://example.invalid")

    assert cli.main(["note", "get", "status", "worker"]) == 7

    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert "\x9b" not in err
    assert "[UNTRUSTED service data]" in err
    assert "\\u001b[2K\\u009b2Kspoofed" in err


def test_claim_on_room_owners_signs_and_prints_the_response(capsys):
    signer = object()

    with patch.object(cli.Identity, "load", return_value=signer):
        with patch.object(cli.Client, "note_set", return_value="ok") as note_set:
            assert cli.main(["claim", "room-owners", "d-x", "worker-2"]) == 0

    note_set.assert_called_once_with(
        "room-owners",
        "d-x",
        "worker-2",
        if_absent=True,
        identity=signer,
    )
    assert "UNTRUSTED\tok" in capsys.readouterr().out


def test_idle_watch_poll_sleeps(monkeypatch):
    class Stop(Exception):
        pass

    class IdleClient:
        def __init__(self):
            self.polls = 0

        def read_room_json(self, room, **kwargs):
            self.polls += 1
            if self.polls == 1:
                return {"messages": []}
            raise Stop

    sleeps = []
    monkeypatch.setattr(cli.time, "sleep", sleeps.append)

    with pytest.raises(Stop):
        cli._watch(IdleClient(), "lobby", None)

    assert sleeps == [1.0]


def test_base_url_is_overridable_for_testing(monkeypatch):
    monkeypatch.setenv("TECHNOCORE_BASE_URL", "http://127.0.0.1:8931")

    with patch.object(cli, "Client") as client_class:
        client_class.return_value.read_room.return_value = ""
        assert cli.main(["read", "lobby"]) == 0

    client_class.assert_called_once_with(base_url="http://127.0.0.1:8931")


def test_keyboard_interrupt_exits_130():
    with patch.object(cli, "_run", side_effect=KeyboardInterrupt):
        assert cli.main(["read", "lobby"]) == 130


def test_truncated_response_is_refused(tmp_path, monkeypatch):
    def fake_open(request, timeout):
        return FakeResponse(b"partial", length=12)

    monkeypatch.setattr(client_module, "_open", fake_open)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    with pytest.raises(ProtocolError, match="truncated"):
        client.note_get("status", "worker")


def test_incomplete_read_becomes_a_protocol_error(tmp_path, monkeypatch):
    def fake_open(request, timeout):
        raise http.client.IncompleteRead(b"partial", 12)

    monkeypatch.setattr(client_module, "_open", fake_open)
    client = Client(
        "https://example.invalid",
        nonce_cache_path=tmp_path / "nonces.json",
    )

    with pytest.raises(ProtocolError, match="IncompleteRead"):
        client.note_get("status", "worker")


def test_unpersistable_nonce_cache_names_the_file(tmp_path, monkeypatch):
    def replace(source, target):
        raise OSError("read-only file system")

    cache_path = tmp_path / "nonces.json"
    client = Client(
        "https://example.invalid",
        nonce_cache_path=cache_path,
    )
    monkeypatch.setattr(client_module.os, "replace", replace)

    with pytest.raises(NonceResolutionError) as raised:
        client._store_nonce("did:key:test", "room:lobby", 1)

    assert str(cache_path) in str(raised.value)


def test_terminal_escapes_are_escaped_in_untrusted_json(capsys):
    text = "\x9b2K\u2028spoofed"

    cli._print_untrusted_json({"text": text})

    out = capsys.readouterr().out
    assert "\x9b" not in out
    assert "\u2028" not in out
    assert json.loads(out)["data"]["text"] == text

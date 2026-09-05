import http.server
import json
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from technocore import cli
from technocore.signing import canonical_message, did_of, signature


ROOM = "lobby"


def _signed_message(
    claimed_key: Ed25519PrivateKey,
    signing_key: Ed25519PrivateKey,
    *,
    seq: int,
    text: str,
) -> dict[str, object]:
    nonce = 1_700_000_000_000 + seq
    return {
        "from": did_of(claimed_key),
        "nonce": nonce,
        "seq": seq,
        "sig": signature(
            signing_key,
            canonical_message(ROOM, str(nonce), text),
        ),
        "text": text,
        "ts": "2026-09-05T12:00:00Z",
    }


@pytest.fixture
def signed_room_server():
    genuine_key = Ed25519PrivateKey.generate()
    different_key = Ed25519PrivateKey.generate()

    genuine = _signed_message(
        genuine_key,
        genuine_key,
        seq=1,
        text="genuine",
    )
    tampered = _signed_message(
        genuine_key,
        genuine_key,
        seq=2,
        text="original",
    )
    tampered["text"] = "tampered"
    wrong_key = _signed_message(
        genuine_key,
        different_key,
        seq=3,
        text="wrong key",
    )
    unsigned = {
        "from": "anonymous",
        "nonce": 1_700_000_000_004,
        "seq": 4,
        "text": "unsigned",
        "ts": "2026-09-05T12:00:00Z",
    }
    messages = [genuine, tampered, wrong_key, unsigned]
    response_body = json.dumps(messages).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, format, *args):
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", messages
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_read_text_labels_real_signature_results(
    signed_room_server,
    monkeypatch,
    capsys,
):
    base_url, messages = signed_room_server
    monkeypatch.setenv("TECHNOCORE_BASE_URL", base_url)

    assert cli.main(["read", ROOM, "--limit", "4"]) == 0

    lines = capsys.readouterr().out.splitlines()
    markers = ["ok", "BAD-SIG", "BAD-SIG", "no-sig"]
    assert len(lines) == len(messages)
    for line, marker, message in zip(lines, markers, messages, strict=True):
        prefix = f"UNTRUSTED\t[{marker}]\t"
        assert line.startswith(prefix)
        assert json.loads(line.removeprefix(prefix)) == message


def test_read_json_adds_real_signature_verdicts(
    signed_room_server,
    monkeypatch,
    capsys,
):
    base_url, messages = signed_room_server
    monkeypatch.setenv("TECHNOCORE_BASE_URL", base_url)

    assert cli.main(["read", ROOM, "--limit", "4", "--json"]) == 0

    output = json.loads(capsys.readouterr().out)
    rendered = output["data"]
    assert output["untrusted"] is True
    assert [message["text"] for message in rendered] == [
        message["text"] for message in messages
    ]
    assert [message["verified"] for message in rendered] == [
        True,
        False,
        False,
        None,
    ]


def test_watch_adds_real_signature_verdicts(signed_room_server, capsys):
    _, messages = signed_room_server

    class StopWatch(Exception):
        pass

    class OnePollClient:
        def __init__(self):
            self.polls = 0

        def read_room_json(self, room, **kwargs):
            self.polls += 1
            if self.polls == 1:
                return messages
            raise StopWatch

    with pytest.raises(StopWatch):
        cli._watch(OnePollClient(), ROOM, None)

    output = [json.loads(line)["data"] for line in capsys.readouterr().out.splitlines()]
    assert [message["text"] for message in output] == [
        message["text"] for message in messages
    ]
    assert [message["verified"] for message in output] == [
        True,
        False,
        False,
        None,
    ]


def test_read_json_help_documents_verification_convention(capsys):
    with pytest.raises(SystemExit) as raised:
        cli.main(["read", "--help"])

    assert raised.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert (
        "verified is true for valid signatures, false for failed signatures, "
        "and null when sig is absent"
    ) in help_text

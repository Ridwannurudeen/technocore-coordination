from __future__ import annotations

import argparse
import json
import os
import sys
import time
import unicodedata
from typing import Any, Sequence

from .client import (
    DEFAULT_BASE_URL,
    SIGNED_NOTE_NAMESPACES,
    Client,
    ClientError,
    ConflictError,
    HTTPStatusError,
    NetworkError,
    NonceResolutionError,
    ProtocolError,
    RateLimitError,
    ValidationError,
    room_messages,
)
from .signing import (
    INVISIBLE_CATEGORIES,
    Identity,
    SeedError,
    SigningError,
    verify_message,
)

WATCH_IDLE_SECONDS = 1.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tc",
        description="Signed-lane coordination CLI for Technocore",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser(
        "whoami",
        help="print the DID and fingerprint derived from the signing seed",
    )

    read = commands.add_parser(
        "read",
        help="read a room",
        description=(
            "Text verdict markers: [ok] is a valid signature, [BAD-SIG] is a "
            "failed signature, and [no-sig] means the signature is absent."
        ),
    )
    read.add_argument("room")
    read.add_argument("--since", type=int)
    read.add_argument("--wait", type=int)
    read.add_argument("--limit", type=int)
    read.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help=(
            "verified is true for valid signatures, false for failed signatures, "
            "and null when sig is absent"
        ),
    )

    say = commands.add_parser("say", help="post a signed room message")
    say.add_argument("room")
    say.add_argument("text")

    watch = commands.add_parser("watch", help="long-poll a room")
    watch.add_argument("room")
    watch.add_argument("--since", type=int)

    note = commands.add_parser("note", help="read or write a note")
    note_commands = note.add_subparsers(dest="note_command", required=True)

    note_get = note_commands.add_parser("get", help="read a note")
    note_get.add_argument("namespace")
    note_get.add_argument("key")

    note_set = note_commands.add_parser("set", help="write a note")
    note_set.add_argument("namespace")
    note_set.add_argument("key")
    note_set.add_argument("value")
    condition = note_set.add_mutually_exclusive_group()
    condition.add_argument("--if", dest="expected")
    condition.add_argument("--if-absent", action="store_true")

    claim = commands.add_parser(
        "claim",
        help="order a CAS claim; this does not fence ownership",
    )
    claim.add_argument("namespace")
    claim.add_argument("key")
    claim.add_argument("worker_id")

    return parser


def _print_untrusted_text(value: str) -> None:
    if not value:
        return
    lines = value.splitlines()
    if not lines:
        print("UNTRUSTED\t")
        return
    for line in lines:
        visible = "".join(
            " " if unicodedata.category(char) in INVISIBLE_CATEGORIES else char
            for char in line
        )
        print(f"UNTRUSTED\t{visible}")


def _terminal_safe_json(value: Any) -> str:
    dumped = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return "".join(
        json.dumps(char, ensure_ascii=True)[1:-1]
        if unicodedata.category(char) in INVISIBLE_CATEGORIES
        else char
        for char in dumped
    )


def _print_untrusted_json(value: Any) -> None:
    print(_terminal_safe_json({"untrusted": True, "data": value}))


def _verification_verdict(room: str, message: dict[str, Any]) -> bool | None:
    if "sig" not in message:
        return None
    return verify_message(room, message)


def _verified_message(room: str, message: dict[str, Any]) -> dict[str, Any]:
    rendered = dict(message)
    rendered["verified"] = _verification_verdict(room, message)
    return rendered


def _verified_payload(room: str, payload: Any) -> Any:
    messages = [
        _verified_message(room, message) for message in room_messages(payload)
    ]
    if isinstance(payload, list):
        return messages
    rendered = dict(payload)
    rendered["messages"] = messages
    return rendered


def _short_did(value: Any) -> str:
    did = str(value).removeprefix("did:key:")
    if len(did) <= 9:
        return did
    return f"{did[:4]}…{did[-4:]}"


def _terminal_safe_room_line(message: dict[str, Any]) -> str:
    rendered = (
        f"[{message.get('seq')}] {message.get('ts')} "
        f"<{_short_did(message.get('from', ''))}> {message.get('text', '')}"
    )
    return "".join(
        " " if unicodedata.category(char) in INVISIBLE_CATEGORIES else char
        for char in rendered
    )


def _print_room_text(room: str, payload: Any) -> None:
    markers = {True: "ok", False: "BAD-SIG", None: "no-sig"}
    for message in room_messages(payload):
        verdict = _verification_verdict(room, message)
        print(f"UNTRUSTED\t[{markers[verdict]}]\t{_terminal_safe_room_line(message)}")


def _identity_for_note(namespace: str) -> Identity | None:
    if namespace in SIGNED_NOTE_NAMESPACES:
        return Identity.load()
    return None


def _watch(client: Client, room: str, since: int | None) -> int:
    cursor = 0 if since is None else since
    poll_counter = 0

    while True:
        payload = client.read_room_json(
            room,
            since=cursor,
            wait=10,
            limit=200,
            poll_counter=poll_counter,
        )
        messages = room_messages(payload)
        if not messages:
            poll_counter += 1
            time.sleep(WATCH_IDLE_SECONDS)
            continue

        next_cursor = cursor
        for message in messages:
            sequence = message.get("seq")
            if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
                raise ProtocolError("room JSON contains a message with a malformed seq")
            _print_untrusted_json(_verified_message(room, message))
            next_cursor = max(next_cursor, sequence)

        if next_cursor == cursor:
            raise ProtocolError("room JSON did not advance the watch cursor")
        cursor = next_cursor
        poll_counter = 0


def _run(args: argparse.Namespace) -> int:
    if args.command == "whoami":
        identity = Identity.load()
        print(f"did: {identity.did}")
        print(f"fingerprint: {identity.fingerprint}")
        return 0

    client = Client(base_url=os.environ.get("TECHNOCORE_BASE_URL", DEFAULT_BASE_URL))

    if args.command == "read":
        payload = client.read_room_json(
            args.room,
            since=args.since,
            wait=args.wait,
            limit=args.limit,
        )
        if args.as_json:
            _print_untrusted_json(_verified_payload(args.room, payload))
        else:
            _print_room_text(args.room, payload)
        return 0

    if args.command == "say":
        response = client.say_signed(
            args.room,
            args.text,
            Identity.load(),
        )
        _print_untrusted_text(response)
        return 0

    if args.command == "watch":
        return _watch(client, args.room, args.since)

    if args.command == "note":
        if args.note_command == "get":
            value = client.note_get(args.namespace, args.key)
            _print_untrusted_text(value)
            return 0

        identity = _identity_for_note(args.namespace)
        response = client.note_set(
            args.namespace,
            args.key,
            args.value,
            expected=args.expected,
            if_absent=args.if_absent,
            identity=identity,
        )
        _print_untrusted_text(response)
        return 0

    if args.command == "claim":
        identity = _identity_for_note(args.namespace)
        response = client.claim(
            args.namespace,
            args.key,
            args.worker_id,
            identity=identity,
        )
        _print_untrusted_text(response)
        print(
            f"claimed {args.namespace}/{args.key} as {args.worker_id}; "
            "claim ordering does not fence ownership"
        )
        return 0

    raise RuntimeError(f"unhandled command {args.command!r}")


def _exit_code(exc: Exception) -> int:
    if isinstance(exc, (SeedError, SigningError, ValidationError)):
        return 2
    if isinstance(exc, NetworkError):
        return 3
    if isinstance(exc, NonceResolutionError):
        return 4
    if isinstance(exc, ConflictError):
        return 5
    if isinstance(exc, RateLimitError):
        return 6
    if isinstance(exc, HTTPStatusError):
        return 7
    if isinstance(exc, ProtocolError):
        return 8
    return 1


def _force_utf8_output() -> None:
    # Rooms carry Chinese, Korean and Japanese text, and a Windows console defaults to
    # cp1252 — printing a CJK line there raises UnicodeEncodeError and kills the command.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


def main(argv: Sequence[str] | None = None) -> int:
    _force_utf8_output()
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except KeyboardInterrupt:
        return 130
    except (ClientError, SigningError) as exc:
        print(f"tc: error: {exc}", file=sys.stderr)
        return _exit_code(exc)


if __name__ == "__main__":
    raise SystemExit(main())

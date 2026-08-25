from __future__ import annotations

import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .signing import (
    MAX_TEXT_CHARS,
    MAX_VALUE_CHARS,
    Identity,
    SigningError,
    swept,
)

DEFAULT_BASE_URL = "https://technocore.chat"
NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}\Z")
ASCII_NONCE_RE = re.compile(r"[0-9]{1,19}\Z")
MAX_SAFE_MILLISECOND_NONCE = 9_999_999_999_999
SIGNED_NOTE_NAMESPACES = frozenset({"room-owners", "room-allow"})
MAX_GET_URL_LENGTH = 16_000


class ClientError(Exception):
    """Base class for Technocore client failures."""


class ValidationError(ClientError):
    """Local input validation failed."""


class NetworkError(ClientError):
    """The service could not be reached."""


class ProtocolError(ClientError):
    """The service returned a malformed or unexpected response."""


class NonceResolutionError(ClientError):
    """A safe nonce floor could not be established."""


def _untrusted_body(body: str) -> str:
    return "[UNTRUSTED service data] " + json.dumps(body, ensure_ascii=False)


class HTTPStatusError(ClientError):
    def __init__(self, status: int, body: str) -> None:
        self.status = status
        self.body = body
        super().__init__(status, body)

    def __str__(self) -> str:
        if self.body:
            return f"HTTP {self.status}: {_untrusted_body(self.body)}"
        return f"HTTP {self.status}"


class ConflictError(HTTPStatusError):
    """A conditional note write lost its race."""

    @property
    def current_value(self) -> str:
        return self.body


class RateLimitError(HTTPStatusError):
    """The service rate limit could not be satisfied safely."""

    def __init__(
        self,
        body: str,
        retry_after: float | None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(429, body)

    def __str__(self) -> str:
        detail = super().__str__()
        if self.retry_after is None:
            return detail
        return f"{detail} (retry after {self.retry_after:g} seconds)"


def validate_name(kind: str, value: str) -> None:
    if not NAME_RE.fullmatch(value):
        raise ValidationError(
            f"{kind} must match ^[a-z0-9][a-z0-9_-]{{0,47}}$"
        )


def _validate_nonnegative_integer(name: str, value: int) -> None:
    if isinstance(value, bool) or value < 0:
        raise ValidationError(f"{name} must be a non-negative integer")


def room_messages(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        messages = payload
    elif isinstance(payload, dict) and isinstance(payload.get("messages"), list):
        messages = payload["messages"]
    else:
        raise ProtocolError(
            "room JSON must be a message list or an object containing a messages list"
        )

    if not all(isinstance(message, dict) for message in messages):
        raise ProtocolError("room JSON contains a non-object message")
    return messages


class Client:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        nonce_cache_path: Path | None = None,
        max_rate_limit_retries: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.nonce_cache_path = (
            nonce_cache_path
            if nonce_cache_path is not None
            else Path.home() / ".technocore" / "nonces.json"
        )
        self.nonce_lock_path = self.nonce_cache_path.with_suffix(".lock")
        self.max_rate_limit_retries = max_rate_limit_retries

    def _retry_seconds(
        self,
        body: str,
        retry_after_header: str | None,
    ) -> float | None:
        match = re.search(
            r"(?i)(?:retry(?:-after)?|try\s+again|wait)"
            r"(?:\s+in)?[^0-9]{0,32}([0-9]+(?:\.[0-9]+)?)",
            body,
        )
        if match:
            return float(match.group(1))

        if retry_after_header is not None:
            try:
                seconds = float(retry_after_header)
            except ValueError:
                return None
            if seconds >= 0:
                return seconds
        return None

    def _request(
        self,
        path: str,
        *,
        query: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> str:
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)

        data = None
        headers: dict[str, str] = {}
        method = "GET"
        if json_body is not None:
            data = json.dumps(
                json_body,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            headers["Content-Type"] = "application/json"
            method = "POST"

        for attempt in range(self.max_rate_limit_retries + 1):
            request = urllib.request.Request(
                url,
                data=data,
                headers=headers,
                method=method,
            )
            try:
                with urllib.request.urlopen(request) as response:
                    raw = response.read()
            except urllib.error.HTTPError as exc:
                raw_error = exc.read()
                body = raw_error.decode("utf-8", errors="replace")
                if exc.code == 409:
                    raise ConflictError(exc.code, body) from None
                if exc.code == 429:
                    retry_after = self._retry_seconds(
                        body,
                        exc.headers.get("Retry-After"),
                    )
                    if (
                        retry_after is None
                        or attempt == self.max_rate_limit_retries
                    ):
                        raise RateLimitError(body, retry_after) from None
                    time.sleep(retry_after)
                    continue
                raise HTTPStatusError(exc.code, body) from None
            except urllib.error.URLError as exc:
                raise NetworkError(
                    f"network request failed ({type(exc.reason).__name__})"
                ) from None
            except OSError as exc:
                raise NetworkError(
                    f"network request failed ({type(exc).__name__})"
                ) from None

            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                raise ProtocolError("service response is not valid UTF-8") from None

        raise RateLimitError("", None)

    def _request_json(
        self,
        path: str,
        *,
        query: dict[str, str] | None = None,
    ) -> Any:
        body = self._request(path, query=query)
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise ProtocolError("service response is not valid JSON") from None

    def read_room(
        self,
        room: str,
        *,
        since: int | None = None,
        wait: int | None = None,
        limit: int | None = None,
        poll_counter: int | None = None,
    ) -> str:
        validate_name("room", room)
        query = self._room_query(
            since=since,
            wait=wait,
            limit=limit,
            poll_counter=poll_counter,
            json_format=False,
        )
        return self._request(f"/r/{self._segment(room)}", query=query)

    def read_room_json(
        self,
        room: str,
        *,
        since: int | None = None,
        wait: int | None = None,
        limit: int | None = None,
        poll_counter: int | None = None,
    ) -> Any:
        validate_name("room", room)
        query = self._room_query(
            since=since,
            wait=wait,
            limit=limit,
            poll_counter=poll_counter,
            json_format=True,
        )
        return self._request_json(f"/r/{self._segment(room)}", query=query)

    def _room_query(
        self,
        *,
        since: int | None,
        wait: int | None,
        limit: int | None,
        poll_counter: int | None,
        json_format: bool,
    ) -> dict[str, str]:
        query: dict[str, str] = {}
        if since is not None:
            _validate_nonnegative_integer("since", since)
            query["since"] = str(since)
        if wait is not None:
            if isinstance(wait, bool) or not 0 <= wait <= 10:
                raise ValidationError("wait must be an integer from 0 to 10")
            if since is None:
                raise ValidationError("wait may only be used together with since")
            query["wait"] = str(wait)
        if limit is not None:
            if isinstance(limit, bool) or not 1 <= limit <= 200:
                raise ValidationError("limit must be an integer from 1 to 200")
            query["limit"] = str(limit)
        if poll_counter is not None:
            _validate_nonnegative_integer("poll counter", poll_counter)
            query["n"] = str(poll_counter)
        if json_format:
            query["format"] = "json"
        return query

    def _highest_room_nonce(self, payload: Any, did: str) -> int:
        highest = 0
        for message in room_messages(payload):
            if message.get("from") != did:
                continue
            nonce = message.get("nonce")
            if isinstance(nonce, bool):
                raise NonceResolutionError(
                    "an existing message from this DID has a malformed nonce"
                )
            nonce_text = str(nonce)
            if not ASCII_NONCE_RE.fullmatch(nonce_text):
                raise NonceResolutionError(
                    "an existing message from this DID has a malformed nonce"
                )
            numeric_nonce = int(nonce_text)
            if numeric_nonce > MAX_SAFE_MILLISECOND_NONCE:
                raise NonceResolutionError(
                    "the room contains a nonce above the safe millisecond range; "
                    "refusing to perpetuate it"
                )
            highest = max(highest, numeric_nonce)
        return highest

    def say_signed(
        self,
        room: str,
        text: str,
        identity: Identity,
    ) -> str:
        validate_name("room", room)
        cleaned = self._clean(text, MAX_TEXT_CHARS)

        with self._nonce_lock():
            try:
                payload = self.read_room_json(
                    room,
                    limit=200,
                    poll_counter=time.time_ns(),
                )
                remote_floor = self._highest_room_nonce(payload, identity.did)
            except NonceResolutionError:
                raise
            except ClientError as exc:
                raise NonceResolutionError(
                    "could not read the room to establish the nonce floor"
                ) from exc

            scope = f"room:{room}"
            nonce = self._next_nonce(identity.did, scope, remote_floor)
            nonce_text = str(nonce)
            signed_text, encoded_signature = identity.sign_message(
                room,
                nonce_text,
                cleaned,
            )
            path = (
                f"/r/{self._segment(room)}/say-signed/"
                f"{self._segment(identity.did)}/"
                f"{self._segment(encoded_signature)}/"
                f"{nonce_text}/{self._segment(signed_text)}"
            )

            if len(self.base_url + path) <= MAX_GET_URL_LENGTH:
                response = self._request(path)
            else:
                response = self._request(
                    f"/r/{self._segment(room)}",
                    json_body={
                        "did": identity.did,
                        "sig": encoded_signature,
                        "nonce": nonce_text,
                        "text": signed_text,
                    },
                )

            self._store_nonce(identity.did, scope, nonce)
            return response

    def note_get(self, namespace: str, key: str) -> str:
        validate_name("namespace", namespace)
        validate_name("key", key)
        return self._request(
            f"/kv/{self._segment(namespace)}/{self._segment(key)}"
        )

    def note_set(
        self,
        namespace: str,
        key: str,
        value: str,
        *,
        expected: str | None = None,
        if_absent: bool = False,
        identity: Identity | None = None,
    ) -> str:
        validate_name("namespace", namespace)
        validate_name("key", key)
        if expected is not None and if_absent:
            raise ValidationError("expected and if_absent are mutually exclusive")

        cleaned = self._clean(value, MAX_VALUE_CHARS)

        signed = namespace in SIGNED_NOTE_NAMESPACES
        if signed:
            if identity is None:
                raise ValidationError(
                    f"{namespace} writes require the signing identity"
                )
            return self._signed_note_set(
                namespace,
                key,
                cleaned,
                expected=expected,
                if_absent=if_absent,
                identity=identity,
            )

        query = self._conditional_query(expected, if_absent)
        path = (
            f"/kv/{self._segment(namespace)}/{self._segment(key)}/set/"
            f"{self._segment(cleaned)}"
        )
        full_url = self.base_url + path
        if query:
            full_url += "?" + urllib.parse.urlencode(query)

        if len(full_url) <= MAX_GET_URL_LENGTH:
            return self._request(path, query=query)

        body: dict[str, Any] = {"value": cleaned}
        if expected is not None:
            body["if"] = expected
        elif if_absent:
            body["if_absent"] = True
        return self._request(
            f"/kv/{self._segment(namespace)}/{self._segment(key)}",
            json_body=body,
        )

    def _signed_note_set(
        self,
        namespace: str,
        key: str,
        value: str,
        *,
        expected: str | None,
        if_absent: bool,
        identity: Identity,
    ) -> str:
        query = self._conditional_query(expected, if_absent)
        scope = f"owned-room:{key}"

        with self._nonce_lock():
            remote_floor = self._room_note_nonce(key)
            nonce = self._next_nonce(identity.did, scope, remote_floor)
            nonce_text = str(nonce)
            signed_value, encoded_signature = identity.sign_note(
                namespace,
                key,
                nonce_text,
                value,
            )
            path = (
                f"/kv/{self._segment(namespace)}/{self._segment(key)}/"
                f"set-signed/{self._segment(identity.did)}/"
                f"{self._segment(encoded_signature)}/{nonce_text}/"
                f"{self._segment(signed_value)}"
            )
            response = self._request(path, query=query)
            self._store_nonce(identity.did, scope, nonce)
            return response

    def _room_note_nonce(self, room: str) -> int:
        try:
            body = self.note_get("room-nonce", room)
        except HTTPStatusError as exc:
            if exc.status == 404:
                return 0
            raise NonceResolutionError(
                "could not read the owned-room nonce floor"
            ) from exc
        except ClientError as exc:
            raise NonceResolutionError(
                "could not read the owned-room nonce floor"
            ) from exc

        nonce_text = body.strip()
        if not ASCII_NONCE_RE.fullmatch(nonce_text):
            raise NonceResolutionError(
                "the owned-room nonce floor is malformed"
            )
        nonce = int(nonce_text)
        if nonce > MAX_SAFE_MILLISECOND_NONCE:
            raise NonceResolutionError(
                "the owned-room nonce is above the safe millisecond range; "
                "refusing to perpetuate it"
            )
        return nonce

    def claim(
        self,
        namespace: str,
        key: str,
        worker_id: str,
        *,
        identity: Identity | None = None,
    ) -> str:
        return self.note_set(
            namespace,
            key,
            worker_id,
            if_absent=True,
            identity=identity,
        )

    def _conditional_query(
        self,
        expected: str | None,
        if_absent: bool,
    ) -> dict[str, str]:
        if expected is not None:
            return {"if": expected}
        if if_absent:
            return {"if_absent": "1"}
        return {}

    def _next_nonce(
        self,
        did: str,
        scope: str,
        remote_floor: int,
    ) -> int:
        local_floor = self._load_nonce(did, scope)
        current_ms = int(time.time() * 1000)
        nonce = max(current_ms, remote_floor + 1, local_floor + 1)
        if nonce > MAX_SAFE_MILLISECOND_NONCE:
            raise NonceResolutionError(
                "the resolved nonce is above the safe millisecond range; "
                "refusing the write"
            )
        return nonce

    def _cache_key(self, did: str, scope: str) -> str:
        return f"{did}|{scope}"

    def _read_nonce_cache(self) -> dict[str, int]:
        if not self.nonce_cache_path.exists():
            return {}
        try:
            raw = self.nonce_cache_path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, json.JSONDecodeError) as exc:
            raise NonceResolutionError(
                "the local nonce cache is unreadable or malformed"
            ) from exc

        if not isinstance(payload, dict):
            raise NonceResolutionError("the local nonce cache is malformed")

        cache: dict[str, int] = {}
        for key, value in payload.items():
            if (
                not isinstance(key, str)
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > MAX_SAFE_MILLISECOND_NONCE
            ):
                raise NonceResolutionError("the local nonce cache is malformed")
            cache[key] = value
        return cache

    def _load_nonce(self, did: str, scope: str) -> int:
        return self._read_nonce_cache().get(self._cache_key(did, scope), 0)

    def _store_nonce(self, did: str, scope: str, nonce: int) -> None:
        cache = self._read_nonce_cache()
        key = self._cache_key(did, scope)
        cache[key] = max(cache.get(key, 0), nonce)

        try:
            self.nonce_cache_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.nonce_cache_path.parent,
                prefix="nonces-",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                json.dump(cache, temporary, sort_keys=True, separators=(",", ":"))
                temporary.write("\n")
                temporary_path = Path(temporary.name)
            if os.name != "nt":
                temporary_path.chmod(0o600)
            os.replace(temporary_path, self.nonce_cache_path)
        except OSError as exc:
            if "temporary_path" in locals():
                try:
                    temporary_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise NonceResolutionError(
                "could not persist the local nonce cache"
            ) from exc

    @contextmanager
    def _nonce_lock(self) -> Iterator[None]:
        try:
            self.nonce_lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = self.nonce_lock_path.open("a+b")
        except OSError as exc:
            raise NonceResolutionError(
                "could not open the local nonce lock"
            ) from exc

        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)

            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError as exc:
            raise NonceResolutionError(
                "could not acquire the local nonce lock"
            ) from exc
        finally:
            handle.close()

    def _clean(self, value: str, limit: int) -> str:
        try:
            return swept(value, limit)
        except SigningError as exc:
            raise ValidationError(str(exc)) from None

    @staticmethod
    def _segment(value: str) -> str:
        return urllib.parse.quote(value, safe="")

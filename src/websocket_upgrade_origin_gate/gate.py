"""Independent RFC 6455 subset for an owned, loopback-only handshake lab."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import secrets
import threading
import time
from urllib.parse import urlsplit


_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_COOKIE_NAME = "lab_session"


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    session_label: str | None = None


class SessionRegistry:
    """In-memory sessions; use non-secret labels because labels enter decision logs."""

    def __init__(self) -> None:
        self._sessions: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def issue(self, label: str, *, lifetime_seconds: float = 60.0) -> str:
        if not label or lifetime_seconds <= 0:
            raise ValueError("session label and lifetime must be positive")
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._sessions[self._digest(token)] = (label, time.monotonic() + lifetime_seconds)
        return token

    def revoke(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(self._digest(token), None)

    def label_if_valid(self, token: str | None) -> str | None:
        if not token:
            return None
        try:
            digest = self._digest(token)
        except UnicodeEncodeError:
            return None
        with self._lock:
            session = self._sessions.get(digest)
        return session[0] if session is not None and session[1] > time.monotonic() else None


def _single_header(headers: HTTPMessage, name: str) -> str | None:
    values = headers.get_all(name)
    if values is None or len(values) != 1:
        return None
    return values[0].strip()


def _session_cookie(headers: HTTPMessage) -> str | None:
    raw = _single_header(headers, "Cookie")
    if raw is None:
        return None
    found: list[str] = []
    for item in raw.split(";"):
        if "=" not in item:
            continue
        name, value = item.strip().split("=", 1)
        if name == _COOKIE_NAME:
            found.append(value.strip())
    if len(found) != 1 or not found[0] or any(not (character.isascii() and (character.isalnum() or character in "-_")) for character in found[0]):
        return None
    return found[0]


class UpgradeGate:
    """Require the exact page origin, target Host, and a live session cookie."""

    def __init__(self, *, allowed_origin: str, sessions: SessionRegistry) -> None:
        try:
            parsed = urlsplit(allowed_origin)
            valid_origin = (
                parsed.scheme == "http"
                and parsed.hostname == "127.0.0.1"
                and parsed.port is not None
                and parsed.port > 0
                and parsed.path == ""
                and parsed.query == ""
                and parsed.fragment == ""
                and parsed.username is None
                and allowed_origin == f"http://127.0.0.1:{parsed.port}"
            )
        except ValueError:
            valid_origin = False
        if not valid_origin:
            raise ValueError("this local experiment accepts only a loopback page origin")
        self.allowed_origin = allowed_origin
        self.sessions = sessions

    def authorize(self, headers: HTTPMessage, expected_host: str) -> GateDecision:
        host = _single_header(headers, "Host")
        if host != expected_host:
            return GateDecision(False, "target_host_mismatch")
        origin = _single_header(headers, "Origin")
        if origin is None or not origin:
            return GateDecision(False, "origin_required")
        if origin != self.allowed_origin:
            return GateDecision(False, "origin_not_allowed")
        token = _session_cookie(headers)
        label = self.sessions.label_if_valid(token)
        if label is None:
            return GateDecision(False, "session_invalid")
        return GateDecision(True, "allowed", label)


class _GateHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path != "/socket" or self.request_version != "HTTP/1.1":
            self._reject(404, "resource_or_protocol_invalid")
            return
        key = self._valid_websocket_key()
        if key is None:
            self._reject(400, "upgrade_headers_invalid")
            return
        decision = self.server.gate.authorize(self.headers, self.server.expected_host)
        if not decision.allowed:
            self._reject(403, decision.reason)
            return

        accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()).decode("ascii")
        self.server.record(101, decision.reason, self.headers, accepted=True, session_label=decision.session_label)
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = True
        self.connection.settimeout(2)
        try:
            if self._read_one_text_frame() == "ping":
                self.server.record_message()
                self.wfile.write(b"\x81\x03ack")
                self.wfile.flush()
        except (OSError, UnicodeDecodeError, ValueError):
            pass

    def _valid_websocket_key(self) -> str | None:
        if _single_header(self.headers, "Host") is None:
            return None
        upgrade = _single_header(self.headers, "Upgrade")
        if upgrade is None or upgrade.lower() != "websocket":
            return None
        connection = _single_header(self.headers, "Connection")
        if connection is None or "upgrade" not in {part.strip().lower() for part in connection.split(",")}:
            return None
        if _single_header(self.headers, "Sec-WebSocket-Version") != "13":
            return None
        key = _single_header(self.headers, "Sec-WebSocket-Key")
        if key is None:
            return None
        try:
            decoded = base64.b64decode(key, validate=True)
        except (ValueError, binascii.Error):
            return None
        return key if len(decoded) == 16 else None

    def _read_one_text_frame(self) -> str:
        prefix = self.rfile.read(2)
        if len(prefix) != 2 or prefix[0] != 0x81 or not prefix[1] & 0x80:
            raise ValueError("expected one masked final text frame")
        length = prefix[1] & 0x7F
        if length > 125:
            raise ValueError("extended frame lengths are outside this lab")
        mask = self.rfile.read(4)
        payload = self.rfile.read(length)
        if len(mask) != 4 or len(payload) != length:
            raise ValueError("incomplete frame")
        return bytes(value ^ mask[index % 4] for index, value in enumerate(payload)).decode("utf-8")

    def _reject(self, status: int, reason: str) -> None:
        self.server.record(status, reason, self.headers, accepted=False)
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def log_message(self, *args: object) -> None:
        pass


class GateServer(ThreadingHTTPServer):
    """A loopback-only server with bounded single-frame application handling."""

    def __init__(self, gate: UpgradeGate) -> None:
        super().__init__(("127.0.0.1", 0), _GateHandler)
        self.gate = gate
        self.expected_host = f"127.0.0.1:{self.server_port}"
        self._events: list[dict[str, object]] = []
        self._message_count = 0
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(2.0)
        return connection, address

    def record(
        self,
        status: int,
        reason: str,
        headers: HTTPMessage,
        *,
        accepted: bool,
        session_label: str | None = None,
    ) -> None:
        with self._lock:
            self._events.append(
                {
                    "status": status,
                    "reason": reason,
                    "accepted": accepted,
                    "origin": self.gate.allowed_origin if _single_header(headers, "Origin") == self.gate.allowed_origin else None,
                    "host": self.expected_host if _single_header(headers, "Host") == self.expected_host else None,
                    "cookie_present": _single_header(headers, "Cookie") is not None,
                    "session_label": session_label,
                }
            )

    def record_message(self) -> None:
        with self._lock:
            self._message_count += 1

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {"events": [dict(event) for event in self._events], "message_count": self._message_count}

    def __enter__(self) -> "GateServer":
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.shutdown()
        self.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

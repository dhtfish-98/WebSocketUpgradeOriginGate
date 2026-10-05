"""Owned page origins and a raw RFC 6455 client for real local handshakes."""

from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
import socket
import threading


_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _PageHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        lab = self.server.lab
        label = self.server.label
        lab.record_page(label, self.path)
        if self.path != "/page":
            self.send_error(404)
            return
        body = lab.browser_page(label).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if label == "A" and lab.browser_token is not None:
            self.send_header("Set-Cookie", f"lab_session={lab.browser_token}; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class LoopbackPages:
    def __init__(self) -> None:
        self.a = ThreadingHTTPServer(("127.0.0.1", 0), _PageHandler)
        self.b = ThreadingHTTPServer(("127.0.0.1", 0), _PageHandler)
        self.a.lab = self.b.lab = self
        self.a.label = "A"
        self.b.label = "B"
        self._page_requests: list[dict[str, str]] = []
        self._lock = threading.Lock()
        self._threads = [
            threading.Thread(target=self.a.serve_forever, daemon=True),
            threading.Thread(target=self.b.serve_forever, daemon=True),
        ]
        self.browser_token: str | None = None
        self.ws_url: str | None = None

    @property
    def a_origin(self) -> str:
        return f"http://127.0.0.1:{self.a.server_port}"

    @property
    def b_origin(self) -> str:
        return f"http://127.0.0.1:{self.b.server_port}"

    def record_page(self, label: str, path: str) -> None:
        with self._lock:
            self._page_requests.append({"origin": label, "path": path})

    def page_requests(self) -> list[dict[str, str]]:
        with self._lock:
            return [dict(item) for item in self._page_requests]

    def browser_page(self, label: str) -> str:
        if self.ws_url is None:
            return "<!doctype html><title>Local origin fixture</title>"
        if label == "B":
            return f"""<!doctype html><meta charset=\"utf-8\"><title>Origin B</title>
<script>
const ws = new WebSocket({json.dumps(self.ws_url)});
ws.onopen = () => {{ ws.send('ping'); parent.postMessage({{from:'B', outcome:'accepted'}}, {json.dumps(self.a_origin)}); }};
ws.onerror = () => parent.postMessage({{from:'B', outcome:'rejected'}}, {json.dumps(self.a_origin)});
</script>"""
        return f"""<!doctype html><meta charset=\"utf-8\"><title>Origin A</title>
<body id=\"result\" data-result=\"pending\"></body>
<script>
const outcomes = {{A:null,B:null}};
function record(which, result) {{
  outcomes[which] = result;
  if (outcomes.A && outcomes.B) document.getElementById('result').dataset.result = JSON.stringify(outcomes);
}}
window.addEventListener('message', event => {{
  if (event.origin === {json.dumps(self.b_origin)} && event.data.from === 'B') record('B', event.data.outcome);
}});
const ws = new WebSocket({json.dumps(self.ws_url)});
ws.onopen = () => ws.send('ping');
ws.onmessage = event => {{ if (event.data === 'ack') record('A', 'accepted_ack'); ws.close(); }};
ws.onerror = () => record('A', 'rejected');
const iframe = document.createElement('iframe');
iframe.src = {json.dumps(self.b_origin + '/page')};
document.body.appendChild(iframe);
</script>"""

    def fetch_both_pages(self) -> list[int]:
        result = []
        for server in (self.a, self.b):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                connection.request("GET", "/page")
                response = connection.getresponse()
                response.read()
                result.append(response.status)
            finally:
                connection.close()
        return result

    def __enter__(self) -> "LoopbackPages":
        for thread in self._threads:
            thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.a.shutdown()
        self.b.shutdown()
        self.a.server_close()
        self.b.server_close()
        for thread in self._threads:
            thread.join(timeout=2)


def websocket_exchange(
    server_port: int,
    *,
    origin: str | None,
    cookie: str | None,
    host: str | None = None,
    extra_headers: tuple[tuple[str, str], ...] = (),
    key: str | None = None,
    send_ping: bool = True,
) -> dict[str, object]:
    """Send a real HTTP Upgrade and one masked text frame to 127.0.0.1."""
    handshake_key = key if key is not None else base64.b64encode(os.urandom(16)).decode("ascii")
    host_value = host if host is not None else f"127.0.0.1:{server_port}"
    lines = [
        "GET /socket HTTP/1.1",
        f"Host: {host_value}",
        "Upgrade: websocket",
        "Connection: keep-alive, Upgrade",
        f"Sec-WebSocket-Key: {handshake_key}",
        "Sec-WebSocket-Version: 13",
    ]
    if origin is not None:
        lines.append(f"Origin: {origin}")
    if cookie is not None:
        lines.append(f"Cookie: {cookie}")
    lines.extend(f"{name}: {value}" for name, value in extra_headers)
    request = "\r\n".join(lines) + "\r\n\r\n"

    with socket.create_connection(("127.0.0.1", server_port), timeout=3) as connection:
        connection.settimeout(3)
        connection.sendall(request.encode("ascii"))
        stream = connection.makefile("rb")
        status_line = stream.readline().decode("ascii").strip()
        response_headers: dict[str, str] = {}
        while True:
            line = stream.readline()
            if line in (b"\r\n", b"", b"\n"):
                break
            name, value = line.decode("ascii").split(":", 1)
            response_headers[name.lower()] = value.strip()
        status = int(status_line.split()[1])
        result: dict[str, object] = {
            "status": status,
            "status_line": status_line,
            "response_headers": response_headers,
            "ack": None,
        }
        if status != 101:
            return result
        expected_accept = base64.b64encode(hashlib.sha1((handshake_key + _GUID).encode()).digest()).decode()
        if response_headers.get("sec-websocket-accept") != expected_accept:
            raise AssertionError("server returned an invalid Sec-WebSocket-Accept")
        if send_ping:
            payload = b"ping"
            mask = os.urandom(4)
            masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
            connection.sendall(bytes((0x81, 0x80 | len(payload))) + mask + masked)
            frame = stream.read(5)
            result["ack"] = frame == b"\x81\x03ack"
        return result

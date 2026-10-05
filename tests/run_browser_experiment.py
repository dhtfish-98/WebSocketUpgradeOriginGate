"""Real Chrome origin check through a private loopback DevTools connection."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

from websocket_upgrade_origin_gate import GateServer, SessionRegistry, UpgradeGate

from lab_support import LoopbackPages


CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class _DevToolsSocket:
    """Minimal client for local DevTools JSON frames; no external dependency."""

    def __init__(self, websocket_url: str) -> None:
        url = urlsplit(websocket_url)
        if url.scheme != "ws" or url.hostname != "127.0.0.1" or url.port is None:
            raise ValueError("DevTools endpoint must be local plain WebSocket")
        self.socket = socket.create_connection((url.hostname, url.port), timeout=3)
        self.socket.settimeout(3)
        self.stream = self.socket.makefile("rb")
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {url.path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{url.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode("ascii"))
        status = self.stream.readline().decode("ascii").strip()
        headers: dict[str, str] = {}
        while True:
            line = self.stream.readline()
            if line in (b"", b"\n", b"\r\n"):
                break
            name, value = line.decode("ascii").split(":", 1)
            headers[name.lower()] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")
        if " 101 " not in status or headers.get("sec-websocket-accept") != expected:
            self.close()
            raise RuntimeError(f"DevTools WebSocket handshake failed: {status}")
        self.next_id = 1

    def _read_exact(self, count: int) -> bytes:
        data = self.stream.read(count)
        if len(data) != count:
            raise EOFError("DevTools WebSocket frame ended early")
        return data

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes((0x80 | opcode, 0x80 | length))
        elif length < 65536:
            header = bytes((0x80 | opcode, 0x80 | 126)) + length.to_bytes(2, "big")
        else:
            header = bytes((0x80 | opcode, 0x80 | 127)) + length.to_bytes(8, "big")
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(header + mask + masked)

    def _receive_json(self) -> dict[str, object]:
        while True:
            header = self._read_exact(2)
            opcode = header[0] & 0x0F
            if header[1] & 0x80:
                raise ValueError("DevTools server unexpectedly masked a frame")
            length = header[1] & 0x7F
            if length == 126:
                length = int.from_bytes(self._read_exact(2), "big")
            elif length == 127:
                length = int.from_bytes(self._read_exact(8), "big")
            if length > 1_000_000:
                raise ValueError("DevTools frame too large")
            payload = self._read_exact(length)
            if opcode == 9:
                self._send_frame(10, payload)
                continue
            if opcode == 8:
                raise EOFError("DevTools socket closed")
            if opcode != 1:
                continue
            return json.loads(payload.decode("utf-8"))

    def evaluate(self, expression: str) -> object:
        request_id = self.next_id
        self.next_id += 1
        command = {
            "id": request_id,
            "method": "Runtime.evaluate",
            "params": {"expression": expression, "returnByValue": True},
        }
        self._send_frame(1, json.dumps(command).encode("utf-8"))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            reply = self._receive_json()
            if reply.get("id") == request_id:
                return reply.get("result", {}).get("result", {}).get("value")
        raise TimeoutError("DevTools Runtime.evaluate did not reply")

    def close(self) -> None:
        self.stream.close()
        self.socket.close()

    def __enter__(self) -> "_DevToolsSocket":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _page_debugger_url(port: int, page_url: str) -> str:
    opener = build_opener(ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{port}/json/list", timeout=3) as response:
        targets = json.load(response)
    for target in targets:
        if target.get("type") == "page" and target.get("url") == page_url:
            return target["webSocketDebuggerUrl"]
    raise RuntimeError("Chrome page target was not exposed by DevTools")


def _run_chrome(page_url: str, output: Path) -> tuple[int, object, str, list[str]]:
    chrome_log = output.with_suffix(".chrome.log")
    outcomes: object = None
    error = ""
    command: list[str] = []
    with tempfile.TemporaryDirectory(prefix="chrome-profile-", dir=output.parent) as profile:
        command = [
            str(CHROME),
            "--headless=new",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-gpu",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            page_url,
        ]
        with chrome_log.open("w") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True)
            try:
                active_port = Path(profile) / "DevToolsActivePort"
                deadline = time.monotonic() + 12
                while not active_port.exists() and time.monotonic() < deadline and process.poll() is None:
                    time.sleep(0.1)
                if not active_port.exists():
                    raise RuntimeError("Chrome did not expose a local DevTools port")
                port = int(active_port.read_text().splitlines()[0])
                debugger_url = _page_debugger_url(port, page_url)
                with _DevToolsSocket(debugger_url) as devtools:
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        raw = devtools.evaluate("document.body && document.body.dataset.result")
                        if isinstance(raw, str) and raw not in {"pending", ""}:
                            outcomes = json.loads(raw)
                            break
                        time.sleep(0.2)
                    if outcomes is None:
                        error = "browser page did not finish both WebSocket attempts within 15 seconds"
            except (OSError, ValueError, RuntimeError, EOFError, TimeoutError, json.JSONDecodeError) as exc:
                error = f"{type(exc).__name__}: {exc}"
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process_exit = process.returncode
    scrubbed_command = [
        argument if not argument.startswith("--user-data-dir=") else "--user-data-dir=<disposable Build profile>"
        for argument in command
    ]
    return process_exit, outcomes, error, scrubbed_command


def run(output: Path) -> dict[str, object]:
    if not CHROME.is_file():
        return {"result": "OPEN", "reason": "Google Chrome executable is not installed"}
    version = subprocess.run([str(CHROME), "--version"], text=True, capture_output=True, timeout=10)
    with LoopbackPages() as pages:
        sessions = SessionRegistry()
        pages.browser_token = sessions.issue("browser_synthetic_session")
        with GateServer(UpgradeGate(allowed_origin=pages.a_origin, sessions=sessions)) as server:
            pages.ws_url = f"ws://127.0.0.1:{server.server_port}/socket"
            process_exit, outcomes, error, command = _run_chrome(pages.a_origin + "/page", output)
            snapshot = server.snapshot()
            page_requests = pages.page_requests()
    checks = {
        "browser_A_received_application_ack": isinstance(outcomes, dict) and outcomes.get("A") == "accepted_ack",
        "browser_B_was_rejected": isinstance(outcomes, dict) and outcomes.get("B") == "rejected",
        "real_page_origins_loaded": {item["origin"] for item in page_requests} == {"A", "B"},
        "accepted_once_rejected_once": sorted(event["status"] for event in snapshot["events"]) == [101, 403],
        "cross_origin_cookie_rejected": any(event["status"] == 403 and event["reason"] == "origin_not_allowed" and event["cookie_present"] for event in snapshot["events"]),
        "only_allowed_message_processed": snapshot["message_count"] == 1,
    }
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "chrome_version": version.stdout.strip(),
        "chrome_process_exit_after_termination": process_exit,
        "chrome_command": command,
        "browser_outcomes": outcomes,
        "browser_error": error,
        "page_origins": {"A": pages.a_origin, "B": pages.b_origin},
        "page_requests": page_requests,
        "server_snapshot": snapshot,
        "chrome_log_path": str(output.with_suffix(".chrome.log")),
        "chrome_log_sha256": hashlib.sha256(output.with_suffix(".chrome.log").read_bytes()).hexdigest(),
        "checks": checks,
        "result": "PASS" if all(checks.values()) else "OPEN",
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: run_browser_experiment.py OUTPUT_JSON")
    destination = Path(sys.argv[1]).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    receipt = run(destination)
    destination.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    print(receipt["result"], destination)
    raise SystemExit(0 if receipt["result"] == "PASS" else 2)

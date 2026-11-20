"""A real HTTP server that misbehaves on request.

Each incoming request takes the next entry from `script`, then falls back to
`default`. Entries:

    ("status", 200)             answer immediately
    ("sleep", seconds, 200)     wait, then answer
    ("drop",)                   close the socket without answering
    ("drip", seconds)           send 200 and a body one byte at a time
    ("redirect", code, url)     answer with a redirect
    ("big", megabytes)          answer with a very large body
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Seen:
    path: str
    headers: dict[str, str]
    body: bytes
    at: float


@dataclass
class Receiver:
    script: list = field(default_factory=list)
    default: tuple = ("status", 200)
    seen: list[Seen] = field(default_factory=list)
    bytes_sent: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def start(self) -> Receiver:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                with outer._lock:
                    outer.seen.append(
                        Seen(
                            self.path,
                            {k.lower(): v for k, v in self.headers.items()},
                            body,
                            time.time(),
                        )
                    )
                    step = outer.script.pop(0) if outer.script else outer.default
                kind = step[0]
                try:
                    if kind == "status":
                        self._reply(step[1])
                    elif kind == "sleep":
                        time.sleep(step[1])
                        self._reply(step[2])
                    elif kind == "drop":
                        self.close_connection = True
                        self.connection.close()
                    elif kind == "drip":
                        n = int(step[1] / 0.1)
                        self.send_response(200)
                        self.send_header("Content-Length", str(n))
                        self.end_headers()
                        for _ in range(n):
                            self.wfile.write(b"x")
                            self.wfile.flush()
                            time.sleep(0.1)
                    elif kind == "big":
                        total = step[1] * 1024 * 1024
                        self.send_response(200)
                        self.send_header("Content-Length", str(total))
                        self.end_headers()
                        chunk = b"x" * 65536
                        for _ in range(total // len(chunk)):
                            self.wfile.write(chunk)
                            outer.bytes_sent += len(chunk)
                    elif kind == "redirect":
                        self.send_response(step[1])
                        self.send_header("Location", step[2])
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def _reply(self, code):
                self.send_response(code)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/hook"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def count(self) -> int:
        with self._lock:
            return len(self.seen)

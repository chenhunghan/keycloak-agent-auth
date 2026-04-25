"""The Resource Server  where capability business logic actually runs.

In gateway mode (what this demo uses), Keycloak validates the agent+jwt,
runs constraint checks, and then proxies the request to this server. The
server simply executes the business logic and returns a JSON body
wrapped in a ``data`` field (per the spec's 5.11 sync response shape).

A production resource server running in direct mode would also validate
the agent JWT itself  either by calling Keycloak's /agent/introspect or
by checking signature + aud locally against the agent's registered public
key. For this mini demo we rely on gateway mode so the resource server
has nothing to auth.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any, Callable, Dict

CapabilityHandler = Callable[[Dict[str, Any]], Dict[str, Any]]


def _make_handler_class(handlers: Dict[str, CapabilityHandler]) -> type:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            # Quiet default access log; we print our own lines below.
            return

        def do_POST(self) -> None:  # noqa: N802
            path = self.path or ""
            handler = handlers.get(path)
            if handler is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(
                    json.dumps({"error": "not_found", "path": path}).encode()
                )
                return
            length = int(self.headers.get("content-length") or 0)
            raw = self.rfile.read(length) if length > 0 else b""
            parsed: Dict[str, Any] = json.loads(raw) if raw else {}
            args = parsed.get("arguments") or {}
            print(
                f"[resource-server] {path}  args={json.dumps(args)}",
                flush=True,
            )
            try:
                data = handler(args)
            except Exception as exc:  # noqa: BLE001
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(exc)}).encode())
                return
            body = json.dumps({"data": data}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            # Matches the JS server: only POST is handled; everything else => 405.
            self.send_response(405)
            self.end_headers()

    return _Handler


class ResourceServer:
    def __init__(self, http_server: ThreadingHTTPServer, port: int) -> None:
        self._server = http_server
        self.port = port
        self._thread: Thread | None = None

    @classmethod
    def start(cls, handlers: Dict[str, CapabilityHandler]) -> "ResourceServer":
        """Start on a random free port (useful for tests)."""
        return cls.start_on(0, handlers)

    @classmethod
    def start_on(
        cls, port: int, handlers: Dict[str, CapabilityHandler]
    ) -> "ResourceServer":
        """Start on a specific port (used by the dockerized demo)."""
        handler_cls = _make_handler_class(handlers)
        server = ThreadingHTTPServer(("0.0.0.0", port), handler_cls)
        bound_port = server.server_address[1]
        print(f"[resource-server] listening on :{bound_port}", flush=True)
        rs = cls(server, bound_port)
        rs._thread = Thread(target=server.serve_forever, daemon=True)
        rs._thread.start()
        return rs

    def url_for(self, path: str, service_host: str = "resource-server") -> str:
        """Capability URL reachable by Keycloak (and the rest of the compose
        network) at the configured service name. When the demo registers a
        capability with this URL as its ``location``, KC's gateway proxy hits it.
        """
        return f"http://{service_host}:{self.port}{path}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def serve_forever(self) -> None:
        """Block the calling thread forever (used by the standalone entrypoint)."""
        if self._thread is not None:
            self._thread.join()

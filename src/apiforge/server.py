"""Multi-threaded HTTP server adapter and zero-socket in-memory TestClient."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from apiforge.app import ApiForgeApp
from apiforge.router import HttpResponse


class TestClient:
    """In-memory test client for executing fast, deterministic HTTP requests against ApiForgeApp."""

    def __init__(
        self,
        app: ApiForgeApp,
        default_headers: dict[str, str] | None = None,
        client_ip: str = "127.0.0.1",
    ) -> None:
        """Initialize the test client with an ApiForgeApp instance and optional headers."""
        self.app = app
        self.default_headers = dict(default_headers or {})
        self.client_ip = client_ip

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Dispatch a synthetic HTTP request through the application pipeline."""
        merged_headers = {**self.default_headers, **(headers or {})}
        if json_body is not None:
            payload = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            merged_headers.setdefault("Content-Type", "application/json")
        else:
            payload = raw_body or b""

        return self.app.handle_request(
            method=method,
            raw_url=path,
            headers=merged_headers,
            body=payload,
            client_ip=self.client_ip,
        )

    def get(self, path: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Send a GET request."""
        return self.request("GET", path, headers=headers)

    def post(
        self,
        path: str,
        *,
        json_body: Any = None,
        raw_body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Send a POST request."""
        return self.request("POST", path, json_body=json_body, raw_body=raw_body, headers=headers)

    def delete(self, path: str, *, headers: dict[str, str] | None = None) -> HttpResponse:
        """Send a DELETE request."""
        return self.request("DELETE", path, headers=headers)


def create_http_handler(app: ApiForgeApp) -> type[BaseHTTPRequestHandler]:
    """Create a BaseHTTPRequestHandler subclass bound to the given ApiForgeApp instance."""

    class ApiForgeRequestHandler(BaseHTTPRequestHandler):
        """HTTP request handler bridging stdlib ThreadingHTTPServer to ApiForgeApp."""

        def _dispatch(self, method: str) -> None:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b""
            header_dict = {k: v for k, v in self.headers.items()}
            client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

            response = app.handle_request(
                method=method,
                raw_url=self.path,
                headers=header_dict,
                body=raw_body,
                client_ip=client_ip,
            )

            self.send_response(response.status_code)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            for k, v in response.headers.items():
                self.send_header(k, v)
            self.end_headers()
            if response.body:
                self.wfile.write(response.body)

        def do_GET(self) -> None:  # noqa: N802
            """Handle HTTP GET requests."""
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            """Handle HTTP POST requests."""
            self._dispatch("POST")

        def do_DELETE(self) -> None:  # noqa: N802
            """Handle HTTP DELETE requests."""
            self._dispatch("DELETE")

        def log_message(self, format_str: str, *args: Any) -> None:
            """Suppress noisy default stderr logging during programmatic runs."""
            return

    return ApiForgeRequestHandler


def create_http_server(app: ApiForgeApp, host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    """Instantiate a ThreadingHTTPServer bound to `(host, port)` for the given app."""
    handler_cls = create_http_handler(app)
    return ThreadingHTTPServer((host, port), handler_cls)

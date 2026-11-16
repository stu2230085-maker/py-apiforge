"""Command-line interface for PyApiForge (`serve`, `routes`, `openapi`, `token`)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from apiforge.app import ApiForgeApp
from apiforge.security import encode_jwt
from apiforge.server import create_http_server


def _build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="apiforge",
        description="PyApiForge — Declarative REST API server, OpenAPI 3.1 generator, and JWT/Webhook toolkit.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="Start the multi-threaded HTTP API server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host address (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8000, help="Bind TCP port (default: 8000)")
    serve_parser.add_argument("--db", default="apiforge.db", help="SQLite database file path or :memory:")
    serve_parser.add_argument("--rate-limit", type=int, default=60, help="Token bucket capacity per client")

    subparsers.add_parser("routes", help="Print a formatted table of all registered API routes")

    openapi_parser = subparsers.add_parser("openapi", help="Generate OpenAPI 3.1.0 JSON schema")
    openapi_parser.add_argument("--output", "-o", help="Optional file path to write OpenAPI JSON")

    token_parser = subparsers.add_parser("token", help="Generate a signed HS256 JWT access token")
    token_parser.add_argument("--sub", default="admin", help="Token subject claim (default: admin)")
    token_parser.add_argument("--role", default="admin", help="Token role claim (default: admin)")
    token_parser.add_argument("--ttl", type=int, default=3600, help="Token TTL in seconds (default: 3600)")
    token_parser.add_argument(
        "--secret",
        default="apiforge-default-jwt-secret-key-2026",
        help="HMAC-SHA256 signing secret",
    )

    return parser


def _cmd_routes(app: ApiForgeApp) -> int:
    """Display all registered routes in a clean tabular layout."""
    header = f"{'METHOD':<8} {'PATH':<32} {'AUTH':<8} {'SUMMARY'}"
    print(header)
    print("-" * len(header) + "-" * 24)
    for route in app.routes:
        auth_label = "yes" if route.auth_required else "public"
        print(f"{route.method:<8} {route.path_template:<32} {auth_label:<8} {route.summary}")
    return 0


def _cmd_openapi(app: ApiForgeApp, output_path: str | None) -> int:
    """Output the OpenAPI 3.1.0 specification to stdout or a file."""
    spec_json = json.dumps(app.openapi_spec(), ensure_ascii=False, indent=2)
    if output_path:
        target = Path(output_path)
        target.write_text(spec_json + "\n", encoding="utf-8")
        print(f"OpenAPI 3.1.0 specification written to {target}")
    else:
        print(spec_json)
    return 0


def _cmd_token(sub: str, role: str, ttl: int, secret: str) -> int:
    """Generate and print a signed HS256 JWT token."""
    token = encode_jwt({"sub": sub, "role": role}, secret=secret, ttl_seconds=ttl)
    print(token)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint for `apiforge`."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "token":
        return _cmd_token(args.sub, args.role, args.ttl, args.secret)

    app = ApiForgeApp(db_path=":memory:")
    try:
        if args.command == "routes":
            return _cmd_routes(app)
        if args.command == "openapi":
            return _cmd_openapi(app, args.output)
    finally:
        app.storage.close()
    if args.command == "serve":
        live_app = ApiForgeApp(
            db_path=args.db,
            rate_limit_capacity=args.rate_limit,
        )
        server = create_http_server(live_app, host=args.host, port=args.port)
        print(f"PyApiForge listening on http://{args.host}:{args.port} (Docs: http://{args.host}:{args.port}/docs)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            server.server_close()
            live_app.storage.close()
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())

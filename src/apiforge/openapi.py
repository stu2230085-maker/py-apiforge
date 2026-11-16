"""OpenAPI 3.1.0 specification builder and standalone interactive API documentation UI."""

from __future__ import annotations

import json
from typing import Any

from apiforge.router import RouteDefinition
from apiforge.schema import dataclass_to_json_schema


def _build_operation_object(
    route: RouteDefinition,
    component_schemas: dict[str, Any],
) -> dict[str, Any]:
    """Build an OpenAPI 3.1 operation object for a single RouteDefinition."""
    operation_id = f"{route.method.lower()}_{route.path_template.strip('/').replace('/', '_').replace('{', '').replace('}', '') or 'root'}"
    parameters: list[dict[str, Any]] = [
        {
            "name": param_name,
            "in": "path",
            "required": True,
            "schema": {"type": "string"},
        }
        for param_name in route.param_names
    ]

    operation: dict[str, Any] = {
        "operationId": operation_id,
        "summary": route.summary,
        "description": route.description,
        "tags": route.tags,
        "responses": {
            str(route.status_code): {
                "description": "Successful response",
                "content": {
                    "application/json": {
                        "schema": {"type": "object"},
                    }
                },
            },
            "429": {
                "description": "Rate limit exceeded (RFC 7807 Problem Details)",
            },
        },
    }

    if parameters:
        operation["parameters"] = parameters

    if route.auth_required:
        operation["security"] = [{"BearerAuth": []}, {"ApiKeyAuth": []}]
        operation["responses"]["401"] = {"description": "Unauthorized"}

    if route.request_model is not None:
        model_name = route.request_model.__name__
        component_schemas[model_name] = dataclass_to_json_schema(route.request_model)
        operation["requestBody"] = {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {"$ref": f"#/components/schemas/{model_name}"},
                }
            },
        }
        operation["responses"]["422"] = {"description": "Validation error"}

    return operation


def build_openapi_spec(
    title: str,
    version: str,
    description: str,
    routes: list[RouteDefinition],
) -> dict[str, Any]:
    """Generate a complete OpenAPI 3.1.0 specification dictionary from registered routes."""
    paths: dict[str, dict[str, Any]] = {}
    component_schemas: dict[str, Any] = {}

    for route in routes:
        path_item = paths.setdefault(route.path_template, {})
        path_item[route.method.lower()] = _build_operation_object(route, component_schemas)

    return {
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": version,
            "description": description,
        },
        "paths": paths,
        "components": {
            "schemas": component_schemas,
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                },
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                },
            },
        },
    }


def build_docs_html(spec: dict[str, Any]) -> str:
    """Render a standalone zero-external-dependency interactive API documentation page."""
    spec_json = json.dumps(spec, ensure_ascii=False, indent=2)
    title = spec.get("info", {}).get("title", "PyApiForge API")
    version = spec.get("info", {}).get("version", "1.0.0")

    rows: list[str] = []
    for path, methods in spec.get("paths", {}).items():
        for method, meta in methods.items():
            badge_color = {
                "get": "#0ea5e9",
                "post": "#10b981",
                "put": "#f59e0b",
                "delete": "#ef4444",
            }.get(method.lower(), "#6366f1")
            auth_badge = "🔒 Auth" if meta.get("security") else "🌐 Public"
            summary = meta.get("summary", "")
            rows.append(
                f"<tr>"
                f"<td><span class='badge' style='background:{badge_color}'>{method.upper()}</span></td>"
                f"<td><code>{path}</code></td>"
                f"<td>{summary}</td>"
                f"<td>{auth_badge}</td>"
                f"</tr>"
            )

    routes_html = "\n".join(rows)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{title} v{version} — OpenAPI 3.1 Console</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; }}
    .container {{ max-width: 1080px; margin: 0 auto; }}
    h1 {{ margin-top: 0; color: #38bdf8; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; margin-bottom: 2rem; }}
    th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #94a3b8; text-transform: uppercase; font-size: 0.8rem; }}
    .badge {{ padding: 0.25rem 0.6rem; border-radius: 4px; color: #fff; font-weight: 700; font-size: 0.75rem; }}
    pre {{ background: #1e293b; padding: 1rem; border-radius: 8px; overflow-x: auto; color: #e2e8f0; font-size: 0.85rem; }}
    code {{ color: #38bdf8; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>{title} <small style="font-size:0.6em;color:#94a3b8">v{version} (OpenAPI 3.1.0)</small></h1>
    <p>{spec.get("info", {}).get("description", "")}</p>
    <h2>Registered Endpoints</h2>
    <table>
      <thead><tr><th>Method</th><th>Path</th><th>Summary</th><th>Security</th></tr></thead>
      <tbody>{routes_html}</tbody>
    </table>
    <h2>OpenAPI 3.1.0 Specification</h2>
    <pre id="openapi-spec">{spec_json}</pre>
  </div>
</body>
</html>"""

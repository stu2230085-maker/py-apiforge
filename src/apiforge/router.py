"""Declarative HTTP router, path parameter parser, and RFC 7807 Problem Details handler."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

from apiforge.schema import SchemaValidationError, serialize_value, validate_payload
from apiforge.security import AuthPrincipal


class ApiHttpError(Exception):
    """Structured HTTP exception producing RFC 7807 Problem Details responses."""

    def __init__(
        self,
        status_code: int,
        title: str,
        detail: str,
        error_type: str = "about:blank",
        extensions: dict[str, Any] | None = None,
    ) -> None:
        """Initialize an HTTP error with RFC 7807 fields."""
        super().__init__(detail)
        self.status_code = status_code
        self.title = title
        self.detail = detail
        self.error_type = error_type
        self.extensions = extensions or {}

    def to_problem_dict(self, instance: str = "") -> dict[str, Any]:
        """Serialize exception into an RFC 7807 Problem Details dictionary."""
        problem: dict[str, Any] = {
            "type": self.error_type,
            "title": self.title,
            "status": self.status_code,
            "detail": self.detail,
        }
        if instance:
            problem["instance"] = instance
        problem.update(self.extensions)
        return problem


@dataclass
class RequestContext:
    """Normalized HTTP request object passed to route handlers."""

    method: str
    path: str
    query_params: dict[str, str] = field(default_factory=dict)
    path_params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    raw_body: bytes = b""
    client_ip: str = "127.0.0.1"
    principal: AuthPrincipal | None = None
    validated_body: Any = None

    def json(self) -> Any:
        """Parse and return the request body as JSON."""
        if not self.raw_body:
            return {}
        try:
            return json.loads(self.raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiHttpError(
                status_code=400,
                title="Malformed JSON",
                detail=f"Unable to parse JSON request body: {exc}",
                error_type="https://apiforge.dev/errors/malformed-json",
            ) from exc


@dataclass
class HttpResponse:
    """Normalized HTTP response returned by route handlers and middleware."""

    status_code: int = 200
    body: bytes = b""
    content_type: str = "application/json; charset=utf-8"
    headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def json(
        cls,
        data: Any,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        content_type: str = "application/json; charset=utf-8",
    ) -> HttpResponse:
        """Create a JSON HttpResponse from any serializable object or dataclass."""
        payload = json.dumps(serialize_value(data), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return cls(
            status_code=status_code,
            body=payload,
            content_type=content_type,
            headers=dict(headers or {}),
        )

    @classmethod
    def html(cls, html_text: str, status_code: int = 200) -> HttpResponse:
        """Create an HTML HttpResponse."""
        return cls(
            status_code=status_code,
            body=html_text.encode("utf-8"),
            content_type="text/html; charset=utf-8",
        )

    @classmethod
    def text(cls, plain_text: str, status_code: int = 200) -> HttpResponse:
        """Create a plain-text HttpResponse."""
        return cls(
            status_code=status_code,
            body=plain_text.encode("utf-8"),
            content_type="text/plain; version=0.0.4; charset=utf-8",
        )

    def json_data(self) -> Any:
        """Decode the response body as JSON (convenience helper for tests)."""
        if not self.body:
            return None
        return json.loads(self.body.decode("utf-8"))


RouteHandler = Callable[[RequestContext], Any]


@dataclass
class RouteDefinition:
    """Metadata and compiled matcher for a registered HTTP route."""

    method: str
    path_template: str
    handler: RouteHandler
    summary: str
    description: str
    tags: list[str]
    auth_required: bool
    request_model: type[Any] | None
    status_code: int
    param_names: list[str]
    regex: re.Pattern[str]


_PARAM_PATTERN = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


def compile_path_template(path_template: str) -> tuple[re.Pattern[str], list[str]]:
    """Compile a route template like '/api/v1/tasks/{task_id}' into a regex and parameter list."""
    param_names: list[str] = []
    pos = 0
    parts: list[str] = ["^"]
    for match in _PARAM_PATTERN.finditer(path_template):
        parts.append(re.escape(path_template[pos : match.start()]))
        param_name = match.group(1)
        param_names.append(param_name)
        parts.append(f"(?P<{param_name}>[^/]+)")
        pos = match.end()
    parts.append(re.escape(path_template[pos:]))
    parts.append("$")
    return re.compile("".join(parts)), param_names


def parse_url_and_query(raw_url: str) -> tuple[str, dict[str, str]]:
    """Split a request URL into normalized path and single-value query dictionary."""
    split = urlsplit(raw_url)
    path = split.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    parsed_qs = parse_qs(split.query, keep_blank_values=True)
    query_params = {k: v[-1] for k, v in parsed_qs.items() if v}
    return path, query_params


class Router:
    """Declarative HTTP request router supporting path parameters and schema validation."""

    def __init__(self) -> None:
        """Initialize an empty route table."""
        self._routes: list[RouteDefinition] = []

    @property
    def routes(self) -> list[RouteDefinition]:
        """Return a copy of all registered routes."""
        return list(self._routes)

    def add_route(
        self,
        method: str,
        path_template: str,
        handler: RouteHandler,
        *,
        summary: str | None = None,
        description: str | None = None,
        tags: list[str] | None = None,
        auth_required: bool = False,
        request_model: type[Any] | None = None,
        status_code: int = 200,
    ) -> RouteDefinition:
        """Register a route handler and compile its path template."""
        normalized_method = method.upper()
        normalized_path = path_template if path_template == "/" else path_template.rstrip("/")
        regex, param_names = compile_path_template(normalized_path)
        doc = (handler.__doc__ or "").strip()
        first_line = doc.splitlines()[0].strip() if doc else f"{normalized_method} {normalized_path}"

        route_def = RouteDefinition(
            method=normalized_method,
            path_template=normalized_path,
            handler=handler,
            summary=summary or first_line,
            description=description or doc,
            tags=tags or ["default"],
            auth_required=auth_required,
            request_model=request_model,
            status_code=status_code,
            param_names=param_names,
            regex=regex,
        )
        self._routes.append(route_def)
        return route_def

    def match(self, method: str, path: str) -> tuple[RouteDefinition, dict[str, str]]:
        """Find a matching route for `(method, path)` or raise 404 / 405 ApiHttpError."""
        normalized_method = method.upper()
        allowed_methods: list[str] = []

        for route in self._routes:
            match = route.regex.match(path)
            if match:
                if route.method == normalized_method:
                    return route, match.groupdict()
                allowed_methods.append(route.method)

        if allowed_methods:
            raise ApiHttpError(
                status_code=405,
                title="Method Not Allowed",
                detail=f"Method {normalized_method} not allowed for {path}. Allowed: {', '.join(allowed_methods)}",
                error_type="https://apiforge.dev/errors/method-not-allowed",
                extensions={"allowed_methods": allowed_methods},
            )

        raise ApiHttpError(
            status_code=404,
            title="Resource Not Found",
            detail=f"No route matched {normalized_method} {path}",
            error_type="https://apiforge.dev/errors/not-found",
        )

    def bind_request_model(self, route: RouteDefinition, ctx: RequestContext) -> None:
        """Validate request body against `route.request_model` if configured."""
        if route.request_model is None:
            return
        raw_json = ctx.json()
        try:
            ctx.validated_body = validate_payload(route.request_model, raw_json)
        except SchemaValidationError as exc:
            raise ApiHttpError(
                status_code=422,
                title="Unprocessable Entity",
                detail=str(exc),
                error_type="https://apiforge.dev/errors/validation-error",
                extensions={"errors": exc.errors},
            ) from exc

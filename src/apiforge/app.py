"""Main REST API application wiring routing, security, rate limiting, OpenAPI, and domain endpoints."""

from __future__ import annotations

import threading
import time
from typing import Any

from apiforge.openapi import build_docs_html, build_openapi_spec
from apiforge.ratelimit import TokenBucketRateLimiter
from apiforge.router import (
    ApiHttpError,
    HttpResponse,
    RequestContext,
    RouteDefinition,
    RouteHandler,
    Router,
    parse_url_and_query,
)
from apiforge.schema import (
    TaskCreateRequest,
    TokenRequest,
    WebhookCreateRequest,
)
from apiforge.security import (
    AuthenticationError,
    authenticate_headers,
    encode_jwt,
    generate_secret_token,
)
from apiforge.storage import StorageRepository
from apiforge.worker import TaskWorker


class ApiForgeApp:
    """Declarative REST API application with built-in auth, rate limiting, OpenAPI 3.1, and SQLite."""

    def __init__(
        self,
        *,
        title: str = "PyApiForge Service API",
        version: str = "1.0.0",
        description: str = "Zero-dependency REST API micro-framework with JWT/HMAC auth, rate limiting, and task/webhook engine.",
        db_path: str = ":memory:",
        jwt_secret: str = "apiforge-default-jwt-secret-key-2026",
        api_keys: dict[str, str] | None = None,
        rate_limit_capacity: int = 60,
        rate_limit_refill_per_sec: float = 1.0,
    ) -> None:
        """Initialize the application, storage layer, worker, and default routes."""
        self.title = title
        self.version = version
        self.description = description
        self.jwt_secret = jwt_secret
        self.api_keys = dict(api_keys or {"afg_dev_master_key_2026": "system-admin"})
        self.started_at = time.time()

        self.router = Router()
        self.storage = StorageRepository(db_path=db_path)
        self.worker = TaskWorker(storage=self.storage)
        self.rate_limiter = TokenBucketRateLimiter(
            capacity=rate_limit_capacity,
            refill_rate_per_sec=rate_limit_refill_per_sec,
        )

        self._metrics_lock = threading.Lock()
        self._total_requests = 0
        self._status_counts: dict[int, int] = {}
        self._total_latency_ms = 0.0

        self._register_builtin_routes()

    def get(self, path: str, **kwargs: Any) -> Any:
        """Decorator for registering a GET endpoint."""
        def decorator(func: RouteHandler) -> RouteHandler:
            self.router.add_route("GET", path, func, **kwargs)
            return func
        return decorator

    def post(self, path: str, **kwargs: Any) -> Any:
        """Decorator for registering a POST endpoint."""
        def decorator(func: RouteHandler) -> RouteHandler:
            self.router.add_route("POST", path, func, **kwargs)
            return func
        return decorator

    def delete(self, path: str, **kwargs: Any) -> Any:
        """Decorator for registering a DELETE endpoint."""
        def decorator(func: RouteHandler) -> RouteHandler:
            self.router.add_route("DELETE", path, func, **kwargs)
            return func
        return decorator

    @property
    def routes(self) -> list[RouteDefinition]:
        """Return all registered route definitions."""
        return self.router.routes

    def openapi_spec(self) -> dict[str, Any]:
        """Build and return the OpenAPI 3.1.0 specification dictionary."""
        return build_openapi_spec(
            title=self.title,
            version=self.version,
            description=self.description,
            routes=self.router.routes,
        )

    def handle_request(
        self,
        method: str,
        raw_url: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        client_ip: str = "127.0.0.1",
    ) -> HttpResponse:
        """Execute middleware pipeline (Rate Limit -> Auth -> Validation -> Route -> Audit Log)."""
        start_time = time.perf_counter()
        req_headers = dict(headers or {})
        path, query_params = parse_url_and_query(raw_url)
        client_key = self._extract_client_key(req_headers, client_ip)
        rl_decision = self.rate_limiter.check(client_key)
        rl_headers = rl_decision.to_headers()

        actor = "anonymous"
        try:
            if not rl_decision.allowed:
                raise ApiHttpError(
                    status_code=429,
                    title="Too Many Requests",
                    detail=f"Rate limit of {rl_decision.limit} requests exceeded. Retry in {rl_decision.retry_after}s.",
                    error_type="https://apiforge.dev/errors/rate-limit-exceeded",
                    extensions={"retry_after": rl_decision.retry_after},
                )

            route, path_params = self.router.match(method, path)
            ctx = RequestContext(
                method=method.upper(),
                path=path,
                query_params=query_params,
                path_params=path_params,
                headers=req_headers,
                raw_body=body,
                client_ip=client_ip,
            )

            if route.auth_required:
                try:
                    ctx.principal = authenticate_headers(
                        req_headers,
                        jwt_secret=self.jwt_secret,
                        valid_api_keys=self.api_keys,
                    )
                    actor = ctx.principal.subject
                except AuthenticationError as exc:
                    raise ApiHttpError(
                        status_code=401,
                        title="Unauthorized",
                        detail=str(exc),
                        error_type="https://apiforge.dev/errors/unauthorized",
                    ) from exc

            self.router.bind_request_model(route, ctx)
            result = route.handler(ctx)
            if isinstance(result, HttpResponse):
                response = result
            else:
                response = HttpResponse.json(result, status_code=route.status_code)

        except ApiHttpError as exc:
            problem = exc.to_problem_dict(instance=path)
            response = HttpResponse.json(
                problem,
                status_code=exc.status_code,
                content_type="application/problem+json; charset=utf-8",
            )
        except Exception as exc:
            problem = {
                "type": "https://apiforge.dev/errors/internal-error",
                "title": "Internal Server Error",
                "status": 500,
                "detail": str(exc),
                "instance": path,
            }
            response = HttpResponse.json(
                problem,
                status_code=500,
                content_type="application/problem+json; charset=utf-8",
            )

        for hdr_key, hdr_val in rl_headers.items():
            response.headers.setdefault(hdr_key, hdr_val)

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        self._record_telemetry(
            method=method.upper(),
            path=path,
            status_code=response.status_code,
            latency_ms=latency_ms,
            actor=actor,
            client_ip=client_ip,
        )
        return response

    def _extract_client_key(self, headers: dict[str, str], client_ip: str) -> str:
        """Determine the rate limit bucket key from API key, Bearer token, or client IP."""
        normalized = {k.lower(): v for k, v in headers.items()}
        if "x-api-key" in normalized:
            return f"key:{normalized['x-api-key']}"
        if "authorization" in normalized:
            return f"auth:{normalized['authorization'][:32]}"
        return f"ip:{client_ip}"

    def _record_telemetry(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        actor: str,
        client_ip: str,
    ) -> None:
        """Update in-memory request counters and write an entry to the SQLite audit log."""
        with self._metrics_lock:
            self._total_requests += 1
            self._status_counts[status_code] = self._status_counts.get(status_code, 0) + 1
            self._total_latency_ms += latency_ms
        self.storage.record_audit_log(
            method=method,
            path=path,
            status_code=status_code,
            latency_ms=latency_ms,
            actor=actor,
            client_ip=client_ip,
        )

    def _register_builtin_routes(self) -> None:
        """Register system, authentication, task management, webhook, and audit routes."""

        @self.get("/health", tags=["system"], summary="Service health and uptime check")
        def health_check(_ctx: RequestContext) -> dict[str, Any]:
            """Return service liveness, uptime seconds, and database connectivity status."""
            uptime = round(time.time() - self.started_at, 3)
            return {
                "status": "ok",
                "service": self.title,
                "version": self.version,
                "uptime_seconds": uptime,
                "database": "connected",
            }

        @self.get("/metrics", tags=["system"], summary="Application telemetry and Prometheus metrics")
        def metrics_endpoint(ctx: RequestContext) -> Any:
            """Return request counters and latency telemetry as JSON or Prometheus text format."""
            with self._metrics_lock:
                total = self._total_requests
                avg_latency = round(self._total_latency_ms / total, 3) if total > 0 else 0.0
                status_breakdown = {str(k): v for k, v in sorted(self._status_counts.items())}

            if ctx.query_params.get("format") == "prometheus":
                lines = [
                    "# HELP apiforge_requests_total Total number of HTTP requests processed.",
                    "# TYPE apiforge_requests_total counter",
                    f"apiforge_requests_total {total}",
                    "# HELP apiforge_request_latency_avg_ms Average request latency in milliseconds.",
                    "# TYPE apiforge_request_latency_avg_ms gauge",
                    f"apiforge_request_latency_avg_ms {avg_latency}",
                ]
                for code, count in status_breakdown.items():
                    lines.append(f'apiforge_http_responses_total{{status="{code}"}} {count}')
                return HttpResponse.text("\n".join(lines) + "\n")

            return {
                "requests_total": total,
                "average_latency_ms": avg_latency,
                "status_breakdown": status_breakdown,
                "tasks_count": len(self.storage.list_tasks(limit=200)),
                "webhooks_count": len(self.storage.list_webhooks()),
            }

        @self.get("/openapi.json", tags=["documentation"], summary="OpenAPI 3.1.0 specification JSON")
        def openapi_json(_ctx: RequestContext) -> dict[str, Any]:
            """Return the dynamically generated OpenAPI 3.1.0 JSON schema."""
            return self.openapi_spec()

        @self.get("/docs", tags=["documentation"], summary="Interactive HTML API documentation")
        def openapi_docs(_ctx: RequestContext) -> HttpResponse:
            """Render the interactive HTML documentation console."""
            return HttpResponse.html(build_docs_html(self.openapi_spec()))

        @self.post(
            "/api/v1/auth/token",
            tags=["auth"],
            auth_required=True,
            request_model=TokenRequest,
            status_code=201,
            summary="Issue a signed HS256 JWT access token",
        )
        def issue_token(ctx: RequestContext) -> dict[str, Any]:
            """Issue a signed HS256 JWT token for the requested subject and role."""
            body: TokenRequest = ctx.validated_body
            token = encode_jwt(
                {"sub": body.subject, "role": body.role},
                secret=self.jwt_secret,
                ttl_seconds=body.ttl_seconds,
            )
            return {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": body.ttl_seconds,
                "subject": body.subject,
                "role": body.role,
            }

        @self.post(
            "/api/v1/tasks",
            tags=["tasks"],
            auth_required=True,
            request_model=TaskCreateRequest,
            status_code=201,
            summary="Create a new managed asynchronous task",
        )
        def create_task(ctx: RequestContext) -> dict[str, Any]:
            """Validate and persist a new task in pending state."""
            req: TaskCreateRequest = ctx.validated_body
            owner = ctx.principal.subject if ctx.principal else "anonymous"
            return self.storage.create_task(
                title=req.title,
                action=req.action,
                payload=req.payload,
                priority=req.priority,
                max_retries=req.max_retries,
                webhook_url=req.webhook_url,
                owner=owner,
            )

        @self.get(
            "/api/v1/tasks",
            tags=["tasks"],
            auth_required=True,
            summary="List tasks with optional status filter and pagination",
        )
        def list_tasks(ctx: RequestContext) -> dict[str, Any]:
            """List persisted tasks ordered by priority and creation timestamp."""
            status_filter = ctx.query_params.get("status")
            limit = int(ctx.query_params.get("limit", "50"))
            offset = int(ctx.query_params.get("offset", "0"))
            items = self.storage.list_tasks(status=status_filter, limit=limit, offset=offset)
            return {"items": items, "count": len(items)}

        @self.get(
            "/api/v1/tasks/{task_id}",
            tags=["tasks"],
            auth_required=True,
            summary="Get task details by ID",
        )
        def get_task(ctx: RequestContext) -> dict[str, Any]:
            """Retrieve a single task by its unique identifier."""
            task_id = ctx.path_params["task_id"]
            task = self.storage.get_task(task_id)
            if task is None:
                raise ApiHttpError(
                    status_code=404,
                    title="Task Not Found",
                    detail=f"Task '{task_id}' does not exist",
                    error_type="https://apiforge.dev/errors/task-not-found",
                )
            return task

        @self.post(
            "/api/v1/tasks/{task_id}/process",
            tags=["tasks"],
            auth_required=True,
            summary="Execute a task immediately and dispatch signed webhooks",
        )
        def process_task(ctx: RequestContext) -> dict[str, Any]:
            """Execute the specified task through the worker engine and emit webhook events."""
            task_id = ctx.path_params["task_id"]
            try:
                return self.worker.process_task(task_id)
            except KeyError as exc:
                raise ApiHttpError(
                    status_code=404,
                    title="Task Not Found",
                    detail=f"Task '{task_id}' does not exist",
                    error_type="https://apiforge.dev/errors/task-not-found",
                ) from exc

        @self.delete(
            "/api/v1/tasks/{task_id}",
            tags=["tasks"],
            auth_required=True,
            summary="Delete a task by ID",
        )
        def delete_task(ctx: RequestContext) -> dict[str, Any]:
            """Remove a task record from persistence."""
            task_id = ctx.path_params["task_id"]
            deleted = self.storage.delete_task(task_id)
            if not deleted:
                raise ApiHttpError(
                    status_code=404,
                    title="Task Not Found",
                    detail=f"Task '{task_id}' does not exist",
                    error_type="https://apiforge.dev/errors/task-not-found",
                )
            return {"deleted": True, "task_id": task_id}

        @self.post(
            "/api/v1/webhooks",
            tags=["webhooks"],
            auth_required=True,
            request_model=WebhookCreateRequest,
            status_code=201,
            summary="Register an HMAC-signed event webhook subscription",
        )
        def create_webhook(ctx: RequestContext) -> dict[str, Any]:
            """Create a new webhook endpoint subscription with an HMAC signing secret."""
            req: WebhookCreateRequest = ctx.validated_body
            owner = ctx.principal.subject if ctx.principal else "anonymous"
            secret = req.secret or generate_secret_token("whsec")
            return self.storage.create_webhook(
                target_url=req.target_url,
                events=req.events,
                secret=secret,
                description=req.description,
                owner=owner,
            )

        @self.get(
            "/api/v1/webhooks",
            tags=["webhooks"],
            auth_required=True,
            summary="List registered webhook subscriptions and recent deliveries",
        )
        def list_webhooks(ctx: RequestContext) -> dict[str, Any]:
            """List all registered webhook endpoints and recent signed delivery records."""
            task_id = ctx.query_params.get("task_id")
            subscriptions = self.storage.list_webhooks()
            deliveries = self.storage.list_webhook_deliveries(task_id=task_id)
            return {
                "subscriptions": subscriptions,
                "deliveries": deliveries,
            }

        @self.get(
            "/api/v1/audit-logs",
            tags=["audit"],
            auth_required=True,
            summary="List recent HTTP request audit log entries",
        )
        def list_audit_logs(ctx: RequestContext) -> dict[str, Any]:
            """Fetch recent API audit logs recorded in SQLite."""
            limit = int(ctx.query_params.get("limit", "50"))
            logs = self.storage.list_audit_logs(limit=limit)
            return {"items": logs, "count": len(logs)}

"""PyApiForge — Declarative REST API micro-framework, OpenAPI 3.1 generator, and task/webhook engine."""

from apiforge.app import ApiForgeApp
from apiforge.ratelimit import RateLimitDecision, TokenBucketRateLimiter
from apiforge.router import ApiHttpError, HttpResponse, RequestContext, Router
from apiforge.schema import (
    ApiKeyCreateRequest,
    SchemaValidationError,
    TaskBatchCreateRequest,
    TaskCreateRequest,
    TaskUpdateRequest,
    TokenRequest,
    WebhookCreateRequest,
    dataclass_to_json_schema,
    validate_payload,
)
from apiforge.security import (
    AuthenticationError,
    AuthPrincipal,
    decode_jwt,
    encode_jwt,
    sign_webhook_payload,
    verify_api_key,
    verify_webhook_signature,
)
from apiforge.server import TestClient, create_http_server
from apiforge.storage import StorageRepository
from apiforge.worker import TaskWorker

__version__ = "1.0.0"

__all__ = [
    "ApiForgeApp",
    "ApiHttpError",
    "ApiKeyCreateRequest",
    "AuthPrincipal",
    "AuthenticationError",
    "HttpResponse",
    "RateLimitDecision",
    "RequestContext",
    "Router",
    "SchemaValidationError",
    "StorageRepository",
    "TaskBatchCreateRequest",
    "TaskCreateRequest",
    "TaskUpdateRequest",
    "TaskWorker",
    "TestClient",
    "TokenBucketRateLimiter",
    "TokenRequest",
    "WebhookCreateRequest",
    "create_http_server",
    "dataclass_to_json_schema",
    "decode_jwt",
    "encode_jwt",
    "sign_webhook_payload",
    "validate_payload",
    "verify_api_key",
    "verify_webhook_signature",
]

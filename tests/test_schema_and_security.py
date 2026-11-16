"""Unit tests for schema validation, JSON Schema generation, JWT/HMAC security, and rate limiting."""

from __future__ import annotations

import unittest

from apiforge.ratelimit import TokenBucketRateLimiter
from apiforge.schema import (
    SchemaValidationError,
    TaskCreateRequest,
    TaskUpdateRequest,
    WebhookCreateRequest,
    dataclass_to_json_schema,
    validate_payload,
)
from apiforge.security import (
    AuthenticationError,
    authenticate_headers,
    decode_jwt,
    encode_jwt,
    sign_webhook_payload,
    verify_api_key,
    verify_webhook_signature,
)


class TestSchemaAndSecurity(unittest.TestCase):
    """Test suite for schema validation, JWT/HMAC crypto, and token bucket rate limiting."""

    def test_validate_task_create_request_success(self) -> None:
        """Valid payload should instantiate TaskCreateRequest with defaults."""
        raw = {
            "title": "Normalize user events",
            "payload": {"User_ID": 42, "Event": "signup"},
            "priority": 4,
        }
        req = validate_payload(TaskCreateRequest, raw)
        self.assertIsInstance(req, TaskCreateRequest)
        self.assertEqual(req.title, "Normalize user events")
        self.assertEqual(req.action, "transform_payload")
        self.assertEqual(req.priority, 4)
        self.assertIsNone(req.webhook_url)

    def test_validate_task_create_request_invalid_priority(self) -> None:
        """Out-of-range priority or empty title should raise SchemaValidationError."""
        raw = {"title": "   ", "priority": 9}
        with self.assertRaises(SchemaValidationError) as ctx:
            validate_payload(TaskCreateRequest, raw)
        fields = {err["field"] for err in ctx.exception.errors}
        self.assertIn("title", fields)
        self.assertIn("priority", fields)

    def test_dataclass_to_json_schema_structure(self) -> None:
        """Generated JSON Schema should match OpenAPI 3.1 property and nullable conventions."""
        schema = dataclass_to_json_schema(TaskCreateRequest)
        self.assertEqual(schema["type"], "object")
        self.assertIn("title", schema["required"])
        self.assertEqual(schema["properties"]["priority"]["type"], "integer")
        self.assertEqual(schema["properties"]["webhook_url"]["type"], ["string", "null"])

    def test_validate_task_update_request_domain_constraints(self) -> None:
        """Partial task updates should validate only supplied metadata fields."""
        req = validate_payload(TaskUpdateRequest, {"title": "Updated", "payload": {"key": "value"}})
        self.assertEqual(req.title, "Updated")
        self.assertEqual(req.priority, None)

        with self.assertRaises(SchemaValidationError) as ctx:
            validate_payload(TaskUpdateRequest, {"title": " ", "priority": 6, "max_retries": -1})
        self.assertEqual(
            {error["field"] for error in ctx.exception.errors},
            {"title", "priority", "max_retries"},
        )

    def test_webhook_validation_requires_http_url(self) -> None:
        """WebhookCreateRequest should reject non-HTTP target URLs."""
        with self.assertRaises(SchemaValidationError):
            validate_payload(WebhookCreateRequest, {"target_url": "ftp://example.com/hook"})

    def test_jwt_encode_and_decode_roundtrip(self) -> None:
        """HS256 JWT tokens should verify and preserve claims when valid."""
        secret = "unit-test-secret-key"
        token = encode_jwt({"sub": "user-123", "role": "admin"}, secret=secret, ttl_seconds=60, now=1000)
        claims = decode_jwt(token, secret=secret, now=1030)
        self.assertEqual(claims["sub"], "user-123")
        self.assertEqual(claims["role"], "admin")
        self.assertEqual(claims["iat"], 1000)
        self.assertEqual(claims["exp"], 1060)

    def test_jwt_rejects_expired_and_tampered_tokens(self) -> None:
        """Expired or tampered JWT tokens should raise AuthenticationError."""
        secret = "unit-test-secret-key"
        token = encode_jwt({"sub": "user-123"}, secret=secret, ttl_seconds=30, now=1000)
        with self.assertRaises(AuthenticationError):
            decode_jwt(token, secret=secret, now=1031)
        with self.assertRaises(AuthenticationError):
            decode_jwt(token, secret="wrong-secret", now=1010)

    def test_api_key_and_header_authentication(self) -> None:
        """API key and Bearer token headers should resolve into AuthPrincipal."""
        valid_keys = {"afg_live_key_abc": "service-worker"}
        principal = verify_api_key("afg_live_key_abc", valid_keys)
        self.assertEqual(principal.subject, "service-worker")
        self.assertEqual(principal.auth_method, "api_key")

        jwt_token = encode_jwt({"sub": "alice", "role": "developer"}, secret="jwt-sec")
        jwt_principal = authenticate_headers(
            {"Authorization": f"Bearer {jwt_token}"},
            jwt_secret="jwt-sec",
            valid_api_keys=valid_keys,
        )
        self.assertEqual(jwt_principal.subject, "alice")
        self.assertEqual(jwt_principal.auth_method, "jwt")

    def test_webhook_hmac_signature_verification(self) -> None:
        """Webhook HMAC-SHA256 signatures should validate payload integrity and timestamp window."""
        body = b'{"event":"task.completed","task_id":"tsk_1"}'
        secret = "whsec_test_secret"
        sig_header, ts = sign_webhook_payload(body, secret, timestamp=2000)
        self.assertTrue(verify_webhook_signature(body, sig_header, secret, now=2100))
        self.assertFalse(verify_webhook_signature(body, sig_header, secret, now=2600))
        self.assertFalse(verify_webhook_signature(b'{"tampered":true}', sig_header, secret, now=2100))

    def test_token_bucket_rate_limiter_refill_and_blocking(self) -> None:
        """TokenBucketRateLimiter should block when exhausted and recover as time advances."""
        limiter = TokenBucketRateLimiter(capacity=2, refill_rate_per_sec=1.0)
        d1 = limiter.check("client-a", now=100.0)
        d2 = limiter.check("client-a", now=100.0)
        d3 = limiter.check("client-a", now=100.0)

        self.assertTrue(d1.allowed)
        self.assertEqual(d1.remaining, 1)
        self.assertTrue(d2.allowed)
        self.assertEqual(d2.remaining, 0)
        self.assertFalse(d3.allowed)
        self.assertGreaterEqual(d3.retry_after, 1)
        self.assertIn("Retry-After", d3.to_headers())

        d4 = limiter.check("client-a", now=101.5)
        self.assertTrue(d4.allowed)


if __name__ == "__main__":
    unittest.main()

"""HS256 JWT authentication, constant-time API key verification, and HMAC webhook signing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any


class AuthenticationError(PermissionError):
    """Raised when an API key or JWT token fails verification."""


@dataclass(frozen=True)
class AuthPrincipal:
    """Authenticated caller identity extracted from JWT or API key."""

    subject: str
    role: str
    auth_method: str
    claims: dict[str, Any]


def _b64url_encode(data: bytes) -> str:
    """Encode raw bytes using URL-safe Base64 without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    """Decode a URL-safe Base64 string, restoring padding as required."""
    padding = "=" * ((4 - len(encoded) % 4) % 4)
    return base64.urlsafe_b64decode((encoded + padding).encode("ascii"))


def encode_jwt(
    payload: dict[str, Any],
    secret: str,
    ttl_seconds: int = 3600,
    now: int | None = None,
) -> str:
    """Create a signed HS256 JSON Web Token (JWT) with iat and exp claims."""
    issued_at = int(time.time()) if now is None else now
    header = {"alg": "HS256", "typ": "JWT"}
    body = {
        "iat": issued_at,
        "exp": issued_at + ttl_seconds,
        **payload,
    }
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    body_b64 = _b64url_encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header_b64}.{body_b64}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)
    return f"{header_b64}.{body_b64}.{sig_b64}"


def decode_jwt(token: str, secret: str, now: int | None = None) -> dict[str, Any]:
    """Verify and decode an HS256 JWT token, validating signature and expiration."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthenticationError("Malformed JWT token: expected 3 segments")

    header_b64, body_b64, sig_b64 = parts
    signing_input = f"{header_b64}.{body_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()

    try:
        provided_sig = _b64url_decode(sig_b64)
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        claims = json.loads(_b64url_decode(body_b64).decode("utf-8"))
    except Exception as exc:
        raise AuthenticationError("Malformed JWT encoding") from exc

    if header.get("alg") != "HS256":
        raise AuthenticationError(f"Unsupported JWT algorithm: {header.get('alg')}")

    if not hmac.compare_digest(provided_sig, expected_sig):
        raise AuthenticationError("Invalid JWT signature")

    current_time = int(time.time()) if now is None else now
    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and current_time >= exp:
        raise AuthenticationError("JWT token has expired")

    return dict(claims)


def verify_api_key(provided_key: str, valid_keys: dict[str, str]) -> AuthPrincipal:
    """Verify an API key against a mapping of {api_key: owner_subject} in constant time."""
    if not provided_key:
        raise AuthenticationError("Missing API key")

    matched_subject: str | None = None
    for candidate_key, subject in valid_keys.items():
        if hmac.compare_digest(provided_key.encode("utf-8"), candidate_key.encode("utf-8")):
            matched_subject = subject

    if matched_subject is None:
        raise AuthenticationError("Invalid API key")

    return AuthPrincipal(
        subject=matched_subject,
        role="admin",
        auth_method="api_key",
        claims={"sub": matched_subject, "role": "admin"},
    )


def authenticate_headers(
    headers: dict[str, str],
    jwt_secret: str,
    valid_api_keys: dict[str, str],
) -> AuthPrincipal:
    """Authenticate an HTTP request using either Authorization Bearer JWT or X-API-Key."""
    normalized = {k.lower(): v for k, v in headers.items()}

    api_key = normalized.get("x-api-key")
    if api_key:
        return verify_api_key(api_key.strip(), valid_api_keys)

    auth_header = normalized.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        raw_token = auth_header[7:].strip()
        claims = decode_jwt(raw_token, jwt_secret)
        subject = str(claims.get("sub", "anonymous"))
        role = str(claims.get("role", "developer"))
        return AuthPrincipal(
            subject=subject,
            role=role,
            auth_method="jwt",
            claims=claims,
        )

    raise AuthenticationError(
        "Authentication required: provide 'Authorization: Bearer <jwt>' or 'X-API-Key: <key>' header"
    )


def sign_webhook_payload(payload_bytes: bytes, secret: str, timestamp: int | None = None) -> tuple[str, int]:
    """Compute an HMAC-SHA256 webhook signature header value ('t=<ts>,v1=<hex>')."""
    ts = int(time.time()) if timestamp is None else timestamp
    signed_content = f"{ts}.".encode("ascii") + payload_bytes
    digest = hmac.new(secret.encode("utf-8"), signed_content, hashlib.sha256).hexdigest()
    return f"t={ts},v1={digest}", ts


def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str,
    secret: str,
    tolerance_seconds: int = 300,
    now: int | None = None,
) -> bool:
    """Verify an HMAC-SHA256 webhook signature header and check replay tolerance."""
    parts: dict[str, str] = {}
    for item in signature_header.split(","):
        if "=" in item:
            k, v = item.split("=", 1)
            parts[k.strip()] = v.strip()

    if "t" not in parts or "v1" not in parts:
        return False

    try:
        ts = int(parts["t"])
    except ValueError:
        return False

    current_time = int(time.time()) if now is None else now
    if abs(current_time - ts) > tolerance_seconds:
        return False

    expected_header, _ = sign_webhook_payload(payload_bytes, secret, timestamp=ts)
    expected_v1 = expected_header.split(",v1=", 1)[1]
    return hmac.compare_digest(parts["v1"], expected_v1)


def generate_secret_token(prefix: str = "afg") -> str:
    """Generate a cryptographically strong random token with a recognizable prefix."""
    return f"{prefix}_{secrets.token_urlsafe(24)}"

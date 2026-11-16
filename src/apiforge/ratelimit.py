"""Thread-safe Token Bucket rate limiter with standard X-RateLimit-* header generation."""

from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    """Result of evaluating a client request against the token bucket."""

    allowed: bool
    limit: int
    remaining: int
    reset_epoch: int
    retry_after: int

    def to_headers(self) -> dict[str, str]:
        """Build standard HTTP rate limit headers."""
        headers = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Reset": str(self.reset_epoch),
        }
        if not self.allowed:
            headers["Retry-After"] = str(max(1, self.retry_after))
        return headers


@dataclass
class _BucketState:
    """Mutable token bucket state per client key."""

    tokens: float
    last_refill: float


class TokenBucketRateLimiter:
    """Token Bucket rate limiter keyed by client identity (API key or IP address)."""

    def __init__(self, capacity: int = 60, refill_rate_per_sec: float = 1.0) -> None:
        """Initialize the limiter with bucket capacity and token refill rate per second."""
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if refill_rate_per_sec <= 0:
            raise ValueError("refill_rate_per_sec must be positive")
        self.capacity = capacity
        self.refill_rate = refill_rate_per_sec
        self._buckets: dict[str, _BucketState] = {}
        self._lock = threading.Lock()

    def check(self, client_key: str, cost: float = 1.0, now: float | None = None) -> RateLimitDecision:
        """Consume tokens for `client_key` and return a RateLimitDecision."""
        current_time = time.time() if now is None else now
        with self._lock:
            bucket = self._buckets.get(client_key)
            if bucket is None:
                bucket = _BucketState(tokens=float(self.capacity), last_refill=current_time)
                self._buckets[client_key] = bucket
            else:
                elapsed = max(0.0, current_time - bucket.last_refill)
                bucket.tokens = min(float(self.capacity), bucket.tokens + elapsed * self.refill_rate)
                bucket.last_refill = current_time

            if bucket.tokens >= cost:
                bucket.tokens -= cost
                allowed = True
                retry_after = 0
            else:
                allowed = False
                deficit = cost - bucket.tokens
                retry_after = max(1, int(math.ceil(deficit / self.refill_rate)))

            remaining = max(0, int(math.floor(bucket.tokens)))
            missing_to_full = max(0.0, float(self.capacity) - bucket.tokens)
            reset_epoch = int(math.ceil(current_time + (missing_to_full / self.refill_rate)))

            return RateLimitDecision(
                allowed=allowed,
                limit=self.capacity,
                remaining=remaining,
                reset_epoch=reset_epoch,
                retry_after=retry_after,
            )

    def reset(self) -> None:
        """Clear all tracked client buckets."""
        with self._lock:
            self._buckets.clear()

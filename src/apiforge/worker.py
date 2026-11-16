"""Background task execution engine and HMAC-signed webhook event dispatcher."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

from apiforge.security import sign_webhook_payload
from apiforge.storage import StorageRepository

ActionHandler = Callable[[dict[str, Any]], dict[str, Any]]


def _handle_transform_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize keys and summarize values in a task payload."""
    normalized = {str(k).strip().lower(): v for k, v in payload.items()}
    return {
        "processed_keys": sorted(normalized.keys()),
        "field_count": len(normalized),
        "normalized": normalized,
    }


def _handle_compute_stats(payload: dict[str, Any]) -> dict[str, Any]:
    """Compute descriptive statistics over a numeric `values` list in the payload."""
    raw_values = payload.get("values", [])
    if not isinstance(raw_values, list) or not raw_values:
        raise ValueError("Payload must include a non-empty list under 'values'")
    numbers = [float(x) for x in raw_values]
    total = sum(numbers)
    count = len(numbers)
    mean = total / count
    variance = sum((x - mean) ** 2 for x in numbers) / count
    return {
        "count": count,
        "sum": round(total, 6),
        "min": min(numbers),
        "max": max(numbers),
        "mean": round(mean, 6),
        "std_dev": round(variance**0.5, 6),
    }


def _handle_hash_content(payload: dict[str, Any]) -> dict[str, Any]:
    """Compute SHA-256 and SHA-512 digests of the provided `text` field."""
    text = str(payload.get("text", ""))
    raw_bytes = text.encode("utf-8")
    return {
        "byte_length": len(raw_bytes),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "sha512": hashlib.sha512(raw_bytes).hexdigest(),
    }


def _handle_text_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    """Analyze character, word, unique word, and line counts in text."""
    text = str(payload.get("text", ""))
    words = [word.lower() for word in text.split() if word]
    return {
        "char_count": len(text),
        "word_count": len(words),
        "unique_word_count": len(set(words)),
        "line_count": len(text.splitlines()) if text else 0,
    }


def _handle_json_filter(payload: dict[str, Any]) -> dict[str, Any]:
    """Filter a JSON object to the requested keys."""
    data = payload.get("data", {})
    keys = payload.get("keys", [])
    if not isinstance(data, dict):
        raise ValueError("Payload field 'data' must be a dict")
    if not isinstance(keys, list):
        raise ValueError("Payload field 'keys' must be a list")
    return {
        "filtered": {key: data[key] for key in keys if key in data},
        "matched_count": sum(1 for key in keys if key in data),
    }


class TaskWorker:
    """Executes queued tasks with retry tracking and dispatches signed webhook events."""

    def __init__(self, storage: StorageRepository, default_webhook_secret: str = "whsec_default") -> None:
        """Initialize the task worker with built-in action handlers."""
        self.storage = storage
        self.default_webhook_secret = default_webhook_secret
        self._handlers: dict[str, ActionHandler] = {
            "transform_payload": _handle_transform_payload,
            "compute_stats": _handle_compute_stats,
            "hash_content": _handle_hash_content,
            "text_analysis": _handle_text_analysis,
            "json_filter": _handle_json_filter,
        }

    def register_action(self, action_name: str, handler: ActionHandler) -> None:
        """Register a custom task execution handler."""
        self._handlers[action_name] = handler

    def list_actions(self) -> list[dict[str, str]]:
        """List registered task actions and their descriptions."""
        return [
            {"name": name, "description": (handler.__doc__ or "").strip()}
            for name, handler in sorted(self._handlers.items())
        ]

    def process_task(self, task_id: str) -> dict[str, Any]:
        """Execute a single task synchronously, updating status and emitting webhooks."""
        task = self.storage.get_task(task_id)
        if task is None:
            raise KeyError(f"Task '{task_id}' not found")

        attempts = int(task["attempts"]) + 1
        max_retries = int(task["max_retries"])
        action = str(task["action"])
        payload = dict(task["payload"])

        handler = self._handlers.get(action)
        try:
            if payload.get("force_error"):
                raise RuntimeError(str(payload["force_error"]))
            if handler is None:
                raise ValueError(f"Unsupported task action: '{action}'")

            result = handler(payload)
            updated = self.storage.update_task_execution(
                task_id,
                status="completed",
                attempts=attempts,
                result=result,
                error_message=None,
            )
            event_type = "task.completed"
        except Exception as exc:
            final_status = "failed" if attempts >= max(1, max_retries) else "retrying"
            updated = self.storage.update_task_execution(
                task_id,
                status=final_status,
                attempts=attempts,
                result=None,
                error_message=str(exc),
            )
            event_type = "task.failed"

        if updated is None:
            raise RuntimeError(f"Task '{task_id}' disappeared during processing")

        deliveries = self._dispatch_webhooks(event_type, updated)
        return {
            "task": updated,
            "webhook_deliveries": deliveries,
        }

    def _dispatch_webhooks(self, event_type: str, task: dict[str, Any]) -> list[dict[str, Any]]:
        """Emit HMAC-signed webhook notifications for matching subscriptions and task webhook_url."""
        deliveries: list[dict[str, Any]] = []
        event_payload = {
            "event": event_type,
            "timestamp": int(time.time()),
            "data": {
                "task_id": task["id"],
                "title": task["title"],
                "action": task["action"],
                "status": task["status"],
                "attempts": task["attempts"],
                "result": task["result"],
                "error_message": task["error_message"],
            },
        }
        payload_bytes = json.dumps(event_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

        for sub in self.storage.list_webhooks():
            if event_type in sub["events"] or "*" in sub["events"]:
                sig_header, _ = sign_webhook_payload(payload_bytes, sub["secret"])
                record = self.storage.record_webhook_delivery(
                    webhook_id=sub["id"],
                    target_url=sub["target_url"],
                    event_type=event_type,
                    task_id=task["id"],
                    signature=sig_header,
                    payload=event_payload,
                )
                deliveries.append(record)

        direct_url = task.get("webhook_url")
        if direct_url:
            sig_header, _ = sign_webhook_payload(payload_bytes, self.default_webhook_secret)
            record = self.storage.record_webhook_delivery(
                webhook_id=None,
                target_url=str(direct_url),
                event_type=event_type,
                task_id=task["id"],
                signature=sig_header,
                payload=event_payload,
            )
            deliveries.append(record)

        return deliveries

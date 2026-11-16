"""Thread-safe SQLite3 persistence layer for tasks, webhooks, deliveries, and audit logs."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from typing import Any


class StorageRepository:
    """SQLite3 persistence repository supporting WAL mode and in-memory testing."""

    def __init__(self, db_path: str = ":memory:") -> None:
        """Initialize the SQLite connection and create schema tables."""
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        """Create tables for tasks, webhooks, webhook deliveries, and audit logs."""
        with self._lock:
            cursor = self._conn.cursor()
            if self.db_path != ":memory:":
                cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    action TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    priority INTEGER NOT NULL DEFAULT 3,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    max_retries INTEGER NOT NULL DEFAULT 3,
                    webhook_url TEXT,
                    result_json TEXT,
                    error_message TEXT,
                    owner TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS webhooks (
                    id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    events_json TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    description TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    id TEXT PRIMARY KEY,
                    webhook_id TEXT,
                    target_url TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    actor TEXT NOT NULL,
                    client_ip TEXT NOT NULL
                );
                """
            )
            self._conn.commit()

    def create_task(
        self,
        *,
        title: str,
        action: str,
        payload: dict[str, Any],
        priority: int,
        max_retries: int,
        webhook_url: str | None,
        owner: str,
    ) -> dict[str, Any]:
        """Insert a new task in `pending` state and return its dictionary representation."""
        now = time.time()
        task_id = f"tsk_{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tasks (
                    id, title, action, payload_json, status, priority,
                    attempts, max_retries, webhook_url, result_json, error_message,
                    owner, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'pending', ?, 0, ?, ?, NULL, NULL, ?, ?, ?)
                """,
                (
                    task_id,
                    title,
                    action,
                    json.dumps(payload, ensure_ascii=False),
                    priority,
                    max_retries,
                    webhook_url,
                    owner,
                    now,
                    now,
                ),
            )
            self._conn.commit()
        task = self.get_task(task_id)
        if task is None:
            raise RuntimeError("Failed to retrieve created task")
        return task

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        """Fetch a single task by ID or return None if not found."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return self._row_to_task(row) if row else None

    def list_tasks(
        self,
        *,
        status: str | None = None,
        min_priority: int | None = None,
        query_text: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List tasks ordered by priority descending and creation time descending."""
        query = "SELECT * FROM tasks"
        conditions: list[str] = []
        params: list[Any] = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if min_priority is not None:
            conditions.append("priority >= ?")
            params.append(min_priority)
        if query_text:
            conditions.append("(instr(lower(title), lower(?)) > 0 OR instr(lower(action), lower(?)) > 0)")
            params.extend([query_text, query_text])
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY priority DESC, created_at DESC LIMIT ? OFFSET ?"
        params.extend([max(1, min(limit, 200)), max(0, offset)])
        with self._lock:
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return [self._row_to_task(row) for row in rows]

    def task_stats(self) -> dict[str, dict[str, int] | int]:
        """Return aggregate task counts grouped by status and priority."""
        standard_statuses = ("pending", "retrying", "completed", "failed", "cancelled")
        standard_priorities = ("1", "2", "3", "4", "5")
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            status_rows = self._conn.execute(
                "SELECT status, COUNT(*) AS count FROM tasks GROUP BY status"
            ).fetchall()
            priority_rows = self._conn.execute(
                "SELECT priority, COUNT(*) AS count FROM tasks GROUP BY priority"
            ).fetchall()
        by_status = {status: 0 for status in standard_statuses}
        by_status.update({row["status"]: row["count"] for row in status_rows})
        by_priority = {priority: 0 for priority in standard_priorities}
        by_priority.update({str(row["priority"]): row["count"] for row in priority_rows})
        return {"total_tasks": total, "by_status": by_status, "by_priority": by_priority}

    def update_task_execution(
        self,
        task_id: str,
        *,
        status: str,
        attempts: int,
        result: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> dict[str, Any] | None:
        """Update task execution status, attempt counter, result payload, or error message."""
        now = time.time()
        result_json = json.dumps(result, ensure_ascii=False) if result is not None else None
        with self._lock:
            self._conn.execute(
                """
                UPDATE tasks
                SET status = ?, attempts = ?, result_json = ?, error_message = ?, updated_at = ?
                WHERE id = ?
                """,
                (status, attempts, result_json, error_message, now, task_id),
            )
            self._conn.commit()
        return self.get_task(task_id)

    def delete_task(self, task_id: str) -> bool:
        """Delete a task by ID and return True if a row was removed."""
        with self._lock:
            cursor = self._conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def create_webhook(
        self,
        *,
        target_url: str,
        events: list[str],
        secret: str,
        description: str,
        owner: str,
    ) -> dict[str, Any]:
        """Register a webhook subscription and return its dictionary record."""
        now = time.time()
        webhook_id = f"whk_{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO webhooks (id, target_url, events_json, secret, description, owner, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    webhook_id,
                    target_url,
                    json.dumps(events, ensure_ascii=False),
                    secret,
                    description,
                    owner,
                    now,
                ),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,)).fetchone()
        return self._row_to_webhook(row)

    def list_webhooks(self) -> list[dict[str, Any]]:
        """List all registered webhook subscriptions."""
        with self._lock:
            rows = self._conn.execute("SELECT * FROM webhooks ORDER BY created_at DESC").fetchall()
        return [self._row_to_webhook(row) for row in rows]

    def get_webhook(self, webhook_id: str) -> dict[str, Any] | None:
        """Fetch a single webhook by ID or return None if not found."""
        with self._lock:
            row = self._conn.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,)).fetchone()
        return self._row_to_webhook(row) if row else None

    def delete_webhook(self, webhook_id: str) -> bool:
        """Delete a webhook by ID and return True if a row was removed."""
        with self._lock:
            cursor = self._conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def record_webhook_delivery(
        self,
        *,
        webhook_id: str | None,
        target_url: str,
        event_type: str,
        task_id: str,
        signature: str,
        payload: dict[str, Any],
        status: str = "delivered",
    ) -> dict[str, Any]:
        """Persist a signed webhook delivery record."""
        delivery_id = f"dlv_{uuid.uuid4().hex[:12]}"
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO webhook_deliveries (
                    id, webhook_id, target_url, event_type, task_id, signature, payload_json, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delivery_id,
                    webhook_id,
                    target_url,
                    event_type,
                    task_id,
                    signature,
                    json.dumps(payload, ensure_ascii=False),
                    status,
                    now,
                ),
            )
            self._conn.commit()
        return {
            "id": delivery_id,
            "webhook_id": webhook_id,
            "target_url": target_url,
            "event_type": event_type,
            "task_id": task_id,
            "signature": signature,
            "status": status,
            "created_at": now,
        }

    def list_webhook_deliveries(self, task_id: str | None = None) -> list[dict[str, Any]]:
        """List recorded webhook delivery events, optionally filtered by task_id."""
        with self._lock:
            if task_id:
                rows = self._conn.execute(
                    "SELECT * FROM webhook_deliveries WHERE task_id = ? ORDER BY created_at DESC",
                    (task_id,),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM webhook_deliveries ORDER BY created_at DESC LIMIT 100"
                ).fetchall()
        return [
            {
                "id": row["id"],
                "webhook_id": row["webhook_id"],
                "target_url": row["target_url"],
                "event_type": row["event_type"],
                "task_id": row["task_id"],
                "signature": row["signature"],
                "payload": json.loads(row["payload_json"]),
                "status": row["status"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def record_audit_log(
        self,
        *,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        actor: str,
        client_ip: str,
    ) -> None:
        """Append an HTTP request audit log entry."""
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO audit_logs (timestamp, method, path, status_code, latency_ms, actor, client_ip)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (time.time(), method, path, status_code, round(latency_ms, 3), actor, client_ip),
            )
            self._conn.commit()

    def list_audit_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Fetch recent API audit log entries."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 200)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        with self._lock:
            self._conn.close()

    @staticmethod
    def _row_to_task(row: sqlite3.Row) -> dict[str, Any]:
        """Convert a SQLite row from `tasks` into a structured dictionary."""
        return {
            "id": row["id"],
            "title": row["title"],
            "action": row["action"],
            "payload": json.loads(row["payload_json"]),
            "status": row["status"],
            "priority": row["priority"],
            "attempts": row["attempts"],
            "max_retries": row["max_retries"],
            "webhook_url": row["webhook_url"],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
            "error_message": row["error_message"],
            "owner": row["owner"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _row_to_webhook(row: sqlite3.Row) -> dict[str, Any]:
        """Convert a SQLite row from `webhooks` into a structured dictionary."""
        return {
            "id": row["id"],
            "target_url": row["target_url"],
            "events": json.loads(row["events_json"]),
            "secret": row["secret"],
            "description": row["description"],
            "owner": row["owner"],
            "created_at": row["created_at"],
        }

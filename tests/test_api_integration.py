"""End-to-end integration tests for ApiForgeApp, task processing, webhooks, and HTTP server."""

from __future__ import annotations

import json
import csv
import io
import threading
import unittest
from urllib.request import Request, urlopen

from apiforge.app import ApiForgeApp
from apiforge.cli import main as cli_main
from apiforge.security import verify_webhook_signature
from apiforge.server import TestClient, create_http_server


class TestApiIntegration(unittest.TestCase):
    """End-to-end integration tests covering auth, tasks, webhooks, rate limits, and live HTTP."""

    def setUp(self) -> None:
        """Create a fresh in-memory ApiForgeApp and authenticated TestClient for each test."""
        self.api_key = "afg_test_secret_key"
        self.app = ApiForgeApp(
            db_path=":memory:",
            jwt_secret="integration-jwt-secret",
            api_keys={self.api_key: "test-operator"},
            rate_limit_capacity=50,
        )
        self.client = TestClient(self.app, default_headers={"X-API-Key": self.api_key})

    def tearDown(self) -> None:
        """Close the in-memory SQLite storage after each test."""
        self.app.storage.close()

    def test_health_docs_and_openapi_endpoints(self) -> None:
        """Public health, docs, and openapi.json endpoints should respond without auth."""
        public_client = TestClient(self.app)
        health_res = public_client.get("/health")
        self.assertEqual(health_res.status_code, 200)
        self.assertEqual(health_res.json_data()["status"], "ok")
        self.assertIn("X-RateLimit-Remaining", health_res.headers)

        docs_res = public_client.get("/docs")
        self.assertEqual(docs_res.status_code, 200)
        self.assertIn("text/html", docs_res.content_type)
        self.assertIn(b"OpenAPI 3.1.0", docs_res.body)

        spec_res = public_client.get("/openapi.json")
        self.assertEqual(spec_res.status_code, 200)
        self.assertEqual(spec_res.json_data()["openapi"], "3.1.0")

    def test_unauthorized_request_returns_rfc7807_problem(self) -> None:
        """Protected routes should return 401 with RFC 7807 Problem Details when unauthenticated."""
        unauth_client = TestClient(self.app)
        res = unauth_client.get("/api/v1/tasks")
        self.assertEqual(res.status_code, 401)
        self.assertEqual(unauth_client.get("/api/v1/tasks/stats").status_code, 401)
        self.assertIn("application/problem+json", res.content_type)
        problem = res.json_data()
        self.assertEqual(problem["status"], 401)
        self.assertEqual(problem["title"], "Unauthorized")

    def test_worker_actions_endpoint_and_built_in_actions(self) -> None:
        """The actions endpoint lists built-ins and tasks can execute each new action."""
        unauth_res = TestClient(self.app).get("/api/v1/actions")
        self.assertEqual(unauth_res.status_code, 401)

        actions_res = self.client.get("/api/v1/actions")
        self.assertEqual(actions_res.status_code, 200)
        actions_data = actions_res.json_data()
        self.assertEqual(actions_data["count"], len(actions_data["actions"]))
        self.assertEqual(
            [action["name"] for action in actions_data["actions"]],
            ["compute_stats", "hash_content", "json_filter", "text_analysis", "transform_payload"],
        )
        self.assertTrue(next(action for action in actions_data["actions"] if action["name"] == "json_filter")["description"])

        text_task = self.client.post(
            "/api/v1/tasks",
            json_body={
                "title": "Analyze text",
                "action": "text_analysis",
                "payload": {"text": "Hello hello\nworld"},
            },
        ).json_data()
        text_result = self.client.post(f"/api/v1/tasks/{text_task['id']}/process").json_data()["task"]["result"]
        self.assertEqual(text_result, {"char_count": 17, "word_count": 3, "unique_word_count": 2, "line_count": 2})

        json_task = self.client.post(
            "/api/v1/tasks",
            json_body={
                "title": "Filter JSON",
                "action": "json_filter",
                "payload": {"data": {"keep": 1, "other": 2}, "keys": ["keep", "missing", "keep"]},
            },
        ).json_data()
        json_result = self.client.post(f"/api/v1/tasks/{json_task['id']}/process").json_data()["task"]["result"]
        self.assertEqual(json_result, {"filtered": {"keep": 1}, "matched_count": 2})

    def test_jwt_issuance_and_bearer_auth_flow(self) -> None:
        """Client should be able to exchange an API key for a JWT and use Bearer authentication."""
        token_res = self.client.post(
            "/api/v1/auth/token",
            json_body={"subject": "ci-runner", "role": "developer", "ttl_seconds": 1800},
        )
        self.assertEqual(token_res.status_code, 201)
        access_token = token_res.json_data()["access_token"]

        jwt_client = TestClient(self.app, default_headers={"Authorization": f"Bearer {access_token}"})
        tasks_res = jwt_client.get("/api/v1/tasks")
        self.assertEqual(tasks_res.status_code, 200)
        self.assertEqual(tasks_res.json_data()["count"], 0)

    def test_task_lifecycle_and_signed_webhook_delivery(self) -> None:
        """Creating and processing a task should compute results and emit verified HMAC webhooks."""
        wh_secret = "whsec_integration_12345"
        wh_res = self.client.post(
            "/api/v1/webhooks",
            json_body={
                "target_url": "https://hooks.example.org/events",
                "events": ["task.completed", "task.failed"],
                "secret": wh_secret,
                "description": "Primary event sink",
            },
        )
        self.assertEqual(wh_res.status_code, 201)

        create_res = self.client.post(
            "/api/v1/tasks",
            json_body={
                "title": "Compute sensor statistics",
                "action": "compute_stats",
                "payload": {"values": [10, 20, 30, 40]},
                "priority": 5,
            },
        )
        self.assertEqual(create_res.status_code, 201)
        task_id = create_res.json_data()["id"]

        proc_res = self.client.post(f"/api/v1/tasks/{task_id}/process")
        self.assertEqual(proc_res.status_code, 200)
        proc_data = proc_res.json_data()
        self.assertEqual(proc_data["task"]["status"], "completed")
        self.assertEqual(proc_data["task"]["result"]["mean"], 25.0)
        self.assertEqual(len(proc_data["webhook_deliveries"]), 1)

        wh_list = self.client.get(f"/api/v1/webhooks?task_id={task_id}").json_data()
        delivery = wh_list["deliveries"][0]
        raw_payload = json.dumps(delivery["payload"], separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.assertTrue(
            verify_webhook_signature(
                raw_payload,
                delivery["signature"],
                wh_secret,
                now=delivery["payload"]["timestamp"],
            )
        )

        del_res = self.client.delete(f"/api/v1/tasks/{task_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.json_data()["deleted"])

    def test_webhook_ping_and_deletion(self) -> None:
        """Webhook ping should record a signed delivery and deletion should remove the subscription."""
        wh_secret = "whsec_ping_test_12345"
        wh_res = self.client.post(
            "/api/v1/webhooks",
            json_body={
                "target_url": "https://hooks.example.org/ping",
                "events": ["webhook.ping"],
                "secret": wh_secret,
                "description": "Ping test sink",
            },
        )
        self.assertEqual(wh_res.status_code, 201)
        webhook_id = wh_res.json_data()["id"]

        ping_res = self.client.post(f"/api/v1/webhooks/{webhook_id}/test")
        self.assertEqual(ping_res.status_code, 200)
        delivery = self.client.get("/api/v1/webhooks?task_id=ping").json_data()["deliveries"][0]
        self.assertEqual(delivery["event_type"], "webhook.ping")
        self.assertEqual(delivery["task_id"], "ping")
        raw_payload = json.dumps(delivery["payload"], separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.assertTrue(
            verify_webhook_signature(
                raw_payload,
                delivery["signature"],
                wh_secret,
                now=delivery["payload"]["timestamp"],
            )
        )

        del_res = self.client.delete(f"/api/v1/webhooks/{webhook_id}")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.json_data(), {"deleted": True, "webhook_id": webhook_id})
        self.assertEqual(self.client.post(f"/api/v1/webhooks/{webhook_id}/test").status_code, 404)

    def test_batch_task_creation_and_csv_export(self) -> None:
        """Batch task creation should persist tasks that can be exported as CSV."""
        batch_res = self.client.post(
            "/api/v1/tasks/batch",
            json_body={
                "tasks": [
                    {"title": "First batch task", "action": "transform_payload"},
                    {"title": "Second batch task", "priority": 5},
                ]
            },
        )
        self.assertEqual(batch_res.status_code, 201)
        batch_data = batch_res.json_data()
        self.assertEqual(batch_data["count"], 2)
        self.assertEqual(len(batch_data["items"]), 2)

        export_res = self.client.get("/api/v1/tasks/export?format=csv")
        self.assertEqual(export_res.status_code, 200)
        self.assertEqual(export_res.content_type, "text/csv; charset=utf-8")
        rows = list(csv.DictReader(io.StringIO(export_res.body.decode("utf-8"))))
        self.assertEqual(
            rows[0].keys(),
            {
                "id",
                "title",
                "action",
                "status",
                "priority",
                "attempts",
                "max_retries",
                "owner",
                "created_at",
                "updated_at",
            },
        )
        self.assertEqual({row["title"] for row in rows}, {"First batch task", "Second batch task"})

    def test_task_filtering_and_statistics(self) -> None:
        """Task listing should filter by minimum priority and case-insensitive keyword."""
        for title, action, priority in (
            ("Deploy needle", "release", 5),
            ("Review docs", "needle_scan", 4),
            ("Low priority needle", "cleanup", 2),
        ):
            response = self.client.post(
                "/api/v1/tasks",
                json_body={"title": title, "action": action, "priority": priority},
            )
            self.assertEqual(response.status_code, 201)

        filtered = self.client.get("/api/v1/tasks?min_priority=4&q=NEEDLE")
        self.assertEqual(filtered.status_code, 200)
        self.assertEqual({item["title"] for item in filtered.json_data()["items"]}, {"Deploy needle", "Review docs"})

        stats = self.client.get("/api/v1/tasks/stats")
        self.assertEqual(stats.status_code, 200)
        stats_data = stats.json_data()
        self.assertEqual(stats_data["total_tasks"], 3)
        self.assertEqual(stats_data["by_status"]["pending"], 3)
        self.assertEqual(stats_data["by_priority"], {"1": 0, "2": 1, "3": 0, "4": 1, "5": 1})

    def test_failed_task_retry_and_audit_metrics(self) -> None:
        """Tasks that fail should transition to retrying/failed and be recorded in audit logs and metrics."""
        create_res = self.client.post(
            "/api/v1/tasks",
            json_body={
                "title": "Failing job",
                "action": "transform_payload",
                "payload": {"force_error": "upstream timeout"},
                "max_retries": 2,
            },
        )
        task_id = create_res.json_data()["id"]

        first_try = self.client.post(f"/api/v1/tasks/{task_id}/process").json_data()
        self.assertEqual(first_try["task"]["status"], "retrying")
        self.assertEqual(first_try["task"]["attempts"], 1)

        second_try = self.client.post(f"/api/v1/tasks/{task_id}/process").json_data()
        self.assertEqual(second_try["task"]["status"], "failed")
        self.assertEqual(second_try["task"]["attempts"], 2)

        metrics_json = self.client.get("/metrics").json_data()
        self.assertGreaterEqual(metrics_json["requests_total"], 3)

        prom_res = self.client.get("/metrics?format=prometheus")
        self.assertIn(b"apiforge_requests_total", prom_res.body)

        audit_res = self.client.get("/api/v1/audit-logs?limit=5").json_data()
        self.assertGreaterEqual(audit_res["count"], 3)

    def test_task_cancellation_and_retry_reset(self) -> None:
        """Tasks can be cancelled and failed tasks can be reset for another attempt."""
        create_res = self.client.post(
            "/api/v1/tasks",
            json_body={"title": "Cancellable job", "action": "transform_payload"},
        )
        task_id = create_res.json_data()["id"]

        cancel_res = self.client.post(f"/api/v1/tasks/{task_id}/cancel")
        self.assertEqual(cancel_res.status_code, 200)
        cancelled = cancel_res.json_data()
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["attempts"], 0)

        retry_res = self.client.post(f"/api/v1/tasks/{task_id}/retry")
        self.assertEqual(retry_res.status_code, 200)
        reset = retry_res.json_data()
        self.assertEqual(reset["status"], "pending")
        self.assertEqual(reset["attempts"], 0)
        self.assertIsNone(reset["result"])
        self.assertIsNone(reset["error_message"])

        completed_res = self.client.post(
            "/api/v1/tasks",
            json_body={"title": "Completed job", "action": "transform_payload"},
        )
        completed_id = completed_res.json_data()["id"]
        self.assertEqual(self.client.post(f"/api/v1/tasks/{completed_id}/process").status_code, 200)

        conflict_res = self.client.post(f"/api/v1/tasks/{completed_id}/cancel")
        self.assertEqual(conflict_res.status_code, 409)
        conflict = conflict_res.json_data()
        self.assertEqual(conflict["title"], "Task Conflict")
        self.assertEqual(conflict["detail"], "Completed tasks cannot be cancelled")

    def test_retry_reset_failed_task(self) -> None:
        """A failed task can be reset with its attempts, result, and error cleared."""
        create_res = self.client.post(
            "/api/v1/tasks",
            json_body={
                "title": "Retryable job",
                "action": "transform_payload",
                "payload": {"force_error": "upstream timeout"},
                "max_retries": 1,
            },
        )
        task_id = create_res.json_data()["id"]
        failed = self.client.post(f"/api/v1/tasks/{task_id}/process").json_data()["task"]
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["attempts"], 1)

        reset_res = self.client.post(f"/api/v1/tasks/{task_id}/retry")
        self.assertEqual(reset_res.status_code, 200)
        reset = reset_res.json_data()
        self.assertEqual(reset["status"], "pending")
        self.assertEqual(reset["attempts"], 0)
        self.assertIsNone(reset["result"])
        self.assertIsNone(reset["error_message"])

    def test_rate_limit_enforcement_returns_429(self) -> None:
        """Exceeding the token bucket limit should return HTTP 429 Too Many Requests."""
        strict_app = ApiForgeApp(
            db_path=":memory:",
            api_keys={self.api_key: "tester"},
            rate_limit_capacity=2,
            rate_limit_refill_per_sec=0.01,
        )
        strict_client = TestClient(strict_app)
        self.assertEqual(strict_client.get("/health").status_code, 200)
        self.assertEqual(strict_client.get("/health").status_code, 200)
        blocked = strict_client.get("/health")
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.json_data()["title"], "Too Many Requests")
        strict_app.storage.close()

    def test_live_threading_http_server_and_cli(self) -> None:
        """ThreadingHTTPServer and CLI commands should work end-to-end."""
        server = create_http_server(self.app, host="127.0.0.1", port=0)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            req = Request(f"http://127.0.0.1:{port}/health")
            with urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                body = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(body["status"], "ok")
        finally:
            server.shutdown()
            server.server_close()

        self.assertEqual(cli_main(["routes"]), 0)
        self.assertEqual(cli_main(["token", "--sub", "cli-user"]), 0)


if __name__ == "__main__":
    unittest.main()

"""End-to-end integration tests for ApiForgeApp, task processing, webhooks, and HTTP server."""

from __future__ import annotations

import json
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
        self.assertIn("application/problem+json", res.content_type)
        problem = res.json_data()
        self.assertEqual(problem["status"], 401)
        self.assertEqual(problem["title"], "Unauthorized")

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

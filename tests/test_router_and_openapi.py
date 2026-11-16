"""Unit tests for declarative routing, path parameters, and OpenAPI 3.1.0 schema generation."""

from __future__ import annotations

import unittest

from apiforge.app import ApiForgeApp
from apiforge.router import ApiHttpError, RequestContext, Router, parse_url_and_query


class TestRouterAndOpenAPI(unittest.TestCase):
    """Test suite for URL matching, HTTP 404/405 handling, and OpenAPI 3.1 spec generation."""

    def test_router_path_params_and_method_matching(self) -> None:
        """Router should extract path parameters and distinguish 404 vs 405 errors."""
        router = Router()

        def dummy_handler(ctx: RequestContext) -> dict[str, str]:
            """Fetch item by ID."""
            return {"id": ctx.path_params["item_id"]}

        router.add_route("GET", "/items/{item_id}", dummy_handler, tags=["items"])

        route, params = router.match("GET", "/items/abc-99")
        self.assertEqual(route.path_template, "/items/{item_id}")
        self.assertEqual(params, {"item_id": "abc-99"})

        with self.assertRaises(ApiHttpError) as mna:
            router.match("DELETE", "/items/abc-99")
        self.assertEqual(mna.exception.status_code, 405)

        with self.assertRaises(ApiHttpError) as nf:
            router.match("GET", "/nonexistent")
        self.assertEqual(nf.exception.status_code, 404)

    def test_parse_url_and_query_normalization(self) -> None:
        """URL parser should strip trailing slashes and extract query parameters."""
        path, query = parse_url_and_query("/api/v1/tasks/?status=completed&limit=10")
        self.assertEqual(path, "/api/v1/tasks")
        self.assertEqual(query, {"status": "completed", "limit": "10"})

    def test_openapi_3_1_generation(self) -> None:
        """ApiForgeApp should generate a valid OpenAPI 3.1.0 document with schemas and security."""
        app = ApiForgeApp(db_path=":memory:")
        try:
            spec = app.openapi_spec()
        finally:
            app.storage.close()

        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertIn("/health", spec["paths"])
        self.assertIn("/api/v1/tasks", spec["paths"])
        self.assertIn("/api/v1/tasks/{task_id}", spec["paths"])
        self.assertIn("TaskCreateRequest", spec["components"]["schemas"])
        self.assertIn("BearerAuth", spec["components"]["securitySchemes"])
        self.assertIn("ApiKeyAuth", spec["components"]["securitySchemes"])


if __name__ == "__main__":
    unittest.main()

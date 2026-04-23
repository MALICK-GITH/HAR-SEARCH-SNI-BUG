#!/usr/bin/env python3
"""Regression tests for analysis history routes."""

import os
import unittest
import uuid
from unittest.mock import Mock, patch

import psycopg2

import app as app_module


class HistoryRoutesTestCase(unittest.TestCase):
    """Cover history success paths and JSON error handling."""

    def setUp(self):
        app_module.get_database.cache_clear()
        self.client = app_module.app.test_client()

    def tearDown(self):
        app_module.get_database.cache_clear()

    def test_index_route_renders_successfully(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_save_history_requires_filename_and_analysis_data(self):
        response = self.client.post("/api/history/save", json={"filename": "sample.har"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json(),
            {"error": "filename and analysis_data are required"},
        )

    def test_history_detail_returns_not_found_when_record_is_missing(self):
        fake_database = Mock()
        fake_database.get_analysis.return_value = None

        with patch.object(app_module, "get_database", return_value=fake_database):
            response = self.client.get("/api/history/999999")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.get_json(), {"error": "Analysis not found"})

    def test_history_list_returns_json_when_database_access_fails(self):
        with patch.object(
            app_module,
            "get_database",
            side_effect=psycopg2.OperationalError("database unavailable"),
        ):
            response = self.client.get("/api/history/list")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json(), {"error": "database unavailable"})

    def test_history_search_reports_missing_database_url_cleanly(self):
        with patch.object(
            app_module,
            "get_database",
            side_effect=RuntimeError("DATABASE_URL environment variable is required."),
        ):
            response = self.client.get("/api/history/search?query=sample")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.get_json(),
            {"error": "DATABASE_URL environment variable is required."},
        )

    @unittest.skipUnless(os.getenv("DATABASE_URL"), "DATABASE_URL is not set")
    def test_history_smoke_flow_with_live_database(self):
        unique_filename = f"smoke-{uuid.uuid4().hex}.har"
        analysis_id = None
        payload = {
            "filename": unique_filename,
            "file_size": 1234,
            "analysis_data": {
                "total_requests": 3,
                "domains": {"example.com": 2, "cdn.example.com": 1},
                "security": {"score": 88, "grade": "A"},
                "free_surf": {"detected": False, "max_score": 0, "verdict": "none"},
                "host_proxy_tls": {"max_score": 12, "verdict": "low-risk"},
            },
            "metadata": {"source": "unittest"},
        }

        try:
            save_response = self.client.post("/api/history/save", json=payload)
            self.assertEqual(save_response.status_code, 200)
            save_data = save_response.get_json()
            self.assertTrue(save_data["success"])
            analysis_id = save_data["analysis_id"]

            list_response = self.client.get("/api/history/list?limit=50")
            self.assertEqual(list_response.status_code, 200)
            list_data = list_response.get_json()
            self.assertTrue(any(row["id"] == analysis_id for row in list_data["analyses"]))

            search_response = self.client.get(f"/api/history/search?query={unique_filename}&limit=50")
            self.assertEqual(search_response.status_code, 200)
            search_data = search_response.get_json()
            self.assertTrue(any(row["id"] == analysis_id for row in search_data["analyses"]))

            get_response = self.client.get(f"/api/history/{analysis_id}")
            self.assertEqual(get_response.status_code, 200)
            get_data = get_response.get_json()
            self.assertEqual(get_data["analysis"]["filename"], unique_filename)

        finally:
            if analysis_id is not None:
                delete_response = self.client.delete(f"/api/history/{analysis_id}")
                self.assertEqual(delete_response.status_code, 200)
                self.assertEqual(
                    delete_response.get_json(),
                    {"success": True, "message": "Analysis deleted"},
                )


if __name__ == "__main__":
    unittest.main()

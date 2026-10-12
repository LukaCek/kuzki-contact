"""Tests for per-request QR logs, deduplication, legacy rows and admin access."""
import base64
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as scan_app


def auth():
    token = base64.b64encode("admin:test-password".encode()).decode("ascii")
    return {"Authorization": "Basic " + token}


class ScanRequestLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "scans.db")
        for field, value in [
            ("DB_PATH", self.db_path),
            ("ADMIN_USER", "admin"),
            ("ADMIN_PASSWORD", "test-password"),
        ]:
            p = patch.object(scan_app, field, value)
            p.start()
            self.addCleanup(p.stop)
        self.client = scan_app.app.test_client()

    def post(self, poster="abc123", scan_id="12345678abcdefgh"):
        return self.client.post("/scan", query_string={"p": poster, "s": scan_id})

    def data(self):
        with scan_app.db() as conn:
            counted = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            logged = conn.execute(
                "SELECT result, http_status, poster_id FROM scan_requests ORDER BY id"
            ).fetchall()
        return counted, [tuple(row) for row in logged]

    def test_each_post_has_own_log_and_duplicates_not_counted(self):
        self.assertEqual(self.post().status_code, 204)
        self.assertEqual(self.post().status_code, 204)
        self.assertEqual(self.data(), (1, [
            ("counted", 204, "abc123"),
            ("duplicate", 204, "abc123"),
        ]))

    def test_invalid_requests_logged_without_count(self):
        self.assertEqual(self.post("!", "12345678abcdefgh").status_code, 400)
        self.assertEqual(self.post("abc123", "short").status_code, 400)
        self.assertEqual(self.data(), (0, [
            ("invalid_poster", 400, "!"),
            ("invalid_scan", 400, "abc123"),
        ]))

    def test_stats_request_page_requires_auth(self):
        self.post()
        response = self.client.get("/stats/requests")
        self.assertEqual(response.status_code, 401)

    def test_stats_request_page_shows_individual_rows(self):
        self.post()
        self.post()
        response = self.client.get("/stats/requests", headers=auth())
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Nov sken", response.data)
        self.assertIn(b"Podvojen", response.data)
        self.assertIn(b"abc123", response.data)
        self.assertIn(b"Posamezni zahtevki", response.data)
        self.assertIn(b"Skupaj zabele", response.data)

    def test_summary_has_tab_links(self):
        response = self.client.get("/stats", headers=auth())
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'/stats/requests', response.data)

    def test_old_scans_are_imported_into_history_once(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "poster_id TEXT NOT NULL, scan_id TEXT NOT NULL UNIQUE, "
                "scanned_at INTEGER NOT NULL)"
            )
            conn.execute(
                "INSERT INTO scans(poster_id, scan_id, scanned_at) "
                "VALUES('preizkus1', 'legacy-12345678', 1700000000)"
            )
        self.client.get("/stats/requests", headers=auth())
        self.client.get("/stats/requests", headers=auth())
        counted, logged = self.data()
        self.assertEqual(counted, 1)
        self.assertEqual(logged, [("counted", 204, "preizkus1")])

    def test_paginated_log_is_newest_first(self):
        for index in range(52):
            self.post(scan_id=f"12345678abcdef{index:04d}")
        page1 = self.client.get("/stats/requests", headers=auth())
        self.assertEqual(page1.status_code, 200)
        self.assertIn(b"Naslednja", page1.data)
        self.assertIn(b"12345678abcdef0051", page1.data)
        self.assertNotIn(b"12345678abcdef0000", page1.data)
        page2 = self.client.get("/stats/requests?page=2", headers=auth())
        self.assertEqual(page2.status_code, 200)
        self.assertIn(b"12345678abcdef0000", page2.data)
        self.assertIn(b"Prej", page2.data)


if __name__ == "__main__":
    unittest.main()

"""Regression tests for Basic auth with Unicode credentials.

Run from the repository root:
    python -m unittest discover -s backend/tests -v
"""
import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as scan_app


def basic_auth(username, password):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


class StatsAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patches = [
            patch.object(scan_app, "DB_PATH", os.path.join(self.tmp.name, "scans.db")),
            patch.object(scan_app, "ADMIN_USER", "uporabnik-ž"),
            patch.object(scan_app, "ADMIN_PASSWORD", "močno-geslo-čšž"),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        self.client = scan_app.app.test_client()

    def test_stats_accepts_unicode_credentials(self):
        response = self.client.get(
            "/stats", headers=basic_auth("uporabnik-ž", "močno-geslo-čšž")
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"QR skeni", response.data)

    def test_stats_csv_accepts_unicode_credentials(self):
        response = self.client.get(
            "/stats.csv", headers=basic_auth("uporabnik-ž", "močno-geslo-čšž")
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"poster_id", response.data)

    def test_wrong_unicode_password_returns_401_not_500(self):
        response = self.client.get(
            "/stats", headers=basic_auth("uporabnik-ž", "napačno-geslo")
        )
        self.assertEqual(response.status_code, 401)

    def test_wrong_unicode_username_returns_401_not_500(self):
        response = self.client.get(
            "/stats", headers=basic_auth("drug-uporabnik-š", "močno-geslo-čšž")
        )
        self.assertEqual(response.status_code, 401)

    def test_missing_auth_requires_login(self):
        response = self.client.get("/stats")
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()

"""Integration tests for poster labels and consent-gated device details."""
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
    token = base64.b64encode(b"admin:test-password").decode("ascii")
    return {"Authorization": "Basic " + token}


class PosterAndDeviceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dbpath = os.path.join(self.tmp.name, "scans.db")
        for key, value in (
            ("DB_PATH", self.dbpath),
            ("ADMIN_USER", "admin"),
            ("ADMIN_PASSWORD", "test-password"),
        ):
            p = patch.object(scan_app, key, value)
            p.start()
            self.addCleanup(p.stop)
        self.client = scan_app.app.test_client()

    def post_scan(self, scanid="12345678abcdefgh", body="",
                  headers=None):
        return self.client.post(
            "/scan?p=abc123&s=" + scanid, data=body, headers=headers or {}
        )

    def test_basic_request_headers_recorded_without_browser_fingerprint(self):
        response = self.post_scan(headers={
            "User-Agent": "Mozilla/5.0 Sample",
            "Accept-Language": "sl-SI,sl",
            "CF-IPCountry": "SI",
        })
        self.assertEqual(response.status_code, 204)
        with scan_app.db() as conn:
            row = conn.execute("SELECT * FROM scan_requests").fetchone()
        self.assertEqual(row["user_agent"], "Mozilla/5.0 Sample")
        self.assertEqual(row["accept_language"], "sl-SI,sl")
        self.assertEqual(row["country"], "SI")
        self.assertEqual(row["browser_id"], "")
        self.assertEqual(row["device_details"], "")
        page = self.client.get("/stats/requests", headers=auth())
        self.assertIn(b"Mozilla/5.0 Sample", page.data)

    def test_opted_in_device_id_is_groupable(self):
        import json
        bid = "12345678-1234-4234-8234-123456789abc"
        body = json.dumps({
            "consent": True, "browser_id": bid,
            "details": {"screen": "1080x2400", "timezone": "Europe/Ljubljana",
                        "unexpected_property": "secret"}
        })
        self.assertEqual(self.post_scan(body=body).status_code, 204)
        self.assertEqual(self.post_scan(scanid="12345678abcdefgh-other", body=body).status_code, 204)
        with scan_app.db() as conn:
            row = conn.execute(
                "SELECT browser_id,device_details FROM scan_requests LIMIT 1"
            ).fetchone()
        self.assertEqual(row["browser_id"], bid)
        self.assertIn("1080x2400", row["device_details"])
        self.assertNotIn("secret", row["device_details"])
        page = self.client.get("/stats/requests?browser=" + bid, headers=auth())
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Stran 1 / 1", page.data)
        self.assertEqual(page.data.count(b"Podrobnosti"), 2)

    def test_no_consent_does_not_save_device(self):
        import json
        body = json.dumps({
            "browser_id": "12345678-1234-4234-8234-123456789abc",
            "details": {"screen": "1080x2400"}
        })
        self.post_scan(body=body)
        with scan_app.db() as conn:
            row = conn.execute(
                "SELECT browser_id,device_details FROM scan_requests"
            ).fetchone()
        self.assertEqual(row["browser_id"], "")
        self.assertEqual(row["device_details"], "")

    def test_enrich_and_forget_keeps_scan_count(self):
        import json
        bid = "12345678-1234-4234-8234-123456789abc"
        self.post_scan()
        payload = json.dumps({
            "consent": True, "browser_id": bid, "details": {"screen": "100x200"}
        })
        enriched = self.client.post(
            "/scan/enrich?p=abc123&s=12345678abcdefgh", data=payload
        )
        self.assertEqual(enriched.status_code, 204)
        deleted = self.client.post("/privacy/forget", data=json.dumps({"browser_id": bid}))
        self.assertEqual(deleted.status_code, 204)
        with scan_app.db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            row = conn.execute(
                "SELECT browser_id,device_details FROM scan_requests"
            ).fetchone()
        self.assertEqual(count, 1)
        self.assertEqual(row["browser_id"], "")
        self.assertEqual(row["device_details"], "")

    def test_unauthenticated_poster_edit_rejected(self):
        response = self.client.post(
            "/stats/posters", data={"poster_id": "abc123", "label": "CTK"}
        )
        self.assertEqual(response.status_code, 401)

    def test_missing_csrf_rejected(self):
        response = self.client.post(
            "/stats/posters", headers=auth(),
            data={"poster_id": "abc123", "label": "CTK"}
        )
        self.assertEqual(response.status_code, 403)

    def test_existing_poster_named_and_renamed(self):
        self.post_scan()
        token = scan_app.csrf_token()
        for label in ("Knjižnica CTK", "Knjižnica CTK – vhod"):
            response = self.client.post(
                "/stats/posters", headers=auth(),
                data={"csrf": token, "poster_id": "abc123", "label": label}
            )
            self.assertEqual(response.status_code, 303)
        summary = self.client.get("/stats", headers=auth())
        self.assertIn("Knjižnica CTK – vhod".encode(), summary.data)
        events = self.client.get("/stats/requests", headers=auth())
        self.assertIn("Knjižnica CTK – vhod".encode(), events.data)
        csv = self.client.get("/stats.csv", headers=auth())
        self.assertIn("Knjižnica CTK – vhod".encode(), csv.data)

    def test_new_poster_before_first_scan(self):
        response = self.client.post(
            "/stats/posters", headers=auth(),
            data={"csrf": scan_app.csrf_token(), "poster_id": "", "label": "Knjižnica CTK"}
        )
        self.assertEqual(response.status_code, 303)
        page = self.client.get("/stats/posters", headers=auth())
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"kuski.qd.je/?p=", page.data)
        self.assertIn("Knjižnica CTK".encode(), page.data)

    def test_escaping_and_input_validation(self):
        bad = self.client.post(
            "/stats/posters", headers=auth(),
            data={"csrf": scan_app.csrf_token(), "poster_id": "abc123",
                  "label": "<img src=x onerror=alert(1)>"}
        )
        self.assertEqual(bad.status_code, 303)
        page = self.client.get("/stats/posters", headers=auth())
        self.assertNotIn(b"<img src=x", page.data)
        self.assertIn(b"&lt;img", page.data)
        bad_code = self.client.post(
            "/stats/posters", headers=auth(),
            data={"csrf": scan_app.csrf_token(), "poster_id": "!",
                  "label": "CTK"}
        )
        self.assertEqual(bad_code.status_code, 400)

    def test_old_database_migrates_without_losing_scans(self):
        with sqlite3.connect(self.dbpath) as conn:
            conn.execute(
                "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "poster_id TEXT,scan_id TEXT UNIQUE,scanned_at INTEGER)"
            )
            conn.execute(
                "CREATE TABLE scan_requests (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "poster_id TEXT,scan_id TEXT,requested_at INTEGER,"
                "result TEXT,http_status INTEGER)"
            )
            conn.execute(
                "INSERT INTO scans(poster_id,scan_id,scanned_at) "
                "VALUES('abc123','legacy12345678',1700000000)"
            )
            conn.execute(
                "INSERT INTO scan_requests(poster_id,scan_id,requested_at,result,http_status) "
                "VALUES('abc123','legacy12345678',1700000000,'counted',204)"
            )
        page = self.client.get("/stats", headers=auth())
        self.assertEqual(page.status_code, 200)
        with scan_app.db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            logcount = conn.execute("SELECT COUNT(*) FROM scan_requests").fetchone()[0]
            cols = [x[1] for x in conn.execute("PRAGMA table_info(scan_requests)")]
        self.assertEqual((count, logcount), (1, 1))
        self.assertIn("browser_id", cols)


if __name__ == "__main__":
    unittest.main()

"""Integration tests for physical flyer IDs grouped into 15-flyer locations."""
import csv
import io
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as scan_app


def authentication():
    import base64
    return {"Authorization": "Basic " + base64.b64encode(b"admin:test-password").decode()}


class LocationInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_file = os.path.join(self.tmp.name, "scans.db")
        for attr, value in (("DB_PATH", self.db_file), ("ADMIN_USER", "admin"),
                            ("ADMIN_PASSWORD", "test-password")):
            p = patch.object(scan_app, attr, value)
            p.start()
            self.addCleanup(p.stop)
        self.client = scan_app.app.test_client()

    def add_location(self, name, mode="batch"):
        return self.client.post(
            "/stats/locations", headers=authentication(),
            data={"csrf": scan_app.csrf_token(), "name": name, "mode": mode}
        )

    def assign(self, code, name):
        return self.client.post(
            "/stats/posters", headers=authentication(),
            data={"csrf": scan_app.csrf_token(), "poster_id": code, "label": name}
        )

    def test_creates_exactly_fifteen_distinct_qr_ids_for_one_location(self):
        response = self.add_location("Knjižnica CTK")
        self.assertEqual(response.status_code, 303)
        with scan_app.db() as conn:
            places = conn.execute("SELECT * FROM locations").fetchall()
            ids = conn.execute("SELECT poster_id FROM poster_labels").fetchall()
        self.assertEqual(len(places), 1)
        self.assertEqual(places[0]["name"], "Knjižnica CTK")
        self.assertEqual(places[0]["capacity"], 15)
        self.assertEqual(len(ids), 15)
        self.assertEqual(len({x["poster_id"] for x in ids}), 15)
        self.assertTrue(all(len(x["poster_id"]) == 24 for x in ids))
        summary = self.client.get("/stats/posters", headers=authentication())
        self.assertEqual(summary.status_code, 200)
        self.assertIn("Knjižnica CTK".encode(), summary.data)
        self.assertIn(b"15 / 15", summary.data)

    def test_location_summaries_sum_unique_flyer_scans(self):
        self.add_location("CTK")
        with scan_app.db() as conn:
            flyers = [r["poster_id"] for r in conn.execute(
                "SELECT poster_id FROM poster_labels ORDER BY poster_id LIMIT 2"
            ).fetchall()]
        for i, poster_id in enumerate((flyers[0], flyers[0], flyers[1])):
            response = self.client.post(
                "/scan", query_string={"p": poster_id, "s": f"unique-scanner-0{i}"}
            )
            self.assertEqual(response.status_code, 204)
        with scan_app.db() as conn:
            rows = conn.execute(
                "SELECT poster_id, COUNT(*) AS scans FROM scans GROUP BY poster_id"
            ).fetchall()
        self.assertEqual(sorted(x["scans"] for x in rows), [1, 2])
        locations = scan_app.location_rows()
        self.assertEqual(locations[0]["flyers"], 15)
        self.assertEqual(locations[0]["scans"], 3)
        dashboard = self.client.get("/stats", headers=authentication())
        self.assertIn("CTK".encode(), dashboard.data)
        self.assertIn(b"15/15", dashboard.data)
        history = self.client.get("/stats/requests", headers=authentication())
        self.assertIn("CTK".encode(), history.data)
        self.assertEqual(sum(row["scans"] for row in scan_app.stats_rows()), 3)

    def test_empty_location_can_register_fifteen_existing_codes_but_no_sixteenth(self):
        self.assertEqual(self.add_location("FE", "empty").status_code, 303)
        for i in range(15):
            self.assertEqual(self.assign(f"flyer{i:05d}", "FE").status_code, 303)
        blocked = self.assign("flyer-16-qr", "FE")
        self.assertEqual(blocked.status_code, 409)
        with scan_app.db() as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM poster_labels WHERE location_id="
                "(SELECT id FROM locations WHERE name='FE')"
            ).fetchone()[0], 15)
            self.assertIsNone(conn.execute(
                "SELECT 1 FROM poster_labels WHERE poster_id='flyer-16-qr'"
            ).fetchone())
        self.assertEqual(self.assign("flyer00001", "FE").status_code, 303)

    def test_moving_flyer_releases_old_location_slot(self):
        self.add_location("Prva", "empty")
        self.add_location("Druga", "empty")
        self.assertEqual(self.assign("phys0001", "Prva").status_code, 303)
        self.assertEqual(self.assign("phys0001", "Druga").status_code, 303)
        self.assertEqual(
            [(r["name"], r["flyers"]) for r in scan_app.location_rows()],
            [("Druga", 1), ("Prva", 0)]
        )

    def test_csv_inventory_includes_location_id_and_url_without_scan(self):
        self.add_location("CTK")
        response = self.client.get("/stats/flyers.csv", headers=authentication())
        self.assertEqual(response.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(response.get_data(as_text=True))))
        self.assertEqual(len(rows), 15)
        self.assertTrue(all(r["location"] == "CTK" for r in rows))
        self.assertTrue(all(r["qr_url"].endswith("?p=" + r["flyer_id"]) for r in rows))
        with scan_app.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_requests").fetchone()[0], 0)

    def test_duplicate_locations_case_insensitive(self):
        self.assertEqual(self.add_location("Knjižnica CTK").status_code, 303)
        self.assertEqual(self.add_location("KNJIŽNICA CTK").status_code, 409)
        self.assertEqual(len(scan_app.location_rows()), 1)

    def test_admin_protected_and_csrf_checked(self):
        self.assertEqual(self.client.post("/stats/locations",
                                         data={"name": "CTK"}).status_code, 401)
        self.assertEqual(self.client.post("/stats/locations",
                                         headers=authentication(),
                                         data={"name": "CTK"}).status_code, 403)
        self.assertEqual(self.client.get("/stats/flyers.csv").status_code, 401)

    def test_preserves_legacy_scans_and_groups_labels(self):
        with sqlite3.connect(self.db_file) as conn:
            conn.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT,"
                         "poster_id TEXT, scan_id TEXT UNIQUE, scanned_at INTEGER)")
            conn.execute("CREATE TABLE poster_labels (poster_id TEXT PRIMARY KEY, label TEXT NOT NULL)")
            for i in range(2):
                poster_id = "oldflyer" + str(i)
                conn.execute("INSERT INTO poster_labels VALUES (?,?)", (poster_id, "CTK"))
                conn.execute("INSERT INTO scans(poster_id, scan_id, scanned_at)"
                             " VALUES (?,?,?)", (poster_id, "legacyscan" + str(i), 1700000000))
        report = self.client.get("/stats", headers=authentication())
        self.assertEqual(report.status_code, 200)
        places = scan_app.location_rows()
        self.assertEqual(len(places), 1)
        self.assertEqual(places[0]["name"], "CTK")
        self.assertEqual(places[0]["flyers"], 2)
        self.assertEqual(places[0]["scans"], 2)
        self.assertEqual(self.add_location("Brezovica").status_code, 303)
        self.client.get("/stats", headers=authentication())
        with scan_app.db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 2)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scan_requests").fetchone()[0], 2)

    def test_rejects_bad_location_and_unknown_mode(self):
        self.assertEqual(self.add_location(" ", "batch").status_code, 400)
        self.assertEqual(self.add_location("CTK", "unknown").status_code, 400)
        self.assertEqual(self.assign("invalid!", "CTK").status_code, 400)


if __name__ == "__main__":
    unittest.main()

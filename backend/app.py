import csv
import hmac
import io
import os
import re
import sqlite3
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, Response, jsonify, request

DB_PATH = os.getenv("DB_PATH", "/data/scans.db")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

POSTER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,24}$")
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,80}$")

app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poster_id TEXT NOT NULL,
            scan_id TEXT NOT NULL UNIQUE,
            scanned_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_poster_time "
        "ON scans(poster_id, scanned_at)"
    )
    return conn


def unauthorized():
    return Response(
        "Authentication required",
        status=401,
        headers={"WWW-Authenticate": 'Basic realm="Kuzki scan stats"'},
    )


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not ADMIN_PASSWORD:
            return Response(
                "ADMIN_PASSWORD is not configured.",
                status=503,
                mimetype="text/plain",
            )

        auth = request.authorization
        if not auth:
            return unauthorized()

        # compare_digest accepts arbitrary Unicode credentials as UTF-8 bytes.
        user_ok = hmac.compare_digest(
            (auth.username or "").encode("utf-8"), ADMIN_USER.encode("utf-8")
        )
        pass_ok = hmac.compare_digest(
            (auth.password or "").encode("utf-8"), ADMIN_PASSWORD.encode("utf-8")
        )
        if not (user_ok and pass_ok):
            return unauthorized()

        return view(*args, **kwargs)

    return wrapped


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/scan")
def scan():
    poster_id = (request.args.get("p") or "").strip()
    scan_id = (request.args.get("s") or "").strip()

    if not POSTER_ID_RE.fullmatch(poster_id):
        return Response(status=400)
    if not SCAN_ID_RE.fullmatch(scan_id):
        return Response(status=400)

    now = int(datetime.now(timezone.utc).timestamp())

    with db() as conn:
        try:
            conn.execute(
                "INSERT INTO scans (poster_id, scan_id, scanned_at) VALUES (?, ?, ?)",
                (poster_id, scan_id, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # Same beacon retried: do not double count.
            pass

    return Response(status=204)


def stats_rows():
    with db() as conn:
        return conn.execute(
            """
            SELECT
                poster_id,
                COUNT(*) AS scans,
                MIN(scanned_at) AS first_scan,
                MAX(scanned_at) AS last_scan,
                SUM(
                    CASE
                        WHEN scanned_at >= CAST(strftime('%s','now') AS INTEGER) - 86400
                        THEN 1 ELSE 0
                    END
                ) AS scans_24h
            FROM scans
            GROUP BY poster_id
            ORDER BY scans DESC, last_scan DESC
            """
        ).fetchall()


def fmt_time(ts):
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


@app.get("/stats")
@admin_required
def stats():
    rows = stats_rows()
    total = sum(row["scans"] for row in rows)

    body = [
        "<!doctype html><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Kuzki QR stats</title>",
        "<style>",
        "body{font-family:system-ui,sans-serif;max-width:900px;margin:40px auto;padding:0 16px;color:#18231e}",
        "table{border-collapse:collapse;width:100%}th,td{padding:10px 12px;border-bottom:1px solid #ddd;text-align:left}",
        "th{background:#f5f3ee}code{font-size:1.05em}a{color:#173e2e}",
        "</style>",
        f"<h1>QR skeni</h1><p>Skupaj: <strong>{total}</strong></p>",
        "<p><a href='/stats.csv'>Prenesi CSV</a></p>",
        "<table><thead><tr><th>Plakat ID</th><th>Skeni</th><th>24 h</th><th>Prvi</th><th>Zadnji</th></tr></thead><tbody>",
    ]

    for row in rows:
        body.append(
            "<tr>"
            f"<td><code>{row['poster_id']}</code></td>"
            f"<td>{row['scans']}</td>"
            f"<td>{row['scans_24h']}</td>"
            f"<td>{fmt_time(row['first_scan'])}</td>"
            f"<td>{fmt_time(row['last_scan'])}</td>"
            "</tr>"
        )

    body.append("</tbody></table>")
    return Response("".join(body), mimetype="text/html")


@app.get("/stats.csv")
@admin_required
def stats_csv():
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["poster_id", "scans", "scans_24h", "first_scan_utc", "last_scan_utc"]
    )

    for row in stats_rows():
        writer.writerow(
            [
                row["poster_id"],
                row["scans"],
                row["scans_24h"],
                fmt_time(row["first_scan"]),
                fmt_time(row["last_scan"]),
            ]
        )

    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=kuzki-scans.csv"},
    )


@app.get("/")
def root():
    return jsonify(service="kuzki-scan", status="ok")

import csv
import hashlib
import json
import secrets
import hmac
import io
import os
import re
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from html import escape

from flask import Flask, Response, jsonify, redirect, request

DB_PATH = os.getenv("DB_PATH", "/data/scans.db")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

POSTER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,24}$")
SCAN_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
BROWSER_ID_RE = re.compile(r"^[a-f0-9-]{36}$")


app = Flask(__name__)


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    # Serialize first-time migration and import earlier counted scans into
    # the request history without losing existing aggregate data.
    conn.execute("BEGIN IMMEDIATE")
    try:
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
        already_has_log = conn.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'scan_requests'"
        ).fetchone() is not None

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                poster_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                requested_at INTEGER NOT NULL,
                result TEXT NOT NULL,
                http_status INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_requests_time "
            "ON scan_requests(requested_at DESC, id DESC)"
        )
        if not already_has_log:
            # Older accepted scans predate per-request logging.
            conn.execute(
                """
                INSERT INTO scan_requests
                    (poster_id, scan_id, requested_at, result, http_status)
                SELECT poster_id, scan_id, scanned_at, 'counted', 204
                FROM scans ORDER BY id
                """
            )
        # Add non-identifying HTTP metadata fields without dropping old rows.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_requests)")}
        for field in ("user_agent", "accept_language", "country", "client_hints",
                      "browser_id", "device_details"):
            if field not in cols:
                conn.execute(f"ALTER TABLE scan_requests ADD COLUMN {field} TEXT DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scan_requests_browser "
            "ON scan_requests(browser_id, requested_at DESC)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS poster_labels ("
            "poster_id TEXT PRIMARY KEY, label TEXT NOT NULL)"
        )
        conn.commit()
    except Exception:
        conn.rollback()
        conn.close()
        raise
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


def parse_consent_data():
    if len(request.get_data(cache=True)) > 2048:
        return None
    try:
        data = json.loads(request.get_data(as_text=True) or "{}")
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("consent") is not True:
        return None
    bid = data.get("browser_id")
    if not isinstance(bid, str) or not BROWSER_ID_RE.fullmatch(bid):
        return None
    details = data.get("details", {})
    if not isinstance(details, dict):
        return None
    allowed = ("language", "timezone", "platform", "screen", "viewport",
               "pixel_ratio", "color_depth", "touch_points", "cores",
               "memory_gb", "network_type")
    clean = {}
    for key in allowed:
        value = details.get(key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            clean[key] = str(value)[:80]
    return bid, json.dumps(clean, ensure_ascii=False)


@app.post("/scan")
def scan():
    poster_id = (request.args.get("p") or "").strip()
    scan_id = (request.args.get("s") or "").strip()
    now = int(datetime.now(timezone.utc).timestamp())

    if not POSTER_ID_RE.fullmatch(poster_id):
        result, status = "invalid_poster", 400
    elif not SCAN_ID_RE.fullmatch(scan_id):
        result, status = "invalid_scan", 400
    else:
        result, status = "counted", 204

    # Technical request headers; never store IP addresses.
    user_agent = (request.headers.get("User-Agent") or "")[:400]
    language = (request.headers.get("Accept-Language") or "")[:120]
    country = (request.headers.get("CF-IPCountry") or "")[:10]
    hints = " | ".join(filter(None, [
        request.headers.get("Sec-CH-UA"),
        request.headers.get("Sec-CH-UA-Platform"),
        request.headers.get("Sec-CH-UA-Mobile"),
    ]))[:400]
    device = parse_consent_data()
    browser_id, device_details = device if device else ("", "")

    with db() as conn:
        if result == "counted":
            try:
                conn.execute(
                    "INSERT INTO scans (poster_id, scan_id, scanned_at) VALUES (?, ?, ?)",
                    (poster_id, scan_id, now),
                )
            except sqlite3.IntegrityError:
                result = "duplicate"

        conn.execute(
            """INSERT INTO scan_requests
                (poster_id, scan_id, requested_at, result, http_status,
                 user_agent, accept_language, country, client_hints, browser_id, device_details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (poster_id[:80], scan_id[:80], now, result, status,
             user_agent, language, country, hints, browser_id, device_details),
        )
    return Response(status=status)


@app.post("/scan/enrich")
def enrich_scan():
    poster_id = (request.args.get("p") or "").strip()
    scan_id = (request.args.get("s") or "").strip()
    if not POSTER_ID_RE.fullmatch(poster_id) or not SCAN_ID_RE.fullmatch(scan_id):
        return Response(status=400)
    device = parse_consent_data()
    if device is None:
        return Response(status=400)
    with db() as conn:
        result = conn.execute(
            """UPDATE scan_requests SET browser_id=?, device_details=?
               WHERE poster_id=? AND scan_id=? AND result='counted'""",
            (*device, poster_id, scan_id),
        )
    return Response(status=204 if result.rowcount else 404)


@app.post("/privacy/forget")
def forget_browser():
    if len(request.get_data(cache=True)) > 1024:
        return Response(status=400)
    try:
        data = json.loads(request.get_data(as_text=True) or "{}")
    except (ValueError, TypeError):
        return Response(status=400)
    browser_id = data.get("browser_id") if isinstance(data, dict) else None
    if not isinstance(browser_id, str) or not BROWSER_ID_RE.fullmatch(browser_id):
        return Response(status=400)
    with db() as conn:
        conn.execute(
            "UPDATE scan_requests SET browser_id='', device_details='' WHERE browser_id=?",
            (browser_id,),
        )
    return Response(status=204)



def stats_rows():
    with db() as conn:
        return conn.execute(
            """
            SELECT
                s.poster_id,
                COALESCE(p.label, '') AS label,
                COUNT(*) AS scans,
                MIN(s.scanned_at) AS first_scan,
                MAX(s.scanned_at) AS last_scan,
                SUM(
                    CASE
                        WHEN s.scanned_at >= CAST(strftime('%s','now') AS INTEGER) - 86400
                        THEN 1 ELSE 0
                    END
                ) AS scans_24h
            FROM scans s
            LEFT JOIN poster_labels p ON p.poster_id = s.poster_id
            GROUP BY s.poster_id
            ORDER BY scans DESC, last_scan DESC
            """
        ).fetchall()


def fmt_time(ts):
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


STATS_CSS = (
    "<style>"
    "body{font-family:system-ui,sans-serif;max-width:1000px;margin:34px auto;"
    "padding:0 16px;color:#18231e}"
    "table{border-collapse:collapse;width:100%;font-size:14px}"
    "th,td{padding:10px 12px;border-bottom:1px solid #ddd;text-align:left}"
    "th{background:#f5f3ee}code{font-size:.95em;overflow-wrap:anywhere}"
    "a{color:#173e2e}"
    ".tabs{display:flex;gap:8px;margin:0 0 24px;flex-wrap:wrap}"
    ".tabs a{display:inline-block;padding:10px 15px;border-radius:10px;"
    "text-decoration:none;background:#f3f1ed}"
    ".tabs a.active{background:#173e2e;color:#fff}"
    ".table-wrap{overflow-x:auto}"
    ".muted{color:#647069}"
    ".pager{display:flex;gap:15px;margin:18px 0;align-items:center}"
    "input{font:inherit;border:1px solid #bbb;border-radius:8px;padding:8px;max-width:100%}"
    "button{font:inherit;border:0;border-radius:8px;padding:9px 13px;background:#173e2e;color:#fff;cursor:pointer}"
    ".label{font-weight:700}.sub{font-size:12px;color:#647069}.panel{background:#f5f3ee;padding:14px;border-radius:12px;margin:18px 0}"
    "form.inline{display:flex;gap:6px;align-items:center;flex-wrap:wrap}"
    "details{max-width:440px}summary{cursor:pointer}"
    "</style>"
)


def stats_tabs(active):
    summary = ' class="active"' if active == "summary" else ""
    requests_tab = ' class="active"' if active == "requests" else ""
    posters_tab = ' class="active"' if active == "posters" else ""
    return (
        '<nav class="tabs" aria-label="Statistika">'
        f'<a href="/stats"{summary}>Pregled</a>'
        f'<a href="/stats/requests"{requests_tab}>Posamezni zahtevki</a>'
        f'<a href="/stats/posters"{posters_tab}>Plakati</a>'
        '</nav>'
    )


@app.get("/stats")
@admin_required
def stats():
    rows = stats_rows()
    total = sum(row["scans"] for row in rows)

    body = [
        "<!doctype html><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Kuzki QR stats</title>",
        STATS_CSS,
        stats_tabs("summary"),
        f"<h1>QR skeni</h1><p>Skupaj: <strong>{total}</strong></p>",
        "<p><a href='/stats.csv'>Prenesi CSV</a></p>",
        '<div class="table-wrap">',
        "<table><thead><tr><th>Plakat</th><th>ID</th><th>Skeni</th><th>24 h</th><th>Prvi</th><th>Zadnji</th></tr></thead><tbody>",
    ]

    for row in rows:
        body.append(
            "<tr>"
            f"<td><span class='label'>{escape(row['label']) or '—'}</span></td>"
            f"<td><code>{escape(row['poster_id'])}</code></td>"
            f"<td>{row['scans']}</td>"
            f"<td>{row['scans_24h']}</td>"
            f"<td>{fmt_time(row['first_scan'])}</td>"
            f"<td>{fmt_time(row['last_scan'])}</td>"
            "</tr>"
        )

    body.append("</tbody></table></div>")
    return Response("".join(body), mimetype="text/html")



@app.get("/stats/requests")
@admin_required
def stats_requests():
    per_page = 50
    try:
        requested_page = max(1, int(request.args.get("page", "1")))
    except (ValueError, TypeError):
        requested_page = 1

    with db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scan_requests").fetchone()[0]
        page_count = max(1, (total + per_page - 1) // per_page)
        page = min(requested_page, page_count)
        rows = conn.execute(
            """
            SELECT id, poster_id, scan_id, requested_at, result, http_status
            FROM scan_requests
            ORDER BY requested_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (per_page, (page - 1) * per_page),
        ).fetchall()

    labels = {
        "counted": "Nov sken",
        "duplicate": "Podvojen",
        "invalid_poster": "Napačen ID plakata",
        "invalid_scan": "Napačen ID zahtevka",
    }

    body = [
        "<!doctype html><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Posamezni QR zahtevki</title>",
        STATS_CSS,
        stats_tabs("requests"),
        f"<h1>Posamezni zahtevki</h1><p>Skupaj zabeleženih: <strong>{total}</strong></p>",
        "<p class='muted'>Vsaka zahteva POST /scan je samostojna vrstica. "
        "Podvojitve se ne prištejejo k skenom. Časi so prikazani v UTC. "
        "IP naslovi se ne shranjujejo.</p>",
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Čas</th><th>Plakat ID</th><th>ID zahtevka</th>"
        "<th>Rezultat</th><th>HTTP</th>"
        "</tr></thead><tbody>",
    ]

    for row in rows:
        body.append(
            "<tr>"
            f"<td>{fmt_time(row['requested_at'])}</td>"
            f"<td><code>{escape(row['poster_id'])}</code></td>"
            f"<td><code>{escape(row['scan_id'])}</code></td>"
            f"<td>{labels.get(row['result'], escape(row['result']))}</td>"
            f"<td>{row['http_status']}</td>"
            "</tr>"
        )

    if not rows:
        body.append("<tr><td colspan='5'>Ni zahtevkov.</td></tr>")

    body.append("</tbody></table></div>")
    body.append('<nav class="pager" aria-label="Strani zahtevkov">')
    if page > 1:
        body.append(f'<a href="/stats/requests?page={page-1}">← Prejšnja</a>')
    body.append(f"<span>Stran {page} / {page_count}</span>")
    if page < page_count:
        body.append(f'<a href="/stats/requests?page={page+1}">Naslednja →</a>')
    body.append("</nav>")
    return Response("".join(body), mimetype="text/html")


@app.get("/stats.csv")
@admin_required
def stats_csv():
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(
        ["poster_id", "label", "scans", "scans_24h", "first_scan_utc", "last_scan_utc"]
    )

    for row in stats_rows():
        writer.writerow(
            [
                row["poster_id"],
                row["label"],
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

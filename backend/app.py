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
        # Location-based flyer inventory (v2), added without dropping
        # scans, history or existing poster labels.
        conn.execute(
            """CREATE TABLE IF NOT EXISTS locations (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                   capacity INTEGER NOT NULL DEFAULT 15 CHECK(capacity >= 1),
                   created_at INTEGER NOT NULL
               )"""
        )
        label_columns = {r[1] for r in conn.execute("PRAGMA table_info(poster_labels)")}
        if "location_id" not in label_columns:
            conn.execute("ALTER TABLE poster_labels ADD COLUMN location_id INTEGER REFERENCES locations(id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_poster_labels_location "
            "ON poster_labels(location_id)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"
        )
        if not conn.execute("SELECT 1 FROM schema_migrations WHERE version=2").fetchone():
            # Historical labels represented places. Group them by identical
            # name and preserve each poster's existing scan statistics.
            old_places = conn.execute(
                """SELECT TRIM(label) AS name, COUNT(*) AS n
                   FROM poster_labels
                   WHERE TRIM(label) <> '' AND location_id IS NULL
                   GROUP BY TRIM(label) COLLATE NOCASE"""
            ).fetchall()
            now = int(datetime.now(timezone.utc).timestamp())
            for place in old_places:
                conn.execute(
                    """INSERT OR IGNORE INTO locations(name, capacity, created_at)
                       VALUES (?, ?, ?)""",
                    (place["name"], max(15, place["n"]), now),
                )
                conn.execute(
                    """UPDATE poster_labels
                       SET location_id=(SELECT id FROM locations WHERE name=? COLLATE NOCASE)
                       WHERE TRIM(label)=? COLLATE NOCASE AND location_id IS NULL""",
                    (place["name"], place["name"]),
                )
            conn.execute("INSERT INTO schema_migrations(version) VALUES (2)")
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




LOCATION_NAME_MAX = 80
DEFAULT_FLIERS_PER_LOCATION = 15


def validate_location_name(value):
    name = (value or "").strip()
    if (not 1 <= len(name) <= LOCATION_NAME_MAX
            or any(ord(char) < 32 for char in name)):
        return None
    return name


def make_flyer_id(conn):
    # 96-bit random token; do not reuse an ID from older scan history.
    for _ in range(12):
        candidate = secrets.token_hex(12)
        used = conn.execute(
            """SELECT 1 FROM poster_labels WHERE poster_id=?
               UNION SELECT 1 FROM scans WHERE poster_id=?
               UNION SELECT 1 FROM scan_requests WHERE poster_id=?""",
            (candidate, candidate, candidate),
        ).fetchone()
        if not used:
            return candidate
    raise RuntimeError("Failed to allocate a unique flyer identifier")


def location_rows():
    with db() as conn:
        return conn.execute(
            """SELECT l.id, l.name, l.capacity,
                      COUNT(DISTINCT p.poster_id) AS flyers,
                      COUNT(s.id) AS scans,
                      SUM(CASE WHEN s.scanned_at >= CAST(strftime('%s','now') AS INTEGER)-86400
                          THEN 1 ELSE 0 END) AS scans_24h
               FROM locations l
               LEFT JOIN poster_labels p ON p.location_id=l.id
               LEFT JOIN scans s ON s.poster_id=p.poster_id
               GROUP BY l.id
               ORDER BY l.name COLLATE NOCASE"""
        ).fetchall()


def assign_flyer_to_location(conn, poster_id, name):
    """Move/create one flyer, enforcing the 15-flyer limit atomically."""
    location = conn.execute(
        "SELECT id, capacity FROM locations WHERE name=? COLLATE NOCASE", (name,)
    ).fetchone()
    if location is None:
        conn.execute(
            "INSERT INTO locations(name,capacity,created_at) VALUES (?,15,?)",
            (name, int(datetime.now(timezone.utc).timestamp())),
        )
        location = conn.execute(
            "SELECT id, capacity FROM locations WHERE name=? COLLATE NOCASE", (name,)
        ).fetchone()

    old = conn.execute(
        "SELECT location_id FROM poster_labels WHERE poster_id=?", (poster_id,)
    ).fetchone()
    if old is None or old["location_id"] != location["id"]:
        used = conn.execute(
            "SELECT COUNT(*) FROM poster_labels WHERE location_id=?", (location["id"],)
        ).fetchone()[0]
        if used >= location["capacity"]:
            return False
    conn.execute(
        """INSERT INTO poster_labels(poster_id,label,location_id)
           VALUES (?,?,?)
           ON CONFLICT(poster_id) DO UPDATE
           SET label=excluded.label, location_id=excluded.location_id""",
        (poster_id, name, location["id"]),
    )
    return True


@app.post("/stats/locations")
@admin_required
def create_location():
    if not hmac.compare_digest(
        (request.form.get("csrf") or "").encode("utf-8"),
        csrf_token().encode("utf-8"),
    ):
        return Response("Neveljavno varnostno preverjanje.", status=403)
    name = validate_location_name(request.form.get("name"))
    if not name:
        return Response("Neveljavno ime lokacije.", status=400)

    mode = (request.form.get("mode") or "batch").strip()
    if mode not in ("batch", "empty"):
        return Response("Neveljaven način ustvarjanja.", status=400)
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute(
            "SELECT 1 FROM locations WHERE name=? COLLATE NOCASE", (name,)
        ).fetchone():
            return Response("Lokacija s tem imenom že obstaja.", status=409)
        conn.execute(
            """INSERT INTO locations(name,capacity,created_at)
               VALUES (?,?,?)""",
            (name, DEFAULT_FLIERS_PER_LOCATION, int(datetime.now(timezone.utc).timestamp())),
        )
        location_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        if mode == "batch":
            for _ in range(DEFAULT_FLIERS_PER_LOCATION):
                poster_id = make_flyer_id(conn)
                conn.execute(
                    "INSERT INTO poster_labels(poster_id,label,location_id) VALUES (?,?,?)",
                    (poster_id, name, location_id),
                )
    return redirect("/stats/posters", code=303)


@app.get("/stats/flyers.csv")
@admin_required
def flyers_csv():
    """Inventory export of QR destinations without triggering actual scans."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["location", "flyer_id", "qr_url", "scans"])
    with db() as conn:
        rows = conn.execute(
            """SELECT l.name AS location, p.poster_id,
                      COUNT(s.id) AS scans
               FROM poster_labels p
               LEFT JOIN locations l ON l.id=p.location_id
               LEFT JOIN scans s ON s.poster_id=p.poster_id
               GROUP BY p.poster_id
               ORDER BY l.name COLLATE NOCASE, p.poster_id"""
        ).fetchall()
    for row in rows:
        writer.writerow([
            row["location"] or "",
            row["poster_id"],
            "https://kuski.qd.je/?p=" + row["poster_id"],
            row["scans"],
        ])
    return Response(
        out.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=kuzki-fliers.csv"},
    )


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
    browser_filter = (request.args.get("browser") or "").strip().lower()
    if browser_filter and not BROWSER_ID_RE.fullmatch(browser_filter):
        return Response("Invalid browser ID", status=400)
    clause = "WHERE r.browser_id = ?" if browser_filter else ""
    params = (browser_filter,) if browser_filter else ()

    with db() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM scan_requests r {clause}", params
        ).fetchone()[0]
        page_count = max(1, (total + per_page - 1) // per_page)
        page = min(requested_page, page_count)
        rows = conn.execute(
            f"""
            SELECT r.*, COALESCE(p.label, '') AS label
            FROM scan_requests r
            LEFT JOIN poster_labels p ON p.poster_id = r.poster_id
            {clause}
            ORDER BY r.requested_at DESC, r.id DESC
            LIMIT ? OFFSET ?
            """,
            (*params, per_page, (page - 1) * per_page),
        ).fetchall()

    labels = {
        "counted": "Nov sken",
        "duplicate": "Podvojen",
        "invalid_poster": "Napačen ID plakata",
        "invalid_scan": "Napačen ID zahtevka",
    }
    base = "/stats/requests" + (f"?browser={browser_filter}" if browser_filter else "")
    body = [
        "<!doctype html><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Posamezni QR zahtevki</title>",
        STATS_CSS, stats_tabs("requests"),
        f"<h1>Posamezni zahtevki</h1><p>Skupaj zabeleženih: <strong>{total}</strong></p>",
        "<p class='muted'>Običajni podatki HTTP-zahteve ne omogočajo zanesljive "
        "identifikacije naprave. ID brskalnika in podrobnosti naprave se hranijo "
        "le ob prostovoljni privolitvi. IP naslovov ne shranjujemo.</p>",
    ]
    if browser_filter:
        body.append(
            f"<p>Brskalnik: <code>{browser_filter}</code> "
            '<a href="/stats/requests">Počisti filter</a></p>'
        )
    body.append(
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Čas (UTC)</th><th>Plakat</th><th>Rezultat</th>"
        "<th>Brskalnik ID</th><th>Podatki o zahtevku</th>"
        "</tr></thead><tbody>"
    )
    for row in rows:
        browser_id = row["browser_id"] or ""
        device_link = (
            f'<a href="/stats/requests?browser={browser_id}">'
            f'<code>{browser_id[:8]}…</code></a>'
            if browser_id else "—"
        )
        parts = [
            ("ID zahtevka", row["scan_id"]),
            ("User-Agent", row["user_agent"]),
            ("Jezik HTTP", row["accept_language"]),
            ("Država Cloudflare", row["country"]),
            ("Client Hints", row["client_hints"]),
            ("Naprava (privolitev)", row["device_details"]),
        ]
        details = "".join(
            f"<div><b>{label}:</b> <code>{escape(value or '—')}</code></div>"
            for label, value in parts
        )
        body.append(
            "<tr>"
            f"<td>{fmt_time(row['requested_at'])}</td>"
            f"<td><span class='label'>{escape(row['label']) or '—'}</span>"
            f"<div><code>{escape(row['poster_id'])}</code></div></td>"
            f"<td>{labels.get(row['result'], escape(row['result']))}"
            f" <span class='sub'>HTTP {row['http_status']}</span></td>"
            f"<td>{device_link}</td>"
            f"<td><details><summary>Podrobnosti</summary>{details}</details></td>"
            "</tr>"
        )
    if not rows:
        body.append("<tr><td colspan='5'>Ni zahtevkov.</td></tr>")
    body.append("</tbody></table></div>")
    body.append('<nav class="pager" aria-label="Strani zahtevkov">')
    separator = "&" if browser_filter else "?"
    if page > 1:
        body.append(f'<a href="{base}{separator}page={page-1}">← Prejšnja</a>')
    body.append(f"<span>Stran {page} / {page_count}</span>")
    if page < page_count:
        body.append(f'<a href="{base}{separator}page={page+1}">Naslednja →</a>')
    body.append("</nav>")
    return Response("".join(body), mimetype="text/html")


def csrf_token():
    return hmac.new(
        ADMIN_PASSWORD.encode("utf-8"), b"poster-labels-v1", hashlib.sha256
    ).hexdigest()


@app.get("/stats/posters")
@admin_required
def stats_posters():
    token = csrf_token()
    with db() as conn:
        rows = conn.execute(
            """
            SELECT ids.poster_id, COALESCE(p.label, '') AS label,
                   COUNT(s.id) AS scans
            FROM (SELECT poster_id FROM scans
                  UNION SELECT poster_id FROM poster_labels) ids
            LEFT JOIN poster_labels p ON p.poster_id = ids.poster_id
            LEFT JOIN scans s ON s.poster_id = ids.poster_id
            GROUP BY ids.poster_id
            ORDER BY label COLLATE NOCASE, ids.poster_id
            """
        ).fetchall()
    body = [
        "<!doctype html><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Plakati in oznake</title>", STATS_CSS, stats_tabs("posters"),
        "<h1>Poimenovanje plakatov</h1>",
        "<p class='muted'>Ime lahko spremeniš, ne da bi spreminjal QR-kodo.</p>",
        '<div class="panel">'
        '<button type="button" id="open-flier-scanner">+ Dodaj flier</button>'
        '<p class="muted">Vpiši ime lokacije in skeniraj QR-kodo na plakatu. '
        'Skeniranje v administraciji ne poveča števila obiskov.</p></div>',
        '<div class="table-wrap"><table><thead><tr>',
        '<th>Ime</th><th>QR ID</th><th>Skeni</th><th>Spremeni ime</th>',
        '</tr></thead><tbody>',
    ]
    for row in rows:
        code = escape(row["poster_id"])
        name = escape(row["label"])
        body.append(
            "<tr>"
            f"<td><span class='label'>{name or '—'}</span></td>"
            f"<td><code>{code}</code></td>"
            f"<td>{row['scans']}</td>"
            '<td><form method="post" action="/stats/posters" class="inline">'
            f'<input type="hidden" name="csrf" value="{token}">'
            f'<input type="hidden" name="poster_id" value="{code}">'
            f'<input name="label" value="{name}" maxlength="80" required aria-label="Ime">'
            '<button type="submit">Shrani</button></form></td>'
            "</tr>"
        )
    if not rows:
        body.append("<tr><td colspan='4'>Ni plakatov.</td></tr>")
    body.append("</tbody></table></div>")
    body.extend([
        '<style>'
        '.flier-dialog{border:0;border-radius:18px;box-shadow:0 18px 90px #0003;'
        'width:min(94vw,560px);max-height:92dvh;padding:22px;overflow:auto;'
        'color:#18231e;font-family:system-ui,sans-serif}'
        '.flier-dialog::backdrop{background:#0009}'
        '.flier-dialog h2{margin:0 0 8px}'
        '.flier-dialog p{line-height:1.5}'
        '.flier-dialog input[type=text]{width:100%;margin:6px 0 14px;'
        'min-height:42px;box-sizing:border-box}'
        '.flier-dialog input[type=file]{width:100%;max-width:100%;margin:9px 0}'
        '.flier-dialog details{max-width:100%;margin:14px 0}'
        '.flier-dialog .actions{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}'
        '.flier-dialog .secondary{background:#eee;color:#18231e}'
        '#flier-reader{width:100%;margin:12px 0;overflow:hidden}'
        '#flier-reader[hidden]{display:none!important}'
        '#flier-scanner-status{min-height:18px}'
        '</style>',
        '<dialog id="flier-scanner-dialog" class="flier-dialog" '
        'aria-labelledby="flier-modal-title">',
        '<form method="post" action="/stats/posters" id="flier-scanner-form">',
        f'<input type="hidden" name="csrf" value="{token}">',
        '<input type="hidden" name="poster_id" id="flier-poster-id">',
        '<h2 id="flier-modal-title">Dodaj flier</h2>',
        '<p class="muted">1. Vpiši ime lokacije. 2. S kamero preberi QR-kodo '
        'na plakatu. Ime se samodejno shrani brez odpiranja QR povezave.</p>',
        '<label for="flier-name">Ime / lokacija</label>',
        '<input type="text" id="flier-name" name="label" required maxlength="80" '
        'placeholder="Knjižnica CTK" autocomplete="off">',
        '<div class="actions"><button type="button" id="flier-open-camera">'
        'Odpri kamero in skeniraj QR</button></div>',
        '<div id="flier-reader" hidden></div>',
        '<p id="flier-scanner-status" role="status" aria-live="polite"></p>',
        '<details><summary>Če kamera ne dela: naloži fotografijo ali prilepi URL</summary>',
        '<label for="flier-qr-image">Fotografija s QR-kodo</label>',
        '<input id="flier-qr-image" type="file" accept="image/*">',
        '<label for="flier-paste">Povezava iz QR-kode</label>',
        '<input type="text" id="flier-paste" placeholder="https://kuski.qd.je/?p=a1b2c3">',
        '<button type="button" id="flier-use-paste">Uporabi to povezavo</button>',
        '</details>',
        '<div class="actions"><button type="button" class="secondary" '
        'id="flier-cancel">Prekliči</button></div>',
        '</form></dialog>',
        '<script src="/static/poster-scanner.js" defer></script>',
    ])
    return Response("".join(body), mimetype="text/html")


@app.post("/stats/posters")
@admin_required
def rename_poster():
    provided = (request.form.get("csrf") or "").encode("utf-8")
    if not hmac.compare_digest(provided, csrf_token().encode("utf-8")):
        return Response("Neveljavno varnostno preverjanje.", status=403)
    poster_id = (request.form.get("poster_id") or "").strip()
    label = (request.form.get("label") or "").strip()
    if not poster_id:
        # Reserve a fresh ID that has not appeared in previous scans.
        with db() as conn:
            while True:
                poster_id = secrets.token_hex(3)
                occupied = conn.execute(
                    """SELECT 1 FROM poster_labels WHERE poster_id=?
                       UNION SELECT 1 FROM scans WHERE poster_id=?""",
                    (poster_id, poster_id),
                ).fetchone()
                if not occupied:
                    break
    if (not POSTER_ID_RE.fullmatch(poster_id) or not 1 <= len(label) <= 80
            or any(ord(char) < 32 for char in label)):
        return Response("Neveljaven ID ali ime plakata.", status=400)
    with db() as conn:
        conn.execute(
            """INSERT INTO poster_labels (poster_id, label) VALUES (?, ?)
               ON CONFLICT(poster_id) DO UPDATE SET label=excluded.label""",
            (poster_id, label),
        )
    return redirect("/stats/posters", code=303)


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

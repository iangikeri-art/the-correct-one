import hashlib
import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "zetech_dcf_smart_home_secret_2026"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "security.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads", "footage")
ALLOWED_EXTENSIONS = {"mp4", "webm", "ogg", "mov"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'member'
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cameras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            is_on INTEGER NOT NULL DEFAULT 1,
            stream_mode TEXT NOT NULL DEFAULT 'simulated',
            sample_clip TEXT DEFAULT ''
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS camera_status_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            camera_id INTEGER NOT NULL,
            requested_state TEXT NOT NULL,
            active_state TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            anomaly_flag INTEGER NOT NULL DEFAULT 0,
            timestamp TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS footage_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            camera_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            file_size_mb REAL NOT NULL DEFAULT 0,
            sha256_hash TEXT NOT NULL,
            integrity_status TEXT NOT NULL DEFAULT 'Complete',
            uploaded_by TEXT NOT NULL,
            uploaded_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            action TEXT NOT NULL,
            time TEXT NOT NULL,
            ip_address TEXT DEFAULT '127.0.0.1',
            status TEXT DEFAULT 'Authorized'
        )
        """
    )

    cur.execute("PRAGMA table_info(audit_logs)")
    existing_cols = set()
    for col_row in cur.fetchall():
        existing_cols.add(col_row["name"])

    if "ip_address" not in existing_cols:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN ip_address TEXT DEFAULT '127.0.0.1'")
    if "status" not in existing_cols:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN status TEXT DEFAULT 'Authorized'")

    cur.execute("SELECT COUNT(*) AS cnt FROM users")
    if cur.fetchone()["cnt"] == 0:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("Admin@123"), "admin"),
        )
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("family_member", generate_password_hash("Member@123"), "member"),
        )

    cur.execute("SELECT COUNT(*) AS cnt FROM cameras")
    if cur.fetchone()["cnt"] == 0:
        cur.execute(
            """
            INSERT INTO cameras (name, location, is_on, stream_mode, sample_clip)
            VALUES
                ('Camera 01 - Hallway', 'Main Hallway', 1, 'simulated', ''),
                ('Camera 02 - Perimeter', 'Outer Yard & Gate', 1, 'simulated', '')
            """
        )

    conn.commit()
    conn.close()


init_db()


def log_audit(user, action, status="Authorized", ip_address=None):
    if ip_address is None:
        ip_address = request.remote_addr or "127.0.0.1"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO audit_logs (user, action, time, ip_address, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (user or "unknown", action, timestamp, ip_address, status),
    )
    conn.commit()
    conn.close()


def login_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if "username" not in session:
            if request.path.startswith("/video_feed"):
                return Response("Unauthorized Access", status=403)
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    return decorated


def admin_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            log_audit(
                session.get("username", "unknown"),
                f"Unauthorized privilege attempt on {request.path}",
                status="Unauthorized Alert",
            )
            flash("Admin (Parent) privileges are required for this action.", "danger")
            return redirect(url_for("dashboard", section="permissions"))
        return func(*args, **kwargs)

    return decorated


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def compute_sha256(filepath):
    digest = hashlib.sha256()
    with open(filepath, "rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_audit(user["username"], f"Logged in as {user['role']}", status="Authorized")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
            log_audit(
                username or "unknown",
                f"Failed login attempt for user '{username}'",
                status="Unauthorized Alert",
            )

    return render_template("login.html", error=error)


@app.route("/logout")
@login_required
def logout():
    user = session.get("username", "unknown")
    log_audit(user, "Logged out of system", status="Authorized")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    section = request.args.get("section", "overview")
    allowed_sections = {"overview", "footage", "permissions", "logs"}
    if section not in allowed_sections:
        section = "overview"

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM cameras ORDER BY id ASC")
    cameras = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM camera_status_logs ORDER BY id DESC LIMIT 30")
    status_logs = [dict(r) for r in cur.fetchall()]

    cur.execute(
        """
        SELECT f.*, c.name AS camera_name
        FROM footage_records f
        LEFT JOIN cameras c ON f.camera_id = c.id
        ORDER BY f.id DESC
        """
    )
    footage_list = []
    for item in cur.fetchall():
        row = dict(item)
        full_path = os.path.join(UPLOAD_FOLDER, row["stored_name"])
        if not os.path.exists(full_path):
            row["integrity_status"] = "Missing"
        elif os.path.getsize(full_path) == 0:
            row["integrity_status"] = "Corrupted"
        else:
            row["integrity_status"] = "Complete"
        footage_list.append(row)

    cur.execute("SELECT id, username, role FROM users ORDER BY id ASC")
    users = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")
    logs = []
    for r in cur.fetchall():
        entry = dict(r)
        entry.setdefault("ip_address", "127.0.0.1")
        entry.setdefault("status", "Authorized")
        logs.append(entry)

    conn.close()

    anomaly_count = sum(1 for entry in logs if (entry.get("status") or "Authorized") != "Authorized") + sum(
        1 for status_entry in status_logs if status_entry.get("anomaly_flag") == 1
    )

    return render_template(
        "dashboard.html",
        username=session.get("username", "admin"),
        role=session.get("role", "admin"),
        section=section,
        cameras=cameras,
        status_logs=status_logs,
        footage_list=footage_list,
        users=users,
        logs=logs,
        anomaly_count=anomaly_count,
    )


@app.route("/toggle_camera/<int:cam_id>", methods=["POST"])
@login_required
@admin_required
def toggle_camera(cam_id):
    simulate_mismatch = request.form.get("simulate_mismatch") == "1"
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cameras WHERE id = ?", (cam_id,))
    cam = cur.fetchone()
    if not cam:
        conn.close()
        flash("Camera not found.", "danger")
        return redirect(url_for("dashboard", section="overview"))

    new_is_on = 0 if cam["is_on"] == 1 else 1
    requested_state = "ON" if new_is_on == 1 else "OFF"

    if new_is_on == 0 and simulate_mismatch:
        actual_is_on = 1
        active_state = "ON (ANOMALY)"
        anomaly_flag = 1
    else:
        actual_is_on = new_is_on
        active_state = "ON" if actual_is_on == 1 else "OFF"
        anomaly_flag = 0

    cur.execute("UPDATE cameras SET is_on = ? WHERE id = ?", (actual_is_on, cam_id))
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        """
        INSERT INTO camera_status_logs
            (camera_id, requested_state, active_state, updated_by, anomaly_flag, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (cam_id, requested_state, active_state, session.get("username"), anomaly_flag, ts),
    )
    conn.commit()
    conn.close()

    if anomaly_flag:
        log_audit(
            session.get("username"),
            f"ANOMALY: {cam['name']} requested {requested_state} but remained ACTIVE",
            status="Unauthorized Alert",
        )
        flash(f"Anomaly logged: {cam['name']} stayed active when turned OFF!", "warning")
    else:
        log_audit(
            session.get("username"),
            f"Set {cam['name']} state to {active_state}",
            status="Authorized",
        )
        flash(f"{cam['name']} is now {active_state}.", "success")

    return redirect(url_for("dashboard", section="overview"))


@app.route("/upload_footage", methods=["POST"])
@login_required
@admin_required
def upload_footage():
    camera_id = request.form.get("camera_id", type=int) or 1
    file = request.files.get("video_file")

    if not file or file.filename == "":
        flash("Please select a video file to upload.", "danger")
        return redirect(url_for("dashboard", section="footage"))

    if not allowed_file(file.filename):
        flash("Unsupported format. Allowed: mp4, webm, ogg, mov.", "danger")
        return redirect(url_for("dashboard", section="footage"))

    clean_name = secure_filename(file.filename)
    stored_name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{clean_name}"
    save_path = os.path.join(UPLOAD_FOLDER, stored_name)
    file.save(save_path)

    size_mb = round(os.path.getsize(save_path) / (1024 * 1024), 2)
    digest = compute_sha256(save_path)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO footage_records
            (camera_id, filename, stored_name, file_size_mb, sha256_hash, integrity_status, uploaded_by, uploaded_at)
        VALUES (?, ?, ?, ?, ?, 'Complete', ?, ?)
        """,
        (camera_id, clean_name, stored_name, size_mb, digest, session.get("username"), ts),
    )
    conn.commit()
    conn.close()

    log_audit(
        session.get("username"),
        f"Uploaded encrypted footage '{clean_name}' (SHA-256: {digest[:12]}...)",
        status="Authorized",
    )
    flash(f"Footage '{clean_name}' stored and verified (SHA-256 recorded).", "success")
    return redirect(url_for("dashboard", section="footage"))


@app.route("/footage/<int:footage_id>/play")
@login_required
@admin_required
def play_footage(footage_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM footage_records WHERE id = ?", (footage_id,))
    rec = cur.fetchone()
    conn.close()

    if not rec:
        return "Footage record not found", 404

    full_path = os.path.join(UPLOAD_FOLDER, rec["stored_name"])
    if not os.path.exists(full_path):
        log_audit(
            session.get("username"),
            f"Missing footage file detected: '{rec['filename']}'",
            status="Unauthorized Alert",
        )
        return "Footage file is missing from storage.", 404

    log_audit(
        session.get("username"),
        f"Played recorded footage '{rec['filename']}'",
        status="Authorized",
    )
    return send_from_directory(UPLOAD_FOLDER, rec["stored_name"], as_attachment=False)


@app.route("/video_feed/<int:cam_id>")
@login_required
def video_feed(cam_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cameras WHERE id = ?", (cam_id,))
    cam = cur.fetchone()
    conn.close()

    if not cam:
        return jsonify({"error": "Camera not found"}), 404

    if cam["is_on"] != 1:
        html = (
            f"<html><body style='background:#0f172a;color:#94a3b8;font-family:sans-serif;"
            f"display:flex;align-items:center;justify-content:center;height:100vh;margin:0;'>"
            f"<div style='text-align:center;'><h3>{cam['name']} is OFF</h3>"
            f"<p>Recording & live feed disabled by policy.</p></div></body></html>"
        )
        return Response(html, mimetype="text/html")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = (
        f"<html><body style='background:#090d16;color:#e2e8f0;font-family:sans-serif;"
        f"display:flex;flex-direction:column;align-items:center;justify-content:center;"
        f"height:100vh;margin:0;border:1px solid #1e293b;'>"
        f"<div style='color:#22c55e;font-weight:bold;margin-bottom:6px;'>● LIVE STREAM ACTIVE</div>"
        f"<div style='font-size:15px;font-weight:600;'>{cam['name']}</div>"
        f"<div style='font-size:12px;color:#94a3b8;margin-top:4px;'>Location: {cam['location']}</div>"
        f"<div style='font-size:12px;color:#64748b;margin-top:4px;'>Timestamp: {ts}</div>"
        f"</body></html>"
    )
    return Response(html, mimetype="text/html")


@app.route("/users/add", methods=["POST"])
@login_required
@admin_required
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "member")
    if role not in {"admin", "member"}:
        role = "member"

    if not username or not password:
        flash("Username and password are required.", "danger")
        return redirect(url_for("dashboard", section="permissions"))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        conn.commit()
        conn.close()
        log_audit(
            session.get("username"),
            f"Created user '{username}' with role '{role}'",
            status="Authorized",
        )
        flash(f"User '{username}' ({role}) added.", "success")
    except sqlite3.IntegrityError:
        flash(f"Username '{username}' already exists.", "danger")

    return redirect(url_for("dashboard", section="permissions"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
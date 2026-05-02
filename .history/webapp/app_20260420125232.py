import eventlet

eventlet.monkey_patch()

import os
import sys
import ssl
import socket
import json
import subprocess
import datetime
import sqlite3
import secrets
import hashlib
import re
import logging
import ipaddress
import uuid
from functools import wraps
from urllib.parse import urlparse

from apscheduler.schedulers.background import BackgroundScheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    redirect,
    url_for,
    Response,
    stream_with_context,
    g,
    flash,
    abort,
)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_socketio import SocketIO

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message

import requests

from port_scanner import scan_target, scan_generator_sync, parse_ports

from sonic_recon import (
    analyze_port_scan,
    analyze_ssl,
    analyze_dns,
    analyze_whois,
    analyze_ping,
    analyze_headers,
    analyze_subdomains,
    analyze_geolocation,
    analyze_cve,
)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "cyberscan.db")


def _env_bool(key, default=True):
    v = os.environ.get(key)
    if v is None:
        return default
    return str(v).lower() in ("1", "true", "yes", "on")


app = Flask(__name__, template_folder="templates", static_folder="static")
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Secure session cookies require HTTPS; browsers ignore them on http:// (e.g. LAN IP).
# Default Secure only when RENDER (or explicit SESSION_COOKIE_SECURE) indicates HTTPS deployment.
_default_session_cookie_secure = str(os.environ.get("RENDER", "")).lower() in (
    "1",
    "true",
    "yes",
)

# Allow forcing HTTPS even on non-Render deployments
_force_https = os.environ.get("FORCE_HTTPS", "").lower() in ("1", "true", "yes")
if _force_https:
    _default_session_cookie_secure = True

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY")
    or os.environ.get("APP_SECRET_KEY", "change-this-in-production"),
    SESSION_COOKIE_SECURE=_env_bool(
        "SESSION_COOKIE_SECURE", _default_session_cookie_secure
    ),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=30),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    WTF_CSRF_TIME_LIMIT=None,
    WTF_CSRF_SSL_STRICT=False,
)

# Mail (optional — scheduled scan alerts)
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "1") == "1"
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get(
    "MAIL_DEFAULT_SENDER", "noreply@cyberscan.local"
)

bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
mail = Mail(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False,
)
login_manager = LoginManager(app)
# Send guests to the landing page first; they choose Register or Login from there.
login_manager.login_view = "home"
login_manager.login_message = None
login_manager.remember_cookie_duration = datetime.timedelta(days=30)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


def get_remote_address():
    # Check for trusted proxy headers first
    if request.headers.get("X-Forwarded-For"):
        # Use the first IP in the X-Forwarded-For header
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    elif request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    else:
        return request.remote_addr


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    strategy="fixed-window",
)


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _table_columns(cursor, table):
    cursor.execute("PRAGMA table_info(%s)" % table)
    return {row[1] for row in cursor.fetchall()}


def init_db():
    db = sqlite3.connect(DB_PATH)
    c = db.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT,
            last_login_ip TEXT,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT,
            remember_token TEXT,
            reset_token TEXT,
            reset_token_expiry TEXT,
            is_admin INTEGER DEFAULT 0,
            is_super_admin INTEGER DEFAULT 0,
            org_id TEXT,
            is_active INTEGER DEFAULT 1
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS shared_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL,
            key_prefix TEXT,
            label TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS api_usage_daily (
            user_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            count INTEGER DEFAULT 0,
            PRIMARY KEY (user_id, day),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS organizations (
            org_id TEXT PRIMARY KEY,
            org_name TEXT UNIQUE NOT NULL,
            org_admin_user_id INTEGER,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (org_admin_user_id) REFERENCES users(id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS license_metadata (
            license_id TEXT PRIMARY KEY,
            license_key TEXT UNIQUE NOT NULL,
            org_name TEXT NOT NULL,
            org_admin_name TEXT NOT NULL,
            org_admin_email TEXT NOT NULL,
            org_admin_password_hash TEXT,
            created_by INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT,
            is_active INTEGER DEFAULT 1,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS org_licenses (
            org_license_id TEXT PRIMARY KEY,
            org_id TEXT NOT NULL,
            license_id TEXT NOT NULL,
            linked_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (org_id) REFERENCES organizations(org_id),
            FOREIGN KEY (license_id) REFERENCES license_metadata(license_id),
            UNIQUE (org_id, license_id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS user_org_mapping (
            user_id INTEGER NOT NULL,
            org_id TEXT NOT NULL,
            role TEXT NOT NULL,
            assigned_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            PRIMARY KEY (user_id, org_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (org_id) REFERENCES organizations(org_id)
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            ports TEXT DEFAULT '1-1024',
            frequency TEXT NOT NULL,
            last_run TEXT,
            next_run TEXT NOT NULL,
            last_open_ports TEXT,
            notify_email INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )
    cols = _table_columns(c, "users")
    migrations = [
        ("full_name", "ALTER TABLE users ADD COLUMN full_name TEXT"),
        (
            "created_at",
            "ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP",
        ),
        ("last_login", "ALTER TABLE users ADD COLUMN last_login TEXT"),
        ("last_login_ip", "ALTER TABLE users ADD COLUMN last_login_ip TEXT"),
        (
            "failed_attempts",
            "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0",
        ),
        ("locked_until", "ALTER TABLE users ADD COLUMN locked_until TEXT"),
        ("remember_token", "ALTER TABLE users ADD COLUMN remember_token TEXT"),
        ("reset_token", "ALTER TABLE users ADD COLUMN reset_token TEXT"),
        ("reset_token_expiry", "ALTER TABLE users ADD COLUMN reset_token_expiry TEXT"),
        ("is_admin", "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0"),
        ("is_super_admin", "ALTER TABLE users ADD COLUMN is_super_admin INTEGER DEFAULT 0"),
        ("org_id", "ALTER TABLE users ADD COLUMN org_id TEXT"),
    ]
    for name, stmt in migrations:
        if name not in cols:
            try:
                c.execute(stmt)
            except sqlite3.OperationalError:
                pass
    db.commit()
    db.close()


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]
        self.password_hash = row["password_hash"]
        self.full_name = row["full_name"]
        self.failed_attempts = row["failed_attempts"] or 0
        self.locked_until = row["locked_until"]
        self.org_id = row["org_id"] if "org_id" in row.keys() else None
        self.is_admin = bool(row["is_admin"]) if "is_admin" in row.keys() else False
        self.is_super_admin = bool(row["is_super_admin"] or row["is_admin"]) if "is_super_admin" in row.keys() else bool(row["is_admin"])

    @staticmethod
    def from_id(uid):
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        return User(row) if row else None

    @staticmethod
    def by_username_or_email(identifier):
        db = get_db()
        row = db.execute(
            "SELECT * FROM users WHERE username = ? OR LOWER(email) = LOWER(?)",
            (identifier, identifier),
        ).fetchone()
        return User(row) if row else None


@login_manager.user_loader
def load_user(user_id):
    return User.from_id(int(user_id))


def _is_bcrypt_hash(pw):
    return isinstance(pw, str) and pw.startswith("$2")


def _verify_password(user, plain):
    h = user.password_hash
    if _is_bcrypt_hash(h):
        return bcrypt.check_password_hash(h, plain)
    # Legacy plaintext migration
    if h == plain:
        return True
    return False


def _hash_password(plain):
    return bcrypt.generate_password_hash(plain).decode("utf-8")


def _generate_unique_username(base_name):
    db = get_db()
    username = re.sub(r"[^a-zA-Z0-9]", "", base_name.lower()) or "user"
    original = username
    suffix = 1
    while db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        username = f"{original}{suffix}"
        suffix += 1
    return username


def generate_license_key():
    import random
    import string

    part1 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    part2 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    part3 = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    return f"NITS-{part1}-{part2}-{part3}"


def generate_temp_password():
    import random
    import string

    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(random.choices(chars, k=12))


def log_action(user_id, action, details):
    logger = logging.getLogger("admin_audit")
    logger.info("user_id=%s action=%s details=%s", user_id, action, json.dumps(details))


def _client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


PRIVATE_SCAN_MSG = (
    "Scanning private or reserved IP ranges is not permitted on CyberScan."
)


def is_private_ip(host):
    """
    Check if host is a private or reserved IP address.
    Supports both IPv4 and IPv6 addresses.
    """
    try:
        if not host or not str(host).strip():
            return False
        h = str(host).strip()
        h = h.replace("https://", "").replace("http://", "").split("/")[0]
        # Handle IPv6 addresses in brackets [ipv6] or raw ::1
        if h.startswith("[") and "]" in h:
            h = h[1 : h.index("]")]
        elif ":" in h and h.count(":") >= 1:
            # IPv6 address - split on ':' to get the address part
            h = h.split(":")[0] if h.split(":")[0] else h

        try:
            ip = ipaddress.ip_address(h)
        except ValueError:
            # Not an IP, try hostname resolution
            ip = ipaddress.ip_address(socket.gethostbyname(h))

        # Check all private/reserved conditions
        bad = ip.is_private or ip.is_loopback or ip.is_multicast
        if getattr(ip, "is_reserved", False):
            bad = True
        # Additional IPv6-specific checks
        if hasattr(ip, "is_site_local") and ip.is_site_local:
            bad = True
        return bool(bad)
    except Exception:
        return False


def _scan_actor_username():
    try:
        if current_user.is_authenticated:
            return current_user.username
    except Exception:
        pass
    return "anonymous"


def _private_scan_blocked_response(target_raw):
    logger.warning(
        "Blocked private IP scan: %s by %s",
        target_raw,
        _scan_actor_username(),
    )
    return jsonify({"error": PRIVATE_SCAN_MSG}), 403


def _host_from_url(url: str) -> str:
    if not url:
        return ""
    u = url.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "https://" + u
    try:
        p = urlparse(u)
        return (p.hostname or "").strip()
    except ValueError:
        return ""


def _safe_next_redirect():
    """Open-redirect safe target for post-login/register (relative path or same-host URL)."""
    raw = (request.form.get("next") or request.args.get("next") or "").strip()
    if not raw or "\n" in raw or "\r" in raw:
        return None
    if raw.startswith("/") and not raw.startswith("//"):
        return raw
    try:
        p = urlparse(raw)
        if p.scheme in ("http", "https") and p.path:
            req_host = (request.host or "").lower().split(":")[0]
            phost = (p.hostname or "").lower()
            if phost and phost == req_host:
                path = p.path if p.path.startswith("/") else "/" + p.path
                return path + (("?" + p.query) if p.query else "")
    except ValueError:
        pass
    return None


def _parse_ping_metrics(output: str, reachable: bool):
    """Extract packet loss % and average RTT (ms) from ping stdout (Windows / Linux)."""
    loss_pct = None
    avg_ms = None
    if not output:
        return loss_pct, avg_ms
    m = re.search(r"\((\d+)%\s*loss\)", output, re.I)
    if m:
        loss_pct = float(m.group(1))
    if loss_pct is None:
        m = re.search(r"(\d+(?:\.\d+)?)%\s*packet\s*loss", output, re.I)
        if m:
            loss_pct = float(m.group(1))
    m = re.search(r"Average\s*=\s*(\d+)\s*ms", output, re.I)
    if m:
        avg_ms = float(m.group(1))
    if avg_ms is None:
        m = re.search(
            r"=\s*[\d.]+\s*/\s*([\d.]+)\s*/\s*[\d.]+\s*/\s*[\d.]+\s*ms",
            output,
            re.I,
        )
        if m:
            avg_ms = float(m.group(1))
    if loss_pct is None and not reachable:
        loss_pct = 100.0
    return loss_pct, avg_ms


def _host_matches_cert(host: str, cn: str, sans: list) -> bool:
    host = (host or "").lower().strip().rstrip(".")
    cn = (cn or "").lower().strip()
    if cn.startswith("*."):
        base = cn[2:]
        if host == base or host.endswith("." + base):
            return True
    if cn and (host == cn or host.endswith("." + cn)):
        return True
    for s in sans or []:
        s = str(s).lower().strip()
        if s.startswith("*."):
            b = s[2:]
            if host == b or host.endswith("." + b):
                return True
        if host == s:
            return True
    return False


def _ssl_cert_extras(cert, host: str, ssock) -> dict:
    """Augment SSL JSON for Sonic Recon (signature, self-signed, hostname match)."""
    extras = {
        "signature_algorithm": "",
        "self_signed": False,
        "subject_mismatch": False,
        "chain_incomplete": False,
    }
    try:
        subj = dict(x[0] for x in cert.get("subject", ()))
        cn = subj.get("commonName", "") or subj.get("commonname", "")
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        extras["self_signed"] = cert.get("subject") == cert.get("issuer")
        extras["subject_mismatch"] = not _host_matches_cert(host, cn, sans)
    except Exception:
        pass
    try:
        der = ssock.getpeercert(binary_form=True)
        if der:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                co = x509.load_der_x509_certificate(der, default_backend())
                extras["signature_algorithm"] = co.signature_algorithm_oid._name
            except Exception:
                pass
    except Exception:
        pass
    return extras


def _dns_sonic_context(domain: str, records: dict) -> dict:
    ctx = {"dmarc_txt": [], "dkim_found": False, "zone_transfer_exposed": False}
    try:
        import dns.resolver
        import dns.query
        import dns.zone

        try:
            ans = dns.resolver.resolve("_dmarc." + domain, "TXT", lifetime=4)
            ctx["dmarc_txt"] = [str(r).strip('"') for r in ans]
        except Exception:
            pass
        for sel in (
            "default",
            "google",
            "selector1",
            "selector2",
            "k1",
            "smtp",
            "mandrill",
            "s1",
            "s2",
        ):
            try:
                dns.resolver.resolve(f"{sel}._domainkey.{domain}", "TXT", lifetime=2)
                ctx["dkim_found"] = True
                break
            except Exception:
                continue
        try:
            ns_ans = dns.resolver.resolve(domain, "NS", lifetime=4)
            for ns in ns_ans:
                ns_host = str(ns.target).rstrip(".")
                try:
                    a_ans = dns.resolver.resolve(ns_host, "A", lifetime=3)
                    ns_ip = str(a_ans[0])
                    xfr = dns.query.xfr(ns_ip, domain, lifetime=3)
                    dns.zone.from_xfr(xfr)
                    ctx["zone_transfer_exposed"] = True
                    break
                except Exception:
                    continue
        except Exception:
            pass
    except ImportError:
        pass
    return ctx


def _whois_sonic_context(w, result: dict) -> dict:
    """Augment WHOIS payload for Sonic Recon (privacy / transfer hints)."""
    out = dict(result)
    emails = out.get("emails")
    es = ""
    if emails:
        if isinstance(emails, list):
            es = " ".join(str(e) for e in emails).lower()
        else:
            es = str(emails).lower()
    redacted = "redact" in es or "data protected" in es or "gdpr" in es or not es
    out["privacy_disabled"] = bool(es and "@" in es and not redacted)
    try:
        ud = getattr(w, "updated_date", None)
        if isinstance(ud, list) and ud:
            ud = ud[0]
        if isinstance(ud, datetime.datetime):
            age_days = (datetime.datetime.utcnow() - ud.replace(tzinfo=None)).days
            if 0 <= age_days <= 30:
                out["recent_transfer"] = True
    except Exception:
        pass
    return out


def _parse_iso(dt_str):
    if not dt_str:
        return None
    try:
        return datetime.datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except ValueError:
        return None


def _api_key_hash(raw_key):
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _get_api_limit():
    """Get daily API limit from environment variable, default to 100"""
    try:
        return int(os.environ.get("API_DAILY_LIMIT", "100"))
    except ValueError:
        return 100


def _get_user_for_api_key():
    key = request.headers.get("X-API-Key") or request.args.get("key")
    if not key:
        return None, None
    kh = _api_key_hash(key)
    db = get_db()
    row = db.execute(
        "SELECT user_id FROM api_keys WHERE key_hash = ?", (kh,)
    ).fetchone()
    if not row:
        return None, None
    user = User.from_id(row["user_id"])
    return user, row


def _api_usage_today(user_id):
    day = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    db = get_db()
    row = db.execute(
        "SELECT count FROM api_usage_daily WHERE user_id = ? AND day = ?",
        (user_id, day),
    ).fetchone()
    return row["count"] if row else 0


def _increment_api_usage(user_id):
    day = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    db = get_db()
    db.execute(
        """
        INSERT INTO api_usage_daily (user_id, day, count) VALUES (?, ?, 1)
        ON CONFLICT(user_id, day) DO UPDATE SET count = count + 1
        """,
        (user_id, day),
    )
    db.commit()


def api_key_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user, _ = _get_user_for_api_key()
        if not user:
            return jsonify({"error": "Invalid or missing API key"}), 401
        used = _api_usage_today(user.id)
        limit = _get_api_limit()
        if used >= limit:
            return jsonify({"error": f"Daily API limit reached ({limit}/day)"}), 429
        _increment_api_usage(user.id)
        g.api_user = user
        return fn(*args, **kwargs)

    return wrapper


@app.context_processor
def inject_csrf():
    return {"csrf_token": generate_csrf}


# ─── PAGES ────────────────────────────────────────────────────────────────────


@app.route("/")
def home():
    return render_template("landing.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "CyberScan", "version": "1.0.0"}), 200


@app.route("/dashboard")
@login_required
def dashboard():
    welcome = session.pop("login_welcome", None)
    return render_template("dashboard.html", login_welcome=welcome)


@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_super_admin:
        return redirect(url_for("dashboard"))
    return render_template("admin_dashboard.html")


@app.route('/api/admin/users', methods=['GET'])
@login_required
def get_all_users():
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied"}), 403
    db = get_db()
    rows = db.execute(
        """
        SELECT u.id, u.username, u.email, u.is_active, u.created_at, u.org_id, u.is_super_admin,
               o.org_name,
               m.role
        FROM users u
        LEFT JOIN organizations o ON u.org_id = o.org_id
        LEFT JOIN user_org_mapping m ON u.id = m.user_id AND m.org_id = u.org_id AND m.is_active = 1
        WHERE u.is_active = 1
        """
    ).fetchall()
    users = []
    for u in rows:
        role = "super_admin" if u["is_super_admin"] else (u["role"] or "user")
        users.append(
            {
                "user_id": str(u["id"]),
                "username": u["username"],
                "email": u["email"],
                "org_name": u["org_name"],
                "role": role,
                "is_active": bool(u["is_active"]),
                "created_at": u["created_at"],
            }
        )
    return jsonify(users)


@app.route('/api/admin/orgs', methods=['GET'])
@login_required
def get_all_orgs():
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied"}), 403
    db = get_db()
    org_rows = db.execute(
        "SELECT org_id, org_name, org_admin_user_id, is_active, created_at FROM organizations WHERE is_active = 1"
    ).fetchall()
    orgs = []
    for o in org_rows:
        admin_name = None
        if o["org_admin_user_id"]:
            admin_row = db.execute(
                "SELECT username FROM users WHERE id = ?", (o["org_admin_user_id"],)
            ).fetchone()
            admin_name = admin_row["username"] if admin_row else None
        users_count = db.execute(
            "SELECT COUNT(1) AS cnt FROM users WHERE org_id = ? AND is_active = 1", (o["org_id"],)
        ).fetchone()["cnt"]
        licenses_count = db.execute(
            "SELECT COUNT(1) AS cnt FROM org_licenses WHERE org_id = ? AND is_active = 1",
            (o["org_id"],),
        ).fetchone()["cnt"]
        orgs.append(
            {
                "org_id": o["org_id"],
                "org_name": o["org_name"],
                "org_admin_name": admin_name or "N/A",
                "users_count": users_count,
                "licenses_count": licenses_count,
                "is_active": bool(o["is_active"]),
                "created_at": o["created_at"],
            }
        )
    return jsonify(orgs)


@app.route('/api/admin/licenses', methods=['GET'])
@login_required
def get_all_licenses():
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied"}), 403
    db = get_db()
    rows = db.execute(
        "SELECT * FROM license_metadata WHERE is_active = 1"
    ).fetchall()
    licenses = []
    for l in rows:
        licenses.append(
            {
                "license_id": l["license_id"],
                "license_key": l["license_key"],
                "org_name": l["org_name"],
                "org_admin_name": l["org_admin_name"],
                "org_admin_email": l["org_admin_email"],
                "created_at": l["created_at"],
                "expires_at": l["expires_at"],
                "is_active": bool(l["is_active"]),
            }
        )
    return jsonify(licenses)


@app.route('/api/admin/licenses/create', methods=['POST'])
@login_required
def create_license():
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied. Super Admin only."}), 403
    data = request.get_json(silent=True) or {}
    if not all(k in data for k in ["org_name", "org_admin_name", "org_admin_email"]):
        return jsonify({"error": "Missing required fields"}), 400
    org_name = (data["org_name"] or "").strip()
    org_admin_name = (data["org_admin_name"] or "").strip()
    org_admin_email = (data["org_admin_email"] or "").strip().lower()
    if not org_name or not org_admin_name or not org_admin_email:
        return jsonify({"error": "Missing required fields"}), 400
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", org_admin_email):
        return jsonify({"error": "Invalid email address"}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        if cursor.execute(
            "SELECT 1 FROM users WHERE LOWER(email) = LOWER(?)",
            (org_admin_email,),
        ).fetchone():
            return jsonify({"error": "Email already registered"}), 409
        license_key = generate_license_key()
        temp_password = generate_temp_password()
        created_at = datetime.datetime.utcnow().isoformat() + "Z"
        org_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO organizations (org_id, org_name, is_active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (org_id, org_name, created_at, created_at),
        )
        username_base = org_admin_email.split("@")[0]
        user_name = _generate_unique_username(username_base)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, full_name, is_admin, is_super_admin, org_id, created_at) VALUES (?, ?, ?, ?, 0, 0, ?, ?)",
            (
                user_name,
                org_admin_email,
                _hash_password(temp_password),
                org_admin_name,
                org_id,
                created_at,
            ),
        )
        org_admin_id = cursor.lastrowid
        cursor.execute(
            "UPDATE organizations SET org_admin_user_id = ? WHERE org_id = ?",
            (org_admin_id, org_id),
        )
        license_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO license_metadata (license_id, license_key, org_name, org_admin_name, org_admin_email, org_admin_password_hash, created_by, created_at, is_active, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (
                license_id,
                license_key,
                org_name,
                org_admin_name,
                org_admin_email,
                _hash_password(temp_password),
                current_user.id,
                created_at,
                created_at,
            ),
        )
        cursor.execute(
            "INSERT INTO org_licenses (org_license_id, org_id, license_id, linked_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (str(uuid.uuid4()), org_id, license_id, created_at),
        )
        cursor.execute(
            "INSERT INTO user_org_mapping (user_id, org_id, role, assigned_at, is_active) VALUES (?, ?, ?, ?, 1)",
            (org_admin_id, org_id, "org_admin", created_at),
        )
        db.commit()
        log_action(
            current_user.id,
            "license_created",
            {"license_key": license_key, "org_name": org_name},
        )
        return jsonify(
            {
                "license_key": license_key,
                "org_admin_email": org_admin_email,
                "org_admin_password": temp_password,
                "message": "License created. Share password with Org Admin. Must change on first login.",
            }
        ), 201
    except sqlite3.IntegrityError as e:
        db.rollback()
        return jsonify({"error": "A record could not be created: %s" % str(e)}), 400
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/licenses/<license_id>', methods=['DELETE'])
@login_required
def remove_license(license_id):
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied"}), 403
    db = get_db()
    try:
        license_row = db.execute(
            "SELECT * FROM license_metadata WHERE license_id = ?", (license_id,)
        ).fetchone()
        if not license_row:
            return jsonify({"error": "License not found"}), 404
        db.execute(
            "UPDATE license_metadata SET is_active = 0, updated_at = ? WHERE license_id = ?",
            (datetime.datetime.utcnow().isoformat() + "Z", license_id),
        )
        db.execute(
            "UPDATE org_licenses SET is_active = 0 WHERE license_id = ?",
            (license_id,),
        )
        org_rows = db.execute(
            "SELECT DISTINCT o.org_admin_user_id FROM organizations o JOIN org_licenses ol ON o.org_id = ol.org_id WHERE ol.license_id = ?",
            (license_id,),
        ).fetchall()
        for org_row in org_rows:
            if org_row["org_admin_user_id"]:
                db.execute(
                    "UPDATE users SET is_active = 0 WHERE id = ?",
                    (org_row["org_admin_user_id"],),
                )
        db.commit()
        log_action(
            current_user.id,
            "license_removed",
            {"license_key": license_row["license_key"]},
        )
        return jsonify({"message": "License removed successfully"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/orgs/link', methods=['POST'])
@login_required
def link_org_to_license():
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied"}), 403
    data = request.get_json(silent=True) or {}
    if not data.get("org_id") or not data.get("license_id"):
        return jsonify({"error": "Missing required fields"}), 400
    db = get_db()
    try:
        org = db.execute(
            "SELECT * FROM organizations WHERE org_id = ?", (data["org_id"],)
        ).fetchone()
        license_row = db.execute(
            "SELECT * FROM license_metadata WHERE license_id = ?", (data["license_id"],)
        ).fetchone()
        if not org or not license_row:
            return jsonify({"error": "Organization or License not found"}), 404
        existing = db.execute(
            "SELECT * FROM org_licenses WHERE org_id = ? AND license_id = ?",
            (data["org_id"], data["license_id"]),
        ).fetchone()
        if existing:
            if existing["is_active"]:
                return jsonify({"error": "Already linked"}), 409
            db.execute(
                "UPDATE org_licenses SET is_active = 1, linked_at = ? WHERE org_license_id = ?",
                (datetime.datetime.utcnow().isoformat() + "Z", existing["org_license_id"]),
            )
        else:
            db.execute(
                "INSERT INTO org_licenses (org_license_id, org_id, license_id, linked_at, is_active) VALUES (?, ?, ?, ?, 1)",
                (str(uuid.uuid4()), data["org_id"], data["license_id"], datetime.datetime.utcnow().isoformat() + "Z"),
            )
        db.commit()
        log_action(
            current_user.id,
            "org_linked_to_license",
            {"org_name": org["org_name"], "license_key": license_row["license_key"]},
        )
        return jsonify({"message": "Organization linked to license"}), 201
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/orgs/unlink', methods=['POST'])
@login_required
def unlink_org_from_license():
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied"}), 403
    data = request.get_json(silent=True) or {}
    if not data.get("org_id") or not data.get("license_id"):
        return jsonify({"error": "Missing required fields"}), 400
    db = get_db()
    try:
        org_license = db.execute(
            "SELECT * FROM org_licenses WHERE org_id = ? AND license_id = ? AND is_active = 1",
            (data["org_id"], data["license_id"]),
        ).fetchone()
        if not org_license:
            return jsonify({"error": "Link not found"}), 404
        db.execute(
            "UPDATE org_licenses SET is_active = 0 WHERE org_license_id = ?",
            (org_license["org_license_id"],),
        )
        org = db.execute("SELECT * FROM organizations WHERE org_id = ?", (data["org_id"],)).fetchone()
        license_row = db.execute(
            "SELECT * FROM license_metadata WHERE license_id = ?", (data["license_id"],)
        ).fetchone()
        db.commit()
        log_action(
            current_user.id,
            "org_unlinked_from_license",
            {"org_name": org["org_name"] if org else data["org_id"], "license_key": license_row["license_key"] if license_row else data["license_id"]},
        )
        return jsonify({"message": "Organization unlinked from license"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/users/<user_id>/password', methods=['PUT'])
@login_required
def change_user_password(user_id):
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied"}), 403
    db = get_db()
    try:
        user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_row:
            return jsonify({"error": "User not found"}), 404
        temp_password = generate_temp_password()
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (_hash_password(temp_password), user_id),
        )
        db.commit()
        log_action(
            current_user.id,
            "password_reset",
            {"target_user_id": user_id, "target_username": user_row["username"]},
        )
        return jsonify(
            {
                "user_id": str(user_id),
                "new_password": temp_password,
                "message": "Password changed. Share new password with user.",
            }
        ), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@login_required
def remove_user(user_id):
    if not current_user.is_super_admin:
        return jsonify({"error": "Access denied"}), 403
    if str(current_user.id) == str(user_id):
        return jsonify({"error": "Cannot delete yourself"}), 400
    db = get_db()
    try:
        user_row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_row:
            return jsonify({"error": "User not found"}), 404
        db.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        db.commit()
        log_action(
            current_user.id,
            "user_removed",
            {"removed_user_id": user_id, "username": user_row["username"]},
        )
        return jsonify({"message": "User removed successfully"}), 200
    except Exception as e:
        db.rollback()
        return jsonify({"error": str(e)}), 500


@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        return _register_post()
    return render_template("register.html", next=request.args.get("next"))


def _register_post():
    data = request.form
    full_name = (data.get("full_name") or "").strip()
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    confirm = data.get("confirm_password") or ""
    terms = data.get("terms")
    errors = []
    if not full_name:
        errors.append("Full name is required.")
    if not re.match(r"^[a-zA-Z0-9]+$", username):
        errors.append("Username must be alphanumeric only.")
    elif len(username) < 2:
        errors.append("Username is too short.")
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        errors.append("Enter a valid email address.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if password != confirm:
        errors.append("Passwords do not match.")
    if not terms:
        errors.append("You must accept the terms to register.")
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        errors.append("Username is already taken.")
    if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        errors.append("Email is already registered.")
    if errors:
        if (
            request.is_json
            or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        ):
            return jsonify({"ok": False, "errors": errors}), 400
        for e in errors:
            flash(e, "error")
        next_val = (data.get("next") or "").strip() or None
        return render_template("register.html", next=next_val), 400
    pw_hash = _hash_password(password)
    cur = db.execute(
        """
        INSERT INTO users (username, email, password_hash, full_name)
        VALUES (?, ?, ?, ?)
        """,
        (username, email, pw_hash, full_name),
    )
    new_uid = cur.lastrowid
    # Record first session in DB so the next credential login shows "welcome back"
    # (welcome banner after signup still uses session last_login=None → first-login copy).
    reg_ip = _client_ip()
    reg_now = datetime.datetime.utcnow().isoformat() + "Z"
    db.execute(
        "UPDATE users SET last_login = ?, last_login_ip = ? WHERE id = ?",
        (reg_now, reg_ip, new_uid),
    )
    db.commit()
    logger.info("New user: %s", username)
    new_user = User.from_id(new_uid)
    session.permanent = False
    login_user(new_user, remember=False)
    session["login_welcome"] = {
        "username": new_user.username,
        "last_login": None,
        "last_ip": None,
    }
    dest = _safe_next_redirect() or url_for("dashboard")
    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "redirect": dest})
    return redirect(dest)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        return _login_post()
    locked_until = session.pop("display_locked_until", None)
    return render_template(
        "login.html", locked_until=locked_until, next=request.args.get("next")
    )


def _login_post():
    identifier = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    remember = (
        request.form.get("remember") == "1" or request.form.get("remember") == "on"
    )
    user_row = User.by_username_or_email(identifier)
    db = get_db()
    now = datetime.datetime.utcnow()

    def fail_response(msg, locked_iso=None, failures=0):
        next_q = (
            request.form.get("next") or request.args.get("next") or ""
        ).strip() or None
        payload = {
            "ok": False,
            "message": msg,
            "failures": failures,
            "locked_until": locked_iso,
        }
        if (
            request.is_json
            or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        ):
            return jsonify(payload), 401 if not locked_iso else 423
        flash(msg, "error")
        return render_template(
            "login.html", locked_until=locked_iso, next=next_q
        ), 401 if not locked_iso else 423

    if user_row:
        lu = _parse_iso(user_row.locked_until)
        if lu and lu > now:
            session["display_locked_until"] = user_row.locked_until
            logger.warning("Locked: %s", user_row.username)
            return fail_response(
                "Account locked. Try again later.",
                locked_iso=user_row.locked_until,
                failures=user_row.failed_attempts,
            )

    if not identifier or not password:
        logger.warning(
            "Failed login: %s from %s", identifier or "(empty)", _client_ip()
        )
        return fail_response("Invalid credentials. Please try again.", failures=0)

    if not user_row:
        logger.warning("Failed login: %s from %s", identifier, _client_ip())
        return fail_response("Invalid credentials. Please try again.", failures=0)

    if not _verify_password(user_row, password):
        fails = (user_row.failed_attempts or 0) + 1
        locked_iso = None
        if fails >= 5:
            locked_until = now + datetime.timedelta(minutes=15)
            locked_iso = locked_until.isoformat() + "Z"
            db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                (locked_iso, user_row.id),
            )
        else:
            db.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = NULL WHERE id = ?",
                (fails, user_row.id),
            )
        db.commit()
        refreshed = User.by_username_or_email(identifier)
        if fails >= 5:
            session["display_locked_until"] = locked_iso
            logger.warning("Locked: %s", user_row.username)
            return fail_response(
                "Too many failed attempts. Account locked for 15 minutes.",
                locked_iso=locked_iso,
                failures=fails,
            )
        logger.warning("Failed login: %s from %s", identifier, _client_ip())
        return fail_response(
            "Invalid credentials. Please try again.",
            failures=fails,
        )

    # Success
    old_ll = user_row  # re-fetch for last_login fields
    row = db.execute(
        "SELECT last_login, last_login_ip FROM users WHERE id = ?", (user_row.id,)
    ).fetchone()
    prev_login = row["last_login"]
    prev_ip = row["last_login_ip"]
    ip = _client_ip()
    now_iso = datetime.datetime.utcnow().isoformat() + "Z"
    if not _is_bcrypt_hash(user_row.password_hash):
        new_hash = _hash_password(password)
        db.execute(
            """
            UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL,
            last_login = ?, last_login_ip = ? WHERE id = ?
            """,
            (new_hash, now_iso, ip, user_row.id),
        )
    else:
        db.execute(
            """
            UPDATE users SET failed_attempts = 0, locked_until = NULL,
            last_login = ?, last_login_ip = ? WHERE id = ?
            """,
            (now_iso, ip, user_row.id),
        )
    db.commit()
    user_obj = User.from_id(user_row.id)
    logger.info("Login: %s from %s", user_obj.username, _client_ip())
    session.permanent = remember
    login_user(user_obj, remember=remember)
    welcome = {
        "username": user_obj.username,
        "last_login": prev_login,
        "last_ip": prev_ip,
    }
    session["login_welcome"] = welcome
    dest = _safe_next_redirect() or url_for("dashboard")
    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "redirect": dest})
    return redirect(dest)


@app.route("/logout")
@login_required
def logout():
    username = current_user.username if current_user.is_authenticated else "unknown"
    # Explicitly clear remember cookie
    logout_user()
    session.clear()
    # Clear remember cookie explicitly
    response = redirect(url_for("home"))
    response.set_cookie("remember_token", "", expires=0, httponly=True, samesite="Lax")
    logger.info("User logged out: %s", username)
    return response


@app.route("/profile")
@login_required
def profile():
    row = (
        get_db()
        .execute(
            "SELECT username, email, full_name, created_at, last_login, last_login_ip FROM users WHERE id = ?",
            (current_user.id,),
        )
        .fetchone()
    )
    return render_template("profile.html", account=row)


@app.route("/check-username")
@limiter.limit("30 per minute")
def check_username():
    u = (request.args.get("u") or "").strip()
    if not u or not re.match(r"^[a-zA-Z0-9]+$", u):
        return jsonify({"available": False, "invalid": True})
    db = get_db()
    taken = (
        db.execute("SELECT 1 FROM users WHERE username = ?", (u,)).fetchone()
        is not None
    )
    return jsonify({"available": not taken})


@app.route("/check-email")
@limiter.limit("30 per minute")
def check_email():
    e = (request.args.get("e") or "").strip().lower()
    if not e or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e):
        return jsonify({"available": False, "invalid": True})
    db = get_db()
    taken = (
        db.execute("SELECT 1 FROM users WHERE email = ?", (e,)).fetchone() is not None
    )
    return jsonify({"available": not taken})


@app.route("/forgot-password", methods=["POST"])
@limiter.limit("10 per minute")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    token = secrets.token_urlsafe(32)
    exp = (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat() + "Z"
    db = get_db()
    row = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if row:
        db.execute(
            "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?",
            (token, exp, row["id"]),
        )
        db.commit()
    return jsonify({"sent": True})


# ─── QUICK SCAN (PUBLIC) ──────────────────────────────────────────────────────


@app.route("/quick-scan")
def quick_scan_page():
    return render_template("quick_scan.html")


@app.route("/stream_scan_public")
@limiter.limit("1 per hour")
def stream_scan_public():
    target = request.args.get("target")
    threads = min(int(request.args.get("threads", 50)), 100)
    timeout = float(request.args.get("timeout", 1.0))
    service = request.args.get("service") == "on"
    if not target:
        return jsonify({"error": "target required"}), 400
    if is_private_ip(target):
        return _private_scan_blocked_response(target)
    logger.info("Scan: quick_public_portscan on %s by anonymous", target)

    def generate():
        try:
            total_ports = len(parse_ports("1-100"))
        except Exception:
            total_ports = 0
        yield f"data: {json.dumps({'type': 'meta', 'total': total_ports})}\n\n"
        scanned_count = 0
        opens = []
        try:
            for port, is_open, svc, banner in scan_generator_sync(
                target, "1-100", threads, timeout, service
            ):
                scanned_count += 1
                if is_open:
                    opens.append({"port": port, "service": svc, "banner": banner})
                msg = {
                    "type": "result",
                    "port": port,
                    "open": is_open,
                    "service": svc,
                    "banner": banner,
                    "scanned": scanned_count,
                }
                yield f"data: {json.dumps(msg)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'complete', 'ai_analysis': analyze_port_scan(opens)})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


# ─── SHARED REPORT ────────────────────────────────────────────────────────────


@app.route("/api/share-report", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def share_report():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    results = data.get("results")
    if not target or not isinstance(results, list):
        return jsonify({"error": "target and results required"}), 400
    token = secrets.token_urlsafe(24)
    exp = (datetime.datetime.utcnow() + datetime.timedelta(days=7)).isoformat() + "Z"
    payload = json.dumps({"target": target, "results": results})
    db = get_db()
    db.execute(
        """
        INSERT INTO shared_reports (token, user_id, payload, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (token, current_user.id, payload, exp),
    )
    db.commit()
    return jsonify({"url": url_for("public_report", token=token, _external=True)})


@app.route("/report/<token>")
def public_report(token):
    db = get_db()
    row = db.execute(
        "SELECT payload, expires_at FROM shared_reports WHERE token = ?", (token,)
    ).fetchone()
    if not row:
        abort(404)
    exp = _parse_iso(row["expires_at"])
    if exp and exp < datetime.datetime.utcnow():
        abort(410)
    try:
        data = json.loads(row["payload"])
    except json.JSONDecodeError:
        abort(404)
    return render_template("report_public.html", data=data, token=token)


# ─── HIBP TOOL ────────────────────────────────────────────────────────────────


@app.route("/api/breach-check", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def breach_check():
    data = request.get_json(silent=True) or {}
    query = (data.get("query") or "").strip()
    if not query:
        return jsonify({"error": "query required"}), 400
    api_key = os.environ.get("HIBP_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "Server is not configured with HIBP_API_KEY"}), 503
    import urllib.parse

    headers = {"hibp-api-key": api_key, "User-Agent": "CyberScan-Auth-Toolkit"}
    out = {"breaches": [], "mode": None}
    try:
        if "@" in query:
            out["mode"] = "email"
            enc = urllib.parse.quote(query)
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{enc}",
                headers=headers,
                timeout=15,
            )
            if r.status_code == 404:
                out["breaches"] = []
            elif r.status_code == 200:
                out["breaches"] = r.json()
            else:
                return jsonify(
                    {"error": "HIBP API error", "status": r.status_code}
                ), 502
        else:
            out["mode"] = "domain"
            enc = urllib.parse.quote(query)
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={enc}",
                headers=headers,
                timeout=15,
            )
            if r.status_code != 200:
                return jsonify(
                    {"error": "HIBP API error", "status": r.status_code}
                ), 502
            out["breaches"] = r.json() or []
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502
    return jsonify(out)


# ─── SCHEDULED SCANS ──────────────────────────────────────────────────────────


def _next_run_iso(frequency, from_dt=None):
    base = from_dt or datetime.datetime.utcnow()
    if frequency == "daily":
        n = base + datetime.timedelta(days=1)
    elif frequency == "weekly":
        n = base + datetime.timedelta(weeks=1)
    elif frequency == "monthly":
        n = base + datetime.timedelta(days=30)
    else:
        n = base + datetime.timedelta(days=1)
    return n.isoformat() + "Z"


@app.route("/api/schedules", methods=["GET", "POST"])
@login_required
def schedules():
    db = get_db()
    if request.method == "GET":
        rows = db.execute(
            "SELECT * FROM scan_schedules WHERE user_id = ? ORDER BY id DESC",
            (current_user.id,),
        ).fetchall()
        return jsonify({"schedules": [dict(r) for r in rows]})
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    ports = (data.get("ports") or "1-1024").strip()
    frequency = (data.get("frequency") or "").strip().lower()
    notify = 1 if data.get("notify_email") else 0
    if not target or frequency not in ("daily", "weekly", "monthly"):
        return jsonify({"error": "Invalid schedule"}), 400
    if is_private_ip(target):
        return _private_scan_blocked_response(target)
    logger.info(
        "Scan: schedule_portscan on %s by %s",
        target,
        current_user.username,
    )
    nr = _next_run_iso(frequency)
    db.execute(
        """
        INSERT INTO scan_schedules (user_id, target, ports, frequency, next_run, notify_email)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (current_user.id, target, ports, frequency, nr, notify),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/schedules/<int:sid>", methods=["DELETE"])
@login_required
def schedule_delete(sid):
    db = get_db()
    db.execute(
        "DELETE FROM scan_schedules WHERE id = ? AND user_id = ?",
        (sid, current_user.id),
    )
    db.commit()
    return jsonify({"ok": True})


def run_due_schedules():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    now = datetime.datetime.utcnow()
    rows = c.execute("SELECT * FROM scan_schedules").fetchall()
    for sch in rows:
        nxt = _parse_iso(sch["next_run"])
        if not nxt or nxt > now:
            continue
        uname_row = c.execute(
            "SELECT username FROM users WHERE id = ?", (sch["user_id"],)
        ).fetchone()
        uname = uname_row["username"] if uname_row else str(sch["user_id"])
        if is_private_ip(sch["target"]):
            logger.warning(
                "Blocked private IP scan: %s by %s",
                sch["target"],
                uname,
            )
            c.execute(
                "UPDATE scan_schedules SET last_run = ?, next_run = ? WHERE id = ?",
                (
                    now.isoformat() + "Z",
                    _next_run_iso(sch["frequency"], now),
                    sch["id"],
                ),
            )
            db.commit()
            continue
        logger.info("Scan: scheduled_portscan on %s by %s", sch["target"], uname)
        try:
            results = scan_target(
                sch["target"],
                ports=sch["ports"] or "1-1024",
                threads=80,
                timeout=1.0,
                service=True,
            )
        except Exception as e:
            results = []
            err = str(e)
        else:
            err = None
        open_ports = sorted({p for p, _s, _b in results})
        prev_raw = sch["last_open_ports"]
        try:
            prev = set(json.loads(prev_raw)) if prev_raw else set()
        except json.JSONDecodeError:
            prev = set()
        new_open = sorted(set(open_ports) - set(prev))
        c.execute(
            "UPDATE scan_schedules SET last_run = ?, last_open_ports = ?, next_run = ? WHERE id = ?",
            (
                now.isoformat() + "Z",
                json.dumps(open_ports),
                _next_run_iso(sch["frequency"], now),
                sch["id"],
            ),
        )
        db.commit()
        if sch["notify_email"] and app.config.get("MAIL_SERVER"):
            user = c.execute(
                "SELECT email, username FROM users WHERE id = ?", (sch["user_id"],)
            ).fetchone()
            if user and user["email"]:
                subj = f"[CyberScan] Scheduled scan: {sch['target']}"
                body = f"Scan finished for {sch['target']}.\nOpen ports: {open_ports}\n"
                if err:
                    body += f"Error: {err}\n"
                if new_open:
                    body += f"New open ports vs last run: {new_open}\n"
                try:
                    with app.app_context():
                        mail.send(
                            Message(
                                subj,
                                recipients=[user["email"]],
                                body=body,
                            )
                        )
                except Exception:
                    pass
    db.close()


_scheduler = None

SELF_PING_URL = os.environ.get(
    "SELF_PING_URL",
    "https://cyberscan.nitechsaprk.in/health",
)


def self_ping():
    try:
        requests.get(SELF_PING_URL, timeout=10)
        logger.info("Self-ping successful")
    except Exception:
        pass


def start_scheduler():
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(run_due_schedules, "interval", minutes=1, id="sched_scans")
    if os.environ.get("RENDER") or os.environ.get("ENABLE_SELF_PING", "").lower() in (
        "1",
        "true",
        "yes",
    ):
        _scheduler.add_job(self_ping, "interval", minutes=14, id="self_ping")
    _scheduler.start()


if (not app.debug) or (os.environ.get("WERKZEUG_RUN_MAIN") == "true"):
    start_scheduler()


# ─── API KEYS (WEB UI) ───────────────────────────────────────────────────────


@app.route("/api-access")
@login_required
def api_access_page():
    db = get_db()
    keys = db.execute(
        "SELECT id, key_prefix, label, created_at FROM api_keys WHERE user_id = ? ORDER BY id DESC",
        (current_user.id,),
    ).fetchall()
    used = _api_usage_today(current_user.id)
    return render_template(
        "api_access.html",
        api_keys=keys,
        api_used=used,
        api_remaining=max(0, 100 - used),
    )


@app.route("/api/api-keys", methods=["POST"])
@login_required
def create_api_key():
    data = request.get_json(silent=True) or {}
    label = (data.get("label") or "default").strip()[:80]
    raw = "cs_" + secrets.token_urlsafe(32)
    kh = _api_key_hash(raw)
    prefix = raw[:12] + "…"
    db = get_db()
    db.execute(
        "INSERT INTO api_keys (user_id, key_hash, key_prefix, label) VALUES (?, ?, ?, ?)",
        (current_user.id, kh, prefix, label),
    )
    db.commit()
    return jsonify({"key": raw, "prefix": prefix})


@app.route("/api/api-keys/<int:kid>", methods=["DELETE"])
@login_required
def revoke_api_key(kid):
    db = get_db()
    db.execute(
        "DELETE FROM api_keys WHERE id = ? AND user_id = ?", (kid, current_user.id)
    )
    db.commit()
    return jsonify({"ok": True})


# ─── DEVELOPER API (API KEY) ─────────────────────────────────────────────────


@app.route("/api/portscan")
@api_key_required
def api_portscan():
    target = request.args.get("target", "").strip()
    r = request.args.get("range", "1-1024")
    if not target:
        return jsonify({"error": "target required"}), 400

    # Validate port range to prevent resource exhaustion
    try:
        port_list = parse_ports(r)
        if len(port_list) > 10000:
            return jsonify(
                {"error": "Port range too large. Maximum 10000 ports allowed."}
            ), 400
    except Exception:
        return jsonify({"error": "Invalid port range"}), 400

    if is_private_ip(target):
        return _private_scan_blocked_response(target)
    logger.info("Scan: api_portscan on %s by %s", target, g.api_user.username)
    try:
        results = scan_target(target, ports=r, threads=100, timeout=1.0, service=True)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    out = [{"port": p, "service": s, "banner": b} for p, s, b in results]
    return jsonify({"target": target, "results": out})


@app.route("/api/ssl")
@api_key_required
def api_ssl():
    host = (
        request.args.get("target", "")
        .strip()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )
    port = int(request.args.get("port", 443))
    if not host:
        return jsonify({"error": "target required"}), 400
    if is_private_ip(host):
        return _private_scan_blocked_response(host)
    logger.info("Scan: api_ssl on %s by %s", host, g.api_user.username)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
        expire_str = cert.get("notAfter", "")
        expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_dt - datetime.datetime.utcnow()).days
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        return jsonify(
            {
                "host": host,
                "valid": True,
                "subject": subject.get("commonName", host),
                "issuer": issuer.get("organizationName", "Unknown"),
                "expires": expire_str,
                "days_left": days_left,
                "protocol": protocol,
                "cipher": cipher[0] if cipher else "Unknown",
                "sans": sans[:20],
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/dns")
@api_key_required
def api_dns():
    domain = request.args.get("target", "").strip()
    if not domain:
        return jsonify({"error": "target required"}), 400
    if is_private_ip(domain):
        return _private_scan_blocked_response(domain)
    logger.info("Scan: api_dns on %s by %s", domain, g.api_user.username)
    try:
        import dns.resolver

        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return jsonify({"domain": domain, "records": records})
    except ImportError:
        try:
            ip = socket.gethostbyname(domain)
            return jsonify({"domain": domain, "records": {"A": [ip]}})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/api/whois")
@api_key_required
def api_whois_api():
    domain = request.args.get("target", "").strip()
    if not domain:
        return jsonify({"error": "target required"}), 400
    if is_private_ip(domain):
        return _private_scan_blocked_response(domain)
    logger.info("Scan: api_whois on %s by %s", domain, g.api_user.username)
    try:
        import whois

        w = whois.whois(domain)

        def safe(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val) if val else None

        return jsonify(
            {
                "domain": domain,
                "registrar": safe(w.registrar),
                "creation_date": safe(w.creation_date),
                "expiration_date": safe(w.expiration_date),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── PORT SCANNER (SESSION) ────────────────────────────────────────────────────


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    data = request.json or {}
    target = data.get("target") or request.form.get("target")
    ports = data.get("ports", "1-1024")
    threads = int(data.get("threads", 100))
    timeout = float(data.get("timeout", 1.0))
    service = bool(data.get("service", True))

    if not target:
        return jsonify({"error": "target required"}), 400

    # Validate port range to prevent resource exhaustion
    try:
        port_list = parse_ports(ports)
        if len(port_list) > 10000:
            return jsonify(
                {"error": "Port range too large. Maximum 10000 ports allowed."}
            ), 400
    except Exception:
        return jsonify({"error": "Invalid port range"}), 400

    if is_private_ip(target):
        return _private_scan_blocked_response(target)
    logger.info("Scan: portscan on %s by %s", target, current_user.username)
    try:
        results = scan_target(
            target, ports=ports, threads=threads, timeout=timeout, service=service
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    out = [{"port": p, "service": s, "banner": b} for p, s, b in results]
    return jsonify(
        {"target": target, "results": out, "ai_analysis": analyze_port_scan(out)}
    )


@app.route("/check_port", methods=["POST"])
@login_required
def check_port():
    data = request.json or {}
    target = data.get("target")
    port = data.get("port")
    if not target or not port:
        return jsonify({"error": "Target and port required"}), 400
    if is_private_ip(target):
        return _private_scan_blocked_response(target)
    logger.info("Scan: check_port on %s by %s", target, current_user.username)
    try:
        port = int(port)
        results = scan_target(
            target, ports=str(port), threads=1, timeout=2.0, service=False
        )
        is_open = len(results) > 0
        return jsonify({"target": target, "port": port, "open": is_open})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stream_scan")
@login_required
def stream_scan():
    target = request.args.get("target")
    ports = request.args.get("ports", "1-1024")
    threads = int(request.args.get("threads", 100))
    timeout = float(request.args.get("timeout", 1.0))
    service = request.args.get("service") == "on"

    if not target:
        return jsonify({"error": "target required"}), 400

    # Validate port range to prevent resource exhaustion
    try:
        port_list = parse_ports(ports)
        if len(port_list) > 10000:
            return jsonify(
                {"error": "Port range too large. Maximum 10000 ports allowed."}
            ), 400
    except Exception:
        return jsonify({"error": "Invalid port range"}), 400

    if is_private_ip(target):
        return _private_scan_blocked_response(target)
    logger.info("Scan: stream_portscan on %s by %s", target, current_user.username)

    def generate():
        try:
            total_ports = len(parse_ports(ports))
        except Exception:
            total_ports = 0
        yield f"data: {json.dumps({'type': 'meta', 'total': total_ports})}\n\n"
        scanned_count = 0
        opens = []
        try:
            for port, is_open, svc, banner in scan_generator_sync(
                target, ports, threads, timeout, service
            ):
                scanned_count += 1
                if is_open:
                    opens.append({"port": port, "service": svc, "banner": banner})
                msg = {
                    "type": "result",
                    "port": port,
                    "open": is_open,
                    "service": svc,
                    "banner": banner,
                    "scanned": scanned_count,
                }
                yield f"data: {json.dumps(msg)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'complete', 'ai_analysis': analyze_port_scan(opens)})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/api/ssl_check", methods=["POST"])
@login_required
def ssl_check():
    data = request.json or {}
    host = (
        data.get("host", "")
        .strip()
        .replace("https://", "")
        .replace("http://", "")
        .split("/")[0]
    )
    port = int(data.get("port", 443))
    if not host:
        return jsonify({"error": "host required"}), 400
    if is_private_ip(host):
        return _private_scan_blocked_response(host)
    logger.info("Scan: ssl_check on %s by %s", host, current_user.username)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()
                extras = _ssl_cert_extras(cert, host, ssock)

        expire_str = cert.get("notAfter", "")
        expire_dt = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (expire_dt - datetime.datetime.utcnow()).days

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        payload = {
            "host": host,
            "valid": True,
            "subject": subject.get("commonName", host),
            "issuer": issuer.get("organizationName", "Unknown"),
            "expires": expire_str,
            "days_left": days_left,
            "protocol": protocol,
            "cipher": cipher[0] if cipher else "Unknown",
            "sans": sans[:10],
            **extras,
        }
        payload["ai_analysis"] = analyze_ssl(payload)
        return jsonify(payload)
    except ssl.SSLCertVerificationError as e:
        bad = {"host": host, "valid": False, "error": f"Certificate invalid: {e}"}
        bad["ai_analysis"] = analyze_ssl(bad)
        return jsonify(bad)
    except Exception as e:
        err = {"host": host, "valid": False, "error": str(e)}
        err["ai_analysis"] = analyze_ssl(err)
        return jsonify(err), 500


@app.route("/api/dns_lookup", methods=["POST"])
@login_required
def dns_lookup():
    data = request.json or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if is_private_ip(domain):
        return _private_scan_blocked_response(domain)
    logger.info("Scan: dns_lookup on %s by %s", domain, current_user.username)
    try:
        import dns.resolver

        records = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        sonic_ctx = _dns_sonic_context(domain, records)
        payload = {"domain": domain, "records": records, **sonic_ctx}
        payload["ai_analysis"] = analyze_dns(payload)
        return jsonify(payload)
    except ImportError:
        try:
            ip = socket.gethostbyname(domain)
            records = {"A": [ip], "note": "Install dnspython for full lookup"}
            payload = {"domain": domain, "records": records}
            payload["ai_analysis"] = analyze_dns(payload)
            return jsonify(payload)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/whois", methods=["POST"])
@login_required
def whois_lookup():
    data = request.json or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if is_private_ip(domain):
        return _private_scan_blocked_response(domain)
    logger.info("Scan: whois on %s by %s", domain, current_user.username)
    try:
        import whois

        w = whois.whois(domain)

        def safe(val):
            if isinstance(val, list):
                return [str(v) for v in val]
            return str(val) if val else None

        result = {
            "domain": domain,
            "registrar": safe(w.registrar),
            "creation_date": safe(w.creation_date),
            "expiration_date": safe(w.expiration_date),
            "updated_date": safe(w.updated_date),
            "name_servers": safe(w.name_servers),
            "status": safe(w.status),
            "emails": safe(w.emails),
            "country": safe(w.country),
            "org": safe(w.org),
        }
        result = _whois_sonic_context(w, result)
        result["ai_analysis"] = analyze_whois(result)
        return jsonify(result)
    except ImportError:
        return jsonify(
            {"error": "python-whois not installed. Run: pip install python-whois"}
        ), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/ping", methods=["POST"])
@login_required
def ping():
    data = request.json or {}
    host = data.get("host", "").strip()
    count = min(int(data.get("count", 4)), 10)
    if not host:
        return jsonify({"error": "host required"}), 400
    if is_private_ip(host):
        return _private_scan_blocked_response(host)
    logger.info("Scan: ping on %s by %s", host, current_user.username)
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:")
    if not all(c in allowed for c in host):
        return jsonify({"error": "Invalid host"}), 400
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", str(count), "-w", "2000", host]
        else:
            cmd = ["ping", "-c", str(count), "-W", "2", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout or result.stderr
        reachable = result.returncode == 0
        rtt = None
        for line in output.splitlines():
            if "rtt" in line or "round-trip" in line or "Average" in line:
                parts = line.split("=")
                if len(parts) > 1:
                    seg = parts[1].strip()
                    if "/" in seg:
                        rtt = seg.split("/")[1].strip() + " ms"
                    else:
                        rtt = seg.split(" ")[0] + " ms"
        loss_pct, avg_ms = _parse_ping_metrics(output, reachable)
        payload = {
            "host": host,
            "reachable": reachable,
            "output": output,
            "avg_rtt": rtt,
            "packet_loss_pct": loss_pct,
            "avg_latency_ms": avg_ms,
        }
        payload["ai_analysis"] = analyze_ping(payload)
        return jsonify(payload)
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping timed out"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


_SUBDOMAIN_PREFIXES = (
    "www",
    "mail",
    "ftp",
    "admin",
    "administrator",
    "vpn",
    "remote",
    "dev",
    "staging",
    "test",
    "beta",
    "api",
    "dashboard",
    "portal",
    "webmail",
    "cpanel",
    "backup",
    "old",
    "legacy",
    "internal",
    "intranet",
    "jenkins",
    "gitlab",
    "jira",
    "cdn",
    "blog",
    "shop",
    "img",
    "static",
    "m",
    "app",
    "secure",
    "support",
    "docs",
    "status",
)


def _subdomain_http_alive(name: str) -> bool:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    for verify in (True, False):
        for scheme in ("https", "http"):
            try:
                r = requests.head(
                    f"{scheme}://{name}",
                    timeout=2.8,
                    allow_redirects=True,
                    verify=verify,
                    headers={"User-Agent": "CyberScan-SubdomainProbe/1.0"},
                )
                if r.status_code < 600:
                    return True
            except Exception:
                continue
    return False


@app.route("/api/headers_analyze", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def headers_analyze():
    data = request.json or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    hdr_host = _host_from_url(url)
    if hdr_host and is_private_ip(hdr_host):
        return _private_scan_blocked_response(hdr_host)
    logger.info(
        "Scan: headers_analyze on %s by %s", hdr_host or url, current_user.username
    )
    try:
        r = requests.get(
            url,
            timeout=14,
            allow_redirects=True,
            headers={"User-Agent": "CyberScan-SonicRecon/1.0"},
        )
        hdrs = {k: v for k, v in r.headers.items()}
        payload = {"url": r.url, "status_code": r.status_code, "headers": hdrs}
        payload["ai_analysis"] = analyze_headers({"headers": hdrs})
        return jsonify(payload)
    except Exception as e:
        err_payload = {"url": url, "error": str(e), "headers": {}}
        err_payload["ai_analysis"] = analyze_headers({"error": str(e), "headers": {}})
        return jsonify(err_payload), 200


@app.route("/api/subdomain_scan", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def subdomain_scan():
    data = request.json or {}
    domain = (data.get("domain") or "").strip().lower().rstrip(".")
    if not domain:
        return jsonify({"error": "domain required"}), 400
    if is_private_ip(domain):
        return _private_scan_blocked_response(domain)
    logger.info("Scan: subdomain_scan on %s by %s", domain, current_user.username)
    found = []
    try:
        import dns.resolver
    except ImportError:
        return jsonify({"error": "dnspython required"}), 500
    for sub in _SUBDOMAIN_PREFIXES:
        fqdn = f"{sub}.{domain}"
        try:
            dns.resolver.resolve(fqdn, "A", lifetime=3)
        except Exception:
            try:
                dns.resolver.resolve(fqdn, "AAAA", lifetime=3)
            except Exception:
                continue
        dead = not _subdomain_http_alive(fqdn)
        found.append({"name": fqdn, "dead": dead})
    payload = {"domain": domain, "subdomains": found}
    payload["ai_analysis"] = analyze_subdomains(found)
    return jsonify(payload)


@app.route("/api/geolocation", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def geolocation():
    data = request.json or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        ip = _client_ip()
    if is_private_ip(ip):
        return _private_scan_blocked_response(ip)
    logger.info("Scan: geolocation on %s by %s", ip, current_user.username)
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,query",
            timeout=10,
        )
        j = r.json()
        if j.get("status") != "success":
            return jsonify({"error": j.get("message") or "Geolocation failed"}), 502
        client_cc = ""
        cip = _client_ip()
        if cip and cip != j.get("query"):
            try:
                cr = requests.get(
                    f"http://ip-api.com/json/{cip}?fields=status,countryCode",
                    timeout=6,
                )
                cj = cr.json()
                if cj.get("status") == "success":
                    client_cc = cj.get("countryCode") or ""
            except Exception:
                pass
        payload = {
            "ip": j.get("query"),
            "country": j.get("country"),
            "country_code": j.get("countryCode"),
            "city": j.get("city"),
            "isp": j.get("isp"),
            "org": j.get("org"),
            "client_country_code": client_cc,
        }
        payload["ai_analysis"] = analyze_geolocation(payload)
        return jsonify(payload)
    except Exception as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/cve_search", methods=["POST"])
@login_required
@limiter.limit("15 per minute")
def cve_search():
    data = request.json or {}
    query = (data.get("query") or "").strip()
    if not query:
        return jsonify({"error": "query required"}), 400
    logger.info("Scan: cve_search for %s by %s", query[:120], current_user.username)
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query[:200], "resultsPerPage": 25},
            timeout=22,
            headers={"User-Agent": "CyberScan-SonicRecon/1.0 (security toolkit)"},
        )
        if r.status_code != 200:
            return jsonify({"error": "NVD API error", "status": r.status_code}), 502
        body = r.json()
        critical_count = 0
        high_count = 0
        max_cvss = 0.0
        items = []
        for v in body.get("vulnerabilities") or []:
            cve = v.get("cve") or {}
            cid = cve.get("id", "")
            desc = ""
            try:
                dlist = cve.get("descriptions") or []
                for d in dlist:
                    if (d.get("lang") or "").lower() == "en":
                        desc = d.get("value") or ""
                        break
                if not desc and dlist:
                    desc = dlist[0].get("value") or ""
            except Exception:
                pass
            score = None
            sev = ""
            metrics = cve.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                arr = metrics.get(key) or []
                if not arr:
                    continue
                cd = arr[0].get("cvssData") or {}
                score = cd.get("baseScore")
                sev = (
                    cd.get("baseSeverity") or arr[0].get("baseSeverity") or ""
                ).upper()
                break
            if score is not None:
                fs = float(score)
                max_cvss = max(max_cvss, fs)
                if fs >= 9.0 or sev == "CRITICAL":
                    critical_count += 1
                elif fs >= 7.0 or sev == "HIGH":
                    high_count += 1
            elif sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1
            items.append(
                {
                    "id": cid,
                    "description": (desc or "")[:400],
                    "base_score": score,
                    "severity": sev,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}" if cid else "",
                }
            )
        cve_blob = {
            "critical_count": critical_count,
            "high_count": high_count,
            "max_cvss": max_cvss,
        }
        payload = {"query": query, "cves": items, **cve_blob}
        payload["ai_analysis"] = analyze_cve(cve_blob)
        return jsonify(payload)
    except requests.RequestException as e:
        return jsonify({"error": str(e)}), 502


def bootstrap_admin_from_env():
    au = (os.environ.get("ADMIN_USERNAME") or "").strip()
    ap = os.environ.get("ADMIN_PASSWORD") or ""
    if not au or not ap:
        return
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    c = db.cursor()
    row = c.execute("SELECT id FROM users WHERE username = ?", (au,)).fetchone()
    ph = bcrypt.generate_password_hash(ap).decode("utf-8")
    em = (os.environ.get("ADMIN_EMAIL") or f"{au}@cyberscan.local").strip()
    try:
        if row:
            c.execute(
                "UPDATE users SET password_hash = ?, is_admin = 1, is_super_admin = 1 WHERE id = ?",
                (ph, row["id"]),
            )
        else:
            c.execute(
                """
                INSERT INTO users (username, email, password_hash, full_name, is_admin, is_super_admin)
                VALUES (?, ?, ?, ?, 1, 1)
                """,
                (au, em, ph, "Administrator"),
            )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
    finally:
        db.close()


@app.errorhandler(404)
def error_404(_e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def error_500(_e):
    logger.error("HTTP 500: %s", _e)
    return render_template("500.html"), 500


@app.errorhandler(429)
def error_429(_e):
    return render_template("429.html"), 429


with app.app_context():
    init_db()
    bootstrap_admin_from_env()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    socketio.run(
        app, host="0.0.0.0", port=port, debug=False, allow_unsafe_werkzeug=True
    )

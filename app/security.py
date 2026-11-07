import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import abort, current_app, g, request
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit
from .db import begin, get_db

COOKIE = "tv_session"
SESSION_HOURS = 8
DUMMY_HASH = generate_password_hash("timing-equaliser-password")
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,32}$")


def now():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_token(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def check_password_policy(pw):
    if not isinstance(pw, str) or len(pw) < 10 or len(pw) > 200:
        abort(400, "password must be 10-200 characters")


def hash_password(pw):
    return generate_password_hash(pw, method=current_app.config.get("PW_HASH_METHOD", "scrypt"))


def verify_password(stored_hash, pw):
    return check_password_hash(stored_hash, pw)


def create_session(db, user_id):
    tok = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    t = now()
    db.execute(
        "INSERT INTO sessions(token_hash,user_id,csrf,created_at,expires_at) VALUES (?,?,?,?,?)",
        (hash_token(tok), user_id, csrf, iso(t), iso(t + timedelta(hours=SESSION_HOURS))),
    )
    return tok, csrf


def revoke_user_sessions(db, user_id):
    db.execute("UPDATE sessions SET revoked=1 WHERE user_id=?", (user_id,))


def load_session():
    """Resolve the cookie to a user on EVERY request, straight from the DB (no caching)."""
    g.user = None
    g.csrf = None
    tok = request.cookies.get(COOKIE)
    if not tok or len(tok) > 100:
        return
    row = get_db().execute(
        """SELECT s.csrf AS csrf, u.id AS id, u.username AS username,
                  u.display_name AS display_name, u.role AS role
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash=? AND s.revoked=0 AND s.expires_at>? AND u.active=1""",
        (hash_token(tok), iso(now())),
    ).fetchone()
    if row:
        g.user = {k: row[k] for k in ("id", "username", "display_name", "role")}
        g.csrf = row["csrf"]


def origin_check():
    origin = request.headers.get("Origin")
    if request.method not in ("GET", "HEAD", "OPTIONS") and origin:
        if urlparse(origin).netloc != request.host:
            abort(403, "cross-origin request refused")


def auth(*roles):
    """Authentication + coarse role gate + CSRF. Document-level authorisation is authz.authorize()."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if g.user is None:
                abort(401, "authentication required")
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                sent = request.headers.get("X-CSRF-Token", "")
                if not hmac.compare_digest(sent, g.csrf or ""):
                    abort(403, "missing or invalid CSRF token")
                begin(get_db())
            if roles and g.user["role"] not in roles:
                audit.append(get_db(), "route.denied", outcome="denied", actor=g.user,
                             detail={"path": request.path, "method": request.method, "role": g.user["role"]})
                abort(403, "your role may not do this")
            return fn(*a, **kw)
        return wrapper
    return deco

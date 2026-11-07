import hashlib
import hmac
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, current_app, g, jsonify, make_response, request, send_file

from . import audit, authz, security, services, storage
from .db import get_db
from .security import auth, iso, now

bp = Blueprint("api", __name__)


def body():
    b = request.get_json(silent=True)
    if not isinstance(b, dict):
        abort(400, "JSON object body required")
    return b


def s(v, field, maxlen, required=False):
    if v is None:
        v = ""
    if not isinstance(v, str):
        abort(400, f"{field} must be a string")
    v = v.strip()
    if required and not v:
        abort(400, f"{field} is required")
    if len(v) > maxlen:
        abort(400, f"{field} too long (max {maxlen})")
    return v


def like_escape(v):
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def doc_json(row, level):
    return {"id": row["id"], "name": row["name"], "category": row["category"],
            "description": row["description"], "created_at": row["created_at"],
            "updated_at": row["updated_at"], "deleted_at": row["deleted_at"],
            "current_version": row["current_version"], "my_access": level}


# ---------------------------------------------------------------- auth
@bp.post("/login")
def login():
    db = get_db()
    security.begin(db)
    b = body()
    username = s(b.get("username"), "username", 64).lower()
    pw = b.get("password")
    if not username or not isinstance(pw, str) or len(pw) > 200:
        abort(400, "username and password required")
    ip = request.remote_addr
    since = iso(now() - timedelta(minutes=15))
    fails_user = db.execute("SELECT COUNT(*) c FROM login_attempts WHERE username=? AND ok=0 AND ts>?",
                            (username, since)).fetchone()["c"]
    fails_ip = db.execute("SELECT COUNT(*) c FROM login_attempts WHERE ip=? AND ok=0 AND ts>?",
                          (ip, since)).fetchone()["c"]
    if fails_user >= 5 or fails_ip >= 30:
        audit.append(db, "auth.login", outcome="denied", actor_name=None,
                     detail={"username": username, "reason": "rate_limited"})
        abort(429, "too many failed attempts; try again in 15 minutes")
    u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    good = security.verify_password(u["password_hash"] if u else security.DUMMY_HASH, pw)  # equal work either way
    if not (u and u["active"] and good):
        db.execute("INSERT INTO login_attempts(ts,username,ip,ok) VALUES (?,?,?,0)", (iso(now()), username, ip))
        audit.append(db, "auth.login", outcome="failed", detail={"username": username})
        abort(401, "invalid credentials")
    db.execute("DELETE FROM login_attempts WHERE username=? AND ok=0", (username,))
    tok, csrf = security.create_session(db, u["id"])
    user = {"id": u["id"], "username": u["username"], "display_name": u["display_name"], "role": u["role"]}
    audit.append(db, "auth.login", actor=user)
    resp = make_response(jsonify(user=user, csrf=csrf))
    resp.set_cookie(security.COOKIE, tok, httponly=True, samesite="Lax",
                    secure=current_app.config["SECURE_COOKIES"], max_age=security.SESSION_HOURS * 3600)
    return resp


@bp.post("/logout")
@auth()
def logout():
    from .security import hash_token
    get_db().execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (hash_token(request.cookies[security.COOKIE]),))
    audit.append(get_db(), "auth.logout", actor=g.user)
    resp = jsonify(ok=True)
    resp.delete_cookie(security.COOKIE)
    return resp


@bp.get("/me")
def me():
    if g.user is None:
        return jsonify(user=None)
    return jsonify(user=g.user, csrf=g.csrf)


# ---------------------------------------------------------------- documents
@bp.get("/documents")
@auth()
def list_documents():
    db, u, a = get_db(), g.user, request.args
    if u["role"] == "admin":
        return jsonify(documents=[])
    trash = a.get("scope") == "trash"
    where = ["d.deleted_at IS NOT NULL AND d.owner_id=:uid"] if trash else \
            ["d.deleted_at IS NULL AND (d.owner_id=:uid OR g.user_id IS NOT NULL)"]
    p = {"uid": u["id"], "now": iso(now())}
    if a.get("scope") == "mine":
        where.append("d.owner_id=:uid")
    elif a.get("scope") == "shared":
        where.append("d.owner_id<>:uid")
    if a.get("q"):
        where.append("d.name LIKE :q ESCAPE '\\'"); p["q"] = "%" + like_escape(a["q"][:100]) + "%"
    if a.get("owner"):
        where.append("(o.username LIKE :ow ESCAPE '\\' OR o.display_name LIKE :ow ESCAPE '\\')")
        p["ow"] = "%" + like_escape(a["owner"][:64]) + "%"
    if a.get("category"):
        where.append("d.category=:cat"); p["cat"] = a["category"][:50]
    if a.get("from"):
        where.append("d.created_at>=:f"); p["f"] = a["from"][:20]
    if a.get("to"):
        where.append("d.created_at<=:t"); p["t"] = a["to"][:10] + "T23:59:59Z" if len(a["to"]) <= 10 else a["to"][:20]
    rows = db.execute(f"""
        SELECT d.*, o.username AS owner_username, o.display_name AS owner_name,
               CASE WHEN d.owner_id=:uid THEN 'owner' ELSE g.level END AS lvl
        FROM documents d JOIN users o ON o.id=d.owner_id
        LEFT JOIN grants g ON g.doc_id=d.id AND g.user_id=:uid AND (g.expires_at IS NULL OR g.expires_at>:now)
        WHERE {' AND '.join(where)} ORDER BY d.updated_at DESC LIMIT 200""", p).fetchall()
    out = []
    for r in rows:
        j = doc_json(r, r["lvl"]); j["owner"] = {"username": r["owner_username"], "name": r["owner_name"]}
        out.append(j)
    return jsonify(documents=out)


@bp.post("/documents")
@auth("owner")
def upload_document():
    f = request.files.get("file")
    if f is None:
        abort(400, "file is required")
    data = f.read(storage.MAX_BYTES + 1)
    try:
        doc_id = services.create_document(
            get_db(), current_app.config["FILES_DIR"], g.user,
            s(request.form.get("name"), "name", 200), s(request.form.get("category"), "category", 50),
            s(request.form.get("description"), "description", 1000), f.filename, data)
    except storage.UploadError as e:
        audit.append(get_db(), "document.upload", outcome="denied", actor=g.user,
                     detail={"reason": str(e), "filename": storage.clean_filename(f.filename)})
        get_db().execute("COMMIT")  # keep the refusal on record, then report it
        abort(400, str(e))
    return jsonify(id=doc_id), 201


@bp.get("/documents/<int:doc_id>")
@auth()
def get_document(doc_id):
    db = get_db()
    doc, level = authz.authorize(db, g.user, doc_id, "read", "document.view")
    owner = db.execute("SELECT username, display_name FROM users WHERE id=?", (doc["owner_id"],)).fetchone()
    vers = db.execute("""SELECT v.version_no, v.original_filename, v.size, v.sha256, v.created_at, u.username AS by
                         FROM versions v JOIN users u ON u.id=v.uploaded_by WHERE v.doc_id=? ORDER BY v.version_no DESC""",
                      (doc_id,)).fetchall()
    j = doc_json(doc, level)
    j["owner"] = {"username": owner["username"], "name": owner["display_name"]}
    j["versions"] = [dict(v) for v in vers]
    return jsonify(j)


@bp.patch("/documents/<int:doc_id>")
@auth()
def edit_document(doc_id):
    db = get_db(); security.begin(db)
    doc, _ = authz.authorize(db, g.user, doc_id, "edit", "document.edit")
    b = body()
    new = {"name": s(b.get("name", doc["name"]), "name", 200, True),
           "category": s(b.get("category", doc["category"]), "category", 50),
           "description": s(b.get("description", doc["description"]), "description", 1000)}
    changes = {k: [doc[k], v] for k, v in new.items() if doc[k] != v}
    db.execute("UPDATE documents SET name=?,category=?,description=?,updated_at=? WHERE id=?",
               (new["name"], new["category"], new["description"], iso(now()), doc_id))
    audit.append(db, "document.edit", actor=g.user, doc_id=doc_id, detail={"changes": changes})
    return jsonify(ok=True)


@bp.post("/documents/<int:doc_id>/versions")
@auth()
def new_version(doc_id):
    db = get_db()
    doc, _ = authz.authorize(db, g.user, doc_id, "edit", "document.version.add")
    f = request.files.get("file")
    if f is None:
        abort(400, "file is required")
    try:
        n = services.add_version(db, current_app.config["FILES_DIR"], g.user, doc, f.filename,
                                 f.read(storage.MAX_BYTES + 1))
    except storage.UploadError as e:
        audit.append(db, "document.version.add", outcome="denied", actor=g.user, doc_id=doc_id, detail={"reason": str(e)})
        db.execute("COMMIT")
        abort(400, str(e))
    return jsonify(version=n), 201


@bp.get("/documents/<int:doc_id>/download")
@auth()
def download(doc_id):
    db = get_db()
    doc, _ = authz.authorize(db, g.user, doc_id, "read", "document.download")
    try:
        vn = int(request.args.get("version", doc["current_version"]))
    except ValueError:
        abort(400, "bad version")
    ver = db.execute("SELECT * FROM versions WHERE doc_id=? AND version_no=?", (doc_id, vn)).fetchone()  # scoped to doc
    if ver is None:
        abort(404, "not found")
    try:
        data = storage.read_blob(current_app.config["FILES_DIR"], ver["storage_key"])
    except (OSError, ValueError):
        audit.append(db, "document.download", outcome="failed", actor=g.user, doc_id=doc_id,
                     detail={"version": vn, "reason": "blob missing"})
        db.execute("COMMIT")
        abort(500, "stored file is unavailable")
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), ver["sha256"]):
        audit.append(db, "document.download", outcome="failed", actor=g.user, doc_id=doc_id,
                     detail={"version": vn, "reason": "integrity mismatch"})
        db.execute("COMMIT")
        abort(500, "stored file failed its integrity check")
    audit.append(db, "document.download", actor=g.user, doc_id=doc_id, detail={"version": vn, "sha256": ver["sha256"]})
    resp = send_file(io.BytesIO(data), mimetype=ver["mime"], as_attachment=True, download_name=ver["original_filename"])
    resp.headers["Cache-Control"] = "no-store"
    return resp


@bp.delete("/documents/<int:doc_id>")
@auth()
def delete_document(doc_id):
    db = get_db()
    doc, _ = authz.authorize(db, g.user, doc_id, "owner", "document.delete")
    db.execute("UPDATE documents SET deleted_at=?, updated_at=? WHERE id=?", (iso(now()), iso(now()), doc_id))
    audit.append(db, "document.delete", actor=g.user, doc_id=doc_id, detail={"name": doc["name"]})
    return jsonify(ok=True)


@bp.post("/documents/<int:doc_id>/restore")
@auth()
def restore_document(doc_id):
    db = get_db()
    doc, _ = authz.authorize(db, g.user, doc_id, "owner", "document.restore", allow_deleted=True)
    if not doc["deleted_at"]:
        abort(409, "document is not deleted")
    db.execute("UPDATE documents SET deleted_at=NULL, updated_at=? WHERE id=?", (iso(now()), doc_id))
    audit.append(db, "document.restore", actor=g.user, doc_id=doc_id, detail={"name": doc["name"]})
    return jsonify(ok=True)


# ---------------------------------------------------------------- permissions (owner only)
@bp.get("/users/lookup")
@auth("owner")
def lookup_users():
    q = like_escape(s(request.args.get("q"), "q", 32).lower())
    rows = get_db().execute(
        """SELECT username, display_name FROM users WHERE active=1 AND role<>'admin' AND id<>?
           AND (username LIKE ? ESCAPE '\\' OR lower(display_name) LIKE ? ESCAPE '\\') ORDER BY username LIMIT 10""",
        (g.user["id"], f"%{q}%", f"%{q}%")).fetchall()
    return jsonify(users=[dict(r) for r in rows])


@bp.get("/documents/<int:doc_id>/grants")
@auth()
def list_grants(doc_id):
    db = get_db()
    authz.authorize(db, g.user, doc_id, "owner", "permission.list")
    rows = db.execute("""SELECT u.id AS user_id, u.username, u.display_name, g.level, g.created_at, g.expires_at, g.suggestion_id
                         FROM grants g JOIN users u ON u.id=g.user_id WHERE g.doc_id=? ORDER BY u.username""", (doc_id,)).fetchall()
    return jsonify(grants=[dict(r) for r in rows])


@bp.put("/documents/<int:doc_id>/grants")
@auth()
def put_grant(doc_id):
    db = get_db()
    doc, _ = authz.authorize(db, g.user, doc_id, "owner", "permission.grant")
    b = body()
    level = b.get("level")
    if level not in ("read", "edit"):
        abort(400, "level must be 'read' or 'edit'")
    target = db.execute("SELECT * FROM users WHERE username=?", (s(b.get("username"), "username", 64, True).lower(),)).fetchone()
    if not target or not target["active"] or target["role"] == "admin" or target["id"] == g.user["id"]:
        abort(400, "cannot grant access to that user")
    exp = b.get("expires_at")
    if exp:
        try:
            dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        except ValueError:
            abort(400, "expires_at must be ISO-8601")
        if dt <= now():
            abort(400, "expires_at must be in the future")
        exp = iso(dt.astimezone(timezone.utc))
    else:
        exp = None
    sid = b.get("suggestion_id")
    if sid is not None:
        sug = db.execute("SELECT * FROM suggestions WHERE id=? AND doc_id=? AND suggested_user_id=?",
                         (sid if isinstance(sid, int) else -1, doc_id, target["id"])).fetchone()
        if not sug:
            abort(400, "suggestion does not match this document and user")
    before = db.execute("SELECT level, expires_at FROM grants WHERE doc_id=? AND user_id=?", (doc_id, target["id"])).fetchone()
    db.execute("""INSERT INTO grants(doc_id,user_id,level,granted_by,created_at,expires_at,suggestion_id) VALUES (?,?,?,?,?,?,?)
                  ON CONFLICT(doc_id,user_id) DO UPDATE SET level=excluded.level, granted_by=excluded.granted_by,
                  created_at=excluded.created_at, expires_at=excluded.expires_at, suggestion_id=excluded.suggestion_id""",
               (doc_id, target["id"], level, g.user["id"], iso(now()), exp, sid))
    audit.append(db, "permission.grant", actor=g.user, doc_id=doc_id, target_user_id=target["id"],
                 detail={"level": level, "expires_at": exp, "to": target["username"], "suggestion_id": sid,
                         "human_confirmed": True, "previous": dict(before) if before else None})
    return jsonify(ok=True)


@bp.delete("/documents/<int:doc_id>/grants/<int:user_id>")
@auth()
def revoke_grant(doc_id, user_id):
    db = get_db()
    authz.authorize(db, g.user, doc_id, "owner", "permission.revoke")
    old = db.execute("SELECT g.level, u.username FROM grants g JOIN users u ON u.id=g.user_id WHERE g.doc_id=? AND g.user_id=?",
                     (doc_id, user_id)).fetchone()
    if not old:
        abort(404, "no such grant")
    db.execute("DELETE FROM grants WHERE doc_id=? AND user_id=?", (doc_id, user_id))
    audit.append(db, "permission.revoke", actor=g.user, doc_id=doc_id, target_user_id=user_id,
                 detail={"from": old["username"], "had": old["level"]})
    return jsonify(ok=True)


@bp.get("/documents/<int:doc_id>/suggestions")
@auth()
def suggestions(doc_id):
    """Heuristic (not an LLM) suggestions. Advice only: creating one never grants access."""
    db = get_db()
    doc, _ = authz.authorize(db, g.user, doc_id, "owner", "suggestion.create")
    rows = db.execute(
        """SELECT u.id, u.username, u.display_name, COUNT(*) n FROM grants g
           JOIN documents d ON d.id=g.doc_id JOIN users u ON u.id=g.user_id
           WHERE d.owner_id=? AND d.category=? AND d.id<>? AND d.category<>'' AND u.active=1 AND u.role<>'admin'
             AND g.user_id NOT IN (SELECT user_id FROM grants WHERE doc_id=?)
           GROUP BY u.id ORDER BY n DESC LIMIT 5""",
        (g.user["id"], doc["category"], doc_id, doc_id)).fetchall()
    out = []
    for r in rows:
        reason = f"{r['display_name']} has access to {r['n']} other '{doc['category']}' document(s) you own."
        cur = db.execute("INSERT INTO suggestions(doc_id,suggested_user_id,reason,created_at) VALUES (?,?,?,?)",
                         (doc_id, r["id"], reason, iso(now())))
        audit.append(db, "suggestion.create", actor=g.user, doc_id=doc_id, target_user_id=r["id"],
                     detail={"suggestion_id": cur.lastrowid, "reason": reason, "source": "heuristic", "grants_access": False})
        out.append({"suggestion_id": cur.lastrowid, "username": r["username"], "display_name": r["display_name"], "reason": reason})
    return jsonify(suggestions=out)


@bp.get("/documents/<int:doc_id>/audit")
@auth()
def doc_audit(doc_id):
    db = get_db()
    authz.authorize(db, g.user, doc_id, "owner", "audit.view")
    rows = db.execute("""SELECT seq, ts, actor_name, action, outcome, target_user_id, detail FROM audit
                         WHERE doc_id=? ORDER BY seq DESC LIMIT 200""", (doc_id,)).fetchall()
    return jsonify(events=[dict(r) for r in rows])

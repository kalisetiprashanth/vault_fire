from datetime import timedelta

from flask import Blueprint, abort, current_app, g, jsonify, request

from . import audit, security
from .api import body, like_escape, s
from .db import get_db
from .security import auth, iso, now

bp = Blueprint("admin", __name__)
ROLES = ("admin", "owner", "viewer")


@bp.get("/users")
@auth("admin")
def users():
    rows = get_db().execute("SELECT id, username, display_name, role, active, created_at FROM users ORDER BY id").fetchall()
    return jsonify(users=[dict(r) for r in rows])


@bp.post("/users")
@auth("admin")
def create_user():
    db, b = get_db(), body()
    username = s(b.get("username"), "username", 32, True).lower()
    if not security.USERNAME_RE.match(username):
        abort(400, "username: 3-32 chars of a-z 0-9 . _ -")
    if b.get("role") not in ROLES:
        abort(400, "bad role")
    security.check_password_policy(b.get("password"))
    if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        abort(409, "username taken")
    cur = db.execute("INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                     (username, s(b.get("display_name"), "display_name", 80) or username,
                      security.hash_password(b["password"]), b["role"], iso(now())))
    audit.append(db, "user.create", actor=g.user, target_user_id=cur.lastrowid, detail={"username": username, "role": b["role"]})
    return jsonify(id=cur.lastrowid), 201


def _target(uid):
    t = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not t:
        abort(404, "no such user")
    return t


@bp.post("/users/<int:uid>/disable")
@auth("admin")
def disable(uid):
    t = _target(uid)
    if t["id"] == g.user["id"]:
        abort(400, "you cannot disable yourself")
    db = get_db()
    db.execute("UPDATE users SET active=0 WHERE id=?", (uid,))
    security.revoke_user_sessions(db, uid)          # takes effect on their very next request
    audit.append(db, "user.disable", actor=g.user, target_user_id=uid, detail={"username": t["username"]})
    return jsonify(ok=True)


@bp.post("/users/<int:uid>/enable")
@auth("admin")
def enable(uid):
    t = _target(uid)
    get_db().execute("UPDATE users SET active=1 WHERE id=?", (uid,))
    audit.append(get_db(), "user.enable", actor=g.user, target_user_id=uid, detail={"username": t["username"]})
    return jsonify(ok=True)


@bp.post("/users/<int:uid>/role")
@auth("admin")
def set_role(uid):
    t, b, db = _target(uid), body(), get_db()
    if b.get("role") not in ROLES:
        abort(400, "bad role")
    if t["id"] == g.user["id"]:
        abort(400, "you cannot change your own role")
    db.execute("UPDATE users SET role=? WHERE id=?", (b["role"], uid))
    security.revoke_user_sessions(db, uid)
    audit.append(db, "user.role", actor=g.user, target_user_id=uid, detail={"from": t["role"], "to": b["role"]})
    return jsonify(ok=True)


@bp.post("/users/<int:uid>/password")
@auth("admin")
def reset_password(uid):
    t, b, db = _target(uid), body(), get_db()
    security.check_password_policy(b.get("password"))
    db.execute("UPDATE users SET password_hash=? WHERE id=?", (security.hash_password(b["password"]), uid))
    security.revoke_user_sessions(db, uid)
    audit.append(db, "user.password_reset", actor=g.user, target_user_id=uid, detail={"username": t["username"]})
    return jsonify(ok=True)


@bp.get("/documents")
@auth("admin")
def documents_meta():
    """Metadata only. Admins can see that documents exist and who holds them, never the content."""
    rows = get_db().execute(
        """SELECT d.id, d.name, d.category, d.created_at, d.deleted_at, d.current_version, o.username AS owner,
                  (SELECT COUNT(*) FROM grants g WHERE g.doc_id=d.id) AS grant_count,
                  (SELECT MAX(ts) FROM audit a WHERE a.doc_id=d.id) AS last_activity
           FROM documents d JOIN users o ON o.id=d.owner_id ORDER BY d.id DESC LIMIT 500""").fetchall()
    return jsonify(documents=[dict(r) for r in rows])


@bp.get("/audit")
@auth("admin")
def audit_view():
    a, where, p = request.args, [], []
    for col, key in (("action", "action"), ("outcome", "outcome"), ("actor_name", "actor")):
        if a.get(key):
            where.append(f"{col}=?"); p.append(a[key][:64])
    if a.get("prefix"):
        where.append("action LIKE ? ESCAPE '\\'"); p.append(like_escape(a["prefix"][:32]) + "%")
    if a.get("doc_id", "").isdigit():
        where.append("doc_id=?"); p.append(int(a["doc_id"]))
    lim = min(int(a["limit"]), 500) if a.get("limit", "").isdigit() else 100
    rows = get_db().execute(
        f"SELECT seq, ts, actor_name, action, outcome, doc_id, target_user_id, ip, detail FROM audit "
        f"{'WHERE ' + ' AND '.join(where) if where else ''} ORDER BY seq DESC LIMIT ?", (*p, lim)).fetchall()
    return jsonify(events=[dict(r) for r in rows])


@bp.get("/audit/verify")
@auth("admin")
def audit_verify():
    """Optional ?anchor_seq=&anchor_hash= : a head you recorded earlier outside this system."""
    a = request.args
    seq = int(a["anchor_seq"]) if a.get("anchor_seq", "").isdigit() else None
    return jsonify(audit.verify(get_db(), current_app.config["AUDIT_KEY"], seq, a.get("anchor_hash", "")[:64]))


@bp.get("/alerts")
@auth("admin")
def alerts():
    db, out = get_db(), []
    day, hour = iso(now() - timedelta(hours=24)), iso(now() - timedelta(hours=1))
    for r in db.execute("""SELECT actor_name, COUNT(*) c FROM audit WHERE outcome='denied' AND actor_id IS NOT NULL
                           AND ts>? GROUP BY actor_id HAVING c>=3 ORDER BY c DESC""", (day,)):
        out.append({"kind": "repeated_denials", "severity": "high",
                    "message": f"{r['actor_name']} was refused access {r['c']} times in 24h (possible probing)", "count": r["c"]})
    for r in db.execute("""SELECT json_extract(detail,'$.username') u, COUNT(*) c FROM audit WHERE action='auth.login'
                           AND outcome IN ('failed','denied') AND ts>? GROUP BY u HAVING c>=5 ORDER BY c DESC""", (day,)):
        out.append({"kind": "login_failures", "severity": "high",
                    "message": f"{r['u']}: {r['c']} failed/blocked logins in 24h", "count": r["c"]})
    for r in db.execute("""SELECT actor_name, COUNT(*) c FROM audit WHERE action='document.download' AND outcome='ok'
                           AND ts>? GROUP BY actor_id HAVING c>=20 ORDER BY c DESC""", (hour,)):
        out.append({"kind": "download_burst", "severity": "medium",
                    "message": f"{r['actor_name']} downloaded {r['c']} files in the last hour", "count": r["c"]})
    for r in db.execute("""SELECT actor_name, COUNT(*) c FROM audit WHERE action='permission.grant' AND ts>?
                           AND json_extract(detail,'$.level')='edit' GROUP BY actor_id HAVING c>=5""", (day,)):
        out.append({"kind": "many_edit_grants", "severity": "medium",
                    "message": f"{r['actor_name']} granted EDIT access {r['c']} times in 24h", "count": r["c"]})
    for r in db.execute("""SELECT actor_name, ts FROM audit WHERE action='user.role' AND ts>? ORDER BY seq DESC""", (day,)):
        out.append({"kind": "role_change", "severity": "medium", "message": f"role change by {r['actor_name']} at {r['ts']}", "count": 1})
    for r in db.execute("""SELECT a.actor_name, a.ts, u.username FROM audit a LEFT JOIN users u ON u.id=a.target_user_id
                           WHERE a.action='user.password_reset' AND a.ts>? ORDER BY a.seq DESC""", (day,)):
        out.append({"kind": "password_reset", "severity": "high",
                    "message": f"{r['actor_name']} reset the password of {r['username']} at {r['ts']} - an admin could now sign in as them", "count": 1})
    return jsonify(alerts=out)

import hashlib
import hmac
import json
from datetime import datetime, timezone

from flask import current_app, has_request_context, request

from .db import begin

GENESIS = "GENESIS"


def _canon(prev, ts, actor_id, actor_name, action, outcome, doc_id, target, ip, detail):
    return json.dumps([prev, ts, actor_id, actor_name, action, outcome, doc_id, target, ip, detail],
                      separators=(",", ":"), ensure_ascii=True)


def _mac(key, payload):
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def append(db, action, outcome="ok", actor=None, doc_id=None, target_user_id=None, detail=None, actor_name=None):
    """Append one record inside the caller's transaction, so an action and its audit row commit or
    roll back together. BEGIN IMMEDIATE serialises concurrent appends -> one linear chain."""
    begin(db)
    key = current_app.config["AUDIT_KEY"]
    last = db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    prev = last["hash"] if last else GENESIS
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    ip = request.remote_addr if has_request_context() else None
    d = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    aid = actor["id"] if actor else None
    aname = actor["username"] if actor else actor_name
    h = _mac(key, _canon(prev, ts, aid, aname, action, outcome, doc_id, target_user_id, ip, d))
    db.execute(
        """INSERT INTO audit(ts,actor_id,actor_name,action,outcome,doc_id,target_user_id,ip,detail,prev_hash,hash)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (ts, aid, aname, action, outcome, doc_id, target_user_id, ip, d, prev, h),
    )


def verify(db, key, anchor_seq=None, anchor_hash=None):
    """Recompute the whole chain. Detects edited rows, deleted rows (hash link + sequence gap) and,
    if the caller supplies a head recorded earlier somewhere else (anchor), truncation of the tail."""
    prev, n, seen_anchor = GENESIS, 0, False
    for r in db.execute("SELECT * FROM audit ORDER BY seq ASC"):
        exp = _mac(key, _canon(r["prev_hash"], r["ts"], r["actor_id"], r["actor_name"], r["action"],
                               r["outcome"], r["doc_id"], r["target_user_id"], r["ip"], r["detail"]))
        if r["prev_hash"] != prev or r["seq"] != n + 1 or not hmac.compare_digest(exp, r["hash"]):
            return {"ok": False, "checked": n, "first_bad_seq": r["seq"], "head": None, "reason": "chain broken"}
        if anchor_seq is not None and r["seq"] == anchor_seq:
            seen_anchor = hmac.compare_digest(r["hash"], anchor_hash or "")
        prev, n = r["hash"], n + 1
    if anchor_seq is not None and not seen_anchor:
        return {"ok": False, "checked": n, "first_bad_seq": anchor_seq, "head": None,
                "reason": "the anchored record is missing or different (log truncated or rewritten)"}
    last = db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
    return {"ok": True, "checked": n, "first_bad_seq": None,
            "head": {"seq": last["seq"], "hash": last["hash"]} if last else None}

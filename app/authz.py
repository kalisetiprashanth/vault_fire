"""THE authorisation decision. Every route that touches a document goes through authorize().

Rules (and nothing else):
  * admins never get document access (they administer accounts and see metadata/audit only)
  * the owner has 'owner'
  * anyone else needs an unexpired row in `grants`
  * soft-deleted documents are invisible except to the owner (for restore)
Refusals are audited. Users with no access at all get 404 (indistinguishable from a missing id).
"""
from flask import abort

from . import audit
from .security import iso, now

RANK = {"read": 1, "edit": 2, "owner": 3}


def get_access(db, user, doc_id):
    doc = db.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if doc is None or user["role"] == "admin":
        return doc, None
    if doc["owner_id"] == user["id"]:
        return doc, "owner"
    if doc["deleted_at"]:
        return doc, None
    g = db.execute(
        "SELECT level FROM grants WHERE doc_id=? AND user_id=? AND (expires_at IS NULL OR expires_at>?)",
        (doc_id, user["id"], iso(now())),
    ).fetchone()
    return doc, (g["level"] if g else None)


def authorize(db, user, doc_id, need, action, allow_deleted=False):
    doc, level = get_access(db, user, doc_id)
    ok = (level is not None and RANK[level] >= RANK[need]
          and (allow_deleted or not doc["deleted_at"]))
    if ok:
        return doc, level
    audit.append(db, action, outcome="denied", actor=user, doc_id=doc_id,
                 detail={"need": need, "had": level, "exists": doc is not None})
    # 403 only when the caller legitimately knows the document exists (has some access).
    if level is not None and doc is not None and not doc["deleted_at"]:
        abort(403, "insufficient permission")
    abort(404, "not found")

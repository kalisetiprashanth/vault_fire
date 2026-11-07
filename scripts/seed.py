"""Seed demo accounts and documents. Idempotent: does nothing if users already exist.
Passwords can be overridden with TV_SEED_PW_<USERNAME> (recommended for any real deployment)."""
import os

from app import services
from app.db import get_db
from app.security import hash_password, iso, now

DEFAULTS = {
    "admin": ("Ada Admin", "admin", "Admin#Vault2026"),
    "alice": ("Alice Owner", "owner", "Alice#Vault2026"),
    "bob": ("Bob Owner", "owner", "Bob#Vault2026!"),
    "carol": ("Carol Viewer", "viewer", "Carol#Vault2026"),
    "dave": ("Dave Viewer", "viewer", "Dave#Vault2026!"),
}


def _pdf(title):
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 100]>>endobj\ntrailer<</Root 1 0 R>>\n%% " + title.encode() + b"\n%%EOF\n")


def seed_if_empty(app):
    db = get_db()
    if db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]:
        return False
    db.execute("BEGIN IMMEDIATE")
    users = {}
    for uname, (display, role, pw) in DEFAULTS.items():
        pw = os.environ.get(f"TV_SEED_PW_{uname.upper()}", pw)
        cur = db.execute("INSERT INTO users(username,display_name,password_hash,role,created_at) VALUES (?,?,?,?,?)",
                         (uname, display, hash_password(pw), role, iso(now())))
        users[uname] = {"id": cur.lastrowid, "username": uname, "role": role}
    files = app.config["FILES_DIR"]
    from app import audit
    a, b = users["alice"], users["bob"]
    d1 = services.create_document(db, files, a, "Salary letter - Carol", "HR", "Offer letter for Carol", "salary-carol.pdf", _pdf("salary"))
    d2 = services.create_document(db, files, a, "Acme master contract", "Contracts", "Confidential", "acme-contract.pdf", _pdf("acme"))
    d3 = services.create_document(db, files, a, "Salary letter - Dave", "HR", "Offer letter for Dave", "salary-dave.pdf", _pdf("dave"))
    d4 = services.create_document(db, files, b, "Partner drawings rev A", "Engineering", "Shared with partner", "drawings.txt", b"Drawing notes\n")
    for doc, user, level in ((d1, "carol", "read"), (d3, "dave", "read"), (d4, "dave", "edit")):
        db.execute("INSERT INTO grants(doc_id,user_id,level,granted_by,created_at) VALUES (?,?,?,?,?)",
                   (doc, users[user]["id"], level, (a if doc != d4 else b)["id"], iso(now())))
        audit.append(db, "permission.grant", actor=(a if doc != d4 else b), doc_id=doc, target_user_id=users[user]["id"],
                     detail={"level": level, "to": user, "seed": True, "human_confirmed": True})
    db.execute("COMMIT")
    return True

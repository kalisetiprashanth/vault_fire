"""Business operations shared by the API and the seed script. All callers must authorise first."""
from . import audit, storage
from .security import iso, now


def create_document(db, files_dir, owner, name, category, description, filename, data):
    clean, mime = storage.validate_upload(filename, data)
    key, sha = storage.save_blob(files_dir, data)
    t = iso(now())
    cur = db.execute(
        "INSERT INTO documents(owner_id,name,category,description,created_at,updated_at) VALUES (?,?,?,?,?,?)",
        (owner["id"], (name or clean)[:200], (category or "")[:50], (description or "")[:1000], t, t))
    doc_id = cur.lastrowid
    db.execute(
        """INSERT INTO versions(doc_id,version_no,storage_key,original_filename,mime,size,sha256,uploaded_by,created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""", (doc_id, 1, key, clean, mime, len(data), sha, owner["id"], t))
    audit.append(db, "document.upload", actor=owner, doc_id=doc_id,
                 detail={"name": (name or clean)[:200], "filename": clean, "size": len(data), "sha256": sha})
    return doc_id


def add_version(db, files_dir, user, doc, filename, data):
    clean, mime = storage.validate_upload(filename, data)
    key, sha = storage.save_blob(files_dir, data)
    n = doc["current_version"] + 1
    t = iso(now())
    db.execute(
        """INSERT INTO versions(doc_id,version_no,storage_key,original_filename,mime,size,sha256,uploaded_by,created_at)
           VALUES (?,?,?,?,?,?,?,?,?)""", (doc["id"], n, key, clean, mime, len(data), sha, user["id"], t))
    db.execute("UPDATE documents SET current_version=?, updated_at=? WHERE id=?", (n, t, doc["id"]))
    audit.append(db, "document.version.add", actor=user, doc_id=doc["id"],
                 detail={"version": n, "filename": clean, "size": len(data), "sha256": sha})
    return n

"""Proves the tests test something: removes one security control at a time and demands that the
test-suite FAILS. A mutation the tests survive is a hole in the tests. Usage: python scripts/mutation_check.py"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MUTATIONS = [
    ("authorize() always allows", "app/authz.py", "ok = (level is not None and RANK[level] >= RANK[need]\n          and (allow_deleted or not doc[\"deleted_at\"]))", "ok = True"),
    ("permission level ignored (read can edit)", "app/authz.py", "RANK[level] >= RANK[need]", "True"),
    ("grant expiry ignored", "app/authz.py", "(expires_at IS NULL OR expires_at>?)", "(expires_at IS NULL OR expires_at>? OR 1=1)"),
    ("grant not tied to the user", "app/authz.py", "AND user_id=? AND (expires_at", "AND user_id IS NOT NULL AND ? IS NOT NULL AND (expires_at"),
    ("admin gets implicit document access", "app/authz.py", "if doc is None or user[\"role\"] == \"admin\":", "if doc is None:"),
    ("soft-deleted docs stay readable", "app/authz.py", "and (allow_deleted or not doc[\"deleted_at\"]))", ")"),
    ("denied attempts not audited", "app/authz.py", "    audit.append(db, action, outcome=\"denied\", actor=user, doc_id=doc_id,\n                 detail={\"need\": need, \"had\": level, \"exists\": doc is not None})\n", "    pass\n"),
    ("revoked sessions still accepted", "app/security.py", "s.revoked=0 AND", "1=1 AND"),
    ("disabled users keep their session", "app/security.py", "AND u.active=1", "AND 1=1"),
    ("role gate removed", "app/security.py", "if roles and g.user[\"role\"] not in roles:", "if False:"),
    ("CSRF check removed", "app/security.py", "if not hmac.compare_digest(sent, g.csrf or \"\"):", "if False:"),
    ("Origin check removed", "app/security.py", "if urlparse(origin).netloc != request.host:", "if False:"),
    ("audit append-only triggers neutered", "schema.sql", "RAISE(ABORT, 'audit log is append-only')", "1"),
    ("audit chain verification skips MAC", "app/audit.py", " or not hmac.compare_digest(exp, r[\"hash\"])", ""),
    ("audit sequence-gap check removed", "app/audit.py", " or r[\"seq\"] != n + 1", ""),
    ("download version not scoped to document", "app/api.py", "WHERE doc_id=? AND version_no=?\", (doc_id, vn)", "WHERE version_no=?\", (vn,)"),
    ("upload content sniff removed", "app/storage.py", "    if not ok:\n        raise UploadError(f\"file content", "    if False:\n        raise UploadError(f\"file content"),
    ("blob integrity check removed", "app/api.py", "if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), ver[\"sha256\"]):", "if False:"),
    ("login rate-limit removed", "app/api.py", "if fails_user >= 5 or fails_ip >= 30:", "if False:"),
    ("owner-only check on grants lowered to read", "app/api.py", "authz.authorize(db, g.user, doc_id, \"owner\", \"permission.list\")", "authz.authorize(db, g.user, doc_id, \"read\", \"permission.list\")"),
    ("delete requires only edit", "app/api.py", "authz.authorize(db, g.user, doc_id, \"owner\", \"document.delete\")", "authz.authorize(db, g.user, doc_id, \"edit\", \"document.delete\")"),
]


def run(mut):
    name, rel, old, new = mut
    tmp = Path(tempfile.mkdtemp())
    try:
        shutil.copytree(ROOT, tmp / "r", ignore=shutil.ignore_patterns("instance", ".git", "__pycache__", "*.zip"))
        f = tmp / "r" / rel
        src = f.read_text()
        if old not in src:
            return name, "BAD-MUTATION (pattern not found - update this script)"
        f.write_text(src.replace(old, new, 1))
        p = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                           cwd=tmp / "r", capture_output=True, text=True)
        return name, "caught" if p.returncode != 0 else "SURVIVED  <-- tests do not cover this"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    bad = 0
    for m in MUTATIONS:
        n, r = run(m)
        print(f"{r[:8]:9s} {n}" if r == "caught" else f"{r}  {n}")
        bad += r != "caught"
    print(f"\n{len(MUTATIONS) - bad}/{len(MUTATIONS)} mutations caught")
    sys.exit(1 if bad else 0)

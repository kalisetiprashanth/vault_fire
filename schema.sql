-- TrustVault schema (SQLite). Applied idempotently at startup by app/db.py.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE CHECK (username = lower(username)),
  display_name  TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  active        INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL
);

-- Server-side sessions. Only a SHA-256 of the cookie token is stored.
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  csrf       TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS login_attempts (
  id       INTEGER PRIMARY KEY,
  ts       TEXT NOT NULL,
  username TEXT NOT NULL,
  ip       TEXT,
  ok       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(username, ts);

CREATE TABLE IF NOT EXISTS documents (
  id              INTEGER PRIMARY KEY,
  owner_id        INTEGER NOT NULL REFERENCES users(id),
  name            TEXT NOT NULL,
  category        TEXT NOT NULL DEFAULT '',
  description     TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  deleted_at      TEXT,
  current_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS versions (
  id                INTEGER PRIMARY KEY,
  doc_id            INTEGER NOT NULL REFERENCES documents(id),
  version_no        INTEGER NOT NULL,
  storage_key       TEXT NOT NULL UNIQUE,      -- random; never derived from user input
  original_filename TEXT NOT NULL,
  mime              TEXT NOT NULL,
  size              INTEGER NOT NULL,
  sha256            TEXT NOT NULL,
  uploaded_by       INTEGER NOT NULL REFERENCES users(id),
  created_at        TEXT NOT NULL,
  UNIQUE (doc_id, version_no)
);

-- The ONLY place access is granted. Revoking = deleting the row; nothing else caches it.
CREATE TABLE IF NOT EXISTS grants (
  doc_id         INTEGER NOT NULL REFERENCES documents(id),
  user_id        INTEGER NOT NULL REFERENCES users(id),
  level          TEXT NOT NULL CHECK (level IN ('read','edit')),
  granted_by     INTEGER NOT NULL REFERENCES users(id),
  created_at     TEXT NOT NULL,
  expires_at     TEXT,
  suggestion_id  INTEGER,
  PRIMARY KEY (doc_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);

-- Suggestions are advice only. They never create a grant.
CREATE TABLE IF NOT EXISTS suggestions (
  id                INTEGER PRIMARY KEY,
  doc_id            INTEGER NOT NULL REFERENCES documents(id),
  suggested_user_id INTEGER NOT NULL REFERENCES users(id),
  reason            TEXT NOT NULL,
  created_at        TEXT NOT NULL
);

-- Append-only, HMAC hash-chained audit log.
CREATE TABLE IF NOT EXISTS audit (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts             TEXT NOT NULL,
  actor_id       INTEGER,
  actor_name     TEXT,
  action         TEXT NOT NULL,
  outcome        TEXT NOT NULL,              -- ok | denied | failed
  doc_id         INTEGER,                    -- deliberately no FK: refused probes of non-existent ids are logged too
  target_user_id INTEGER,
  ip             TEXT,
  detail         TEXT NOT NULL,              -- canonical JSON
  prev_hash      TEXT NOT NULL,
  hash           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit(doc_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit(actor_id);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;

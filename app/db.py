import sqlite3
from pathlib import Path
from flask import g, current_app

SCHEMA = Path(__file__).resolve().parent.parent / "schema.sql"


def connect(path):
    # isolation_level=None -> we control transactions explicitly (BEGIN IMMEDIATE).
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(path):
    conn = connect(path)
    conn.executescript(SCHEMA.read_text())
    conn.close()


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def begin(db):
    """Take the write lock. Serialises audit-chain appends and check-then-write sequences."""
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")

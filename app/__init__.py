import os
import secrets
from pathlib import Path

from flask import Flask, g, jsonify, send_from_directory
from werkzeug.exceptions import HTTPException

from . import db as dbm
from .storage import MAX_BYTES

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


def _audit_key(data_dir):
    env = os.environ.get("TV_AUDIT_KEY")
    if env:
        return env.encode()
    p = Path(data_dir) / "audit.key"
    if not p.exists():
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    return p.read_text().strip().encode()


def create_app(config=None):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config.update(
        DATA_DIR=os.environ.get("TV_DATA_DIR", "instance"),
        SECURE_COOKIES=os.environ.get("TV_SECURE_COOKIES") == "1",
        TRUST_PROXY=os.environ.get("TV_TRUST_PROXY") == "1",
        MAX_CONTENT_LENGTH=MAX_BYTES + 1024 * 1024,
    )
    if config:
        app.config.update(config)
    data = Path(app.config["DATA_DIR"]).resolve()
    (data / "files").mkdir(parents=True, exist_ok=True)
    app.config["DATA_DIR"] = str(data)
    app.config["DB_PATH"] = str(data / "trustvault.db")
    app.config["FILES_DIR"] = str(data / "files")
    app.config["AUDIT_KEY"] = _audit_key(data)
    dbm.init_db(app.config["DB_PATH"])

    if app.config["TRUST_PROXY"]:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    from . import security
    from .api import bp as api_bp
    from .admin import bp as admin_bp
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")

    @app.before_request
    def _before():
        security.origin_check()
        security.load_session()

    @app.after_request
    def _after(resp):
        db = g.get("db")
        if db is not None and db.in_transaction:
            db.execute("COMMIT" if resp.status_code < 500 else "ROLLBACK")
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if app.config["SECURE_COOKIES"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if not resp.headers.get("Cache-Control"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.teardown_appcontext
    def _close(_exc):
        db = g.pop("db", None)
        if db is not None:
            if db.in_transaction:
                db.execute("ROLLBACK")
            db.close()

    @app.errorhandler(HTTPException)
    def _http(e):
        return jsonify(error=e.description or e.name), e.code

    @app.errorhandler(Exception)
    def _boom(e):
        app.logger.exception("unhandled error")
        db = g.get("db")
        if db is not None and db.in_transaction:
            db.execute("ROLLBACK")
        return jsonify(error="internal error"), 500

    @app.get("/")
    def index():
        r = send_from_directory(app.static_folder, "index.html")
        r.headers["Cache-Control"] = "no-store"
        return r

    return app

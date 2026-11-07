import hashlib
import io
import os
import re
import secrets
import zipfile
from pathlib import Path

MAX_BYTES = 10 * 1024 * 1024
OOXML = {
    "docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "word/"),
    "xlsx": ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xl/"),
    "pptx": ("application/vnd.openxmlformats-officedocument.presentationml.presentation", "ppt/"),
}
MIME = {
    "pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
    "txt": "text/plain; charset=utf-8", "csv": "text/csv; charset=utf-8",
    **{k: v[0] for k, v in OOXML.items()},
}
KEY_RE = re.compile(r"^[0-9a-f]{32}$")


class UploadError(ValueError):
    pass


def clean_filename(name):
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = "".join(c for c in name if c.isprintable() and c not in '<>:"|?*').strip(" .")
    return name[:120]


def validate_upload(filename, data):
    """Allow-list extension, size cap, and a content sniff that must agree with the extension."""
    name = clean_filename(filename)
    if not name or "." not in name:
        raise UploadError("file needs a name with an extension")
    ext = name.rsplit(".", 1)[1].lower()
    if ext not in MIME:
        raise UploadError(f"file type .{ext} is not allowed (allowed: {', '.join(sorted(MIME))})")
    if not data:
        raise UploadError("file is empty")
    if len(data) > MAX_BYTES:
        raise UploadError("file exceeds 10 MB")
    ok = False
    if ext == "pdf":
        ok = data.startswith(b"%PDF-")
    elif ext == "png":
        ok = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif ext in ("jpg", "jpeg"):
        ok = data.startswith(b"\xff\xd8\xff")
    elif ext in ("txt", "csv"):
        try:
            data.decode("utf-8")
            ok = b"\x00" not in data
        except UnicodeDecodeError:
            ok = False
    else:
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
            ok = "[Content_Types].xml" in names and any(n.startswith(OOXML[ext][1]) for n in names)
            ok = ok and not any(n.lower().endswith("vbaproject.bin") for n in names)  # no macros
        except zipfile.BadZipFile:
            ok = False
    if not ok:
        raise UploadError(f"file content does not look like a real .{ext} file")
    return name, MIME[ext]


def blob_path(root, key):
    if not KEY_RE.match(key or ""):
        raise ValueError("bad storage key")
    return Path(root) / key[:2] / key


def save_blob(root, data):
    key = secrets.token_hex(16)
    p = blob_path(root, key)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return key, hashlib.sha256(data).hexdigest()


def read_blob(root, key):
    return blob_path(root, key).read_bytes()

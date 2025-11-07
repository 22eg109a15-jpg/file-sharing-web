# ✅ FIXED web_share.py
import os
import json
import secrets
import datetime
from pathlib import Path
from flask import Flask, request, render_template, redirect, url_for, send_file, flash
from werkzeug.utils import secure_filename
from crypto_utils import derive_key_from_password, fernet_encrypt_bytes, fernet_decrypt_bytes

# --- Configuration ---
BASE_DIR = Path(__file__).parent.resolve()
UPLOADS_DIR = BASE_DIR / "encrypted_store"
DB_FILE = BASE_DIR / "links_db.json"
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200 MB
SALT_HEADER = b"SALT"
SALT_LEN = 16

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

UPLOADS_DIR.mkdir(exist_ok=True)
if not DB_FILE.exists():
    DB_FILE.write_text(json.dumps({}))

# --- Helpers ---
def _load_db():
    return json.loads(DB_FILE.read_text())

def _save_db(db):
    DB_FILE.write_text(json.dumps(db, indent=2))

def _prune_expired():
    db = _load_db()
    now = datetime.datetime.utcnow()
    changed = False
    for token, rec in list(db.items()):
        if now > datetime.datetime.fromisoformat(rec["expires_at"]):
            for f in rec["files"]:
                try:
                    Path(f["enc_path"]).unlink(missing_ok=True)
                except Exception:
                    pass
            del db[token]
            changed = True
    if changed:
        _save_db(db)

def _encrypt_and_store_file(file_storage, pin: str, out_dir: Path, index: int):
    data = file_storage.read()
    salt = secrets.token_bytes(SALT_LEN)
    key = derive_key_from_password(pin, salt)
    token = fernet_encrypt_bytes(data, key)
    blob = SALT_HEADER + salt + token
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_name = secure_filename(file_storage.filename) or f"file_{index}"
    enc_path = out_dir / f"{index:04d}_{safe_name}.enc"
    enc_path.write_bytes(blob)
    return {
        "original_name": file_storage.filename,
        "enc_path": str(enc_path),
        "size": len(data),
    }

def _attempt_decrypt_file(enc_path: Path, pin: str) -> bytes:
    blob = enc_path.read_bytes()
    if not blob.startswith(SALT_HEADER):
        raise ValueError("Invalid file format.")
    salt = blob[4:20]
    token = blob[20:]
    key = derive_key_from_password(pin, salt)
    return fernet_decrypt_bytes(token, key)

# --- Routes ---
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("upload"))

@app.route("/upload", methods=["GET", "POST"])
def upload():
    _prune_expired()
    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        ttl_hours = int(request.form.get("ttl_hours") or 24)
        files = request.files.getlist("files")

        if not pin:
            flash("⚠ Please enter a PIN.", "danger")
            return redirect(request.url)
        if not files or all(f.filename == "" for f in files):
            flash("⚠ Please select at least one file.", "danger")
            return redirect(request.url)

        token = secrets.token_urlsafe(16)
        out_dir = UPLOADS_DIR / token
        files_meta = []

        try:
            for i, f in enumerate(files):
                meta = _encrypt_and_store_file(f, pin, out_dir, i)
                files_meta.append(meta)
        except Exception as e:
            flash(f"❌ Encryption failed: {e}", "danger")
            return redirect(request.url)

        now = datetime.datetime.utcnow()
        expires_at = now + datetime.timedelta(hours=ttl_hours)
        db = _load_db()
        db[token] = {
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "files": files_meta,
            "one_time": bool(request.form.get("one_time")),
        }
        _save_db(db)

        link = url_for("download_page", token=token, _external=True)
        print(f"✅ Generated link: {link}")  # Debug print for terminal
        return render_template("upload_done.html", link=link, token=token, expires_at=expires_at)

    return render_template("upload.html")

@app.route("/download/<token>", methods=["GET", "POST"])
def download_page(token):
    _prune_expired()
    db = _load_db()
    rec = db.get(token)
    if not rec:
        flash("Link not found or expired.", "danger")
        return render_template("download.html", found=False, token=token)

    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        if not pin:
            flash("Please enter the PIN.", "danger")
            return render_template("download.html", found=True, token=token)

        try:
            out_files = []
            for fmeta in rec["files"]:
                data = _attempt_decrypt_file(Path(fmeta["enc_path"]), pin)
                out_files.append((fmeta["original_name"], data))
        except Exception:
            flash("Incorrect PIN or file corrupted.", "danger")
            return render_template("download.html", found=True, token=token)

        from io import BytesIO
        if len(out_files) == 1:
            name, data = out_files[0]
            bio = BytesIO(data)
            return send_file(bio, as_attachment=True, download_name=name)
        else:
            import zipfile
            mem = BytesIO()
            with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
                for name, data in out_files:
                    zf.writestr(secure_filename(name), data)
            mem.seek(0)
            return send_file(mem, as_attachment=True, download_name=f"files_{token}.zip")

    expires_at = datetime.datetime.fromisoformat(rec["expires_at"])
    return render_template("download.html", found=True, token=token, expires_at=expires_at, files=rec["files"])

@app.route("/_db")
def view_db():
    return {"db": _load_db()}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

"""CNS Secure Vault - AES-256-GCM encryption + RSA-PSS (SHA-256) digital signatures."""
import base64, hashlib, io, mimetypes, os, secrets, sqlite3, shutil
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

BASE = Path(__file__).parent
VAULT = BASE / "vault"          # encrypted files (may be tampered)
BACKUP = BASE / "vault_backup"  # pristine copies, used by "Restore"
KEYS = BASE / "keys"
for d in (VAULT, BACKUP, KEYS):
    d.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB upload limit
DB = BASE / "vault.db"
NONCE_LEN = 12

# ---------------------------------------------------------------- keys
def load_keys():
    aes_path, priv_path = KEYS / "aes.key", KEYS / "rsa_private.pem"
    if not aes_path.exists():
        aes_path.write_bytes(AESGCM.generate_key(bit_length=256))
    if not priv_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    private = serialization.load_pem_private_key(priv_path.read_bytes(), None)
    return aes_path.read_bytes(), private, private.public_key()

AES_KEY, PRIVATE_KEY, PUBLIC_KEY = load_keys()
PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

# ------------------------------------------------------------------ db
def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS files(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_name TEXT, stored_name TEXT, signature BLOB,
        original_sha256 TEXT, original_size INTEGER,
        status TEXT DEFAULT 'NOT CHECKED')""")

def get_record(file_id):
    with db() as con:
        return con.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()

def set_status(file_id, status):
    with db() as con:
        con.execute("UPDATE files SET status=? WHERE id=?", (status, file_id))

# -------------------------------------------------------------- crypto
def encrypt_and_sign(plaintext: bytes):
    nonce = secrets.token_bytes(NONCE_LEN)
    blob = nonce + AESGCM(AES_KEY).encrypt(nonce, plaintext, None)  # nonce || ct || tag
    signature = PRIVATE_KEY.sign(blob, PSS, hashes.SHA256())
    return blob, signature

def check(rec):
    """Run both integrity layers independently so the UI can show each result."""
    result = {"signature_ok": False, "gcm_ok": False, "plaintext": None, "error": None}
    path = VAULT / rec["stored_name"]
    if not path.exists():
        result["error"] = "Encrypted file is missing from the vault."
        return result
    blob = path.read_bytes()
    try:
        PUBLIC_KEY.verify(rec["signature"], blob, PSS, hashes.SHA256())
        result["signature_ok"] = True
    except InvalidSignature:
        pass
    try:
        if len(blob) < NONCE_LEN + 16:
            raise InvalidTag()
        result["plaintext"] = AESGCM(AES_KEY).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], None)
        result["gcm_ok"] = True
    except InvalidTag:
        pass
    return result

def verified_plaintext(rec):
    r = check(rec)
    ok = r["signature_ok"] and r["gcm_ok"]
    set_status(rec["id"], "VERIFIED" if ok else "TAMPERED")
    return (r["plaintext"] if ok else None), r

# -------------------------------------------------------------- routes
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/files")
def list_files():
    with db() as con:
        rows = con.execute("SELECT * FROM files ORDER BY id").fetchall()
    return jsonify([{
        "id": r["id"], "name": r["original_name"], "stored": r["stored_name"],
        "status": r["status"], "size": r["original_size"]} for r in rows])

@app.route("/api/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify(error="Choose a file first."), 400
    name = secure_filename(f.filename) or "file"
    data = f.read()
    blob, signature = encrypt_and_sign(data)
    stored = f"enc_{secrets.token_hex(6)}_{name}"
    (VAULT / stored).write_bytes(blob)
    (BACKUP / stored).write_bytes(blob)
    with db() as con:
        cur = con.execute(
            "INSERT INTO files(original_name,stored_name,signature,original_sha256,original_size,status)"
            " VALUES(?,?,?,?,?,?)",
            (name, stored, signature, hashlib.sha256(data).hexdigest(), len(data), "VERIFIED"))
    return jsonify(id=cur.lastrowid, message=f"{name} encrypted and signed.")

@app.route("/api/encrypted/<int:file_id>")
def view_encrypted(file_id):
    """What an attacker (or the server admin) sees: ciphertext only."""
    rec = get_record(file_id)
    if not rec:
        return jsonify(error="Not found"), 404
    blob = (VAULT / rec["stored_name"]).read_bytes()
    preview = blob[:256]
    lines = []
    for i in range(0, len(preview), 16):
        chunk = preview[i:i + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hexpart}  {ascii_}")
    return jsonify(
        hexdump="\n".join(lines),
        base64=base64.b64encode(preview).decode(),
        encrypted_size=len(blob),
        encrypted_sha256=hashlib.sha256(blob).hexdigest(),
        nonce=blob[:NONCE_LEN].hex(),
        signature=rec["signature"].hex(),
        original_sha256=rec["original_sha256"],
        original_size=rec["original_size"],
        truncated=len(blob) > 256)

@app.route("/api/verify/<int:file_id>")
def verify(file_id):
    rec = get_record(file_id)
    if not rec:
        return jsonify(error="Not found"), 404
    plaintext, r = verified_plaintext(rec)
    return jsonify(
        status="VERIFIED" if plaintext is not None else "TAMPERED",
        signature_ok=r["signature_ok"], gcm_ok=r["gcm_ok"], error=r["error"])

@app.route("/api/preview/<int:file_id>")
def preview(file_id):
    """Decrypted preview - only released if signature and GCM tag both pass."""
    rec = get_record(file_id)
    if not rec:
        return jsonify(error="Not found"), 404
    plaintext, r = verified_plaintext(rec)
    if plaintext is None:
        return jsonify(error="Integrity check failed. Decryption refused.",
                       signature_ok=r["signature_ok"], gcm_ok=r["gcm_ok"]), 400
    mime = mimetypes.guess_type(rec["original_name"])[0] or "application/octet-stream"
    if mime.startswith("text/") or mime in ("application/json", "application/xml"):
        return jsonify(kind="text", text=plaintext[:20000].decode("utf-8", "replace"))
    if mime == "application/pdf" or mime.startswith("image/"):
        return jsonify(kind="media", mime=mime, url=f"/api/download/{file_id}?inline=1")
    return jsonify(kind="binary", message=f"No in-browser preview for {mime}. Use Download & Verify.")

@app.route("/api/download/<int:file_id>")
def download(file_id):
    rec = get_record(file_id)
    if not rec:
        return jsonify(error="Not found"), 404
    plaintext, r = verified_plaintext(rec)
    if plaintext is None:
        return jsonify(error="Integrity check failed. File may have been tampered with.",
                       signature_ok=r["signature_ok"], gcm_ok=r["gcm_ok"]), 400
    mime = mimetypes.guess_type(rec["original_name"])[0] or "application/octet-stream"
    return send_file(io.BytesIO(plaintext), mimetype=mime,
                     as_attachment=not request.args.get("inline"),
                     download_name=rec["original_name"])

@app.route("/api/attack/<int:file_id>", methods=["POST"])
def attack(file_id):
    rec = get_record(file_id)
    if not rec:
        return jsonify(error="Not found"), 404
    mode = (request.json or {}).get("mode", "flip_byte")
    path = VAULT / rec["stored_name"]
    blob = bytearray(path.read_bytes())
    if mode == "flip_byte":
        i = secrets.randbelow(len(blob) - NONCE_LEN) + NONCE_LEN
        blob[i] ^= 0x01
        path.write_bytes(bytes(blob))
        msg = f"Flipped one bit at byte {i} of the ciphertext."
    elif mode == "truncate":
        path.write_bytes(bytes(blob[:-8]))
        msg = "Removed the last 8 bytes (part of the GCM tag)."
    elif mode == "swap_signature":
        with db() as con:
            con.execute("UPDATE files SET signature=? WHERE id=?",
                        (secrets.token_bytes(len(rec["signature"])), file_id))
        msg = "Replaced the stored signature with random bytes."
    else:
        return jsonify(error="Unknown attack"), 400
    set_status(file_id, "TAMPERED")
    return jsonify(message=msg)

@app.route("/api/restore/<int:file_id>", methods=["POST"])
def restore(file_id):
    """Put back the pristine ciphertext and signature (demo reset)."""
    rec = get_record(file_id)
    if not rec:
        return jsonify(error="Not found"), 404
    blob = (BACKUP / rec["stored_name"]).read_bytes()
    shutil.copy(BACKUP / rec["stored_name"], VAULT / rec["stored_name"])
    sig = PRIVATE_KEY.sign(blob, PSS, hashes.SHA256())   # re-issue signature
    with db() as con:
        con.execute("UPDATE files SET signature=?, status='VERIFIED' WHERE id=?", (sig, file_id))
    return jsonify(message="File restored from backup and re-signed.")

@app.route("/api/delete/<int:file_id>", methods=["DELETE"])
def delete(file_id):
    rec = get_record(file_id)
    if rec:
        for d in (VAULT, BACKUP):
            (d / rec["stored_name"]).unlink(missing_ok=True)
        with db() as con:
            con.execute("DELETE FROM files WHERE id=?", (file_id,))
    return jsonify(message="Deleted.")

if __name__ == "__main__":
    app.run(debug=True)

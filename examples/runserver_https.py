from flask import Flask, request
import os
import subprocess
from datetime import datetime
import shutil
import stat

app = Flask(__name__)

INCOMING_DIR  = "incoming"
DECRYPTED_DIR = "decrypted"
os.makedirs(INCOMING_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

@app.post("/upload")
def upload():
    # field name "file" must match curl_mime_name(part, "file")
    device_id = request.form.get("device_id", "unknown")

    # flags bitfield (optional)
    flags_str = request.form.get("flags")
    try:
        flags = int(flags_str) if flags_str is not None else 0
    except ValueError:
        flags = 0

    # END SIGNAL: no file,"end=1"
    if "end" in request.form and "file" not in request.files:
        end_value = request.form.get("end")
        print(f"[SERVER] End signal from device '{device_id}', value={end_value}")
        # any cleanup, flush queues, close sessions, etc.
        return "END OK\n", 200

    # NORMAL FILE UPLOAD
    f = request.files.get("file")
    if not f:
        # If neither file nor end -> it's a malformed request
        return "no file field and no end signal\n", 400

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    enc_name = f"{device_id}_{timestamp}_{f.filename}"
    enc_path = os.path.join(INCOMING_DIR, enc_name)

    f.save(enc_path)
    size = os.path.getsize(enc_path)
    print(f"[SERVER] Received file: {enc_path} ({size} bytes), flags={flags}")

    # make incoming file read-only
    try:
        os.chmod(enc_path, stat.S_IREAD)
    except Exception as e:
        print(f"[SERVER] Warning: chmod failed for {enc_path}: {e}")

    # Prepare decrypted/output path
    base_plain = f"{device_id}_{timestamp}_{f.filename}"
    dec_path   = os.path.join(DECRYPTED_DIR, base_plain)

    # decode flags
    enc_enabled   = bool(flags & 0b001)
    enc_symmetric = bool(flags & 0b010)
    enc_all       = bool(flags & 0b100)

    # No encryption – just copy the received file to dec_path
    if not enc_enabled:
        try:
            shutil.copy2(enc_path, dec_path)
            print(f"[SERVER] No encryption, copied to: {dec_path}")
            return "OK\n", 200
        except Exception as e:
            print(f"[SERVER] Copy failed: {e}")
            return "copy failed\n", 500

    # Encrypted – run filesend with proper options
    try:
        cmd = [
            "bin/./filesend",
            "decrypt",
            enc_path,
        ]
        if enc_symmetric:
            cmd.append("--symmetric")
        else:
            cmd.append("--asymmetric")
        if enc_all:
            cmd.append("--all")
        cmd.extend(["--dest", dec_path])

        subprocess.check_call(cmd)
        print(f"[SERVER] Decrypted to: {dec_path}")
    except subprocess.CalledProcessError as e:
        print(f"[SERVER] Decrypt failed: {e}")
        return "decrypt failed\n", 500
    except Exception as e:
        print(f"[SERVER] Unexpected error during decrypt: {e}")
        return "decrypt failed\n", 500

    return "OK\n", 200

if __name__ == "__main__":
    # HTTPS: cert + key
    # For local 0.0.0.0 or 127.0.0.1
    app.run(
        host="127.0.0.1",
        port=8443,
        ssl_context=("certs/server.crt", "keys/server.key"),
        debug=True
    )

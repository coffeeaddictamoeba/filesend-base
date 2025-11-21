# Example of code for starting a server and receiving + decrypting a file

from flask import Flask, request
import os
import subprocess
from datetime import datetime

app = Flask(__name__)

INCOMING_DIR  = "incoming"
DECRYPTED_DIR = "decrypted"
os.makedirs(INCOMING_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

@app.post("/upload")
def upload():
    # field name "file" must match curl_mime_name(part, "file")
    f = request.files.get("file")
    device_id = request.form.get("device_id", "unknown")

    if not f:
        return "no file field", 400

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    enc_name = f"{device_id}_{timestamp}_{f.filename}"
    enc_path = os.path.join(INCOMING_DIR, enc_name)

    f.save(enc_path)
    size = os.path.getsize(enc_path)
    print(f"[SERVER] Received encrypted file: {enc_path} ({size} bytes)")

    # Decrypt
    base_plain = f"{device_id}_{timestamp}_{f.filename}"
    dec_path   = os.path.join(DECRYPTED_DIR, base_plain)

    try:
        subprocess.check_call([
            "bin/./filesend",
            "decrypt",
            enc_path,
            "--asymmetric",
            "--all",
            "--dest",
            dec_path,
        ])
        print(f"[SERVER] Decrypted to: {dec_path}")
    except subprocess.CalledProcessError as e:
        print(f"[SERVER] Decrypt failed: {e}")
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

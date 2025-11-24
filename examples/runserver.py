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
    print(f"[SERVER] Received encrypted file: {enc_path} ({size} bytes)")

    # Decrypt
    base_plain = f"{device_id}_{timestamp}_{f.filename}"
    dec_path   = os.path.join(DECRYPTED_DIR, base_plain)

    # Run filesend binary. Args should match sending format or it will fail
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

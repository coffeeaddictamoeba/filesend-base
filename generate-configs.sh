#!/usr/bin/env bash
set -euo pipefail

mkdir -p server

cat > ./filesend_config <<'EOF'
[global]
device_id = pi
cert_path = test/ca_cert.pem
security_info = true
use_config = true

[send]

# http/https
# url = https://Test:8443/upload
# use_ws = false

# websocket
url = wss://0.0.0.0:8444
use_ws = true

# negative timeout means watching mode (never stops)
# timeout is in seconds
timeout = -1
retry = 5
poll_interval = 1000     # poll_interval is in milliseconds
nthreads = 3
batch_size = 1
batch_format = zip

[crypto]
mode = asymmetric
all     = true
archive = false
force   = false
pub_key_path = test/pub_key.bin
pr_key_path  = test/pr_key.bin
# sym_key_path = test/sym_key.bin   # do not use both key modes simultaneously
dest_path = test/plain_files/
EOF

cat > server/server_config <<'EOF'
[global]
security_info = true
use_config = true

[server]
host = 0.0.0.0
port = 8444

[paths]
incoming_dir  = incoming
decrypted_dir = decrypted

[limits]
max_file_mb     = 32
max_json_kb     = 16
idle_timeout_s  = 30
ping_interval_s = 20
ping_timeout_s  = 20

[auth]
require_auth = false
token_file   = devtokens.json

[dedup]
enable = true
db_path = received_files.sqlite3

[tls]
# If cert/key are empty or absent => runs with no TLS
cert_path = certs/server-date.crt
key_path = keys/server-date.key

[filesend]
bin_path = filesend
decrypt_timeout_s = 60

[logging]
level = INFO
# If empty => terminal-only
file  = logs/server.log
EOF

echo "Created:"
echo "  ./filesend_config"
echo "  ./server/server_config"
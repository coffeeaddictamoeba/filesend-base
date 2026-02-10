# filesend-base

This code provides basic tools for fast, lightweight and secure file sending from one device to another

### Updates

---

- Setup using config files is now also possible for both sender and server (see example files)
- Multithreading supports batch sending
- Archive option is added for sending, encryption and decryption
- File encryption format standardized
- Server-side logging is added

### General Syntax

---

```
filesend send    [--https|--ws] <path> <url> [--encrypt symmetric|asymmetric] [--all] [--timeout <n>] [--retry <n>] [--no-retry] [--batch <n>] [--archive] [--nthreads <n>]
filesend encrypt <path> [--symmetric|--asymmetric] [--all] [--dest <file>] [--force] [--archive]
filesend decrypt <path> [--symmetric|--asymmetric] [--all] [--dest <file>] [--force] [--archive]
filesend verify  <path> <sha256>
```

#### **Configs**

---

Configs are used by default and are applied when no options are specified:

```
filesend <mode> <path>        # will use config

# Examples
filesend decrypt test/
filesend encrypt plain_files/my_file.txt
filesend send my_files/

filesend <mode> <path> --arg  # will use CLI instead of config
```

Example of config file structure (same for sender and server):

```
[global]
device_id = some_device_id_here
cert_path = cert.pem
security_info = true # will be added soon
use_config = true

[send]
# http/https
# url = https://test:8443/upload
# use_ws = false

# websocket
url = wss://0.0.0.0:8444
use_ws = true

timeout = 5
retry = 3
nthreads = 3
batch_size = 1
batch_format = zip

[crypto]
mode = asymmetric
all     = true
archive = false
force   = false
pub_key_path = pub.key
pr_key_path  = pr.key
# sym_key_path = sym.key   # do not use both key modes simultaneously

dest_path = my_dest/
```

#### Mode: `send`

---

Sends a file to a remote HTTPS / WS server.

You may choose whether to encrypt the file before sending it.

```
filesend send [--https|--ws] <path> <url> [--encrypt symmetric|asymmetric] [--all][--timeout <n>] [--retry <n>][--no-retry] [--batch <n>] [--archive] [--nthreads <n>]
```

**Parameters**

* **`send --https|--ws`** – choose the preferrable method of file sending (HTTPS or WebSocket)
* **`<path>`** – path to the file or directory you want to send
* **`<url>`** – full server URL (must include `/upload`)

  Example: `https://myserver.local:8443/upload` (HTTPS) or `ws://0.0.0.0:8444/ws` (WS)
* **`--encrypt symmetric`** – encrypt using libsodium symmetric key
* **`--encrypt asymmetric`** – encrypt using libsodium sealed box (public key)
* **`--all`** – encrypt file **metadata** as well as contents
* **`--timeout`** – monitor `<path>` directory until specified timeout
* **`--retry <n>`** – set the number of retries allowed in case of failed file sending. Default is 3.
* **`--no-retry`** – set number of retries to 0
* **`--batch <n>`** – group `n` files to a compressed batch and send the batch. All policies specified are applied to the **batch** itself, **not the files** inside (i.e. if you use `--encrypt`, only the batch file will be encrypted)
* **`--archive`** – save sent files instead of removing them
* **`--nthreads`** – if compiled with `USE_MULTITHREADING` option, set number of threads to `n`. If running in multithreading mode and this option is not specified, number of threads used is equal to `MAX_WORKERS_MT`.

**Environment variables**

`CERT_PATH` – path to CA certificate used to validate server TLS certificate (both HTTPS and WS)

`SYM_KEY_PATH` – path to symmetric key (if symmetric mode is chosen)

`PUB_KEY_PATH`, `PR_KEY_PATH` – paths to public/private key pair (asymmetric mode)

**Examples**

- Send a file **without** encrypting it: `filesend send data/report.bin "https://myserver.local:8443/upload"`
- Send with symmetric encryption:

```
export SYM_KEY_PATH=/etc/myapp/sym.key
export CERT_PATH=/etc/myapp/ca_cert.pem

filesend send --https images/photo.png "https://myserver.local:8443/upload" \
    --encrypt symmetric
```

- Send from a folder (`logs`) with asymmetric encryption and metadata protection (and stop after a timeout of 30 secs):

```
export PUB_KEY_PATH=/etc/myapp/server_box_pk.bin
export CERT_PATH=/etc/myapp/ca_cert.pem

filesend send --ws logs "ws://0.0.0.0:8444/ws" \
    --encrypt asymmetric --all --timeout 30
```

#### Mode: `encrypt`

---

Encrypts a file locally.

```
filesend encrypt <path> [--symmetric|--asymmetric] [--all] [--dest <file>][--force]
```

**NOTE:** `<path>` supports pattern-based path definition like `*.png` or `log_???.txt`. If you want to use a pattern instead of direct path, put your pattern in " " symbols: `filesend encrypt "*.png" --asymmetric --all`

Arguments:

* **`--asymmetric`** – use sealed box with public key
* **`--symmetric`** – use symmetric key
* **`--dest <file>`** – custom output path
* **`--all`** – encrypt metadata too
* **`--force`** – try to perform encryption on any `<path>` without checking if the file was already encrypted or not. By default, all encrypted files have extension `.enc`
* **`--archive`** – save both plain and encrypted versions of file

- Asymmetric encryption with metadata (The encrypted output will default to `raw/data.bin`):

```
export PUB_KEY_PATH=/etc/myapp/server_box_pk.bin
filesend encrypt raw/data.bin --asymmetric --all
```

- Symmetric encryption:

```
export PUB_KEY_PATH=/etc/myapp/server_box_pk.bin
filesend encrypt raw/data.bin --symmetric --all
```

#### Mode: `decrypt`

---

Decrypts a file previously encrypted with `filesend`. Can be used on server side.

```
filesend decrypt <file> [--symmetric|--asymmetric] [--all] [--dest <file>][--force]
```

Arguments:

* **`--symmetric`** – decrypt with symmetric key
* **`--asymmetric`** – decrypt with private key
* **`--dest <file>`** – output path for decrypted file
* **`--all`** – restore metadata and validate integrity
* **`--force`** – try to perform decryption on any `<path>` without checking if the file was already encrypted or not. By default, all encrypted files have extension `.enc`
* **`--archive`** – save both decrypted and encrypted versions of file

Required environment variables (depending on mode):

* `SYM_KEY_PATH` – for symmetric decrypt
* `PUB_KEY_PATH`, `PR_KEY_PATH` – for asymmetric decrypt

Examples:

- Decrypt symmetric file:

```
export SYM_KEY_PATH=/etc/myapp/sym.key

filesend decrypt backups/db.enc \
    --symmetric --dest db_restored.sql
```

- Decrypt asymmetric encrypted file with metadata

```
export PUB_KEY_PATH=/etc/myapp/server_box_pk.bin
export PR_KEY_PATH=/etc/myapp/server_box_sk.bin

filesend decrypt images/cam01.img.enc \
    --asymmetric --all
```

#### Mode: `verify`

---

```
filesend verify <path> <sha256>
```

Verifies file's SHA-256 (both raw and hex formats). Can be used on server side.

### Notes & Recommendations

**NOTE:** `<path>` in `encrypt` and `decrypt` supports **pattern-based path definition** like `*.png `or `log_???.txt `. If you want to use a pattern instead of direct path, put your pattern in " " symbols: `filesend encrypt "*.png" --asymmetric --all`

* `--all` enables encryption/decryption of **metadata** (mtime, mode, uid/gid).
* URL  **must include `/upload`** , as the server expects this endpoint.
* The hostname in the URL must match the certificate CN/SAN (e.g., `Test`, `localhost`).
* CA certificate for TLS validation must be given via `CERT_PATH`.
* Server *private key* **must never** be on the sending device – only the server should have it.
* Asymmetric encryption is recommended for device - server communication (one-way encryption).
* Symmetric encryption is recommended for local file storage or local pipelines.

#### How to generate server key and certificate

---

```
# CA private key
openssl genrsa -out myCA.key 4096

# CA self-signed certificate (root cert)
openssl req -x509 -new -nodes -key myCA.key -sha256 -days 3650 -out ca_cert.pem

# Create a key
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr

# Sign
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey myCA.key \
   -CAcreateserial -out server.crt -days 365 -sha256
```

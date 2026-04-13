# filesend-base

This code provides basic tools for fast, lightweight and secure file sending from one device to another

### Updates

---

- Setup using config files is now also possible for both sender and server (see example files)
- Multithreading supports batch sending
- Archive option is added for sending, encryption and decryption
- File encryption format standardized
- Server-side logging is added
- Compile-time options are added
- **Dockerization of sender and server code added**
- **Key generation added**

### Defaults

---

- Program is compiled with `FILESEND_PROFILE_FULL` and server is compiled with `FILESEND_PROFILE_MINIMAL_WS`
- When running a server with **Docker**, all the necessary security material (server key, server certificate, encryption keys) is generated and `server_config` is updated **automatically **
- When running a server with **Docker**, server starts **automatically**
- Sender's `filesend` and server are expected to be **different devices** on the **same network** (but you still can run both as separate processes on one machine for testing purposes)
- `--retry <n>` option in `filesend` (same as `retry` field in `filesend_config` ) will retry **only in case of connection failure** but NOT in case of failed file processing
- For the fast setup, defaults are **WebSocket connection**, **TLS via CA certificate** and **asymmetric cryptosystem** for file contents encryption

#### Default Configuration Setup

---

##### **Fast setup using `node-setup.sh`**

For the fast setup everything you need is the repo itself and Docker installed.

```bash
chmod +x node-setup.sh generate-configs.sh  # allow execution
./node-setup.sh --one        # run for testing on single device (creates server + app containers, leaves in app container's shell)
./node-setup.sh --multiple   # run for starting the server and generating all the necessary device configuration inside crypto/asymm/devices (or crypto/symm/devices)
```

- Running with option `--one` will assume you have only one node for both sender and server so the code execution will leave you in a sender's shell so you can select a directory an run the testing on it via `filesend send my_dir/` This option is for fast one-device testing
- Running with option `--multiple` will start the server and prepare the security material for nodes just as a command above but it will not create an app container as it is assumed the app container will run on one or multiple nodes (sender devices) which are different from the server device

If you want to review or modify the default fast setup, check the `setup.json` file.

##### Manual Setup

Fast setup automates all the steps below but for more control over the setup process you can follow the manual setup steps:

1. Build **server** container from the repo root `filesend-base/`:

```bash
   docker build \
      -f Dockerfile.server \
      --build-arg USER_UID="$(id -u)" \
      --build-arg USER_GID="$(id -g)" \
      -t filesend-server-dev .
```

2. Run server from `server/` directory (so we do not copy the files present in `server/` to the current directory once again):

   ```bash
   docker run --rm -it \
      -p 8444:8444 \
      -v "$PWD:/workspace" \
      -e SERVER_MODE=ws \
      filesend-server-dev
   ```
3. Copy the `ca_cert-date.pem`, `pub-date.key` and `pr-date.key` to the sender (machine running `filesend`) and change the `filesend_config` accordingly.
4. Either compile natively (see the list of dependencies and compile options below) or build a container for the **application** from the repo root `filesend-base/`. Do this in a separate process or shell, if running both server and filesend application code on a single machine.

   ```bash
   # Skip first two commands if compiling natively

   # Build
   docker build \
      -f Dockerfile.sender \
      --build-arg USER_ID="$(id -u)" \
      --build-arg GROUP_ID="$(id -u)" \
      -t filesend-app . 

   # Run
   docker run --rm -it \
      --name filesend-dev \
      --user "$(id -u):$(id -g)" \
      --network=host \
      -v "$(pwd):/workspace" \
      -w /workspace \
      filesend-app

   # Either inside of container or natively, compile with:
   make # -DFILESEND_PROFILE_*
   ```
5. After successful compilation, try running `filesend` with some directory containing files. If running from Docker container, this directory should be inside the mounted folder.

   ```bash
   # Directory tree expected:
   # my_dir/        <- run filesend from here
   # - my_files/    <- contains files to send
   # - <...>

   cd my_dir/

   # Run the filesend binary (this exact command will use filesend_config to set up the paramenters of running)
   path/to/./filesend send my_files/
   ```
6. Both of the sides (server and sender) have their logs which explicitly show if sending succeeded or not, and if not then what was the reason.

#### Common Issues

---

1. `decrypt failed`

   * In server logs: ` ERROR | peer=ip:port device=my_device file=my_file.ext.enc | decrypt failed (code=1)`
   * This problem occurs if keys on server and sender sides do not match. To find the reason of the mismatch, check:
     * Are config vaues of key names match on server and sender? Do these keys have same contents?
     * Does the `filesend` binary see the keys?
     * Was the file encrypted?
     * Is `.env` sourced on server? If using CLI, is `.env` sourced on sender? Are `.env` values correct?
   * **Fix:** try to regenerate the keys and update values in configs and `.env`s.
2. On sender: `connection refused`

   * In sender logs: `[WS] connect_tls exception: connect: Connection refused [system:111 at ... in function 'connect']`
   * This problem occurs when the sender and server ports do not match or the server is not running.
     * Check configuration files of both sender and server. Compare sender's `url` field with server's `port` and `host` fields.
     * Check if server is running.
     * Check if you run the correct server (i.e, if sending via WebSocket, running server should be `runserver_ws.py`)
     * If using Docker, check if correct port is exposed and passed in `-p` option when running the container.
   * **Fix:** if you have a problem connecting to a certain port, either change it or temporarily enable network by passing `--network=host` to the server's container on run.
3. On server: `device token missing`

   * Server logs: `Auth is enabled but token file is missing/empty (devtokens.json). All devices will be rejected.`
   * This problem occurs if `server_config` has `require_auth = true` and `devtokens.json` (file with device tokens) does not contain the correct device token.
     * Check if `devtokens.json` exists and has a correct device token.
     * Check if sender's config `filesend_config` has `device_id` set to to device token.
   * **Fix:** if error persists, try setting `require_auth` in `server_config` to `false` or generate new device token and update the necessary files.
4. On sender: `load_verify_file: No such file or directory`

   - Sender logs: `terminate called after throwing an instance of '...' what():  load_verify_file: No such file or directory`
   - This problem occurs when app cannot resolve a path from `filesend_config`.
     - Check if all paths inside `filesend_config` are valid and exist

### Compile-Time Options

---

By default all of the application features are enabled, but if you want to have more control over dependencies, there are three possible options for you to choose from:

| Option                            | Encryption/Decryption | WS/WSS | HTTP/HTTPS | Database | Batching | Multithreading |
| --------------------------------- | --------------------- | ------ | ---------- | -------- | -------- | -------------- |
| `FILESEND_PROFILE_FULL`         | +                     | +      | +          | +        | +        | +              |
| `FILESEND_PROFILE_MINIMAL_WS`   | +                     | +      | -          | -        | -        | -              |
| `FILESEND_PROFILE_MINIMAL_HTTP` | +                     | -      | +          | -        | -        | -              |
| `FILESEND_PROFILE_CUSTOM`       | +                     | ?      | ?          | ?        | ?        | ?              |

`FILESEND_PROFILE_CUSTOM` allows you to specify only the features you prefer, but to do so you need to set up the necessary features inside `include/build_features.h`.

`FILESEND_PROFILE_MINIMAL_*` can be used for server side to receive and decrypt the encrypted files.

### Sending Directory Layout

---

Assume your initial directory for incoming images is `mydir/`

* When running the program in sending mode, it creates a directory tree under the initial directory `mydir/`. This is optional for single-threaded sending but crucial for multithreaded version.
* `mydir/.filesend_archive` - an archive that stores all processed files during the sending. Needs flag `archive` to be set in config or by CLI.
* `mydir/.filesend_outbox` - last directory before a file that is sent to a server. If a file gets there, its preprocessing was successful.
* `mydir/.filesend_tmp` - a directory for temporary file processing steps.
* `mydir/.filesend_spool` - a directory that targets clean multiprocessing pipeline, creating 4 subdirectories:
  * `claimed` - files that the program started to process but didn't assigned to any thread yet;
  * `failed` - files that were processed unsuccessfully for some reason;
  * `outtmp` - directory for temporary file processing;
  * `work` - directory for threads to divide the work on files.
* `mydir/.filesend_cache` - if the database is enabled, this file stores data about sent files to ignore processing a file twice.

### List of Dependencies Used

---

**NOTE:** if using Docker containers, the only dependency needed overall is Docker itself.

These dependencies are required to run `filesend`:

- libsodium (cryptography; necessary)
- libssl (secure connection; necessary)
- libcurl (HTTP/HTTPS connection; optional)
- libboost for boost.beast and boost.asio headers (WebSocket connection; necessary, but can be optional if HTTP connection dependency is present)
- libzip & libarchive (batch archives in `zip`, `tar` and `tar.gz` formats)

These dependencies are required to run server (pip):

- websockets (if using WebSocket)
- aiohttp (if using HTTP)

### General Syntax

---

```
filesend send    [--https|--ws] <path> <url> [--encrypt symmetric|asymmetric] [--all] [--timeout <n>] [--retry <n>] [--no-retry] [--batch <n>] [--archive] [--nthreads <n>] [--poll-interval <n>]
filesend encrypt <path> [--symmetric|--asymmetric] [--all] [--dest <file>] [--force] [--archive]
filesend decrypt <path> [--symmetric|--asymmetric] [--all] [--dest <file>] [--force] [--archive]
filesend verify  <path> <sha256>
filesend keygen [--symmetric|--asymmetric]
```

#### **Limitations**

---

**NOTE:** the options are mostly **independent** (any combination possible) and **protected** (will fail early if some field is incorrect or missing). However, **you cannot:**

- Send via both HTTP and WS simultaneously: select only one
- Encrypt with symmetric and asymmetric keys at the same time: it will break the encryption. Stick with **one** preferred key cryptosystem.
- Pass both `--retry <n>` and `--no-retry` : these options are for **opposite scenarios**. It is not recommended to use `--retry 0` instead of `--no-retry`.
- Not an error, but **avoid sending a single file** instead of a directory with `--batch` option. It will work, but there is no need to create a batch out of 1 file.

**IMPORTANT:** These limitations apply to **config-based setup** as well.

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

Example of **app** config file structure (sender):

```
[global]
device_id = some_device_id_here          # unique identifier of a sender device
cert_path = cert.pem                     # certificate for server connection; place for ca-cert-YYYY-MM-DD.pem
security_info = true                     # will be added soon
use_config = true

[send]
# http/https
# url = https://test:8443/upload         # HTTP/HTTPS URL; must end with /upload
# use_ws = false                         # flag for websocket use; for HTTP/HTTPS is false

# websocket
url = wss://0.0.0.0:8444                 # WS/WSS URL
use_ws = true                            # flag for websocket use; for HTTP/HTTPS is false

timeout = 5                              # if there are no more new files in directory, the app will stop; measured in seconds
retry = 3                                # amount of retries in case of unsuccessful connection; does NOT retry failed file processing
poll_interval = 1000                     # poll interval for incoming directory; measured in milliseconds
nthreads = 3                             # number of sending threads
batch_size = 1                           # amount of files inside a batch archive; if set to 1, no batching is applied
batch_format = zip                       # format of batch archive; can be .zip, .tar or .tar.gz

[crypto]
mode = asymmetric                        # key cryptosystem; can be symmetric (one key) or asymmetric (private and public keys)
all     = true                           # if set to true, includes file metadata when encrypting/decrypting file contents;
archive = false                          # if set to true, saves the files after sending and removes otherwise
force   = false                          # ignores rules for application of encryption/decryption; can encrypt file twice or decrypt file without .enc extension
pub_key_path = pub.key                   # public key
pr_key_path  = pr.key                    # private key (should NOT be stored on sender if no file decryption is planned)
# sym_key_path = sym.key                 # symmetric key; do NOT use both key modes simultaneously

dest_path = my_dest/                     # destiation of processed files
```

Example of **server** config file structure:

```
# Example of server config

[global]
security_info = true              # will be added soon
use_config = true

[server]
host = 0.0.0.0                    # host information
port = 8444                       # port information

[paths]
incoming_dir  = incoming          # directory that accepts incoming files
decrypted_dir = decrypted         # directory that stores decrypted incoming files

[limits]
max_file_mb     = 32
max_json_kb     = 16
idle_timeout_s  = 30
ping_interval_s = 20
ping_timeout_s  = 20

[auth]
require_auth = false              # authenticate by device id
token_file   = devtokens.json     # file that stores information about all allowed devices

[dedup]
enable = true                     # enable file deduplication (if same file comes twice, it is ignored)
db_path = received_files.sqlite3  # received files database path

[tls]
# If cert/key are empty or absent => runs with no TLS
cert_path = certs/server.crt      # server certificate
key_path  = keys/server.key       # server key

[filesend]
bin_path = bin/filesend           # binary with filesend (server needs it for decryption)
decrypt_timeout_s = 60

[logging]
level = INFO                      # log level
# If empty => terminal-only
file  = logs/server.log           # log file path

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
* **`--nthreads`** – if compiled with `USE_MULTITHREADING` option, set number of threads to `n`. If running in multithreading mode and this option is not specified, number of threads used is equal to `MAX_WORKERS_MT`. NOTE: `MAX_WORKER_MT` needs to be properly adjusted for the device on which you plan to run this code. Right now `MAX_WORKER_MT = 4`, but if you wish to have more threads, change the number manually in `include/multithreading_utils.h`.

**Environment variables**

The environment variables are used for server to decrypt the encrypted file (as it uses `filesend` CLI) and in CLI mode for `filesend`. If you run `filesend` with the config, `.env` is ignored.

- `CERT_PATH` – path to CA certificate used to validate server TLS certificate (both HTTPS and WS)
- `SYM_KEY_PATH` – path to symmetric key (if symmetric mode is chosen)
- `PUB_KEY_PATH`, `PR_KEY_PATH` – paths to public/private key pair (asymmetric mode)

**Examples**

- Send a file **without** encrypting it: `filesend send data/report.bin "https://myserver.local:8443/upload"`
- Send with symmetric encryption:

```bash
export SYM_KEY_PATH=/etc/myapp/sym.key
export CERT_PATH=/etc/myapp/ca_cert.pem

filesend send --https images/photo.png "https://myserver.local:8443/upload" --encrypt symmetric
```

- Send from a folder (`logs`) with asymmetric encryption and metadata protection (and stop after a timeout of 30 secs):

```bash
export PUB_KEY_PATH=/etc/myapp/server_box_pk.bin
export CERT_PATH=/etc/myapp/ca_cert.pem

filesend send --ws logs "ws://0.0.0.0:8444/ws" --encrypt asymmetric --all --timeout 30
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

```bash
export PUB_KEY_PATH=/etc/myapp/server_box_pk.bin

filesend encrypt raw/data.bin --asymmetric --all
```

- Symmetric encryption:

```bash
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

```bash
export SYM_KEY_PATH=/etc/myapp/sym.key # or source .env

filesend decrypt backups/db.enc -symmetric --dest db_restored.sql
```

- Decrypt asymmetric encrypted file with metadata

```bash
export PUB_KEY_PATH=/etc/myapp/server_box_pk.bin
export PR_KEY_PATH=/etc/myapp/server_box_sk.bin

filesend decrypt images/cam01.img.enc --asymmetric --all
```

#### Mode: `verify`

---

```
filesend verify <path> <sha256>
```

Verifies file's SHA-256 (both raw and hex formats). Can be used on server side.

#### Mode: `keygen`

---

```
filesend keygen [--symmetric|--asymmetric]
```

Creates a key/keypair suitable for encryption/decryption.

You do not need anything to run it (for example, sourcing `.env` or setting the `filesend_config`). The warnings about using default fields (e.g. `[WARN] No KEY_PATH found in environment. Using default: my_key.bin`) can be safely ignored.

**NOTE:** `keygen` is possible only from CLI, config-based method does not support it.

Alternative key generation method, based on file encryption without any keys available (obsolete):

```bash
# To create a pair of keys run:
touch mytemp.txt && echo "a line of text" > mytemp.txt # create a temporary file
unset PUB_KEY_PATH || true
unset PR_KEY_PATH || true
unset SYM_KEY_PATH || true
bin/./filesend encrypt mytemp.txt --symmetric|--asymmetric # try to encrypt the file without .env sourced
```

### Notes & Recommendations

**NOTE:** `<path>` in `encrypt` and `decrypt` supports **pattern-based path definition** like `*.png `or `log_???.txt `. If you want to use a pattern instead of direct path, put your pattern in " " symbols: `filesend encrypt "*.png" --asymmetric --all`

* `--all` enables encryption/decryption of **metadata** (mtime, mode, uid/gid).
* URL  **must include `/upload`** , as the server expects this endpoint.
* The hostname in the URL must match the certificate CN/SAN (e.g., `Test`, `localhost`).
* Server *private key* **must never** be on the sending device – only the server should have it.
* Asymmetric encryption is recommended for device - server communication (one-way encryption).
* Symmetric encryption is recommended for local file storage or local pipelines.

#### How to generate server key and certificate

---

```bash
# CA private key
openssl genrsa -out myCA.key 4096

# CA self-signed certificate (root cert)
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca_cert.pem

# Create a key
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr

# Sign
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca.key \
   -CAcreateserial -out server.crt -days 365 -sha256
```

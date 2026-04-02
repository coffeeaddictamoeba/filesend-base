"""
Sender (file upload) multipart fields:
  - file      (binary)  [libcurl curl_mime_filedata]
  - device_id (text)
  - flags     (text int)
  - SHA256    (text 64-hex)
  - token     (optional text; server supports it if you add later)

Sender (end-of-stream) multipart fields:
  - end       (text "1")
  - device_id (text)
  - token     (optional)

Config rule:
  - python server_https.py          -> INI mode, loads ./server_config
  - python server_https.py <any...> -> CLI mode

Endpoints:
  - GET  /health
  - POST /upload
"""

import argparse
import asyncio
import configparser
import hashlib
import hmac
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import re
import sqlite3
import ssl
import stat
import subprocess
import sys
from typing import Optional, Dict, Any, Tuple

from aiohttp import web

# Defaults
FILESEND_SERVER_CONFIG: str = "server_config"

FILESEND_BIN_PATH: str = "bin/filesend"
FILESEND_INCOMING_DIR: str = "incoming"
FILESEND_DECRYPTED_DIR: str = "decrypted"
FILESEND_TOKENS_JSON: str = "device_tokens.json" # {"pi":"token", ...}
FILESEND_DATABASE_RECEIVED: str = "received_files.sqlite3"

FILESEND_HOST_DEFAULT: str = "0.0.0.0"
FILESEND_PORT_DEFAULT: int = 8443

MAX_FBYTES_MB_DEFAULT: int = 32
MAX_TBYTES_KB_DEFAULT: int = 16

REQUEST_TIMEOUT_SEC: int = 120
DECRYPT_TIMEOUT_SEC: int = 60

# Optional auth (OFF by default; current sender does not send token)
FILESEND_REQUIRE_AUTH: bool = False

FILESEND_ENABLE_DEDUP: bool = True

@dataclass(frozen=True)
class ServerConfig:
    host: str = FILESEND_HOST_DEFAULT
    port: int = FILESEND_PORT_DEFAULT

    incoming_dir: Path  = Path(FILESEND_INCOMING_DIR)
    decrypted_dir: Path = Path(FILESEND_DECRYPTED_DIR)

    # Limits
    max_file_bytes: int = MAX_FBYTES_MB_DEFAULT * 1024 * 1024
    max_text_part_bytes: int = MAX_TBYTES_KB_DEFAULT * 1024
    request_timeout_sec: int = REQUEST_TIMEOUT_SEC

    require_auth: bool = FILESEND_REQUIRE_AUTH
    token_file: Optional[Path] = Path(FILESEND_TOKENS_JSON)  

    # TLS
    tls_cert: Optional[Path] = None
    tls_key: Optional[Path] = None

    # Decrypt tool
    filesend_bin: Path = Path(FILESEND_BIN_PATH)
    decrypt_timeout_sec: int = DECRYPT_TIMEOUT_SEC

    # Dedup
    enable_dedup: bool = FILESEND_ENABLE_DEDUP
    dedup_db: Path = Path(FILESEND_DATABASE_RECEIVED)

    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None


# Logging
def setup_logging(cfg: ServerConfig) -> logging.Logger:
    logger = logging.getLogger("https_fileserver")
    logger.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    if cfg.log_file:
        cfg.log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = RotatingFileHandler(cfg.log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# Helpers
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

def get_safe_filename(name: str, max_len: int = 150) -> str:
    base = os.path.basename((name or "").strip())
    base = base.replace("\x00", "")
    base = _SAFE_NAME_RE.sub("_", base)
    base = base.strip("._-") or "file"
    return base[:max_len]

def is_valid_sha256_hex(s: str) -> bool:
    if not isinstance(s, str) or len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def now_utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def mkdir_secure(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except Exception:
        pass

def json_ok(data: Dict[str, Any], status: int = 200) -> web.Response:
    return web.json_response(data, status=status)

def json_err(msg: str, status: int = 400, **extra) -> web.Response:
    payload = {"ok": False, "error": msg}
    payload.update(extra)
    return web.json_response(payload, status=status)


# DB
def db_init(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                sha256 TEXT PRIMARY KEY,
                first_seen_utc TEXT NOT NULL,
                last_seen_utc  TEXT NOT NULL,
                count INTEGER NOT NULL,
                last_enc_path TEXT,
                last_dec_path TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

def db_check_and_touch(db_path: Path, sha256_hex: str, enc_path: str, dec_path: str) -> Tuple[bool, int]:
    ts = now_utc_compact()
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute("SELECT count FROM files WHERE sha256 = ?", (sha256_hex,))
        row = cur.fetchone()
        if row:
            count = int(row[0]) + 1
            conn.execute(
                "UPDATE files SET last_seen_utc=?, count=?, last_enc_path=?, last_dec_path=? WHERE sha256=?",
                (ts, count, enc_path, dec_path, sha256_hex),
            )
            conn.commit()
            return True, count
        else:
            conn.execute(
                "INSERT INTO files(sha256, first_seen_utc, last_seen_utc, count, last_enc_path, last_dec_path) "
                "VALUES(?,?,?,?,?,?)",
                (sha256_hex, ts, ts, 1, enc_path, dec_path),
            )
            conn.commit()
            return False, 1
    finally:
        conn.close()


# Auth
def load_tokens(token_file: Optional[Path]) -> Dict[str, str]:
    if not token_file or not token_file.exists():
        return {}
    try:
        data = json.loads(token_file.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    out: Dict[str, str] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, str):
            out[k] = v
    return out

def auth_ok(cfg: ServerConfig, tokens: Dict[str, str], device_id: str, provided_token: str) -> bool:
    if not cfg.require_auth:
        return True
    expected = tokens.get(device_id)
    if not expected:
        return False
    return hmac.compare_digest(expected, provided_token or "")


# Decrypt/copy
def run_filesend_decrypt(cfg: ServerConfig, enc_path: Path, dec_path: Path, flags: int, logger: logging.Logger, ctx: str) -> None:
    enc_enabled   = bool(flags & 0b001) # bit 0 -> encryption enabled
    enc_symmetric = bool(flags & 0b010) # bit 1 -> symmetric (else asymmetric)
    enc_all       = bool(flags & 0b100) # bit 2 -> --all

    if not enc_enabled:
        dec_path.write_bytes(enc_path.read_bytes())
        return

    cmd = [str(cfg.filesend_bin), "decrypt", str(enc_path)]
    cmd.append("--symmetric" if enc_symmetric else "--asymmetric")
    if enc_all:
        cmd.append("--all")
    cmd.extend(["--dest", str(dec_path)])

    res = subprocess.run(
        cmd,
        check=True,
        timeout=cfg.decrypt_timeout_sec,
        capture_output=True,
        text=True,
    )
    if res.stdout:
        logger.debug("%s | filesend stdout: %s", ctx, res.stdout.strip())
    if res.stderr:
        logger.debug("%s | filesend stderr: %s", ctx, res.stderr.strip())


# Handlers
async def handle_health(req: web.Request) -> web.Response:
    return json_ok({"ok": True, "status": "ok"})

async def handle_upload(req: web.Request) -> web.Response:
    cfg: ServerConfig = req.app["cfg"]
    logger: logging.Logger = req.app["logger"]
    tokens: Dict[str, str] = req.app["tokens"]

    peer = req.remote or "unknown-peer"
    ctx_base = f"peer={peer}"

    try:
        return await asyncio.wait_for(
            _handle_upload_inner(req, cfg, logger, tokens, ctx_base),
            timeout=cfg.request_timeout_sec
        )
    except asyncio.TimeoutError:
        logger.warning("%s | request timeout", ctx_base)
        return json_err("request timeout", status=408)

async def _handle_upload_inner(req: web.Request, cfg: ServerConfig, logger: logging.Logger, tokens: Dict[str, str], ctx_base: str) -> web.Response:
    if not (req.content_type or "").lower().startswith("multipart/"):
        logger.warning("%s | rejected: expected multipart/form-data, got %s", ctx_base, req.content_type)
        return json_err("expected multipart/form-data", status=400)

    mkdir_secure(cfg.incoming_dir)
    mkdir_secure(cfg.decrypted_dir)

    reader = await req.multipart()

    fields: Dict[str, str] = {}
    got_file = False

    orig_name = "file"
    safe_name = "file"

    enc_tmp: Optional[Path] = None
    enc_final: Optional[Path] = None
    dec_final: Optional[Path] = None

    received = 0
    hasher = hashlib.sha256()
    f = None

    async def read_small_text(part) -> str:
        raw = await part.read(decode=True)
        if raw is None:
            return ""
        if len(raw) > cfg.max_text_part_bytes:
            raise web.HTTPRequestEntityTooLarge(text=f"{part.name} too large")
        return raw.decode("utf-8", errors="replace").strip()

    try:
        # IMPORTANT:
        # sender sends the "file" part FIRST. We must consume it immediately.
        async for part in reader:
            name = (part.name or "").strip()

            if name == "file":
                got_file = True
                orig_name = part.filename or "file"
                safe_name = get_safe_filename(orig_name)

                ts = now_utc_compact()
                tmp_id = f"tmp_{ts}_{safe_name}"
                enc_tmp = cfg.incoming_dir / (tmp_id + ".part")

                try:
                    fd = os.open(str(enc_tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    f = os.fdopen(fd, "wb", buffering=0)
                except FileExistsError:
                    logger.warning("%s | collision: %s already exists", ctx_base, enc_tmp.name)
                    return json_err("file collision", status=409)

                while True:
                    chunk = await part.read_chunk(size=64 * 1024)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > cfg.max_file_bytes:
                        logger.warning("%s | too large: %d > %d", ctx_base, received, cfg.max_file_bytes)
                        return json_err("file too large", status=413, bytes=received)
                    hasher.update(chunk)
                    f.write(chunk)

                f.flush()
                os.fsync(f.fileno())
                f.close()
                f = None

            else:
                fields[name] = await read_small_text(part)

        # End-of-stream (no file required)
        if fields.get("end", "").strip() == "1":
            device_id = (fields.get("device_id", "")).strip()
            token = (fields.get("token", "")).strip()

            if not device_id:
                logger.warning("%s | end: missing device_id", ctx_base)
                return json_err("missing device_id", status=400)

            if not auth_ok(cfg, tokens, device_id, token):
                logger.warning("%s | end: auth failed device_id=%s", ctx_base, device_id)
                return json_err("auth failed", status=401)

            logger.info("%s | end signal from device=%s", ctx_base, device_id)
            return json_ok({"ok": True, "type": "end_ack", "device_id": device_id})

        # File upload requires file + required fields
        if not got_file:
            logger.warning("%s | upload: missing file part", ctx_base)
            return json_err("missing file part", status=400)

        device_id = (fields.get("device_id", "")).strip()
        token = (fields.get("token", "")).strip()  # optional
        sha256_hex = (fields.get("SHA256", "")).strip().lower()
        flags_s = (fields.get("flags", "0")).strip()

        if not device_id:
            return json_err("missing device_id", status=400)
        if not is_valid_sha256_hex(sha256_hex):
            return json_err("invalid SHA256", status=400)

        try:
            flags = int(flags_s)
        except Exception:
            flags = 0

        if not auth_ok(cfg, tokens, device_id, token):
            logger.warning("%s | upload: auth failed device_id=%s", ctx_base, device_id)
            return json_err("auth failed", status=401)

        # Finalize names now that device_id is known
        ts = now_utc_compact()
        file_id = f"{device_id}_{ts}_{safe_name}"
        enc_final = cfg.incoming_dir / file_id
        dec_final = cfg.decrypted_dir / file_id

        # Move temp file into final location
        assert enc_tmp is not None
        os.replace(enc_tmp, enc_final)

        try:
            os.chmod(enc_final, stat.S_IREAD)
        except Exception:
            pass

        actual_sha = hasher.hexdigest().lower()
        ctx = f"{ctx_base} device={device_id} file={safe_name}"

        logger.info("%s | upload_received bytes=%d expected_sha256=%s actual_sha256=%s flags=%d", ctx, received, sha256_hex, actual_sha, flags)

        if actual_sha != sha256_hex:
            logger.error("%s | checksum mismatch expected=%s actual=%s bytes=%d", ctx, sha256_hex, actual_sha, received)
            return json_err("checksum mismatch", status=400, expected=sha256_hex, actual=actual_sha, bytes=received)

        run_filesend_decrypt(cfg, enc_final, dec_final, flags, logger, ctx)

        try:
            os.chmod(dec_final, 0o600)
        except Exception:
            pass

        is_dup = False
        dup_count = 1
        if cfg.enable_dedup:
            is_dup, dup_count = db_check_and_touch(cfg.dedup_db, actual_sha, str(enc_final), str(dec_final))

        logger.info("%s | upload_done bytes=%d sha256=%s decrypted=%s dedup=%s count=%d", ctx, received, actual_sha, dec_final.name, is_dup, dup_count)

        return json_ok({
            "ok": True,
            "type": "file_done",
            "file_id": file_id,
            "enc_path": str(enc_final),
            "dec_path": str(dec_final),
            "sha256": actual_sha,
            "dedup": bool(is_dup),
            "dedup_count": int(dup_count),
        }, status=200)

    except web.HTTPRequestEntityTooLarge as e:
        logger.warning("%s | entity too large: %s", ctx_base, e.text)
        return json_err(e.text or "entity too large", status=413)
    except subprocess.TimeoutExpired:
        logger.error("%s | decrypt timeout after %ds", ctx_base, cfg.decrypt_timeout_sec)
        return json_err("decrypt timeout", status=504)
    except subprocess.CalledProcessError as e:
        logger.error("%s | decrypt failed (code=%s)", ctx_base, e.returncode)
        return json_err("decrypt failed", status=400)
    except Exception as e:
        logger.exception("%s | internal error: %s", ctx_base, e)
        return json_err("internal server error", status=500)
    finally:
        # Clean up on early errors
        try:
            if f is not None and not f.closed:
                f.close()
        except Exception:
            pass
        try:
            if enc_tmp is not None and enc_tmp.exists():
                enc_tmp.unlink()
        except Exception:
            pass


# INI / CLI Config
def _get_bool(cp: configparser.ConfigParser, section: str, key: str, default: bool) -> bool:
    try:
        return cp.getboolean(section, key, fallback=default)
    except Exception:
        return default

def _get_int(cp: configparser.ConfigParser, section: str, key: str, default: int) -> int:
    try:
        return cp.getint(section, key, fallback=default)
    except Exception:
        return default

def _get_str(cp: configparser.ConfigParser, section: str, key: str, default: str) -> str:
    try:
        return cp.get(section, key, fallback=default)
    except Exception:
        return default

def validate_cfg(cfg: ServerConfig) -> None:
    if not (0 < cfg.port < 65536):
        raise ValueError(f"Invalid port: {cfg.port}")
    if cfg.max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be > 0")
    if cfg.max_text_part_bytes <= 0:
        raise ValueError("max_text_part_bytes must be > 0")
    if cfg.request_timeout_sec <= 0:
        raise ValueError("request_timeout_sec must be > 0")
    if cfg.decrypt_timeout_sec <= 0:
        raise ValueError("decrypt_timeout_sec must be > 0")
    if (cfg.tls_cert is None) ^ (cfg.tls_key is None):
        raise ValueError("TLS invalid: set both tls_cert and tls_key, or neither")

def load_cfg_from_ini(path: Path) -> ServerConfig:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    cp = configparser.ConfigParser()
    cp.read(path, encoding="utf-8")

    host = _get_str(cp, "server", "host", FILESEND_HOST_DEFAULT)
    port = _get_int(cp, "server", "port", FILESEND_PORT_DEFAULT)

    incoming_dir = Path(_get_str(cp, "paths", "incoming_dir", FILESEND_INCOMING_DIR))
    decrypted_dir = Path(_get_str(cp, "paths", "decrypted_dir", FILESEND_DECRYPTED_DIR))

    max_file_mb = _get_int(cp, "limits", "max_file_mb", MAX_FBYTES_MB_DEFAULT)
    max_text_kb = _get_int(cp, "limits", "max_text_kb", MAX_TBYTES_KB_DEFAULT)
    req_timeout_s = _get_int(cp, "limits", "request_timeout_s", REQUEST_TIMEOUT_SEC)

    require_auth = _get_bool(cp, "auth", "require_auth", FILESEND_REQUIRE_AUTH)
    token_file_s = _get_str(cp, "auth", "token_file", FILESEND_TOKENS_JSON).strip()
    token_file = Path(token_file_s) if token_file_s else None

    enable_dedup = _get_bool(cp, "dedup", "enable", FILESEND_ENABLE_DEDUP)
    dedup_db = Path(_get_str(cp, "dedup", "db_path", FILESEND_DATABASE_RECEIVED))

    cert_s = _get_str(cp, "tls", "cert_path", "").strip()
    key_s = _get_str(cp, "tls", "key_path", "").strip()
    tls_cert = Path(cert_s) if cert_s else None
    tls_key = Path(key_s) if key_s else None

    filesend_bin = Path(_get_str(cp, "filesend", "bin_path", FILESEND_BIN_PATH))
    decrypt_timeout_s = _get_int(cp, "filesend", "decrypt_timeout_s", DECRYPT_TIMEOUT_SEC)

    log_level = _get_str(cp, "logging", "level", "INFO").strip() or "INFO"
    log_file_s = _get_str(cp, "logging", "file", "").strip()
    log_file = Path(log_file_s) if log_file_s else None

    cfg = ServerConfig(
        host=host,
        port=port,
        incoming_dir=incoming_dir,
        decrypted_dir=decrypted_dir,
        max_file_bytes=max_file_mb * 1024 * 1024,
        max_text_part_bytes=max_text_kb * 1024,
        request_timeout_sec=req_timeout_s,
        require_auth=require_auth,
        token_file=token_file,
        enable_dedup=enable_dedup,
        dedup_db=dedup_db,
        tls_cert=tls_cert,
        tls_key=tls_key,
        filesend_bin=filesend_bin,
        decrypt_timeout_sec=decrypt_timeout_s,
        log_level=log_level,
        log_file=log_file,
    )
    validate_cfg(cfg)
    return cfg

def parse_cfg_from_cli(argv: list[str]) -> ServerConfig:
    p = argparse.ArgumentParser(description="HTTP/HTTPS receiver")

    p.add_argument("--host", default=FILESEND_HOST_DEFAULT)
    p.add_argument("--port", type=int, default=FILESEND_PORT_DEFAULT)

    p.add_argument("--incoming-dir", default=FILESEND_INCOMING_DIR)
    p.add_argument("--decrypted-dir", default=FILESEND_DECRYPTED_DIR)

    p.add_argument("--max-file-mb", type=int, default=MAX_FBYTES_MB_DEFAULT)
    p.add_argument("--max-text-kb", type=int, default=MAX_TBYTES_KB_DEFAULT)
    p.add_argument("--request-timeout", type=int, default=REQUEST_TIMEOUT_SEC)

    p.add_argument("--require-auth", action="store_true", default=FILESEND_REQUIRE_AUTH)
    p.add_argument("--token-file", default=FILESEND_TOKENS_JSON)

    p.add_argument("--tls-cert", default=None)
    p.add_argument("--tls-key", default=None)

    p.add_argument("--filesend-bin", default=FILESEND_BIN_PATH)
    p.add_argument("--decrypt-timeout", type=int, default=DECRYPT_TIMEOUT_SEC)

    p.add_argument("--dedup", action="store_true", default=FILESEND_ENABLE_DEDUP)
    p.add_argument("--no-dedup", dest="dedup", action="store_false")
    p.add_argument("--dedup-db", default=FILESEND_DATABASE_RECEIVED)

    p.add_argument("--log-level", default="INFO")
    p.add_argument("--log-file", default=None)

    args = p.parse_args(argv)

    cfg = ServerConfig(
        host=args.host,
        port=args.port,
        incoming_dir=Path(args.incoming_dir),
        decrypted_dir=Path(args.decrypted_dir),
        max_file_bytes=int(args.max_file_mb) * 1024 * 1024,
        max_text_part_bytes=int(args.max_text_kb) * 1024,
        request_timeout_sec=int(args.request_timeout),
        require_auth=bool(args.require_auth),
        token_file=Path(args.token_file) if args.token_file else None,
        tls_cert=Path(args.tls_cert) if args.tls_cert else None,
        tls_key=Path(args.tls_key) if args.tls_key else None,
        filesend_bin=Path(args.filesend_bin),
        decrypt_timeout_sec=int(args.decrypt_timeout),
        enable_dedup=bool(args.dedup),
        dedup_db=Path(args.dedup_db),
        log_level=args.log_level,
        log_file=Path(args.log_file) if args.log_file else None,
    )
    validate_cfg(cfg)
    return cfg

def load_config() -> ServerConfig:
    # RULE:
    #   python server_https.py            -> INI mode (server_https.ini)
    #   python server_https.py <any> -> CLI mode
    if len(sys.argv) == 1:
        return load_cfg_from_ini(Path(FILESEND_SERVER_CONFIG))
    return parse_cfg_from_cli(sys.argv[1:])


# TLS
def build_ssl_context(cfg: ServerConfig) -> Optional[ssl.SSLContext]:
    if not cfg.tls_cert or not cfg.tls_key:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cfg.tls_cert), keyfile=str(cfg.tls_key))
    return ctx


# ============================
# App bootstrap
# ============================

def create_app(cfg: ServerConfig, logger: logging.Logger, tokens: Dict[str, str]) -> web.Application:
    # client_max_size is an additional guard; allow multipart overhead
    app = web.Application(client_max_size=cfg.max_file_bytes + 2 * 1024 * 1024)
    app["cfg"] = cfg
    app["logger"] = logger
    app["tokens"] = tokens

    app.router.add_get("/health", handle_health)
    app.router.add_post("/upload", handle_upload)
    return app


def main() -> None:
    cfg = load_config()
    logger = setup_logging(cfg)

    mkdir_secure(cfg.incoming_dir)
    mkdir_secure(cfg.decrypted_dir)

    tokens = load_tokens(cfg.token_file)
    if cfg.require_auth and not tokens:
        logger.warning("Auth enabled but token file missing/empty (%s). All devices will be rejected.", cfg.token_file)

    if cfg.enable_dedup:
        db_init(cfg.dedup_db)
        logger.info("Dedup DB ready at %s", cfg.dedup_db)

    ssl_ctx = build_ssl_context(cfg)
    scheme = "https" if ssl_ctx else "http"

    logger.info("Listening on %s://%s:%d", scheme, cfg.host, cfg.port)
    logger.info("POST %s://%s:%d/upload", scheme, cfg.host, cfg.port)
    logger.info("Multipart fields supported: file, device_id, flags, SHA256 (+ optional token), end=1")

    app = create_app(cfg, logger, tokens)
    web.run_app(app, host=cfg.host, port=cfg.port, ssl_context=ssl_ctx)


if __name__ == "__main__":
    main()
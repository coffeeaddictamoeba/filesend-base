import asyncio
import websockets
import json
import os
import re
import ssl
import stat
import time
import hmac
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import sqlite3
from typing import Optional, Dict, Any, Tuple
import configparser
import argparse
import sys


# Defaults
FILESEND_SERVER_CONFIG: str = "server_config"

FILESEND_BIN_PATH: str = "bin/filesend"
FILESEND_INCOMING_DIR: str = "incoming"
FILESEND_DECRYPTED_DIR: str = "decrypted"
FILESEND_TOKENS_JSON: str = "device_tokens.json" # {"pi":"token", ...}
FILESEND_DATABASE_RECEIVED: str = "received_files.sqlite3"

FILESEND_HOST_DEFAULT: str = "0.0.0.0"
FILESEND_PORT_DEFAULT: int = 8444

MAX_FBYTES_MB_DEFAULT: int = 32
MAX_TBYTES_KB_DEFAULT: int = 16

REQUEST_TIMEOUT_SEC: int = 120
IDLE_TIMEOUT_SEC: int = 30
PING_INTERVAL: int = 20
PING_TIMEOUT: int = 20
DECRYPT_TIMEOUT_SEC: int = 60

# Optional auth (OFF by default; current sender does not send token)
FILESEND_REQUIRE_AUTH: bool = False

FILESEND_ENABLE_DEDUP: bool = True


@dataclass(frozen=True)
class ServerConfig:
    host: str = FILESEND_HOST_DEFAULT
    port: int = FILESEND_PORT_DEFAULT

    incoming_dir: Path = Path(FILESEND_INCOMING_DIR)
    decrypted_dir: Path = Path(FILESEND_DECRYPTED_DIR)

    # Security / limits
    require_auth: bool = FILESEND_REQUIRE_AUTH
    token_file: Optional[Path] = Path(FILESEND_TOKENS_JSON)
    allowed_origins: Tuple[str, ...] = ()  # keep empty unless you want strict origin enforcement

    max_file_bytes: int = MAX_FBYTES_MB_DEFAULT * 1024 * 1024
    max_json_bytes: int = MAX_TBYTES_KB_DEFAULT * 1024

    idle_timeout_sec: int = IDLE_TIMEOUT_SEC
    ping_interval: int = PING_INTERVAL
    ping_timeout: int = PING_TIMEOUT

    # Subprocess
    filesend_bin: Path = Path(FILESEND_BIN_PATH)
    decrypt_timeout_sec: int = DECRYPT_TIMEOUT_SEC

    # TLS
    tls_cert: Optional[Path] = None
    tls_key: Optional[Path] = None

    # Dedup
    enable_dedup: bool = True
    dedup_db: Path = Path(FILESEND_DATABASE_RECEIVED)

    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None


@dataclass
class FileTransferState:
    device_id: str = "unknown"
    flags: int = 0
    filename_raw: str = ""
    filename_safe: str = ""
    expected_sha256: str = ""
    received_bytes: int = 0

    enc_final_path: Optional[Path] = None
    enc_tmp_path: Optional[Path] = None
    dec_final_path: Optional[Path] = None

    hasher: Any = field(default_factory=lambda: hashlib.sha256())
    f: Optional[Any] = None

    def reset(self) -> None:
        if self.f:
            try:
                self.f.close()
            except Exception:
                pass
        self.__dict__.update(FileTransferState().__dict__)


# Logging
def setup_logging(cfg: ServerConfig) -> logging.Logger:
    logger = logging.getLogger("ws_fileserver")
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


# Helpers: validation & safety
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

def sanitize_filename(name: str, max_len: int = 150) -> str:
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
    data = json.loads(token_file.read_text(encoding="utf-8"))
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


# Subprocess wrapper
def run_filesend_decrypt(cfg: ServerConfig, enc_path: Path, dec_path: Path, flags: int, logger: logging.Logger, ctx: str) -> None:
    enc_enabled   = bool(flags & 0b001)
    enc_symmetric = bool(flags & 0b010)
    enc_all       = bool(flags & 0b100)

    if not enc_enabled:
        # copy as "decrypted"
        data = enc_path.read_bytes()
        dec_path.write_bytes(data)
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


# WebSocket protocol helpers
async def send_json(ws, obj: Dict[str, Any]) -> None:
    await ws.send(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))

def get_peer(ws) -> str:
    try:
        return f"{ws.remote_address[0]}:{ws.remote_address[1]}"
    except Exception:
        return "unknown-peer"

def origin_allowed(cfg: ServerConfig, ws) -> bool:
    if not cfg.allowed_origins:
        return True
    origin = ws.request_headers.get("Origin", "")
    return origin in cfg.allowed_origins


async def handle_client(ws, cfg: ServerConfig, logger: logging.Logger, tokens: Dict[str, str]) -> None:
    peer = get_peer(ws)
    state = FileTransferState()
    ok_files = []
    failed_files = []
    ctx_base = f"peer={peer}"

    logger.info("%s | new connection", ctx_base)

    if not origin_allowed(cfg, ws):
        logger.warning("%s | rejected by Origin policy (Origin=%s)", ctx_base, ws.request_headers.get("Origin"))
        await send_json(ws, {"type": "error", "msg": "origin not allowed"})
        await ws.close(code=1008, reason="origin not allowed")
        return

    mkdir_secure(cfg.incoming_dir)
    mkdir_secure(cfg.decrypted_dir)

    try:
        async for msg in ws:
            # Control message
            if isinstance(msg, str):
                if len(msg.encode("utf-8", errors="ignore")) > cfg.max_json_bytes:
                    logger.warning("%s | JSON too large", ctx_base)
                    await send_json(ws, {"type": "error", "msg": "json too large"})
                    continue

                try:
                    data = json.loads(msg)
                except json.JSONDecodeError:
                    logger.warning("%s | invalid JSON: %r", ctx_base, msg[:200])
                    await send_json(ws, {"type": "error", "msg": "invalid json"})
                    continue

                mtype = data.get("type")

                if mtype == "file":
                    if state.f is not None:
                        logger.warning("%s | protocol error: file_start while file open", ctx_base)
                        await send_json(ws, {"type": "error", "msg": "file already open"})
                        continue

                    device_id = data.get("device_id") or "unknown"
                    token = data.get("token") or ""
                    filename = data.get("filename") or ""
                    flags_val = data.get("flags", 0)
                    sha256_hex = (data.get("SHA256") or "").lower()

                    if not filename:
                        await send_json(ws, {"type": "error", "msg": "no filename"})
                        continue
                    if not is_valid_sha256_hex(sha256_hex):
                        await send_json(ws, {"type": "error", "msg": "invalid SHA256"})
                        continue
                    try:
                        flags_int = int(flags_val)
                    except Exception:
                        flags_int = 0

                    if not auth_ok(cfg, tokens, device_id, token):
                        logger.warning("%s | auth failed device_id=%s", ctx_base, device_id)
                        await send_json(ws, {"type": "error", "msg": "auth failed"})
                        await ws.close(code=1008, reason="auth failed")
                        return

                    safe_name = sanitize_filename(filename)
                    ts = now_utc_compact()
                    file_id = f"{device_id}_{ts}_{safe_name}"

                    enc_final = cfg.incoming_dir / file_id
                    enc_tmp = cfg.incoming_dir / (file_id + ".part")
                    dec_final = cfg.decrypted_dir / file_id

                    try:
                        fd = os.open(str(enc_tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        f = os.fdopen(fd, "wb", buffering=0)
                    except FileExistsError:
                        logger.warning("%s | temp exists (collision) %s", ctx_base, enc_tmp)
                        await send_json(ws, {"type": "error", "msg": "file collision"})
                        continue

                    state.device_id = device_id
                    state.flags = flags_int
                    state.filename_raw = filename
                    state.filename_safe = safe_name
                    state.expected_sha256 = sha256_hex
                    state.received_bytes = 0
                    state.enc_final_path = enc_final
                    state.enc_tmp_path = enc_tmp
                    state.dec_final_path = dec_final
                    state.hasher = hashlib.sha256()
                    state.f = f

                    logger.info(
                        "%s | file_start device=%s name=%s flags=%s expected_sha256=%s tmp=%s",
                        ctx_base, device_id, safe_name, flags_int, sha256_hex, enc_tmp.name
                    )
                    await send_json(ws, {"type": "file_ack", "file_id": file_id})

                elif mtype == "file_end":
                    if state.f is None or not state.enc_tmp_path or not state.enc_final_path or not state.dec_final_path:
                        logger.warning("%s | file_end but no open file", ctx_base)
                        await send_json(ws, {"type": "error", "msg": "no open file"})
                        continue

                    try:
                        state.f.flush()
                        os.fsync(state.f.fileno())
                    finally:
                        state.f.close()
                        state.f = None

                    os.replace(state.enc_tmp_path, state.enc_final_path)

                    try:
                        os.chmod(state.enc_final_path, stat.S_IREAD)
                    except Exception:
                        pass

                    actual_sha = state.hasher.hexdigest().lower()
                    ctx = f"{ctx_base} device={state.device_id} file={state.filename_safe}"

                    if actual_sha != state.expected_sha256:
                        logger.error("%s | checksum mismatch expected=%s actual=%s",
                                     ctx, state.expected_sha256, actual_sha)
                        failed_files.append(str(state.enc_final_path))
                        await send_json(ws, {"type": "error", "msg": "checksum mismatch"})
                        state.reset()
                        continue

                    try:
                        run_filesend_decrypt(cfg, state.enc_final_path, state.dec_final_path, state.flags, logger, ctx)

                        try:
                            os.chmod(state.dec_final_path, 0o600)
                        except Exception:
                            pass

                        is_dup = False
                        dup_count = 1
                        if cfg.enable_dedup:
                            is_dup, dup_count = db_check_and_touch(
                                cfg.dedup_db, actual_sha,
                                str(state.enc_final_path), str(state.dec_final_path)
                            )

                        logger.info(
                            "%s | file_done bytes=%d sha256=%s decrypted=%s dedup=%s count=%d",
                            ctx, state.received_bytes, actual_sha, state.dec_final_path.name, is_dup, dup_count
                        )

                        ok_files.append({"enc": str(state.enc_final_path), "dec": str(state.dec_final_path)})
                        await send_json(ws, {
                            "type": "file_done",
                            "enc_path": str(state.enc_final_path),
                            "dec_path": str(state.dec_final_path),
                            "sha256": actual_sha,
                            "dedup": bool(is_dup),
                            "dedup_count": int(dup_count),
                        })

                    except subprocess.TimeoutExpired:
                        logger.error("%s | decrypt timeout after %ds", ctx, cfg.decrypt_timeout_sec)
                        failed_files.append(str(state.enc_final_path))
                        await send_json(ws, {"type": "error", "msg": "decrypt timeout"})
                    except subprocess.CalledProcessError as e:
                        logger.error("%s | decrypt failed (code=%s)", ctx, e.returncode)
                        failed_files.append(str(state.enc_final_path))
                        await send_json(ws, {"type": "error", "msg": "decrypt failed"})
                    except Exception as e:
                        logger.exception("%s | processing failed: %s", ctx, e)
                        failed_files.append(str(state.enc_final_path))
                        await send_json(ws, {"type": "error", "msg": "processing failed"})
                    finally:
                        state.reset()

                elif mtype == "end":
                    logger.info("%s | end ok=%d fail=%d", ctx_base, len(ok_files), len(failed_files))
                    await send_json(ws, {"type": "end_ack", "ok": len(ok_files), "failed": len(failed_files)})
                    break

                else:
                    logger.warning("%s | unknown control type=%r data=%r", ctx_base, mtype, data)
                    await send_json(ws, {"type": "error", "msg": "unknown message type"})

            # Binary message
            else:
                if state.f is None:
                    logger.warning("%s | binary received without file_start", ctx_base)
                    await send_json(ws, {"type": "error", "msg": "binary without file_start"})
                    continue

                state.received_bytes += len(msg)
                if state.received_bytes > cfg.max_file_bytes:
                    ctx = f"{ctx_base} device={state.device_id} file={state.filename_safe}"
                    logger.error("%s | file too large (%d > %d)", ctx, state.received_bytes, cfg.max_file_bytes)
                    await send_json(ws, {"type": "error", "msg": "file too large"})
                    try:
                        state.f.close()
                    except Exception:
                        pass
                    state.f = None
                    try:
                        if state.enc_tmp_path:
                            state.enc_tmp_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    state.reset()
                    continue

                state.hasher.update(msg)
                state.f.write(msg)

    except websockets.ConnectionClosed as cc:
        logger.info("%s | connection closed code=%s reason=%s", ctx_base, cc.code, cc.reason)
    except Exception as e:
        logger.exception("%s | unexpected error: %s", ctx_base, e)
    finally:
        if state.f:
            try:
                state.f.close()
            except Exception:
                pass
        if state.enc_tmp_path and state.enc_tmp_path.exists():
            try:
                state.enc_tmp_path.unlink()
            except Exception:
                pass

        logger.info("%s | summary ok=%d fail=%d", ctx_base, len(ok_files), len(failed_files))


# Config loading
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
    max_json_kb = _get_int(cp, "limits", "max_json_kb", MAX_TBYTES_KB_DEFAULT)
    idle_timeout_s = _get_int(cp, "limits", "idle_timeout_s", IDLE_TIMEOUT_SEC)
    ping_interval_s = _get_int(cp, "limits", "ping_interval_s", PING_INTERVAL)
    ping_timeout_s = _get_int(cp, "limits", "ping_timeout_s", PING_TIMEOUT)

    require_auth = _get_bool(cp, "auth", "require_auth", FILESEND_REQUIRE_AUTH)
    token_file_s = _get_str(cp, "auth", "token_file", FILESEND_TOKENS_JSON).strip()
    token_file = Path(token_file_s) if token_file_s else None

    enable_dedup = _get_bool(cp, "dedup", "enable", True)
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
        max_json_bytes=max_json_kb * 1024,
        idle_timeout_sec=idle_timeout_s,
        ping_interval=ping_interval_s,
        ping_timeout=ping_timeout_s,
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
    p = argparse.ArgumentParser(description="Secure WebSocket file receiver (CLI mode)")

    p.add_argument("--host", default=FILESEND_HOST_DEFAULT)
    p.add_argument("--port", type=int, default=FILESEND_PORT_DEFAULT)

    p.add_argument("--incoming-dir", default=FILESEND_INCOMING_DIR)
    p.add_argument("--decrypted-dir", default=FILESEND_DECRYPTED_DIR)

    p.add_argument("--require-auth", action="store_true", default=FILESEND_REQUIRE_AUTH)
    p.add_argument("--no-auth", dest="require_auth", action="store_false")
    p.add_argument("--token-file", default=FILESEND_TOKENS_JSON)

    p.add_argument("--max-file-mb", type=int, default=MAX_FBYTES_MB_DEFAULT)
    p.add_argument("--max-json-kb", type=int, default=MAX_TBYTES_KB_DEFAULT)
    p.add_argument("--idle-timeout", type=int, default=IDLE_TIMEOUT_SEC)
    p.add_argument("--ping-interval", type=int, default=PING_INTERVAL)
    p.add_argument("--ping-timeout", type=int, default=PING_TIMEOUT)

    p.add_argument("--filesend-bin", default=FILESEND_BIN_PATH)
    p.add_argument("--decrypt-timeout", type=int, default=DECRYPT_TIMEOUT_SEC)

    p.add_argument("--tls-cert", default=None)
    p.add_argument("--tls-key", default=None)

    p.add_argument("--dedup", action="store_true", default=True)
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
        require_auth=bool(args.require_auth),
        token_file=Path(args.token_file) if args.token_file else None,
        max_file_bytes=int(args.max_file_mb) * 1024 * 1024,
        max_json_bytes=int(args.max_json_kb) * 1024,
        idle_timeout_sec=int(args.idle_timeout),
        ping_interval=int(args.ping_interval),
        ping_timeout=int(args.ping_timeout),
        filesend_bin=Path(args.filesend_bin),
        decrypt_timeout_sec=int(args.decrypt_timeout),
        tls_cert=Path(args.tls_cert) if args.tls_cert else None,
        tls_key=Path(args.tls_key) if args.tls_key else None,
        enable_dedup=bool(args.dedup),
        dedup_db=Path(args.dedup_db),
        log_level=args.log_level,
        log_file=Path(args.log_file) if args.log_file else None,
    )

    validate_cfg(cfg)
    return cfg

def validate_cfg(cfg: ServerConfig) -> None:
    if not (0 < cfg.port < 65536):
        raise ValueError(f"Invalid port: {cfg.port}")

    if cfg.max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be > 0")
    if cfg.max_json_bytes <= 0:
        raise ValueError("max_json_bytes must be > 0")
    if cfg.decrypt_timeout_sec <= 0:
        raise ValueError("decrypt_timeout_sec must be > 0")

    if (cfg.tls_cert is None) ^ (cfg.tls_key is None):
        raise ValueError("TLS config invalid: both tls_cert and tls_key must be set, or neither")

    # If auth is enabled, token file should exist (warn later in logs, but not hard error)
    # If you want strict: uncomment
    # if cfg.require_auth and (not cfg.token_file or not cfg.token_file.exists()):
    #     raise ValueError("Auth enabled but token_file missing")

def load_config() -> ServerConfig:
    if len(sys.argv) == 1:
        # file config mode
        ini_path = Path(FILESEND_SERVER_CONFIG)
        return load_cfg_from_ini(ini_path)
    else:
        # CLI mode (skip argv[0])
        return parse_cfg_from_cli(sys.argv[1:])


# TLS
def build_ssl_context(cfg: ServerConfig) -> Optional[ssl.SSLContext]:
    if not cfg.tls_cert or not cfg.tls_key:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cfg.tls_cert), keyfile=str(cfg.tls_key))
    return context


# Main
async def main():
    cfg = load_config()
    logger = setup_logging(cfg)

    mkdir_secure(cfg.incoming_dir)
    mkdir_secure(cfg.decrypted_dir)

    tokens = load_tokens(cfg.token_file)
    if cfg.require_auth and not tokens:
        logger.warning("Auth is enabled but token file is missing/empty (%s). All devices will be rejected.", cfg.token_file)

    if cfg.enable_dedup:
        db_init(cfg.dedup_db)
        logger.info("Dedup DB ready at %s", cfg.dedup_db)

    ssl_context = build_ssl_context(cfg)
    scheme = "wss" if ssl_context else "ws"
    logger.info("Listening on %s://%s:%d", scheme, cfg.host, cfg.port)

    async def handler(ws):
        await handle_client(ws, cfg, logger, tokens)

    async with websockets.serve(
        handler,
        cfg.host,
        cfg.port,
        ssl=ssl_context,
        max_size=None,
        max_queue=32,
        ping_interval=cfg.ping_interval,
        ping_timeout=cfg.ping_timeout,
    ):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())

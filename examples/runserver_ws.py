import asyncio
import websockets
import json
import os
import subprocess
from datetime import datetime
import traceback
import stat
import shutil  # for copying non-encrypted files

INCOMING_DIR  = "incoming_ws"
DECRYPTED_DIR = "decrypted_ws"
os.makedirs(INCOMING_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

def log(*args):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}]", *args)


async def handle_client(ws):
    log("[WS] New connection")

    current_file = None
    current_enc_path = None
    current_device_id = "unknown"
    current_flags = 0  # bitfield coming from the client

    # Track per-connection results
    ok_files = []       # list of dicts: {"enc": ..., "dec": ...}
    failed_files = []   # list of enc paths (or filenames)

    def print_summary(tag="summary"):
        ok_count = len(ok_files)
        fail_count = len(failed_files)
        log(f"[WS] {tag}: {ok_count} files OK, {fail_count} files FAILED")
        if ok_files:
            log("[WS] Successfully received & processed files:")
            for f in ok_files:
                log(f"   OK  enc={f['enc']}  dec={f['dec']}")
        if failed_files:
            log("[WS] Files with errors (decrypt or other):")
            for enc in failed_files:
                log(f"   FAIL enc={enc}")

    try:
        async for msg in ws:
            try:
                # JSON control messages
                if isinstance(msg, str):
                    try:
                        data = json.loads(msg)
                    except json.JSONDecodeError:
                        log("[WS] Invalid JSON:", msg)
                        continue

                    msg_type = data.get("type")

                    if msg_type == "file":
                        filename = data.get("filename")
                        current_device_id = data.get("device_id", "unknown")

                        # flags field from client (bitfield)
                        flags_val = data.get("flags", 0)
                        try:
                            current_flags = int(flags_val)
                        except (TypeError, ValueError):
                            current_flags = 0

                        sha = data.get("SHA256", "")

                        if sha == "":
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "no checksum"
                            }))
                            continue

                        if not filename:
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "no filename"
                            }))
                            continue

                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        enc_name = f"{current_device_id}_{timestamp}_{filename}"
                        current_enc_path = os.path.join(INCOMING_DIR, enc_name)

                        log(f"[WS] Starting new file: {current_enc_path} (flags={current_flags})")
                        current_file = open(current_enc_path, "wb")

                    elif msg_type == "file_end":
                        if current_file is None:
                            log("[WS] file_end but no open file")
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "no open file on file_end"
                            }))
                            # mark as failed if we at least know enc path
                            if current_enc_path:
                                failed_files.append(current_enc_path)
                            continue

                        current_file.close()
                        current_file = None
                        log(f"[WS] Closed file {current_enc_path}")

                        # make incoming file read-only
                        os.chmod(current_enc_path, stat.S_IREAD)  # 0o400

                        base_name = os.path.basename(current_enc_path)
                        dec_path = os.path.join(DECRYPTED_DIR, base_name)

                        # decode flags:
                        # bit 0 -> encryption enabled
                        # bit 1 -> symmetric (else asymmetric)
                        # bit 2 -> --all
                        enc_enabled   = bool(current_flags & 0b001)
                        enc_symmetric = bool(current_flags & 0b010)
                        enc_all       = bool(current_flags & 0b100)

                        try:
                            if sha is not None:
                                try:
                                    cmd = [
                                        "bin/./filesend",
                                        "verify",
                                        current_enc_path,
                                        sha
                                    ]
                                    subprocess.check_call(cmd)
                                except subprocess.CalledProcessError as e:
                                    log(f"[WS] CHECKSUM MISMATCH for {dec_path}")
                                    failed_files.append(current_enc_path)
                                    await ws.send(json.dumps({
                                        "type": "error",
                                        "msg": "checksum mismatch"
                                    }))
                            if not enc_enabled:
                                # no encryption on this file: just copy it as "decrypted"
                                shutil.copy2(current_enc_path, dec_path)
                                log(f"[WS] No encryption, copied to: {dec_path}")
                            else:
                                # build decrypt command depending on flags
                                cmd = [
                                    "bin/./filesend",
                                    "decrypt",
                                    current_enc_path,
                                ]
                                if enc_symmetric:
                                    cmd.append("--symmetric")
                                else:
                                    cmd.append("--asymmetric")
                                if enc_all:
                                    cmd.append("--all")
                                cmd.extend(["--dest", dec_path])

                                subprocess.check_call(cmd)
                                log(f"[WS] Decrypted to: {dec_path}")

                            ok_files.append({
                                "enc": current_enc_path,
                                "dec": dec_path,
                            })
                            await ws.send(json.dumps({
                                "type": "file_done",
                                "enc_path": current_enc_path,
                                "dec_path": dec_path,
                            }))
                        except subprocess.CalledProcessError as e:
                            log(f"[WS] Decrypt failed:", e)
                            failed_files.append(current_enc_path)
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "decrypt failed"
                            }))
                        except Exception as e:
                            log(f"[WS] Processing failed:", e)
                            traceback.print_exc()
                            failed_files.append(current_enc_path)
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "processing failed"
                            }))

                    elif msg_type == "end":
                        log(f"[WS] End signal from device {current_device_id}")
                        print_summary("final summary (on end)")
                        await ws.send(json.dumps({"type": "end_ack"}))
                        break

                    else:
                        log("[WS] Unknown message type:", data)

                # file content (binary)
                else:
                    if current_file is None:
                        log("[WS] Binary received but no file open")
                        continue
                    current_file.write(msg)

            except Exception as e:
                log("[WS] Exception while handling message:", e)
                traceback.print_exc()
                if current_enc_path:
                    failed_files.append(current_enc_path)
                await ws.send(json.dumps({
                    "type": "error",
                    "msg": "internal server error"
                }))
                # you can break here if you want to close on error
                # break

    except websockets.ConnectionClosed as cc:
        log(f"[WS] ConnectionClosed: code={cc.code}, reason={cc.reason}")

    finally:
        if current_file:
            current_file.close()
        # If we didn’t get an explicit "end", still show what we got so far
        print_summary("summary (on close)")
        log("[WS] Handler finished")

async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 8444):
        log("[WS] WebSocket server listening on ws://0.0.0.0:8444/ws")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())

import asyncio
import websockets
import json
import os
import subprocess
from datetime import datetime
import traceback

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

                        if not filename:
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "no filename"
                            }))
                            continue

                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        enc_name = f"{current_device_id}_{timestamp}_{filename}"
                        current_enc_path = os.path.join(INCOMING_DIR, enc_name)

                        log(f"[WS] Starting new file: {current_enc_path}")
                        current_file = open(current_enc_path, "wb")

                    elif msg_type == "file_end":
                        if current_file is None:
                            log("[WS] file_end but no open file")
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "no open file on file_end"
                            }))
                            continue

                        current_file.close()
                        current_file = None
                        log(f"[WS] Closed file {current_enc_path}")

                        base_name = os.path.basename(current_enc_path)
                        dec_path = os.path.join(DECRYPTED_DIR, base_name)

                        try:
                            subprocess.check_call([
                                "bin/./filesend",
                                "decrypt",
                                current_enc_path,
                                "--asymmetric",
                                "--all",
                                "--dest",
                                dec_path,
                            ])
                            log(f"[WS] Decrypted to: {dec_path}")
                            await ws.send(json.dumps({
                                "type": "file_done",
                                "enc_path": current_enc_path,
                                "dec_path": dec_path,
                            }))
                        except subprocess.CalledProcessError as e:
                            log(f"[WS] Decrypt failed:", e)
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "decrypt failed"
                            }))

                    elif msg_type == "end":
                        log(f"[WS] End signal from device {current_device_id}")
                        await ws.send(json.dumps({"type": "end_ack"}))
                        break

                    else:
                        log("[WS] Unknown message type:", data)

                # file content
                else:
                    if current_file is None:
                        log("[WS] Binary received but no file open")
                        continue
                    current_file.write(msg)

            except Exception as e:
                log("[WS] Exception while handling message:", e)
                traceback.print_exc()
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
        log("[WS] Handler finished")

async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 8444):
        log("[WS] WebSocket server listening on ws://0.0.0.0:8444/ws")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
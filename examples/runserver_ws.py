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

async def handle_client(ws):
    print("[WS] New connection")
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
                        print("[WS] Invalid JSON:", msg)
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

                        print(f"[WS] Starting new file: {current_enc_path}")
                        current_file = open(current_enc_path, "wb")

                    elif msg_type == "file_end":
                        if current_file is None:
                            print("[WS] file_end but no open file")
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "no open file on file_end"
                            }))
                            continue

                        current_file.close()
                        current_file = None
                        print(f"[WS] Closed file {current_enc_path}")

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
                            print(f"[WS] Decrypted to: {dec_path}")
                            await ws.send(json.dumps({
                                "type": "file_done",
                                "enc_path": current_enc_path,
                                "dec_path": dec_path,
                            }))
                        except subprocess.CalledProcessError as e:
                            print(f"[WS] Decrypt failed: {e}")
                            await ws.send(json.dumps({
                                "type": "error",
                                "msg": "decrypt failed"
                            }))

                    elif msg_type == "end":
                        print(f"[WS] End signal from device {current_device_id}")
                        await ws.send(json.dumps({"type": "end_ack"}))
                        break

                    else:
                        print("[WS] Unknown message type:", data)

                # file content
                else:
                    if current_file is None:
                        print("[WS] Got binary data with no open file")
                        continue
                    current_file.write(msg)

            except Exception as e:
                print("[WS] Exception while handling message:", e)
                traceback.print_exc()
                await ws.send(json.dumps({
                    "type": "error",
                    "msg": "internal server error"
                }))
                # you can break here if you want to close on error
                # break

    except websockets.ConnectionClosed as cc:
        print(f"[WS] ConnectionClosed: code={cc.code}, reason={cc.reason}")

    finally:
        if current_file:
            current_file.close()
        print("[WS] Handler finished")

async def main():
    async with websockets.serve(handle_client, "0.0.0.0", 8444):
        print("[WS] WebSocket server listening on ws://0.0.0.0:8444/ws")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())

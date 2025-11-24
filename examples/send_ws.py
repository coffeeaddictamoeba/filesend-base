# ws_send.py
import asyncio
import websockets
import json
import os
import sys

# temporary logic for websocket sending on device side

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

async def send_files(ws_url, device_id, file_paths):
    async with websockets.connect(ws_url) as ws:
        for path in file_paths:
            filename = os.path.basename(path)

            # send header
            header = {
                "type": "file",
                "filename": filename,
                "device_id": device_id,
            }
            await ws.send(json.dumps(header))
            print(f"[WS-CLIENT] Sent header for {filename}")

            # send binary data
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(64 * 1024)
                    if not chunk:
                        break
                    await ws.send(chunk)

            # send file_end
            await ws.send(json.dumps({"type": "file_end"}))
            print(f"[WS-CLIENT] Sent file_end for {filename}")

            reply = await ws.recv()
            print("[WS-CLIENT] Reply:", reply)

        # end signal
        await ws.send(json.dumps({"type": "end"}))
        print("[WS-CLIENT] Sent end signal")

        try:
            reply = await ws.recv()
            print("[WS-CLIENT] Reply:", reply)
        except websockets.ConnectionClosed:
            pass

def main():
    if len(sys.argv) < 3:
        print("Usage: ws_send.py <ws_url> <file1> [file2 ...]")
        sys.exit(1)

    ws_url = sys.argv[1]  # for example ws://Test:8444/ws
    files = sys.argv[2:]
    device_id = "pi"

    asyncio.run(send_files(ws_url, device_id, files))

if __name__ == "__main__":
    main()

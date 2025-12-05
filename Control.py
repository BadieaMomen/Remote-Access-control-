import cv2
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
import threading
import socket
import json
import base64
import time
from datetime import datetime
import os,sys
os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))
os.mkdir("Result")
os.chdir("Result")
# ---------------- Config / filenames ----------------
LOG_FILENAME = "logfile.log"
RECV_IMAGE = ".png"
RECV_AUDIO = ".wav"
devices=[]

# ---------------- Utility functions ----------------
def timestamp():
    """Return ISO-like timestamp for logs."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def append_log_to_file(line):
    """Append a log line to disk file for offline inspection."""
    with open(LOG_FILENAME, "a", encoding="utf-8") as f:
        f.write(line + "\n")

class NetSimulatorApp:
    def __init__(self, root):

        self.root = root
        self.sock = None
        self.connected = False

        self.root.title("Remote Control ")
        self.root.geometry("920x560")
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        style = ttk.Style(root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background="#1c1c1e")
        style.configure("TLabel", background="#1c1c1e", foreground="#e9e9e9")
        style.configure("TButton", background="#2e2e2f", foreground="#e9e9e9")
        style.map("TButton", background=[('active', '#3a3a3c')])

        # Left sidebar frame
        sidebar = ttk.Frame(root, width=260, padding=(10,10))
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)

        # Host / Port entry controls
        ttk.Label(sidebar, text="Server Host:").pack(anchor="w")
        self.host_var = tk.StringVar(value="0.0.0.0")
        ttk.Entry(sidebar, textvariable=self.host_var).pack(fill="x", pady=2)

        ttk.Label(sidebar, text="Server Port:").pack(anchor="w", pady=(6,0))
        self.port_var = tk.IntVar(value=5001)
        ttk.Entry(sidebar, textvariable=self.port_var).pack(fill="x", pady=2)

        # Connect / Disconnect buttons
        btn_frame = ttk.Frame(sidebar)
        btn_frame.pack(fill="x", pady=(8,4))
        self.connect_btn = ttk.Button(btn_frame, text="Connect", command=self.on_connect)
        self.connect_btn.pack(side="left", expand=True, fill="x", padx=(0,4))
        self.disconnect_btn = ttk.Button(btn_frame, text="Disconnect", command=self.on_disconnect)
        self.disconnect_btn.pack(side="left", expand=True, fill="x")

        # Small note/warning (educational)
        note = ttk.Label(sidebar, text="Note: Connect only to a test server you control.", font=("Segoe UI", 8))
        note.pack(anchor="w", pady=(8,4))
        # Buttons to send simulated commands
        ttk.Label(sidebar, text="Simulated Commands:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(6,4))
        ttk.Button(sidebar, text="Open PowerShell Console", command=self.cmd_powershell).pack(fill="x", pady=3)
        ttk.Button(sidebar, text="Share file", command=self.cmd_powershell).pack(fill="x", pady=3)
        ttk.Button(sidebar, text="Encrypt Data", command=self.cmd_powershell).pack(fill="x", pady=3)
        ttk.Button(sidebar, text="Decrypt Data", command=self.cmd_powershell).pack(fill="x", pady=3)
        ttk.Button(sidebar, text="Request Screenshot", command=self.cmd_screenshot).pack(fill="x", pady=3)
        ttk.Button(sidebar, text="Request Record Audio (1s)", command=self.cmd_record_audio).pack(fill="x", pady=3)
        ttk.Button(sidebar, text="Request Live Stream", command=self.cmd_live_stream).pack(fill="x", pady=3)

        # Separator and save log
        ttk.Separator(sidebar, orient="horizontal").pack(fill="x", pady=8)
        ttk.Button(sidebar, text="Save Log Snapshot", command=self.save_log).pack(fill="x", pady=4)

        # Main area (logs)
        main = ttk.Frame(root, padding=(10,10))
        main.grid(row=0, column=1, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=1)

        # Header label
        ttk.Label(main, text="Activity & Response Log", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w")

        # ScrolledText widget to show logs
        self.log_box = ScrolledText(main, wrap="word", background="#0b0b0c", foreground="#dcdcdc", insertbackground="#ffffff")
        self.log_box.grid(row=1, column=0, sticky="nsew", pady=(8,0))
        self.log_box.configure(state="disabled")  # read-only

        # Status bar
        status_frame = ttk.Frame(main)
        status_frame.grid(row=2, column=0, sticky="ew", pady=(8,0))
        status_frame.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Disconnected")
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=0, sticky="w")

        self.on_connect()

    def log(self, text):
        """Append a line to the GUI log and persistent file."""
        line = f"[{timestamp()}] {text}"

        self.root.after(0, self._insert_log, line + "\n")
        # append to file
        append_log_to_file(line)

    def _insert_log(self, text):
        """Insert into the ScrolledText widget on the main thread."""
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")
    
        # ---------- Network primitives ----------

    def on_connect(self):
        """Triggered when Connect button is pressed."""
        if self.connected:
            self.log("Already connected.")
            return
        host = self.host_var.get()
        port = int(self.port_var.get())
        
        threading.Thread(target=self._connect_thread, args=(host, port), daemon=True).start()

    def _connect_thread(self, host, port):
        """Background thread to create and manage socket connection."""
        try:
            # Create TCP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # s.settimeout(5)  # 5 second connect timeout
            s.bind((host, port))  # attempt connection
            self.status_var.set(f"listing on {host}:{port}")
            self.log(f"listing on {host}:{port}")
            s.listen()
            soc, add = s.accept()
            self.sock = soc
            self.connected = True
            self.log(f"connection with  {add[0]}:{add[1]}")

            # Start a small listener thread to process incoming messages (if any)
            threading.Thread(target=self._listen_loop, daemon=True).start()
        except Exception as e:
            self.log(f"Connection failed: {e}")
            self.status_var.set("Disconnected")

    def on_disconnect(self):
        """User-requested disconnect."""
        if not self.connected:
            self.log("Not connected.")
            return
        try:
            self.sock.close()
        except Exception:
            pass
        self.sock = None
        self.connected = False
        self.status_var.set("Disconnected")
        self.log("Disconnected from server.")
    def _listen_loop(self):
        try:
            while self.connected:
                # Read 4-byte length prefix (for JSON response)
                hdr = self._recv_all(4)
                if not hdr:
                    break
                length = int.from_bytes(hdr, 'big')
                data = self._recv_all(length)
                if not data:
                    break

                # Parse JSON response
                try:
                    resp = json.loads(data.decode('utf-8'))
                except Exception:
                    self.log("Received non-JSON response or parsing error.")
                    continue

                # Handle response types
                cmd = resp.get("command")
                status = resp.get("status")
                self.log(f"Response for {cmd}: status={status}, keys={list(resp.keys())}")
                if cmd == "powershell" and "output" in resp:
                    out = resp["output"]
                    self.log(f"PowerShell Output:\n{out}")
                if cmd == "encryption"  and "output"  in resp:
                    out = resp["output"]
                    self.log(f"encryption Output:\n{out}")
                if cmd == "sharefile"  and "output" in resp:
                    out = resp["output"]
                    self.log(f"sharefile Output:\n{out}")
                if cmd == "decryption" and "output" in resp:
                    out = resp["output"]
                    self.log(f"decryption Output:\n{out}")

                # If it contained base64 image data, save it
                if "data_base64" in resp:
                    try:
                        b = base64.b64decode(resp["data_base64"])
                        Amg=f"{timestamp()}{RECV_IMAGE}"
                        with open(Amg, "wb") as f:
                            f.write(b)
                        self.log(f"Saved received image as {Amg}")
                    except Exception as e:
                        self.log(f"Error saving image: {e}")

                # If it contained base64 audio data, save it
                if "audio_base64" in resp:
                    try:
                        b = base64.b64decode(resp["audio_base64"])
                        Sound=f"{timestamp}.{RECV_AUDIO}"
                        with open(Sound, "wb") as f:
                            f.write(b)
                        self.log(f"Saved received audio as {Sound}")
                    except Exception as e:
                        self.log(f"Error saving audio: {e}")

                # Special handling for live_screen stream
                if cmd == "live_screen" and resp.get("note"):
                    import cv2, numpy as np

                    self.log("Receiving live stream frames...")

                    video_fname = f"live_stream_{int(time.time())}.mp4"
                    video_writer = None  # initialized on first frame

                    try:
                        while True:
                            try:
                                # Read frame header (4-byte length)
                                hdr2 = self._recv_all(4, timeout=2.0)
                                if not hdr2:
                                    break
                                frame_len = int.from_bytes(hdr2, 'big')
                                frame = self._recv_all(frame_len)
                                if not frame:
                                    break

                                # Decode JPEG -> numpy array -> OpenCV image
                                arr = np.frombuffer(frame, dtype=np.uint8)
                                img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                                if img is None:
                                    self.log("Warning: failed to decode frame; skipping.")
                                    continue

                                # Initialize writer once we know frame size
                                if video_writer is None:
                                    h, w = img.shape[:2]
                                    fourcc = cv2.VideoWriter_fourcc(*'mp4v')  # codec for mp4
                                    fps = 10.0  # adjust based on your stream rate
                                    video_writer = cv2.VideoWriter(video_fname, fourcc, fps, (w, h))
                                    if not video_writer.isOpened():
                                        self.log(f"Error: cannot open video file {video_fname}")
                                        video_writer = None
                                    else:
                                        self.log(f"Started writing video: {video_fname}")

                                # Write frame into video file
                                if video_writer is not None:
                                    video_writer.write(img)

                            except TimeoutError:
                                # likely no more frames
                                break
                            except Exception as e:
                                self.log(f"Error receiving frame: {e}")
                                break

                        self.log("Finished receiving live stream.")

                    finally:
                        # release writer so file is finalized
                        if video_writer is not None:
                            video_writer.release()
                            self.log(f"Saved combined video: {video_fname}")

        except Exception as e:
            self.log(f"Listener error: {e}")
        finally:
            # Clean up connection state
            try:
                if self.sock:
                    self.sock.close()
            except Exception:
                pass
            self.sock = None
            self.connected = False
            self.status_var.set("Disconnected")
            self.log("Connection closed by listener.")


    def _recv_all(self, n, timeout=None):
        """
        Helper to receive exactly n bytes, or None on EOF.
        If timeout is set, raises TimeoutError when recv blocks longer than timeout.
        """
        data = b''
        if timeout is not None:
            # Set temporary timeout on socket

            self.sock.settimeout(timeout)
        try:
            while len(data) < n:
                chunk = self.sock.recv(n - len(data))
                if not chunk:
                    return None
                data += chunk
        except socket.timeout:
            raise TimeoutError("recv timed out")
        finally:
            if timeout is not None:
                # remove timeout
                self.sock.settimeout(None)
        return data

    # ---------- Command senders ----------
    def send_json_command(self, obj):
        """Send a JSON object with 4-byte length prefix. Non-blocking wrapper."""
        if not self.connected or not self.sock:
            self.log("Not connected; cannot send command.")
            return
        try:
            b = json.dumps(obj).encode('utf-8')
            # Send length prefix then payload
            self.sock.send(len(b).to_bytes(4, 'big'))
            self.sock.send(b)
            self.log(f"Sent command: {obj.get('command')}")
        except Exception as e:
            self.log(f"Send failed: {e}")
    def cmd_powershell(self):
        """Open a simple interactive PowerShell command box."""
        win = tk.Toplevel(self.root)
        win.title("Remote PowerShell")
        win.geometry("700x400")

        ttk.Label(win, text="Enter PowerShell command:").pack(anchor="w", padx=10, pady=5)
        entry = ttk.Entry(win)
        entry.pack(fill="x", padx=10)

        output_box = ScrolledText(win, wrap="word", height=15, background="#0b0b0c", foreground="#dcdcdc")
        output_box.pack(fill="both", expand=True, padx=10, pady=10)
        output_box.configure(state="disabled")

        def send_cmd():
            cmd = entry.get().strip()
            if not cmd:
                return
            entry.delete(0, "end")
            self.send_json_command({"command": "powershell", "cmd": cmd})

        ttk.Button(win, text="Send Command", command=send_cmd).pack(pady=5)

    def EncryptData(self):
        pass
    def DecryptData(self):
        pass
    def shareFile(self):
        pass

    def cmd_screenshot(self):
        """User clicked Request Screenshot: send JSON to server."""
        self.send_json_command({"command": "screenshot"})

    def cmd_record_audio(self):
        """Request a 1-second audio recording from server."""
        self.send_json_command({"command": "record_audio", "duration": 5})

    def cmd_live_stream(self):
        """Request server to start streaming frames (safe simulation)."""
        self.send_json_command({"command": "live_screen", "duration": 5})
    # def gettingpowershell(self):
    #     """Request server to start streaming frames (safe simulation)."""
    #     self.send_json_command({"command": "gettingpowershell"})
    # ---------- Misc ----------
    def save_log(self):
        """Save a snapshot of current GUI log to a timestamped file."""
        content = self.log_box.get("1.0", "end").strip()
        if not content:
            self.log("Log is empty; nothing to save.")
            return
        name = f"log_snapshot_{int(time.time())}.txt"
        with open(name, "w", encoding="utf-8") as f:
            f.write(content)
        self.log(f"Saved log snapshot: {name}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetSimulatorApp(root)
    # Write initial log line
    app.log("GUI started.")
    root.mainloop()
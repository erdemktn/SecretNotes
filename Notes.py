import tkinter as tk
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_encrypt_maker():
        
        title = title_entry.get()
        text = secret_text.get("1.0",tk.END)
        secret = master_entry.get()

        if len(title) == 0 or len(text) == 0 or len(secret) == 0:
            messagebox.showinfo(title="Error!", message="Please enter all information.")
        else:
            message_encrypted = encode(secret, text)

        try:
            with open("Not.txt", "a") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        except FileNotFoundError:
            with open("Not.txt", "w") as data_file:
                data_file.write(f'\n{title}\n{message_encrypted}')
        finally:
            title_entry.delete(0, tk.END)
            master_entry.delete(0, tk.END)
            secret_text.delete("1.0",tk.END)
    
         
def decrypt_maker():
    message_encrypted = secret_text.get("1.0", tk.END)
    secret = master_entry.get()

    if len(message_encrypted) == 0 or len(secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all information.")
    else:
        try:
            decrypted_message = decode(secret,message_encrypted)
            secret_text.delete("1.0", tk.END)
            secret_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please make sure of encrypted info.")


win = tk.Tk()
win.geometry("350x550")
FONT=("Calibri",15,"bold")

#PNG EDITOR
img = tk.PhotoImage(file="topsecret.png")
img_label = tk.Label(image=img)
img_label.pack()

#TİTLE EDITOR
title_label = tk.Label(text="Enter your Title",font=FONT)
title_label.pack()
title_entry = tk.Entry(width=35)
title_entry.pack(pady=3)

#SECRET EDITOR
secret_label = tk.Label(text="Enter your Secret",font=FONT)
secret_label.pack()
secret_text = tk.Text(width=40,height=10)
secret_text.pack()

#MASTERKEY EDITOR
master_label = tk.Label(text="Enter Master Key",font=FONT)
master_label.pack()
master_entry = tk.Entry(width=35)
master_entry.pack()

#SAVE AND ENCRYPT EDITOR
save_encrypt_button = tk.Button(text="Save & Encrypt",font=("Calibri",11,"bold"),command=save_encrypt_maker)
save_encrypt_button.pack(pady=5)

#DECRYPT EDITOR
decrypt_button = tk.Button(text="Decrypt",font=("Calibri",11,"bold"),command=decrypt_maker)
decrypt_button.pack()

win.mainloop()
# from Crypto.Cipher import DES
# from Crypto.Util.Padding import pad, unpad
# import os

# # Predefined 64-bit key for DES (8 bytes = 64 bits)
# key = b'8bytekey'

# # Function to apply DES in ECB mode
# def des_ecb_encrypt(plaintext):
#     # Initialize DES cipher in ECB mode
#     des = DES.new(key, DES.MODE_ECB)
#     # Pad the plaintext to be a multiple of 8 bytes (64 bits)
#     padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
#     # Encrypt the plaintext
#     ciphertext = des.encrypt(padded_text)
#     return ciphertext

# def des_ecb_decrypt(ciphertext):
#     # Initialize DES cipher in ECB mode
#     des = DES.new(key, DES.MODE_ECB)
#     # Decrypt the ciphertext
#     decrypted_padded_text = des.decrypt(ciphertext)
#     # Unpad the plaintext
#     plaintext = unpad(decrypted_padded_text, DES.block_size)
#     return plaintext.decode('utf-8')

# # Function to apply DES in CBC mode
# def des_cbc_encrypt(plaintext):
#     # Generate a random 64-bit IV (8 bytes)
#     iv = os.urandom(8)
#     # Initialize DES cipher in CBC mode
#     des = DES.new(key, DES.MODE_CBC, iv)
#     # Pad the plaintext to be a multiple of 8 bytes (64 bits)
#     padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
#     # Encrypt the plaintext
#     ciphertext = des.encrypt(padded_text)
#     return iv + ciphertext  # Prepend IV to the ciphertext for decryption

# def des_cbc_decrypt(ciphertext):
#     # Extract the IV from the ciphertext
#     iv = ciphertext[:8]
#     ciphertext = ciphertext[8:]
#     # Initialize DES cipher in CBC mode with the extracted IV
#     des = DES.new(key, DES.MODE_CBC, iv)
#     # Decrypt the ciphertext
#     decrypted_padded_text = des.decrypt(ciphertext)
#     # Unpad the plaintext
#     plaintext = unpad(decrypted_padded_text, DES.block_size)
#     return plaintext.decode('utf-8')

# # Testing the implementation
# if __name__ == "__main__":
#     message = "This is a test message for DES"

#     # Encrypt and decrypt using ECB mode
#     print("---- ECB Mode ----")
#     ecb_ciphertext = des_ecb_encrypt(message)
#     print(f"Ciphertext (ECB): {ecb_ciphertext}")
#     ecb_decrypted = des_ecb_decrypt(ecb_ciphertext)
#     print(f"Decrypted message (ECB): {ecb_decrypted}\n")

#     # Encrypt and decrypt using CBC mode
#     print("---- CBC Mode ----")
#     cbc_ciphertext = des_cbc_encrypt(message)
#     print(f"Ciphertext (CBC): {cbc_ciphertext}")
#     cbc_decrypted = des_cbc_decrypt(cbc_ciphertext)
#     print(f"Decrypted message (CBC): {cbc_decrypted}")
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import os

# Default key (8 bytes = 64 bits)
key = b'8bytekey'

# Functions for encryption and decryption
def des_ecb_encrypt(plaintext, key):
    des = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = des.encrypt(padded_text)
    return ciphertext

def des_ecb_decrypt(ciphertext, key):
    des = DES.new(key, DES.MODE_ECB)
    decrypted_padded_text = des.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded_text, DES.block_size)
    return plaintext.decode('utf-8')

def des_cbc_encrypt(plaintext, key):
    iv = os.urandom(8)
    des = DES.new(key, DES.MODE_CBC, iv)
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = des.encrypt(padded_text)
    return iv + ciphertext

def des_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:8]
    ciphertext = ciphertext[8:]
    des = DES.new(key, DES.MODE_CBC, iv)
    decrypted_padded_text = des.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded_text, DES.block_size)
    return plaintext.decode('utf-8')

# Create the main window
root = tk.Tk()
root.title("DES Encryption/Decryption")
root.geometry("500x550")  # Increase window height to accommodate extra field

# Variables for user inputs
plaintext = tk.StringVar()
ciphertext = tk.StringVar()
decrypted_text = tk.StringVar()  # Variable to store the decrypted plaintext
key_input = tk.StringVar(value="8bytekey")
mode = tk.StringVar(value="ECB")

# Functions for the buttons
def encrypt_message():
    pt = plaintext.get()
    k = key_input.get().encode('utf-8')
    if len(k) != 8:
        messagebox.showerror("Error", "Key must be exactly 8 characters long.")
        return
    if mode.get() == "ECB":
        ct = des_ecb_encrypt(pt, k)
    else:
        ct = des_cbc_encrypt(pt, k)
    if ct:
        ciphertext.set(ct.hex())

def decrypt_message():
    ct_hex = ciphertext.get()
    k = key_input.get().encode('utf-8')
    if len(k) != 8:
        messagebox.showerror("Error", "Key must be exactly 8 characters long.")
        return
    try:
        ct = bytes.fromhex(ct_hex)
        if mode.get() == "ECB":
            pt = des_ecb_decrypt(ct, k)
        else:
            pt = des_cbc_decrypt(ct, k)
        decrypted_text.set(pt)  # Display decrypted text in the GUI
    except ValueError:
        messagebox.showerror("Error", "Ciphertext must be valid hexadecimal.")
        decrypted_text.set("")  # Clear the decrypted text field if decryption fails
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        decrypted_text.set("")  # Clear the decrypted text field if decryption fails

# Layout of the elements in the window
title_label = tk.Label(root, text="DES Encryption/Decryption", font=("Arial", 16))
title_label.pack(pady=10)

plaintext_label = tk.Label(root, text="Plaintext:")
plaintext_label.pack()
plaintext_entry = tk.Entry(root, textvariable=plaintext, width=60)
plaintext_entry.pack(pady=5)

key_label = tk.Label(root, text="Key (8 characters):")
key_label.pack()
key_entry = tk.Entry(root, textvariable=key_input, width=20)
key_entry.pack(pady=5)

mode_label = tk.Label(root, text="Encryption Mode:")
mode_label.pack()
mode_frame = tk.Frame(root)
mode_frame.pack()
ecb_radio = tk.Radiobutton(mode_frame, text="ECB", variable=mode, value="ECB")
ecb_radio.pack(side=tk.LEFT, padx=10)
cbc_radio = tk.Radiobutton(mode_frame, text="CBC", variable=mode, value="CBC")
cbc_radio.pack(side=tk.LEFT, padx=10)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)
encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt_message)
encrypt_button.pack(side=tk.LEFT, padx=10)
decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_message)
decrypt_button.pack(side=tk.LEFT, padx=10)

ciphertext_label = tk.Label(root, text="Ciphertext (Hexadecimal):")
ciphertext_label.pack()
ciphertext_entry = tk.Entry(root, textvariable=ciphertext, width=60)
ciphertext_entry.pack(pady=5)

decrypted_text_label = tk.Label(root, text="Decrypted Plaintext:")
decrypted_text_label.pack()
decrypted_text_entry = tk.Entry(root, textvariable=decrypted_text, width=60, state='readonly')
decrypted_text_entry.pack(pady=5)

key_info_label = tk.Label(root, text="Key must be exactly 8 characters (64 bits).", fg="red")
key_info_label.pack(pady=5)

# Start the main loop to run the GUI
root.mainloop()

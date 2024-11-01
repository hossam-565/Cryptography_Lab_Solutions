import tkinter as tk
from tkinter import messagebox
import random
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Function to select larger common parameters (p and g) for better security
def select_parameters():
    # Using larger values for demonstration of security
    p = 7919  # Larger prime number for security
    g = 5     # Base
    return p, g

# Function to generate a private key for each user
def generate_private_key():
    return random.randint(1000, 5000)  # Generate a random private key in a larger range

# Function to compute the public value based on the private key
def compute_public_value(private_key, g, p):
    return pow(g, private_key, p)

# Function to compute the shared secret key
def compute_shared_secret(public_value, private_key, p):
    return pow(public_value, private_key, p)

# Function to perform DES encryption with the shared key
def des_encrypt(shared_key, plaintext):
    # Convert shared key to 8-byte format for DES
    des_key = shared_key.to_bytes(8, byteorder='big')
    des = DES.new(des_key, DES.MODE_ECB)
    padded_text = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = des.encrypt(padded_text)
    return ciphertext.hex()

# Function to perform DES decryption with the shared key
def des_decrypt(shared_key, ciphertext_hex):
    des_key = shared_key.to_bytes(8, byteorder='big')
    des = DES.new(des_key, DES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    decrypted_padded_text = des.decrypt(ciphertext)
    plaintext = unpad(decrypted_padded_text, DES.block_size)
    return plaintext.decode('utf-8')

# GUI Code
root = tk.Tk()
root.title("Diffie-Hellman Key Exchange and DES Encryption")
root.geometry("650x670")

# Variables
p_var = tk.StringVar()
g_var = tk.StringVar()
alice_private_var = tk.StringVar()
bob_private_var = tk.StringVar()
alice_public_var = tk.StringVar()
bob_public_var = tk.StringVar()
shared_key_var = tk.StringVar()
plaintext_var = tk.StringVar()
ciphertext_var = tk.StringVar()
decrypted_text_var = tk.StringVar()

# Function to run Diffie-Hellman Key Exchange
def run_diffie_hellman():
    # Step 1: Select common parameters
    p, g = select_parameters()
    p_var.set(p)
    g_var.set(g)
    
    # Step 2: Generate private keys
    alice_private_key = generate_private_key()
    bob_private_key = generate_private_key()
    alice_private_var.set(alice_private_key)
    bob_private_var.set(bob_private_key)
    
    # Step 3: Compute public values
    alice_public_value = compute_public_value(alice_private_key, g, p)
    bob_public_value = compute_public_value(bob_private_key, g, p)
    alice_public_var.set(alice_public_value)
    bob_public_var.set(bob_public_value)
    
    # Step 4: Compute shared secret key
    shared_key_alice = compute_shared_secret(bob_public_value, alice_private_key, p)
    shared_key_bob = compute_shared_secret(alice_public_value, bob_private_key, p)
    
    # Verify that both shared keys are the same
    if shared_key_alice == shared_key_bob:
        shared_key_var.set(shared_key_alice)
        messagebox.showinfo("Success", "Shared secret key established!")
    else:
        messagebox.showerror("Error", "Failed to establish a shared secret key.")

# Function to encrypt the message
def encrypt_message():
    shared_key = int(shared_key_var.get())
    plaintext = plaintext_var.get()
    if not plaintext:
        messagebox.showerror("Error", "Please enter a message to encrypt.")
        return
    ciphertext = des_encrypt(shared_key, plaintext)
    ciphertext_var.set(ciphertext)

# Function to decrypt the message
def decrypt_message():
    shared_key = int(shared_key_var.get())
    ciphertext_hex = ciphertext_var.get()
    if not ciphertext_hex:
        messagebox.showerror("Error", "No ciphertext to decrypt.")
        return
    decrypted_text = des_decrypt(shared_key, ciphertext_hex)
    decrypted_text_var.set(decrypted_text)

# GUI Layout
tk.Label(root, text="Diffie-Hellman Key Exchange Parameters", font=("Arial", 14)).pack(pady=10)

param_frame = tk.Frame(root)
param_frame.pack()
tk.Label(param_frame, text="Prime (p):").grid(row=0, column=0, padx=5, pady=5)
tk.Entry(param_frame, textvariable=p_var, state='readonly').grid(row=0, column=1, padx=5, pady=5)
tk.Label(param_frame, text="Base (g):").grid(row=0, column=2, padx=5, pady=5)
tk.Entry(param_frame, textvariable=g_var, state='readonly').grid(row=0, column=3, padx=5, pady=5)

tk.Label(root, text="Alice's Private Key:").pack()
tk.Entry(root, textvariable=alice_private_var, state='readonly').pack()

tk.Label(root, text="Bob's Private Key:").pack()
tk.Entry(root, textvariable=bob_private_var, state='readonly').pack()

tk.Label(root, text="Alice's Public Value:").pack()
tk.Entry(root, textvariable=alice_public_var, state='readonly').pack()

tk.Label(root, text="Bob's Public Value:").pack()
tk.Entry(root, textvariable=bob_public_var, state='readonly').pack()

tk.Label(root, text="Shared Secret Key:").pack()
tk.Entry(root, textvariable=shared_key_var, state='readonly').pack()

tk.Button(root, text="Generate Shared Key", command=run_diffie_hellman).pack(pady=10)

tk.Label(root, text="Message Encryption using Shared Key (DES)", font=("Arial", 14)).pack(pady=10)

tk.Label(root, text="Plaintext Message:").pack()
tk.Entry(root, textvariable=plaintext_var).pack()

tk.Button(root, text="Encrypt", command=encrypt_message).pack(pady=5)

tk.Label(root, text="Ciphertext (Hexadecimal):").pack()
tk.Entry(root, textvariable=ciphertext_var, state='readonly').pack()

tk.Button(root, text="Decrypt", command=decrypt_message).pack(pady=5)

tk.Label(root, text="Decrypted Message:").pack()
tk.Entry(root, textvariable=decrypted_text_var, state='readonly').pack()

# Run the application
root.mainloop()

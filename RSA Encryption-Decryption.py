import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Util import number
import time

# RSA Key Generation function: Generates the public and private keys based on the chosen key size
def generate_keys(keysize):
    start_time = time.time()

    # Generate two large prime numbers p and q
    p = number.getPrime(keysize // 2)
    q = number.getPrime(keysize // 2)

    # Compute the modulus n = p * q
    n = p * q

    # Compute Euler's Totient function phi(n) = (p-1) * (q-1)
    phi = (p - 1) * (q - 1)

    # Choose the public exponent e (standard is 65537)
    e = 65537

    # Compute the private exponent d, which is the modular inverse of e mod phi
    d = pow(e, -1, phi)

    # Calculate how long it took to generate the keys
    end_time = time.time()
    elapsed_time = end_time - start_time

    # Return the keys and the time it took to generate them
    return (n, e, d), elapsed_time

# Encryption function: Encrypts the plaintext using the public key
def encrypt(plaintext, public_key):
    n, e = public_key
    start_time = time.time()

    # Convert each character of the plaintext to its ASCII value and encrypt it using RSA formula
    cipher = [pow(ord(char), e, n) for char in plaintext]

    # Calculate the time it took to encrypt the message
    end_time = time.time()
    elapsed_time = end_time - start_time

    # Return the ciphertext and the encryption time
    return cipher, elapsed_time

# Decryption function: Decrypts the ciphertext using the private key
def decrypt(ciphertext, private_key, n):
    d = private_key
    start_time = time.time()

    # Decrypt each encrypted character using RSA formula and convert it back to a string
    plain = ''.join([chr(pow(char, d, n)) for char in ciphertext])

    # Calculate the time it took to decrypt the message
    end_time = time.time()
    elapsed_time = end_time - start_time

    # Return the decrypted message and the decryption time
    return plain, elapsed_time

# GUI Class: Defines the layout and functionality of the application
class RSAApp:
    def __init__(self, root):
        self.root = root
        self.root.title("RSA Encryption/Decryption with Execution Time")

        # Drop-down box (Combobox) for selecting key size (512, 1024, 2048 bits)
        self.label_keysize = tk.Label(root, text="Key size (bits):")
        self.label_keysize.pack()
        
        self.keysize_combo = ttk.Combobox(root, values=[512, 1024, 2048])
        self.keysize_combo.set(1024)  # Default key size is 1024 bits
        self.keysize_combo.pack()

        # Button to generate keys
        self.generate_button = tk.Button(root, text="Generate Keys", command=self.generate_keys)
        self.generate_button.pack()

        # Text boxes to display the generated public and private keys
        self.label_public = tk.Label(root, text="Public Key:")
        self.label_public.pack()

        self.public_key_display = tk.Text(root, height=9, width=50)
        self.public_key_display.pack()

        self.label_private = tk.Label(root, text="Private Key:")
        self.label_private.pack()

        self.private_key_display = tk.Text(root, height=9, width=50)
        self.private_key_display.pack()

        # Text box to input the message to be encrypted
        self.label_message = tk.Label(root, text="Message to encrypt:")
        self.label_message.pack()

        self.message_entry = tk.Entry(root)
        self.message_entry.pack()

        # Buttons to perform encryption and decryption
        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack()

        # Text box to display the result of encryption/decryption
        self.label_result = tk.Label(root, text="Result:")
        self.label_result.pack()

        self.result_display = tk.Text(root, height=20, width=50)
        self.result_display.pack()

        # Label to show the execution time for different operations
        self.label_time = tk.Label(root, text="Execution Time:")
        self.label_time.pack()

        self.time_display = tk.Text(root, height=20, width=50)
        self.time_display.pack()

        # Variables to store the keys and ciphertext
        self.public_key = None
        self.private_key = None
        self.n = None
        self.ciphertext = None

    # Function to generate RSA keys based on the selected key size
    def generate_keys(self):
        try:
            # Get the selected key size from the dropdown
            keysize = int(self.keysize_combo.get())
        except ValueError:
            messagebox.showerror("Invalid input", "Please choose a valid key size.")
            return

        # Generate the keys and display them
        (self.n, self.e, self.d), time_taken = generate_keys(keysize)
        self.public_key = (self.n, self.e)
        self.private_key = self.d

        # Clear the previous content in the key display boxes
        self.public_key_display.delete(1.0, tk.END)
        self.private_key_display.delete(1.0, tk.END)

        # Insert the generated keys into the text boxes
        self.public_key_display.insert(tk.END, f"(n={self.n}, e={self.e})")
        self.private_key_display.insert(tk.END, f"(d={self.d})")

        # Append the time taken to generate the keys (without clearing previous times)
        self.time_display.insert(tk.END, f"Keys generated in {time_taken:.4f} seconds\n")

    # Function to encrypt the input message
    def encrypt_message(self):
        if self.public_key is None:
            messagebox.showerror("Error", "Please generate keys first.")
            return

        # Get the plaintext message from the input field
        plaintext = self.message_entry.get()
        if not plaintext:
            messagebox.showerror("Error", "Please enter a message to encrypt.")
            return

        # Encrypt the message and display the ciphertext
        self.ciphertext, time_taken = encrypt(plaintext, self.public_key)
        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, f"Ciphertext: {self.ciphertext}\n")

        # Append the time taken to encrypt the message (without clearing previous times)
        self.time_display.insert(tk.END, f"Message encrypted in {time_taken:.4f} seconds\n")

    # Function to decrypt the ciphertext
    def decrypt_message(self):
        if self.ciphertext is None:
            messagebox.showerror("Error", "Please encrypt a message first.")
            return

        # Decrypt the message and display the plaintext
        plaintext, time_taken = decrypt(self.ciphertext, self.private_key, self.n)
        self.result_display.delete(1.0, tk.END)
        self.result_display.insert(tk.END, f"Decrypted message: {plaintext}\n")

        # Append the time taken to decrypt the message (without clearing previous times)
        self.time_display.insert(tk.END, f"Message decrypted in {time_taken:.4f} seconds\n")

# Running the GUI Application
if __name__ == "__main__":
    root = tk.Tk()  # Create the main window
    app = RSAApp(root)  # Initialize the GUI application
    root.mainloop()  # Start the GUI event loop

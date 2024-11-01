import tkinter as tk
import socket
import threading
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from Crypto.Util.Padding import pad, unpad

class UserInterface:
    def __init__(self, name, port, partner_port):
        self.name = name
        self.port = port
        self.partner_port = partner_port

        # Generate Diffie-Hellman Key Pair using X25519
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.shared_key = None  # Placeholder for the shared key

        # Generate RSA Key Pair
        self.generate_rsa_keys()

        # Placeholders for partner's public keys
        self.partner_public_key = None  # Diffie-Hellman public key
        self.partner_rsa_public_key = None  # RSA public key

        self.des_key = None  # Placeholder for the DES key

        # Set up GUI
        self.setup_gui()

        # Start server to receive messages
        self.start_server()

    def setup_gui(self):
        """Sets up the GUI for the user interface with labels for clarity."""
        self.root = tk.Tk()
        self.root.title(f"User: {self.name}")

        # Label for received messages
        self.msg_display_label = tk.Label(self.root, text="Received Messages:")
        self.msg_display_label.pack()

        # Display area for received messages
        self.msg_display = tk.Text(self.root, height=10, width=50, state=tk.DISABLED)
        self.msg_display.pack()

        # Label for message entry
        self.msg_entry_label = tk.Label(self.root, text="Enter Message to Send:")
        self.msg_entry_label.pack()

        # Entry area for composing messages
        self.msg_entry = tk.Entry(self.root, width=50)
        self.msg_entry.pack()

        # Send button
        self.send_button = tk.Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack()

    def generate_rsa_keys(self):
        """Generates RSA key pair for signing and verification."""
        key = RSA.generate(2048)
        self.rsa_private_key = key
        self.rsa_public_key = key.publickey()

    def exchange_keys(self, partner_public_bytes, partner_rsa_pub_key_bytes, dh_public_signature):
        """Performs Diffie-Hellman key exchange and sets partner's RSA public key."""
        # Load partner's RSA public key
        self.partner_rsa_public_key = RSA.import_key(partner_rsa_pub_key_bytes)

        # Verify the signature of the partner's Diffie-Hellman public key
        if not self.verify_signature_bytes(partner_public_bytes, dh_public_signature):
            self.display_message("Received invalid signature for Diffie-Hellman public key.")
            return False

        # Exchange Diffie-Hellman key
        partner_public_key = x25519.X25519PublicKey.from_public_bytes(partner_public_bytes)
        self.partner_public_key = partner_public_key
        shared_key = self.private_key.exchange(partner_public_key)
        self.des_key = PBKDF2(shared_key, b'salt', dkLen=8)  # 8-byte DES key for CBC mode
        print(f"[{self.name}] Shared DES Key established.")
        return True

    def sign_message(self, message):
        """Signs the message using RSA private key."""
        h = SHA256.new(message)
        signature = pkcs1_15.new(self.rsa_private_key).sign(h)
        return signature

    def verify_signature(self, message, signature):
        """Verifies the RSA signature of the message using the partner's public key."""
        h = SHA256.new(message)
        try:
            pkcs1_15.new(self.partner_rsa_public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def verify_signature_bytes(self, data_bytes, signature):
        """Verifies the RSA signature of the data bytes using the partner's public key."""
        h = SHA256.new(data_bytes)
        try:
            pkcs1_15.new(self.partner_rsa_public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def encrypt_message(self, message):
        """Encrypts the message using DES with CBC mode and the shared key."""
        iv = get_random_bytes(8)  # 8-byte IV for DES
        cipher = DES.new(self.des_key, DES.MODE_CBC, iv)
        padded_message = pad(message.encode(), DES.block_size)
        encrypted_message = iv + cipher.encrypt(padded_message)
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        """Decrypts the message using DES with CBC mode and the shared key."""
        iv = encrypted_message[:8]
        cipher = DES.new(self.des_key, DES.MODE_CBC, iv)
        decrypted_padded_message = cipher.decrypt(encrypted_message[8:])
        decrypted_message = unpad(decrypted_padded_message, DES.block_size).decode()
        return decrypted_message

    def start_server(self):
        """Starts a server to listen for incoming messages."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(('localhost', self.port))
        self.server.listen(5)
        threading.Thread(target=self.receive_message, daemon=True).start()

    def receive_message(self):
        """Receives incoming messages and performs key exchange, decryption, and verification."""
        while True:
            try:
                conn, addr = self.server.accept()
                data = conn.recv(8192)
                conn.close()

                # Parse the received data using length headers
                pointer = 0

                # Get DH public key
                dh_pub_key_length = int.from_bytes(data[pointer:pointer+4], 'big')
                pointer += 4
                dh_public_bytes = data[pointer:pointer+dh_pub_key_length]
                pointer += dh_pub_key_length

                # Get RSA public key
                rsa_pub_key_length = int.from_bytes(data[pointer:pointer+4], 'big')
                pointer += 4
                partner_rsa_pub_key_bytes = data[pointer:pointer+rsa_pub_key_length]
                pointer += rsa_pub_key_length

                # Get DH public key signature
                dh_signature_length = int.from_bytes(data[pointer:pointer+4], 'big')
                pointer += 4
                dh_public_signature = data[pointer:pointer+dh_signature_length]
                pointer += dh_signature_length

                # Get encrypted message
                encrypted_message_length = int.from_bytes(data[pointer:pointer+4], 'big')
                pointer += 4
                encrypted_message = data[pointer:pointer+encrypted_message_length]
                pointer += encrypted_message_length

                # Get message signature
                message_signature_length = int.from_bytes(data[pointer:pointer+4], 'big')
                pointer += 4
                message_signature = data[pointer:pointer+message_signature_length]
                pointer += message_signature_length

                # Perform key exchange and set partner's public key if not already set
                if self.des_key is None:
                    exchange_success = self.exchange_keys(
                        dh_public_bytes,
                        partner_rsa_pub_key_bytes,
                        dh_public_signature
                    )
                    if not exchange_success:
                        self.display_message("Key exchange failed due to invalid signature.")
                        continue

                # Decrypt the message
                if encrypted_message_length > 0:
                    decrypted_message = self.decrypt_message(encrypted_message)

                    # Verify the message signature
                    if self.verify_signature(decrypted_message.encode(), message_signature):
                        self.display_message(f"Received (Verified): {decrypted_message}")
                    else:
                        self.display_message("Received message with invalid signature.")
                else:
                    # No message to process
                    pass

            except Exception as e:
                print(f"Error receiving message: {e}")

    def send_message(self):
        """Encrypts, signs, and sends the message along with public key for Diffie-Hellman exchange."""
        message = self.msg_entry.get()
        self.display_message(f"Sent: {message}")

        # Get your DH public key bytes
        dh_public_bytes = self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

        # Sign your DH public key
        dh_public_signature = self.sign_message(dh_public_bytes)

        # Export your RSA public key in PEM format
        rsa_public_key_bytes = self.rsa_public_key.export_key()

        # Prepare data with length headers
        data_parts = []

        # DH public key
        data_parts.append(len(dh_public_bytes).to_bytes(4, 'big'))
        data_parts.append(dh_public_bytes)

        # RSA public key
        data_parts.append(len(rsa_public_key_bytes).to_bytes(4, 'big'))
        data_parts.append(rsa_public_key_bytes)

        # DH public key signature
        data_parts.append(len(dh_public_signature).to_bytes(4, 'big'))
        data_parts.append(dh_public_signature)

        # If DES key is established, encrypt and sign the message
        if self.des_key is not None:
            encrypted_message = self.encrypt_message(message)
            message_signature = self.sign_message(message.encode())
        else:
            encrypted_message = b''
            message_signature = b''

        # Encrypted message
        data_parts.append(len(encrypted_message).to_bytes(4, 'big'))
        data_parts.append(encrypted_message)

        # Message signature
        data_parts.append(len(message_signature).to_bytes(4, 'big'))
        data_parts.append(message_signature)

        # Combine all parts into one byte string
        data_to_send = b''.join(data_parts)

        try:
            # Connect to the partner's server
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('localhost', self.partner_port))

            # Send the data
            client_socket.sendall(data_to_send)
            client_socket.close()
        except Exception as e:
            print(f"Error sending message: {e}")

    def display_message(self, message):
        """Displays messages in the message display area."""
        self.msg_display.config(state=tk.NORMAL)
        self.msg_display.insert(tk.END, f"{message}\n")
        self.msg_display.config(state=tk.DISABLED)
        # Scroll to the end
        self.msg_display.see(tk.END)

    def run(self):
        """Runs the GUI main loop."""
        self.root.mainloop()

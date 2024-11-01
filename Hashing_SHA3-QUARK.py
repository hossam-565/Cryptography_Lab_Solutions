import tkinter as tk
import time
import os
import psutil
from Crypto.Hash import SHA3_256
import random

# Simplified SHA-3 implementation
def simple_sha3(message: bytes):
    hash_obj = SHA3_256.new()
    hash_obj.update(message)
    return hash_obj.digest()

# Simulation of a lightweight Quark-like hash function
def simple_quark(message: bytes, rounds: int = 8):
    hash_value = 0
    for byte in message:
        hash_value ^= byte
    for _ in range(rounds):
        hash_value = (hash_value << 1 | hash_value >> 7) & 0xFF  # Bitwise rotation
    return bytes([hash_value] * 32)

# Function to measure CPU time and memory usage
def benchmark_hash_function(hash_function, message: bytes):
    process = psutil.Process(os.getpid())
    start_time = time.process_time()
    start_memory = process.memory_info().rss

    # Perform the hashing
    hash_output = hash_function(message)

    end_time = time.process_time()
    end_memory = process.memory_info().rss

    cpu_time = end_time - start_time
    memory_used = max(end_memory - start_memory, 0)  # Ensure we don't show negative values

    return hash_output, cpu_time, memory_used

# Function to handle button click event
def compare_hash_functions():
    input_text = input_entry.get().encode()  # Convert the input text to bytes

    # Benchmark SHA-3
    sha3_output, sha3_cpu_time, sha3_memory = benchmark_hash_function(simple_sha3, input_text)
    
    # Benchmark Quark
    quark_output, quark_cpu_time, quark_memory = benchmark_hash_function(simple_quark, input_text)

    # Update the results in the GUI
    sha3_result.set(f"SHA-3:\nCPU Time: {sha3_cpu_time:.5f} s\nMemory: {sha3_memory} bytes\nHash: {sha3_output.hex()}")
    quark_result.set(f"Quark:\nCPU Time: {quark_cpu_time:.5f} s\nMemory: {quark_memory} bytes\nHash: {quark_output.hex()}")

# Create the GUI
root = tk.Tk()
root.title("SHA-3 vs Quark Comparison")

# Input field for the text to hash
input_label = tk.Label(root, text="Enter text to hash:")
input_label.pack()

input_entry = tk.Entry(root, width=50)
input_entry.pack()

# Button to perform the comparison
compare_button = tk.Button(root, text="Compare", command=compare_hash_functions)
compare_button.pack()

# Results for SHA-3
sha3_result = tk.StringVar()
sha3_label = tk.Label(root, textvariable=sha3_result, justify="left")
sha3_label.pack()

# Results for Quark
quark_result = tk.StringVar()
quark_label = tk.Label(root, textvariable=quark_result, justify="left")
quark_label.pack()

# Run the GUI main loop
root.mainloop()

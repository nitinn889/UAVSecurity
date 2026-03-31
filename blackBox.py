"""

This code should be run on the raspberry pi 
Note: I used a broadcast address so it reads all incoming data 
"""
import socket
import ssl
import os
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# --- CONFIG ---
PORT = 14550
KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes

chacha = ChaCha20Poly1305(KEY)

# --- DATABASE ---
db = sqlite3.connect("blackbox.db")
cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce BLOB,
    encrypted_data BLOB
)
""")

# --- UDP RECEIVER ---
udp_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_in.bind(('0.0.0.0', PORT))

print(f" Pi Blackbox listening on port {PORT}...")

counter = 0

try:
    while True:
        print(" Waiting for telemetry...")
        data, addr = udp_in.recvfrom(2048)

        print(f" RECEIVED from {addr}: {data}")

        # --- ENCRYPT ---
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, data, None)

        # --- STORE ---
        cursor.execute(
            "INSERT INTO logs (nonce, encrypted_data) VALUES (?, ?)",
            (nonce, ciphertext)
        )

        counter += 1
        if counter % 20 == 0:
            db.commit()

        print(f" Stored packet #{counter}")

except Exception as e:
    print(f"Error: {e}")

finally:
    db.commit()
    db.close()

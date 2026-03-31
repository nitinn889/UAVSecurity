import socket
import ssl
import os
import sqlite3
import json
import base64
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# --- CONFIG ---
PORT = 14550
KEY = b'0123456789abcdef0123456789abcdef'

#  PUBLIC KEY (from sender)
PUBLIC_KEY_BYTES = b'W\t\x1e\xa4\xbf\x9e@\x14\xe6$\\03{n\x99W}m\xa0\xbab\xf3\xb5f\x8b:\t[\x03\xd9\x9a'

public_key = Ed25519PublicKey.from_public_bytes(PUBLIC_KEY_BYTES)

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

print(f" Secure Pi Blackbox listening on port {PORT}...")

counter = 0

try:
    while True:
        print(" Waiting for telemetry...")
        data, addr = udp_in.recvfrom(4096)

        print(f" RECEIVED raw packet from {addr}")

        try:
            # --- PARSE PACKET ---
            packet = json.loads(data.decode())

            telemetry = packet["data"]
            signature = base64.b64decode(packet["signature"])

            message = json.dumps(telemetry).encode()

            #  VERIFY SIGNATURE
            try:
                public_key.verify(signature, message)
            except Exception:
                print(" ATTACK DETECTED: Fake Drone / Invalid Signature")
                continue

            #  REPLAY ATTACK CHECK
            packet_time = telemetry["timestamp"]
            current_time = time.time()

            if abs(current_time - packet_time) > 5:
                print(" ATTACK DETECTED: Replay Attack")
                continue

            print("VALID telemetry")

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

            print(f"Stored packet #{counter}")

        except Exception:
            print("Malformed packet / Tampering detected")

except Exception as e:
    print(f"Error: {e}")

finally:
    db.commit()
    db.close()

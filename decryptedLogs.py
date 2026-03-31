
"""
this decrypts the data stored in blackbox.py and dislays
"""
import sqlite3
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# --- CONFIG ---
KEY = b'0123456789abcdef0123456789abcdef'
chacha = ChaCha20Poly1305(KEY)

# --- DB CONNECT ---
db = sqlite3.connect("blackbox.db")
cursor = db.cursor()

print(f"{'ID':<5} | {'ENCRYPTED (hex)':<40} | {'DECRYPTED DATA'}")
print("-" * 100)

try:
    cursor.execute("SELECT id, nonce, encrypted_data FROM logs")
    rows = cursor.fetchall()

    for row in rows:
        log_id, nonce, ciphertext = row

        # Show encrypted data (first few bytes)
        encrypted_preview = ciphertext.hex()[:40]

        try:
            # --- DECRYPT ---
            decrypted_bin = chacha.decrypt(nonce, ciphertext, None)
            telemetry_str = decrypted_bin.decode('utf-8')

            print(f"{log_id:<5} | {encrypted_preview:<40} | {telemetry_str}")

        except Exception:
            print(f"{log_id:<5} | {encrypted_preview:<40} | ❌ DECRYPTION FAILED")

finally:
    db.close()

"""
Secure Raspberry Pi Blackbox with:
- ChaCha20 encryption
- Ed25519 signature verification
- Replay attack detection
- GPS anomaly detection
- Real-time plotting of telemetry and anomalies
"""

import socket
import os
import sqlite3
import json
import base64
import time
import threading

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# For plotting
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# --- CONFIG ---
PORT = 14550
KEY = b'0123456789abcdef0123456789abcdef'  # 32 bytes for ChaCha20
PUBLIC_KEY_BYTES = b'W\t\x1e\xa4\xbf\x9e@\x14\xe6$\\03{n\x99W}m\xa0\xbab\xf3\xb5f\x8b:\t[\x03\xd9\x9a'

chacha = ChaCha20Poly1305(KEY)
public_key = Ed25519PublicKey.from_public_bytes(PUBLIC_KEY_BYTES)

# --- DATABASE ---
db = sqlite3.connect("blackbox.db", check_same_thread=False)
cursor = db.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce BLOB,
    encrypted_data BLOB
)
""")
db.commit()

# --- UDP RECEIVER ---
udp_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_in.bind(('0.0.0.0', PORT))
print(f" Secure Pi Blackbox listening on port {PORT}...")

# --- State ---
counter = 0
last_gps = None

# For plotting
lats, lons, anomaly_flags = [], [], []

# --- PLOTTING SETUP ---
plt.style.use('seaborn-dark')
fig, ax = plt.subplots()
sc = ax.scatter([], [], c=[], cmap='coolwarm', s=50)
ax.set_xlabel("Longitude")
ax.set_ylabel("Latitude")
ax.set_title("Drone GPS Telemetry (Red = Anomaly)")
ax.set_xlim(80.2, 80.35)
ax.set_ylim(13.07, 13.1)

def update_plot(frame):
    sc.set_offsets(list(zip(lons, lats)))
    sc.set_array(anomaly_flags)
    return sc,

ani = FuncAnimation(fig, update_plot, interval=1000, blit=True)
threading.Thread(target=plt.show, daemon=True).start()

# --- MAIN LOOP ---
try:
    while True:
        data, addr = udp_in.recvfrom(4096)

        try:
            packet = json.loads(data.decode())
            telemetry = packet["data"]
            signature = base64.b64decode(packet["signature"])
            message = json.dumps(telemetry, separators=(',', ':')).encode()

            # --- SIGNATURE VERIFICATION ---
            try:
                public_key.verify(signature, message)
            except Exception:
                print(" ATTACK DETECTED: Fake Drone / Invalid Signature")
                continue

            # --- REPLAY ATTACK CHECK ---
            packet_time = telemetry["timestamp"]
            current_time = time.time()
            if abs(current_time - packet_time) > 5:
                print(" ATTACK DETECTED: Replay Attack")
                continue

            # --- GPS ANOMALY DETECTION ---
            current_gps = telemetry["gps"]
            anomaly = 0  # 0 = normal, 1 = anomaly
            if last_gps:
                delta_lat = abs(current_gps["lat"] - last_gps["lat"])
                delta_lon = abs(current_gps["lon"] - last_gps["lon"])
                delta_alt = abs(current_gps["alt"] - last_gps["alt"])
                if delta_lat > 0.01 or delta_lon > 0.01 or delta_alt > 20:
                    print(" GPS ANOMALY DETECTED! Possible spoofing.")
                    anomaly = 1
                    telemetry["status"] = "ANOMALY"
            last_gps = current_gps

            # --- STORE DATA ---
            nonce = os.urandom(12)
            ciphertext = chacha.encrypt(nonce, data, None)
            cursor.execute(
                "INSERT INTO logs (nonce, encrypted_data) VALUES (?, ?)",
                (nonce, ciphertext)
            )
            counter += 1
            if counter % 20 == 0:
                db.commit()
            print(f" Stored packet #{counter}")

            # --- UPDATE PLOT DATA ---
            lats.append(current_gps["lat"])
            lons.append(current_gps["lon"])
            anomaly_flags.append(anomaly)

        except Exception as e:
            print(" Malformed packet / Tampering detected")

except KeyboardInterrupt:
    print("Shutting down blackbox...")

finally:
    db.commit()
    db.close()

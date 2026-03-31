import socket
import time
import json
import math
import random
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# --- CONFIG ---
PI_IP = '192.168.31.55'
PORT = 14550

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"🚁 Sending SECURE telemetry to {PI_IP}...")

# --- CRYPTO SETUP ---
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# ⚠️ PRINT THIS ONCE → copy to Pi
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

print("🔑 PUBLIC KEY (copy this to Pi):")
print(public_bytes)

def sign_message(message):
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode()

# --- INITIAL STATE ---
lat = 13.0827
lon = 80.2707
alt = 50

velocity = 5
heading = 0
battery = 100

t = 0

while True:
    try:
        t += 1

        # --- MOVEMENT ---
        heading += random.uniform(-5, 5)
        heading_rad = math.radians(heading)

        lat += 0.00005 * math.cos(heading_rad)
        lon += 0.00005 * math.sin(heading_rad)

        alt += random.uniform(-1, 1)
        alt = max(10, min(500, alt))

        # --- IMU ---
        pitch = random.uniform(-10, 10)
        roll = random.uniform(-10, 10)
        yaw = heading % 360

        # --- BATTERY ---
        battery -= 0.05
        battery = max(0, battery)

        # --- SIGNAL ---
        signal = random.randint(70, 100)

        # --- TELEMETRY ---
        telemetry = {
            "timestamp": time.time(),
            "gps": {
                "lat": round(lat, 6),
                "lon": round(lon, 6),
                "alt": round(alt, 2)
            },
            "velocity": round(velocity + random.uniform(-1, 1), 2),
            "imu": {
                "pitch": round(pitch, 2),
                "roll": round(roll, 2),
                "yaw": round(yaw, 2)
            },
            "battery": round(battery, 2),
            "signal_strength": signal,
            "status": "OK" if battery > 20 else "LOW_BATTERY"
        }

        # --- SIGNING ---
        message = json.dumps(telemetry).encode('utf-8')
        signature = sign_message(message)

        # --- FINAL PACKET ---
        packet = {
            "data": telemetry,
            "signature": signature
        }

        final_bytes = json.dumps(packet).encode('utf-8')

        # --- SEND ---
        sock.sendto(final_bytes, (PI_IP, PORT))

        print(f"📤 Sent SECURE packet")

        time.sleep(1)

    except Exception as e:
        print(f"❌ Sender error: {e}")
        time.sleep(1)

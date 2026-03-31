import socket
import time
import json
import math
import random
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# --- CONFIG ---
PI_IP = '192.168.31.55'
PORT = 14550

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# --- Drone starting position ---
lat = 13.0827
lon = 80.2707
alt = 50
velocity = 5  # m/s
heading = 0  # degrees

# --- Generate a fixed private key (so signature verification works) ---
private_key = Ed25519PrivateKey.generate()  # For demo, generate once
public_key = private_key.public_key()
# Normally, save private_key and reuse it so Pi's public key matches

print(" Sending realistic telemetry...")

while True:
    # --- Smooth flight movement ---
    heading += random.uniform(-5, 5)  # small turn
    heading_rad = math.radians(heading)
    lat += 0.00005 * math.cos(heading_rad)
    lon += 0.00005 * math.sin(heading_rad)
    alt += random.uniform(-0.5, 0.5)

    # --- Telemetry packet ---
    telemetry = {
        "timestamp": time.time(),
        "gps": {"lat": round(lat, 6), "lon": round(lon, 6), "alt": round(alt, 2)},
        "velocity": velocity + random.uniform(-1, 1),
        "battery": random.randint(50, 100),
        "status": "OK"
    }

    # --- SIGNING ---
    message = json.dumps(telemetry, separators=(',', ':')).encode()
    signature = private_key.sign(message)
    packet = {"data": telemetry, "signature": base64.b64encode(signature).decode()}

    sock.sendto(json.dumps(packet).encode(), (PI_IP, PORT))
    print(f"Sent: {telemetry}")
    time.sleep(0.5)  # send 2 packets per second for smoother graph

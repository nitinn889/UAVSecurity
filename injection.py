import socket
import json
import time
import random

PI_IP = '192.168.31.55'
PORT = 14550

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print("🚨 Continuous GPS Spoofing Started...")

while True:
    spoof_packet = {
        "data": {
            "timestamp": time.time(),
            "gps": {
                "lat": 13.0827 + random.uniform(0.05, 0.1),  # big jump
                "lon": 80.2707 + random.uniform(0.05, 0.1),
                "alt": random.randint(80, 150)
            },
            "velocity": random.randint(50, 120),
            "battery": random.randint(10, 100),
            "status": "SPOOF"
        },
        "signature": "INVALID_BASE64"
    }

    sock.sendto(json.dumps(spoof_packet).encode(), (PI_IP, PORT))
    print("🚨 Spoofed packet sent")

    time.sleep(2)

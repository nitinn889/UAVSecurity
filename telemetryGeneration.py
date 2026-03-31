"""
I have used the Pi's address as 192.168.31.55, this should be changed to the address of your pi, which the router will assign 

type Hostname-I on the pi to get that 

"""
import socket
import time
import json
import math
import random

# --- CONFIG ---
PI_IP = '192.168.31.55'
PORT = 14550

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

print(f"🚁 Sending realistic telemetry to {PI_IP}...")

# --- INITIAL STATE ---
lat = 13.0827   # Example start (Chennai-ish)
lon = 80.2707
alt = 50

velocity = 5  # m/s
heading = 0   # degrees
battery = 100

t = 0

while True:
    t += 1

    # --- SIMULATE MOVEMENT ---
    heading += random.uniform(-5, 5)  # slight turn
    heading_rad = math.radians(heading)

    # Move position gradually
    lat += 0.00005 * math.cos(heading_rad)
    lon += 0.00005 * math.sin(heading_rad)

    # Altitude changes smoothly
    alt += random.uniform(-1, 1)
    alt = max(10, min(500, alt))

    # --- SIMULATE IMU ---
    pitch = random.uniform(-10, 10)
    roll = random.uniform(-10, 10)
    yaw = heading % 360

    # --- BATTERY DRAIN ---
    battery -= 0.05
    battery = max(0, battery)

    # --- SIGNAL QUALITY ---
    signal = random.randint(70, 100)

    # --- TELEMETRY PACKET ---
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

    # --- SEND ---
    message = json.dumps(telemetry).encode('utf-8')
    sock.sendto(message, (PI_IP, PORT))

    print(f"Sent: {telemetry}")

    time.sleep(1)

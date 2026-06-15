# ================================================================
#  SIM-CAMERA — HTTP + RTSP Simulator
#  POSTs camera events to HTTP server
#  Polls /api/camera/poll every 10s for commands
#  Streams footage via RTSP on port 8554
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import os
import json
import time
import random
import threading
import requests
from datetime import datetime

#waiting for Service to run
time.sleep(10)

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
HTTP_SERVER = os.environ.get('HTTP_SERVER', '172.20.0.2')
DEVICE_ID   = os.environ.get('DEVICE_ID', 'camera_01')
INTERVAL    = 20

URL           = f"http://{HTTP_SERVER}:8080/api/camera"
POLL_URL      = f"http://{HTTP_SERVER}:8080/api/camera/poll"
HEARTBEAT_URL = f"http://{HTTP_SERVER}:8080/api/camera/heartbeat"
RTSP_URL      = f"rtsp://172.20.0.10:8554/live"

# ----------------------------------------------------------------
# DEVICE STATE
# ----------------------------------------------------------------
state = {
    "running":    True,
    "night_mode": False
}

EVENT_TYPES   = ["motion", "person", "vehicle", "tamper", "none"]
EVENT_WEIGHTS = [25, 30, 15, 5, 25]

# ----------------------------------------------------------------
# COMMAND HANDLER
# ----------------------------------------------------------------
def handle_command(command):
    if command == "start":
        state["running"] = True
        print(f"[{DEVICE_ID}] Camera started", flush=True)

    elif command == "stop":
        state["running"] = False
        print(f"[{DEVICE_ID}] Camera stopped", flush=True)

    elif command == "restart":
        state["running"] = False
        time.sleep(2)
        state["running"] = True
        print(f"[{DEVICE_ID}] Camera restarted", flush=True)

    else:
        print(f"[{DEVICE_ID}] Unknown command: {command}", flush=True)

# ----------------------------------------------------------------
# COMMAND POLL THREAD — polls /api/camera/poll every 10s
# ----------------------------------------------------------------
def command_loop():
    while True:
        try:
            resp    = requests.get(POLL_URL, timeout=3)
            data    = resp.json()
            command = data.get("command")

            if command:
                print(f"[{DEVICE_ID}] Command received: {command}", flush=True)
                handle_command(command)

        except Exception as e:
            print(f"[{DEVICE_ID}] Command poll error: {e}", flush=True)

        time.sleep(10)

# ----------------------------------------------------------------
# DATA SIMULATION
# ----------------------------------------------------------------
def is_night():
    hour = datetime.now().hour
    return hour >= 20 or hour < 6

def get_camera_event():
    # if stopped — report offline event
    if not state["running"]:
        return {
            "device_id":  DEVICE_ID,
            "event_type": "offline",
            "triggered":  False,
            "night_mode": state["night_mode"],
            "timestamp":  datetime.utcnow().isoformat()
        }

    night = is_night()
    state["night_mode"] = night
    event = random.choices(EVENT_TYPES, weights=EVENT_WEIGHTS)[0]

    return {
        "device_id":     DEVICE_ID,
        "event_type":    event,
        "triggered":     event != "none",
        "snapshot_url":  RTSP_URL if event != "none" else None,
        "resolution":    "1920x1080",
        "fps":           25,
        "bitrate_kbps":  random.randint(1000, 4000),
        "night_mode":    night,
        "ir_active":     night,
        "location":      "front_door",
        "confidence":    round(random.uniform(0.75, 0.99), 2) if event != "none" else None,
        "timestamp":     datetime.utcnow().isoformat()
    }

def get_heartbeat():
    return {
        "device_id":       DEVICE_ID,
        "status":          "online" if state["running"] else "stopped",
        "rtsp_url":        RTSP_URL,
        "uptime_seconds":  int(time.time()),
        "signal_strength": random.randint(-70, -30),
        "timestamp":       datetime.utcnow().isoformat()
    }

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    print(f"[{DEVICE_ID}] Starting — POSTing to {URL} every {INTERVAL}s", flush=True)
    print(f"[{DEVICE_ID}] RTSP stream: {RTSP_URL}", flush=True)

    time.sleep(8)

    # start command polling in background thread
    cmd_thread = threading.Thread(target=command_loop, daemon=True)
    cmd_thread.start()

    heartbeat_counter = 0

    while True:
        try:
            # always send heartbeat
            requests.post(HEARTBEAT_URL, json=get_heartbeat(), timeout=5)

            heartbeat_counter += 1
            if heartbeat_counter >= (INTERVAL // 10):
                data     = get_camera_event()
                response = requests.post(URL, json=data, timeout=5)
                print(f"[{DEVICE_ID}] Event [{data['event_type']}] running:{state['running']} — {response.status_code}", flush=True)
                heartbeat_counter = 0

            # random offline simulation — only when running
            if state["running"] and random.random() < 0.02:
                offline_duration = random.randint(30, 120)
                print(f"[{DEVICE_ID}] Going offline for {offline_duration}s...", flush=True)
                state["running"] = False
                time.sleep(offline_duration)
                state["running"] = True
                print(f"[{DEVICE_ID}] Back online", flush=True)

        except Exception as e:
            print(f"[{DEVICE_ID}] Error: {e}", flush=True)

        time.sleep(10)

if __name__ == '__main__':
    main()
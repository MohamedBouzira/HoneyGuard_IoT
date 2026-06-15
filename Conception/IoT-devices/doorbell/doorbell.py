# ================================================================
#  SIM-DOORBELL — HTTP Simulator
#  POSTs doorbell events to HTTP server
#  Polls /api/doorbell/poll every 10s for commands
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import os
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
DEVICE_ID   = os.environ.get('DEVICE_ID', 'doorbell_01')
INTERVAL    = 30

URL           = f"http://{HTTP_SERVER}:8080/api/doorbell"
POLL_URL      = f"http://{HTTP_SERVER}:8080/api/doorbell/poll"
HEARTBEAT_URL = f"http://{HTTP_SERVER}:8080/api/doorbell/heartbeat"

# ----------------------------------------------------------------
# DEVICE STATE
# ----------------------------------------------------------------
state = {
    "enabled": True,
    "muted":   False
}

battery_level = round(random.uniform(70, 100), 1)

EVENT_TYPES   = ["ring", "motion", "person", "package_delivered", "none"]
EVENT_WEIGHTS = [20, 25, 20, 10, 25]

# ----------------------------------------------------------------
# COMMAND HANDLER
# ----------------------------------------------------------------
def handle_command(command):
    if command == "enable":
        state["enabled"] = True
        state["muted"]   = False
        print(f"[{DEVICE_ID}] Enabled", flush=True)

    elif command == "disable":
        state["enabled"] = False
        print(f"[{DEVICE_ID}] Disabled", flush=True)

    elif command == "mute":
        state["muted"] = True
        print(f"[{DEVICE_ID}] Muted", flush=True)

    else:
        print(f"[{DEVICE_ID}] Unknown command: {command}", flush=True)

# ----------------------------------------------------------------
# COMMAND POLL THREAD
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
    return hour >= 22 or hour < 6

def get_battery():
    global battery_level
    battery_level = max(0, battery_level - random.uniform(0, 0.05))
    return round(battery_level, 1)

def get_doorbell_event():
    # if disabled — report offline
    if not state["enabled"]:
        return {
            "device_id":  DEVICE_ID,
            "event_type": "offline",
            "triggered":  False,
            "timestamp":  datetime.utcnow().isoformat()
        }

    night = is_night()
    event = random.choices(EVENT_TYPES, weights=EVENT_WEIGHTS)[0]

    return {
        "device_id":        DEVICE_ID,
        "event_type":       event,
        "triggered":        event != "none",
        "button_pressed":   event == "ring",
        "visitor_detected": event in ["ring", "person"],
        "package_detected": event == "package_delivered",
        "muted":            state["muted"],
        "night_mode":       night,
        "ir_active":        night,
        "battery_level":    get_battery(),
        "wifi_signal":      random.randint(-70, -30),
        "location":         "front_door",
        "timestamp":        datetime.utcnow().isoformat()
    }

def get_heartbeat():
    return {
        "device_id":     DEVICE_ID,
        "status":        "online" if state["enabled"] else "disabled",
        "battery_level": get_battery(),
        "wifi_signal":   random.randint(-70, -30),
        "firmware":      "2.4.1",
        "timestamp":     datetime.utcnow().isoformat()
    }

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    print(f"[{DEVICE_ID}] Starting — POSTing to {URL} every {INTERVAL}s", flush=True)

    time.sleep(5)

    # start command polling thread
    cmd_thread = threading.Thread(target=command_loop, daemon=True)
    cmd_thread.start()

    heartbeat_counter = 0

    while True:
        try:
            requests.post(HEARTBEAT_URL, json=get_heartbeat(), timeout=5)

            heartbeat_counter += 1
            if heartbeat_counter >= (INTERVAL // 10):
                data     = get_doorbell_event()
                response = requests.post(URL, json=data, timeout=5)
                print(f"[{DEVICE_ID}] Event [{data['event_type']}] enabled:{state['enabled']} muted:{state['muted']} — {response.status_code}", flush=True)
                heartbeat_counter = 0

            if state["enabled"] and random.random() < 0.01:
                offline_duration = random.randint(15, 60)
                print(f"[{DEVICE_ID}] Going offline for {offline_duration}s...", flush=True)
                time.sleep(offline_duration)
                print(f"[{DEVICE_ID}] Back online", flush=True)

        except Exception as e:
            print(f"[{DEVICE_ID}] Error: {e}", flush=True)

        time.sleep(10)

if __name__ == '__main__':
    main()
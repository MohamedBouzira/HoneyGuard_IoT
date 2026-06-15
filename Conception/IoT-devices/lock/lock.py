# ================================================================
#  SIM-LOCK — MQTT Simulator
#  Publishes lock state, battery, tamper alert
#  Listens on home/lock/command for commands from IoT platform
#  PFE 2025 — Mohamed Bouzira & Bakhti Rayane Abderaouef
# ================================================================

import os
import json
import time
import random
import paho.mqtt.client as mqtt
from datetime import datetime

#waiting for Service to run
time.sleep(10)

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
BROKER      = os.environ.get('BROKER', '172.20.0.2')
BROKER_PORT = int(os.environ.get('BROKER_PORT', 1883))
DEVICE_ID   = os.environ.get('DEVICE_ID', 'lock_01')
INTERVAL    = 30

TOPIC_STATE   = "home/lock/state"
TOPIC_BATTERY = "home/lock/battery"
TOPIC_TAMPER  = "home/lock/tamper"
TOPIC_COMMAND = "home/lock/command"

# ----------------------------------------------------------------
# DEVICE STATE
# ----------------------------------------------------------------
state = {
    "locked": True    # starts locked
}

battery_level = random.uniform(70, 100)

# ----------------------------------------------------------------
# CALLBACKS
# ----------------------------------------------------------------
def on_connect(client, userdata, flags, reason_code, properties):
    if reason_code == 0:
        print(f"[{DEVICE_ID}] Connected to broker {BROKER}:{BROKER_PORT}", flush=True)
        client.subscribe(TOPIC_COMMAND)
        print(f"[{DEVICE_ID}] Subscribed to {TOPIC_COMMAND}", flush=True)
    else:
        print(f"[{DEVICE_ID}] Connection failed: {reason_code}", flush=True)

def on_disconnect(client, userdata, flags, reason_code, properties):
    print(f"[{DEVICE_ID}] Disconnected — retrying...", flush=True)

def on_message(client, userdata, msg):
    try:
        payload = msg.payload.decode('utf-8')
        print(f"[{DEVICE_ID}] Command received: {payload}", flush=True)

        data    = json.loads(payload)
        command = data.get("command", payload)

        if command == "lock":
            state["locked"] = True
            print(f"[{DEVICE_ID}] Locked", flush=True)

        elif command == "unlock":
            state["locked"] = False
            print(f"[{DEVICE_ID}] Unlocked", flush=True)

        else:
            print(f"[{DEVICE_ID}] Unknown command: {command}", flush=True)

    except Exception as e:
        print(f"[{DEVICE_ID}] Command parse error: {e}", flush=True)

# ----------------------------------------------------------------
# DATA SIMULATION
# ----------------------------------------------------------------
def get_state():
    return "locked" if state["locked"] else "unlocked"

def get_battery():
    global battery_level
    battery_level = max(0, battery_level - random.uniform(0, 0.1))
    return round(battery_level, 1)

def get_tamper():
    return random.choices([False] * 9 + [True])[0]

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    client = mqtt.Client(
        client_id=DEVICE_ID,
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2
    )
    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    while True:
        try:
            client.connect(BROKER, BROKER_PORT, keepalive=60)
            break
        except Exception as e:
            print(f"[{DEVICE_ID}] Broker not ready, retrying in 5s... ({e})", flush=True)
            time.sleep(5)

    client.loop_start()
    print(f"[{DEVICE_ID}] Starting publish loop every {INTERVAL}s", flush=True)

    while True:
        timestamp = datetime.utcnow().isoformat()

        client.publish(TOPIC_STATE, json.dumps({
            "device_id": DEVICE_ID,
            "value":     get_state(),
            "timestamp": timestamp
        }))

        client.publish(TOPIC_BATTERY, json.dumps({
            "device_id": DEVICE_ID,
            "value":     get_battery(),
            "unit":      "percent",
            "timestamp": timestamp
        }))

        client.publish(TOPIC_TAMPER, json.dumps({
            "device_id": DEVICE_ID,
            "value":     get_tamper(),
            "timestamp": timestamp
        }))

        print(f"[{DEVICE_ID}] Published — state:{get_state()} battery:{round(battery_level,1)}", flush=True)
        time.sleep(INTERVAL)

if __name__ == '__main__':
    main()
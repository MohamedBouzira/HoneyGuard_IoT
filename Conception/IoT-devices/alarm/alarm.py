# ================================================================
#  SIM-ALARM — MQTT Simulator
#  Publishes alarm state, zone events, siren state
#  Listens on home/alarm/command for commands from IoT platform
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
DEVICE_ID   = os.environ.get('DEVICE_ID', 'alarm_01')
INTERVAL    = 30

TOPIC_STATE   = "home/alarm/state"
TOPIC_ZONE    = "home/alarm/zone"
TOPIC_SIREN   = "home/alarm/siren"
TOPIC_COMMAND = "home/alarm/command"

# ----------------------------------------------------------------
# DEVICE STATE
# ----------------------------------------------------------------
state = {
    "armed":  "disarmed",   # disarmed / armed_home / armed_away
    "siren":  False
}

ZONES = ["front_door", "back_door", "living_room", "kitchen", "garage", "bedroom"]

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

        if command == "arm_home":
            state["armed"] = "armed_home"
            state["siren"] = False
            print(f"[{DEVICE_ID}] Armed — home mode", flush=True)

        elif command == "arm_away":
            state["armed"] = "armed_away"
            state["siren"] = False
            print(f"[{DEVICE_ID}] Armed — away mode", flush=True)

        elif command == "disarm":
            state["armed"] = "disarmed"
            state["siren"] = False
            print(f"[{DEVICE_ID}] Disarmed", flush=True)

        else:
            print(f"[{DEVICE_ID}] Unknown command: {command}", flush=True)

    except Exception as e:
        print(f"[{DEVICE_ID}] Command parse error: {e}", flush=True)

# ----------------------------------------------------------------
# DATA SIMULATION
# if armed and motion in zone → trigger siren randomly
# ----------------------------------------------------------------
def get_zone():
    zone      = random.choice(ZONES)
    triggered = False

    # if armed, small chance of zone trigger
    if state["armed"] in ("armed_home", "armed_away"):
        triggered = random.choices([False, True], weights=[92, 8])[0]
        if triggered:
            state["siren"] = True
            print(f"[{DEVICE_ID}] Zone triggered: {zone} — siren activated", flush=True)

    return {"zone": zone, "triggered": triggered}

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
        zone_data = get_zone()

        client.publish(TOPIC_STATE, json.dumps({
            "device_id": DEVICE_ID,
            "value":     state["armed"],
            "timestamp": timestamp
        }))

        client.publish(TOPIC_ZONE, json.dumps({
            "device_id": DEVICE_ID,
            **zone_data,
            "timestamp": timestamp
        }))

        client.publish(TOPIC_SIREN, json.dumps({
            "device_id": DEVICE_ID,
            "value":     state["siren"],
            "timestamp": timestamp
        }))

        print(f"[{DEVICE_ID}] Published — state:{state['armed']} siren:{state['siren']}", flush=True)
        time.sleep(INTERVAL)

if __name__ == '__main__':
    main()